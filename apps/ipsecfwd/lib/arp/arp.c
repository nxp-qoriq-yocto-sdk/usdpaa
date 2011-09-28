/**
 \file arp.c
 */
/*
 * Copyright (C) 2010,2011 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "arp.h"

struct ppac_interface *ipfwd_get_iface_for_ip(in_addr_t ip_addr);

#ifdef ARP_ENABLE
#include "ip/ip_common.h"

#include <usdpaa/dma_mem.h>

#include <netinet/if_ether.h>

#define	ARP_HDR_LEN	28	/**<ARP Header Length */

extern struct config_info config_info;
static spinlock_t arp_lock = SPIN_LOCK_UNLOCKED;

extern int is_iface_ip(in_addr_t ip_addr);

static int arp_handle_request(struct ether_header *eth_hdr,
		       struct node_t *node)
{
	struct ether_arp *arp;

	arp = (typeof(arp))(eth_hdr + 1);
	if (memcmp(arp->arp_tpa, &node->ip, arp->arp_pln))
		return -1;

	memcpy(arp->arp_tpa, arp->arp_spa, arp->arp_pln);
	memcpy(arp->arp_spa, &node->ip, arp->arp_pln);
	arp->arp_op = ARPOP_REPLY;
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,
		sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr->ether_shost, &node->mac, sizeof(eth_hdr->ether_shost));
	memcpy(arp->arp_tha, eth_hdr->ether_dhost, arp->arp_hln);
	memcpy(arp->arp_sha, eth_hdr->ether_shost, arp->arp_hln);
	return 0;
}

void arp_handler(const struct annotations_t *notes, void *data)
{
	struct ether_arp *arp;
	struct neigh_t *n;
	struct node_t new_node;
	struct ppac_interface *dev;
	int merge_flag = 0;
	in_addr_t arp_spa, arp_tpa;

	arp = data + ETHER_HDR_LEN;
	memcpy(&arp_tpa, arp->arp_tpa, arp->arp_pln);
	dev = ipfwd_get_iface_for_ip(arp_tpa);

	if (unlikely(!dev))
		return;

	memcpy(&arp_spa, arp->arp_spa, arp->arp_pln);
	if (arp->arp_op == ARPOP_REPLY)
		pr_info("Got ARP reply from IP %x\n", arp_spa);

	spin_lock(&arp_lock);
	n = neigh_lookup(stack.arp_table, arp_spa, sizeof(arp_spa));
	if (n) {
		if (arp->arp_op == ARPOP_REPLY) {
			/* stop retransmit timer */
			if (NEIGH_STATE_PENDING == n->neigh_state) {
				if (0 != stop_timer(n->retransmit_timer)) {
					pr_err
					    ("%s: stopping timer 0x%x failed\n",
						__func__, n->retransmit_timer);
					return;

				} else
					pr_info("%s: timer 0x%x stopped...\n",
						__func__, n->retransmit_timer);
			/* Send first packet */
			dev->xmit(dev, &n->fd, NULL);
			}
		}

		/* Update ARP cache entry */
		n->neigh_state = NEIGH_STATE_UNKNOWN;
		if (NULL == neigh_update(n, arp->arp_sha,
					 NEIGH_STATE_PERMANENT)) {
			pr_err("%s: unable to update neigh entry\n",
				__func__);
			spin_unlock(&arp_lock);
			return;
		}
		merge_flag = 1;
	}

	if (is_iface_ip(arp_tpa)) {
		pr_info("%s: Target IP is not for own interface\n", __func__);
		free_buff(&notes->dqrr->fd);
		spin_unlock(&arp_lock);
		return;
	}

	if (!merge_flag) {
		memcpy(&new_node.mac, arp->arp_sha, arp->arp_hln);
		memcpy(&new_node.ip, arp->arp_spa, arp->arp_pln);
		if (0 > add_arp_entry(stack.arp_table, NULL, &new_node)) {
			pr_err("%s: failed to add ARP entry\n", __func__);
			free_buff(&notes->dqrr->fd);
			spin_unlock(&arp_lock);
			return;
		}
		merge_flag = 1;
	}

	spin_unlock(&arp_lock);

	if (arp->arp_op == ARPOP_REQUEST) {
		pr_info("Got ARP request from IP 0x%x\n", arp_spa);

		memcpy(&new_node.mac, dev->dev_addr, dev->dev_addr_len);
		memcpy(&new_node.ip, arp->arp_tpa, arp->arp_pln);
		arp_handle_request(data, &new_node);
		dev->xmit(dev, &notes->dqrr->fd, NULL);
		pr_info("Sent ARP reply for IP 0x%x\n", arp_tpa);
	} else {
		free_buff(&notes->dqrr->fd);
	}
}

int arp_send_request(struct ppac_interface *dev, in_addr_t target_ip)
{
	struct ether_arp *arp;
	struct node_t *target_iface_node;
	struct bm_buffer bman_buf;
	struct qm_fd fd;
	struct ether_header *eth_hdr;
	uint32_t len;
	struct eth_port_cfg *p_cfg;

	len = ETHER_HDR_LEN + ARP_HDR_LEN + ETHER_CRC_LEN;
	if (0 >= dpa_allocator_get_buff(buff_allocator, len, &bman_buf)) {
		pr_err("%s: couldn't allocate buf of size %d\n",
			__func__, len);
		return -ENOMEM;
	}

	qm_fd_addr_set64(&fd, bm_buf_addr(&bman_buf));
	fd.bpid = bman_buf.bpid;
	fd.format = qm_fd_contig;
	fd.offset = 0;
	fd.length20 = len;

	eth_hdr = dma_mem_ptov(qm_fd_addr(&fd));
	p_cfg = &config_info.port[dev->ifindex].port_cfg;
	memset(eth_hdr->ether_dhost, -1, sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr->ether_shost, p_cfg->mac_addr,
		sizeof(eth_hdr->ether_shost));
	eth_hdr->ether_type = ETHERTYPE_ARP;

	arp = (typeof(arp))(eth_hdr + 1);
	arp->arp_hrd = ARPHRD_ETHER;
	arp->arp_pro = ETHERTYPE_IP;
	arp->arp_hln = sizeof(arp->arp_sha);
	arp->arp_pln = sizeof(arp->arp_spa);
	arp->arp_op = ARPOP_REQUEST;

	target_iface_node = ipfwd_get_iface_for_ip(target_ip);
	if (!target_iface_node) {
		free_buff(&fd);
		return -ENODEV;
	}

	memcpy(arp->arp_sha, eth_hdr->ether_shost, arp->arp_hln);
	memcpy(arp->arp_spa, &target_iface_node->ip, arp->arp_pln);
	memset(arp->arp_tha, 0, arp->arp_hln);
	memcpy(arp->arp_tpa, &target_ip, arp->arp_pln);

	pr_info("Sending ARP request for IP %x\n", target_ip);
	dev->xmit(dev, &fd, NULL);

	return 0;
}
#endif	/* ARP_ENABLE */

static void arp_solicit(struct neigh_t *n, const void *annotations,
		void *ll_payload)
{
	const struct annotations_t *notes = annotations;
#ifdef STATS_TBD
	decorated_notify_inc_64(&n->nt->stats->solicit_errors);
#endif
	free_buff(&notes->dqrr->fd);
}

static void arp_error_handler(struct neigh_t *n, const void *annotations,
		void *ll_payload)
{
	const struct annotations_t *notes = annotations;
#ifdef STATS_TBD
	decorated_notify_inc_64(&n->nt->stats->protocol_errors);
#endif
	free_buff(&notes->dqrr->fd);
}

static void arp_constructor(struct neigh_t *n)
{
	n->funcs->solicit = &arp_solicit;
	n->funcs->error_handler = &arp_error_handler;
}

int arp_table_init(struct neigh_table_t *nt)
{
	nt->proto_len = sizeof(in_addr_t);
	nt->constructor = arp_constructor;
	nt->config.base_reachable_timeout = 30;
	nt->config.reachable_timeout = 30;
	nt->config.retrans_timeout = 1;
	nt->config.quiesce_timeout = 5;
	nt->config.solicit_queue_len = 1;

	return 0;
}

int add_arp_entry(struct neigh_table_t *arp_tab, struct ppac_interface *dev,
			struct node_t *node)
{
	struct neigh_t *n;

	n = neigh_create(arp_tab);
	if (NULL == n) {
		pr_err("%s: Unable to create Neigh Entry\n", __func__);
		return -EINVAL;
	}

	if (NULL == dev) {
		dev = ipfwd_get_iface_for_ip(node->ip);
		if (NULL == dev) {
			pr_err("%s: failed to get device\n", __func__);
			return -EINVAL;
		}
	}

	if (NULL == neigh_init(arp_tab, n, dev, &node->ip)) {
		pr_err("%s: Unable to init Neigh Entry\n", __func__);
		return -EINVAL;
	}
	if (false == neigh_add(arp_tab, n)) {
		pr_err("%s: Unable to add Neigh Entry\n", __func__);
		return -EINVAL;
	}
	if (NULL ==  neigh_update(n, node->mac.ether_addr_octet,
				  NEIGH_STATE_PERMANENT)) {
		pr_err("%s: Unable to update Neigh Entry\n", __func__);
		return -EINVAL;
	}

	return 0;
}
