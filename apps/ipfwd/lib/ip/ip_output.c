/**
 \file ip_output.c
 */
/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc.
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
#include "net/neigh.h"
#include "app_common.h"
#include "ip/ip.h"
#include "net/rt.h"
#include "ip/ip_common.h"
#include "ip/ip_output.h"
#include "ip/ip_hooks.h"
#include "ethernet/eth.h"
#include "net/net_dev.h"
#include "net/frame_handler.h"
#include "net/ll_cache.h"
#include "ip/ip_rc.h"
#include "ip/ip_common.h"
#include "arp/arp.h"
#include <linux/if_ether.h>
#include <assert.h>

#ifdef NOT_USDPAA
void arp_retransmit_cb(uint32_t timer_id, void *p_data)
{
	uint32_t gw_ip;
	struct neigh_t *n;
	struct net_dev_t *dev;

	APP_DEBUG("%s: ARP retransmit timer ID 0x%x expired", __func__,
			timer_id);

	gw_ip = *(uint32_t *) p_data;
	n = neigh_lookup(stack.arp_table, gw_ip, IP_ADDRESS_BYTES);
	if (unlikely(NULL == n)) {
		APP_ERROR("%s: neighbour entry not found for IP 0x%x",
			__func__, gw_ip);
		return;
	}

	if (n->retransmit_count < 3) {
		dev = n->dev;
		arp_send_request(dev, n->proto_addr[0]);
		n->retransmit_count++;

	} else {
		APP_INFO("%s: MAX no. of %d ARP retransmission attempted",
				__func__, n->retransmit_count);
		if (0 != stop_timer(timer_id)) {
			APP_ERROR("%s Stopping ARP retransmit timer failed",
					 __func__, timer_id);
			return;
		} else
			APP_INFO("%s: ARP retransmit timer 0x%x stopped...",
					__func__, timer_id);

		n->retransmit_count = 0;
		n->neigh_state = NEIGH_STATE_FAILED;
	}
}
#endif

/*
 * If packet length > next_hop mtu, call ip_fragment
 */
enum IP_STATUS ip_send(struct ip_context_t *ctxt,
		       struct annotations_t *notes, struct ip_header_t *ip_hdr)
{
	struct annotations_t *cur_notes;

	assert(notes->dest != NULL);

	markpoint(13);
	cur_notes = notes;
	return ip_output(ctxt, cur_notes, ip_hdr);
}

/*
 * Call intervening POSTROUTING hooks for each frame
 */
enum IP_STATUS ip_output(struct ip_context_t *ctxt,
			 struct annotations_t *notes,
			 struct ip_header_t *ip_hdr)
{
	markpoint(14);
	return exec_hook(ctxt->hooks, IP_HOOK_POSTROUTING, ctxt, notes,
			 ip_hdr, &ip_output_finish, SOURCE_POST_FMAN);
}

/*
 * Find the correct neighbor for this frame, using ARP tables
 */
enum IP_STATUS ip_output_finish(struct ip_context_t *ctxt __UNUSED,
				struct annotations_t *notes,
				struct ip_header_t *ip_hdr,
				enum state source)
{
	struct ll_cache_t *ll_cache;
	struct neigh_t *neighbor;
	struct net_dev_t *dev;
	enum IP_STATUS retval;
	struct ethernet_header_t *ll_hdr;
#ifdef NOT_USDPAA
	uint32_t timer_id;
#endif
#ifdef IPSECFWD_HYBRID_GENERATOR
	uint8_t mac_temp[6];
	uint32_t temp;
#endif

	markpoint(15);
	retval = IP_STATUS_ACCEPT;

	neighbor = notes->dest->neighbor;
	dev = neighbor->dev;
	ll_cache = neighbor->ll_cache;

	if (unlikely(ll_cache == NULL)) {
		if (NEIGH_STATE_PENDING == neighbor->neigh_state) {
			APP_DEBUG("Discarding packet destined for IP 0x%x",
						neighbor->proto_addr[0]);
			APP_DEBUG("ARP entry state is pending");
			/* Discard successive packet (on the assumption the
			 * packet will be retransmitted by a higher network
			 * layer)
			 */
			free_buff(notes->fd);
			return IP_STATUS_DROP;
		}

		APP_INFO("Could not found ARP cache entries for IP 0x%x",
				neighbor->proto_addr[0]);

		/* Save first packet and forward it upon ARP reply */
		memcpy(&neighbor->fd, notes->fd, sizeof(struct qm_fd));

		/* Create and send ARP request */
#ifdef NOT_USDPAA
		arp_send_request(dev, neighbor->proto_addr[0]);
		timer_id = start_timer(ARP_RETRANSMIT_INTERVAL, true, NULL,
				SWI_PRI_HIGH,
				arp_retransmit_cb,
				neighbor->proto_addr);

		if (INV_TIMER_ID == timer_id)
			APP_ERROR("%s: ARP retransmit timer failed", __func__);
		else {
			APP_INFO("%s: ARP retransmit timer 0x%x started...",
				__func__, timer_id);
			neighbor->retransmit_timer = timer_id;
		}
#endif
		neighbor->neigh_state = NEIGH_STATE_PENDING;
		neighbor->retransmit_count = 0;
	} else {
		ll_hdr = (void *)((char *) ip_hdr - (ll_cache->ll_hdr_len));
		ll_cache_output(ll_hdr, ll_cache);
#ifdef IPSECFWD_HYBRID_GENERATOR
		ether_header_swap(ll_hdr);
		temp = ip_hdr->src_addr.word;
		ip_hdr->src_addr.word = ip_hdr->dst_addr.word;
		ip_hdr->dst_addr.word = temp;
#endif
		dev->xmit(dev, notes->fd, ll_hdr);
	}

	return retval;
}
