/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ppac.h>
#include "ppam_if.h"
#include <ppac_interface.h>
#include "internal/compat.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <signal.h>

#include "usdpaa/fsl_dpa_classifier.h"
#include "usdpaa/fsl_dpa_ipsec.h"
#include "xfrm_km.h"
#include "app_config.h"
#include "app_common.h"
#include "neigh_sizing.h"

#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_NEXT(na) ((na) = ((struct nlattr *)((char *)(na) \
				+ NLA_ALIGN((na)->nla_len))))

static int neigh_cc_num_keys[] = NEIGH_TABLES_NUM_KEYS;
static int neigh_cc_key_size[] = NEIGH_TABLES_KEY_SIZE;

static int local_cc_num_keys[] = LOCAL_TABLES_NUM_KEYS;
static int local_cc_key_size[] = LOCAL_TABLES_KEY_SIZE;

static struct fman_if *ib_eth, *ob_eth, *ob_oh_post, *ib_oh;

static void make_bitmask(u8 *mask, int size, int prefixlen)
{
	int nbytes, nbits;
	int i = 0;
	nbytes = prefixlen / 8;
	nbits = prefixlen % 8;

	if (nbytes)
		for (i = 0; i < nbytes; i++)
			mask[i] = 0xFF;
	if (nbits)
		mask[i] = (u8)(~((1<<(8 - nbits)) - 1));
}

static int init_tables(t_Handle *cc_nodes, int *num_keys,
			  int *key_size, int **td)
{
	int i, j, cls_td;
	struct dpa_cls_tbl_params cls_tbl_params;
	int ret;

	*td = malloc(sizeof(int) *  MAX_ETHER_TYPES);
	if (!*td)
		return -ENOMEM;

	for (i = 0; i < MAX_ETHER_TYPES; i++) {
		memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
		cls_tbl_params.cc_node = cc_nodes[i];
		cls_tbl_params.type = DPA_CLS_TBL_EXACT_MATCH;
		cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_KEY;
		cls_tbl_params.exact_match_params.entries_cnt =
			num_keys[i];
		cls_tbl_params.exact_match_params.key_size =
			key_size[i];
		ret = dpa_classif_table_create(&cls_tbl_params,
						&cls_td);
		if (ret < 0) {
			fprintf(stderr, "%s:%d: Error creating table (%d),"
				"err %d\n", __func__, __LINE__, i, ret);
			for (j = 0; j < i; j++) {
				cls_td = (*td)[j];
				dpa_classif_table_free(cls_td);
			}
			free(*td);
			return ret;
		}
		(*td)[i] = cls_td;
	}
	return 0;
}

static int init_neigh_tables(int fm, int port_idx, int port_type,
			     t_Handle *cc_nodes)
{
	int ret;
	struct ppac_interface *ppac_if = get_ppac_if(fm, port_idx, port_type);
	ret = init_tables(cc_nodes, neigh_cc_num_keys, neigh_cc_key_size,
			&ppac_if->ppam_data.hhm_td);
	return ret;
}

static void cleanup_neigh_tables(int fm, int port_idx, int port_type)
{
	int i, td;
	struct ppac_interface *ppac_if = get_ppac_if(fm, port_idx, port_type);
	for (i = 0; i < MAX_ETHER_TYPES; i++) {
		td = (ppac_if->ppam_data.hhm_td)[i];
		dpa_classif_table_free(td);
	}
}

static int init_local_tables(int fm, int port_idx, int port_type,
			t_Handle *cc_nodes)
{
	int ret;
	struct ppac_interface *ppac_if = get_ppac_if(fm, port_idx, port_type);
	ret = init_tables(cc_nodes, local_cc_num_keys, local_cc_key_size,
			&ppac_if->ppam_data.local_td);
	return ret;
}

static void cleanup_local_tables(int fm, int port_idx, int port_type)
{
	int i, td;
	struct ppac_interface *ppac_if = get_ppac_if(fm, port_idx, port_type);
	for (i = 0; i < MAX_ETHER_TYPES; i++) {
		td = (ppac_if->ppam_data.local_td)[i];
		dpa_classif_table_free(td);
	}
}

static int table_insert_entry(int td, u8 *key, u8 *mask,
			      int key_size, int hmd, uint32_t fqid)
{
	int ret;
	struct dpa_offload_lookup_key dpa_key;
	struct dpa_cls_tbl_action def_action;

	dpa_key.byte = key;
	dpa_key.mask = mask;
	dpa_key.size = key_size;
	memset(&def_action, 0 , sizeof(def_action));
	def_action.type = DPA_CLS_TBL_ACTION_ENQ;
	def_action.enable_statistics = false;
	def_action.enq_params.new_fqid = fqid;
	def_action.enq_params.hmd = hmd;
	def_action.enq_params.override_fqid = true;

	ret = dpa_classif_table_insert_entry(td,
		&dpa_key, &def_action, 0, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s(%d) :Failed to create entry",
			__func__, __LINE__);
	}
	return ret;
}

static int table_delete_entry(int td, u8 *key, u8 *mask, int key_size)
{
	struct dpa_offload_lookup_key dpa_key;
	int ret;

	dpa_key.byte = key;
	dpa_key.mask = mask;
	dpa_key.size = key_size;
	ret = dpa_classif_table_delete_entry_by_key(td, &dpa_key);
	if (ret < 0) {
		fprintf(stderr, "%s(%d) :Failed to remove table entry",
			__func__, __LINE__);
	}
	return ret;
}

int create_neigh_hhm(int *hmd, t_Handle fwd_hm,
		struct ether_addr *saddr, struct ether_addr *daddr)
{
	struct dpa_cls_hm_fwd_params fwd_params;
	struct dpa_cls_hm_fwd_resources fwd_res;
	int err = 0;

	*hmd = DPA_OFFLD_DESC_NONE;

	memset(&fwd_params, 0, sizeof(struct dpa_cls_hm_fwd_params));
	memset(&fwd_res, 0, sizeof(struct dpa_cls_hm_fwd_resources));

	fwd_params.fm_pcd = pcd_dev;
	fwd_params.out_if_type = DPA_CLS_HM_IF_TYPE_ETHERNET;

	memcpy(fwd_params.eth.macda, daddr, ETH_ALEN);
	memcpy(fwd_params.eth.macsa, saddr, ETH_ALEN);
	fwd_res.fwd_node = fwd_hm;

	err = dpa_classif_set_fwd_hm(&fwd_params, DPA_OFFLD_DESC_NONE,
				hmd, true, &fwd_res);
	if (err < 0) {
		fprintf(stderr, "%d - Failed to create forward "
				"hm operation\n", err);
		return err;
	}

	return 0;
}

/*
 * __if - FMAN interface where hard header manipulation is performed
 * __oif - output FMAN interface
 * dst_addr - MAC destination address
 * af - address family
 * key - search key (IP4/6 destination address)
 */
int create_neigh_entry(struct fman_if *__if,
			struct fman_if *__oif,
			t_Handle fwd_hm,
			struct ether_addr *dst_addr,
			int af, u8 *key, u8 prefixlen)
{
	int hmd, td, ret;
	struct ppac_interface *ppac_if, *ppac_oif;
	u8 mask[MAX_IP_KEY_SIZE];
	int key_size;

	ret = create_neigh_hhm(&hmd, fwd_hm, &__oif->mac_addr, dst_addr);
	if (ret < 0)
		return ret;

	ppac_oif = get_ppac_if(__oif->fman_idx,
				__oif->mac_idx, __oif->mac_type);
	ppac_if = get_ppac_if(__if->fman_idx,
				__if->mac_idx, __if->mac_type);
	assert(ppac_if);

	if (af == AF_INET) {
		key_size = IPv4_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[ETHER_TYPE_IPv4];
	} else if (af == AF_INET6) {
		key_size = IPv6_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[ETHER_TYPE_IPv6];
	} else {
		return -ENOTSUP;
	}

	if (prefixlen) {
		memset(mask, 0, sizeof(mask));
		make_bitmask(mask, sizeof(mask), prefixlen);
		hexdump(key, key_size);
		hexdump(mask, key_size);

		ret = table_insert_entry(td, key, mask, key_size, hmd,
				ppac_oif->ppam_data.tx_fqids[0]);

	} else {
		ret = table_insert_entry(td, key, NULL, key_size, hmd,
			ppac_oif->ppam_data.tx_fqids[0]);
	}

	return ret;
}

int create_ib_neigh_entry(struct ether_addr *dst_addr,
			  int af, u8 *key, u8 prefixlen)
{
	return create_neigh_entry(ob_oh_post,
			   ib_eth, ob_fwd_hm,
			   dst_addr, af, key, prefixlen);
}

int create_ob_neigh_entry(struct ether_addr *dst_addr,
			  int af, u8 *key, u8 prefixlen)
{
	return create_neigh_entry(ib_oh,
				  ob_eth, ib_fwd_hm,
				  dst_addr, af, key, prefixlen);
}

int remove_neigh_entry(struct fman_if *__if, int af, u8 *key, u8 prefixlen)
{
	struct ppac_interface *ppac_if;
	u8 mask[MAX_IP_KEY_SIZE];
	int td, ret, key_size;

	ppac_if = get_ppac_if(__if->fman_idx, __if->mac_idx, __if->mac_type);
	assert(ppac_if);

	if (af == AF_INET) {
		key_size = IPv4_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[ETHER_TYPE_IPv4];
	} else if (af == AF_INET6) {
		key_size = IPv6_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[ETHER_TYPE_IPv6];
	} else {
		return -ENOTSUP;
	}
	if (prefixlen) {
		memset(mask, 0, sizeof(mask));
		make_bitmask(mask, sizeof(mask), prefixlen);
		hexdump(key, key_size);
		hexdump(mask, key_size);
		ret = table_delete_entry(td, key, mask, key_size);
	} else {
		ret = table_delete_entry(td, key, NULL, key_size);
	}
	return ret;
}

int remove_ib_neigh_entry(int af, u8 *key, u8 prefixlen)
{
	return remove_neigh_entry(ob_oh_post, af, key, prefixlen);
}

int remove_ob_neigh_entry(int af, u8 *key, u8 prefixlen)
{
	return remove_neigh_entry(ib_oh, af, key, prefixlen);
}

/* ifindex - macless interface index. Traffic matching this entry
 * will be delivered to this macless interface.
 * af - address family - IPv4/v6
 * key - address bytes */
int create_local_entry(int ifindex, int af, u8 *key)
{
	int ret = 0;
	int rx_start = 0;
	struct fman_if *__if;
	char macless_name[IF_NAMESIZE];
	struct ppac_interface *ppac_if;
	int td;
	int key_size;

	if (!if_indextoname(ifindex, macless_name))
		return -ENODEV;

	/* get port that sends traffic to macless rx */
	list_for_each_entry(ppac_if, &ifs, node) {
		if (ppac_if->ppam_data.macless_ifindex == ifindex)
			break;
	}
	assert(ppac_if->port_cfg->fman_if->mac_type == fman_mac_1g);

	/* get macless rx fqs */
	list_for_each_entry(__if, fman_if_list, node) {
		if (__if->mac_type == fman_mac_less &&
		    !strcmp(macless_name, __if->macless_info.macless_name)) {
			rx_start = __if->macless_info.rx_start;
			break;
		}
	}

	/* add in the corresponding table for af the entry */
	if (af == AF_INET) {
		td = ppac_if->ppam_data.local_td[ETHER_TYPE_IPv4];
		key_size = IPv4_KEY_SIZE;
	} else if (af == AF_INET6) {
		td = ppac_if->ppam_data.local_td[ETHER_TYPE_IPv6];
		key_size = IPv6_KEY_SIZE;
	} else {
		return -ENOTSUP;
	}
	ret = table_insert_entry(td, key, NULL, key_size, -1, rx_start);

	return ret;
}

int remove_local_entry(int ifindex, int af, u8 *key)
{
	int td, ret = 0;
	int key_size;
	struct ppac_interface *ppac_if;

	list_for_each_entry(ppac_if, &ifs, node) {
		if (ppac_if->ppam_data.macless_ifindex == ifindex)
			break;
	}
	if (af == AF_INET) {
		td = ppac_if->ppam_data.local_td[ETHER_TYPE_IPv4];
		key_size = IPv4_KEY_SIZE;
	} else if (af == AF_INET6) {
		td = ppac_if->ppam_data.local_td[ETHER_TYPE_IPv6];
		key_size = IPv6_KEY_SIZE;
	} else {
		return -ENOTSUP;
	}
	ret = table_delete_entry(td, key, NULL, key_size);

	return ret;
}

static int process_add_del_addr(struct nlmsghdr *nh, int vif_idx, int vof_idx)
{
	struct ifaddrmsg *iam;
	struct nlattr *na;
	u8 *addr;
	int ret;

	iam = (struct ifaddrmsg *)NLMSG_DATA(nh);
	na = (struct nlattr *)(NLMSG_DATA(nh) + NLMSG_ALIGN(sizeof(*iam)));
	addr = NLA_DATA(na);
	if (nh->nlmsg_type == RTM_NEWADDR) {
		TRACE("RTM_NEWADDR link %d af %d\n",
		      iam->ifa_index, iam->ifa_family);
		ret = create_local_entry(iam->ifa_index,
				   iam->ifa_family, addr);
	} else if (nh->nlmsg_type == RTM_DELADDR) {
		TRACE("RTM_DELADDR link %d af %d\n",
		      iam->ifa_index, iam->ifa_family);
		ret = remove_local_entry(iam->ifa_index,
				   iam->ifa_family, addr);
	}

	return ret;
}

static int process_del_neigh(struct nlmsghdr *nh, int vif_idx, int vof_idx)
{
	struct ndmsg *ndm;
	struct nlattr *na;
	struct in_addr dst[IPv4_NUM_KEYS];
	unsigned char dst_len[IPv4_NUM_KEYS];
	int ret, i, num_keys;
	u8 *key;

	ndm = (struct ndmsg *)NLMSG_DATA(nh);
	if (ndm->ndm_ifindex != vif_idx &&
	    ndm->ndm_ifindex != vof_idx)
		return -1;
	na = (struct nlattr *)(NLMSG_DATA(nh) +
		NLMSG_ALIGN(sizeof(*ndm)));
	if (na->nla_type != NDA_DST)
		return -1;
	key = NLA_DATA(na);

	if (ndm->ndm_ifindex == vif_idx &&
	    ndm->ndm_state & (NUD_STALE|NUD_FAILED)) {
		TRACE("RTM_DELNEIGH vif ifindex %d state %02x\n",
		      ndm->ndm_ifindex, ndm->ndm_state);

		ret = remove_ib_neigh_entry(ndm->ndm_family, key, 0);
		num_keys = get_dst_addrs(dst, dst_len,
			(struct in_addr *)key,
			IPv4_NUM_KEYS);
		for (i = 0; i < num_keys; i++)
			ret = remove_ib_neigh_entry(ndm->ndm_family,
						    (u8 *)&dst[i].s_addr,
						    dst_len[i]);

	} else if (ndm->ndm_ifindex == vof_idx &&
		ndm->ndm_state & (NUD_STALE|NUD_FAILED)) {
		TRACE("RTM_DELNEIGH vof ifindex %d state %02x\n",
		      ndm->ndm_ifindex, ndm->ndm_state);

		ret = remove_ob_neigh_entry(ndm->ndm_family, key, 0);
		num_keys = get_dst_addrs(dst, dst_len,
				   (struct in_addr *)key,
				   IPv4_NUM_KEYS);
		for (i = 0; i < num_keys; i++)
			ret = remove_ob_neigh_entry(ndm->ndm_family,
						    (u8 *)&dst[i].s_addr,
						    dst_len[i]);
	}
	return ret;
}

static int process_new_neigh(struct nlmsghdr *nh, int vif_idx, int vof_idx)
{
	struct ndmsg *ndm;
	struct nlattr *na;
	struct ether_addr *lladdr;
	struct in_addr dst[IPv4_NUM_KEYS];
	unsigned char dst_len[IPv4_NUM_KEYS];
	int ret, i, num_keys;
	u8 *key;

	ndm = (struct ndmsg *)NLMSG_DATA(nh);
	if (ndm->ndm_ifindex != vif_idx &&
	    ndm->ndm_ifindex != vof_idx)
		return -1;

	na = (struct nlattr *)(NLMSG_DATA(nh) +
		NLMSG_ALIGN(sizeof(*ndm)));
	if (na->nla_type != NDA_DST)
		return -1;
	key = NLA_DATA(na);
	NLA_NEXT(na);
	if (na->nla_type != NDA_LLADDR)
		return -1;
	lladdr = NLA_DATA(na);

	if (ndm->ndm_ifindex == vif_idx &&
	    (ndm->ndm_state & (NUD_PERMANENT|NUD_REACHABLE))) {
		TRACE("RTM_NEWNEIGH vif ifindex %d state %02x\n",
		      ndm->ndm_ifindex, ndm->ndm_state);
		ret = create_ib_neigh_entry(lladdr, ndm->ndm_family, key, 0);

		num_keys = get_dst_addrs(dst, dst_len,
				    (struct in_addr *)key,
				    IPv4_NUM_KEYS);
		for (i = 0; i < num_keys; i++)
			ret = create_ib_neigh_entry(lladdr, ndm->ndm_family,
					    (u8 *)&dst[i].s_addr, dst_len[i]);
	} else if (ndm->ndm_ifindex == vof_idx &&
		(ndm->ndm_state & (NUD_PERMANENT|NUD_REACHABLE))) {
		TRACE("RTM_NEWNEIGH vof ifindex %d state %02x\n",
		      ndm->ndm_ifindex, ndm->ndm_state);
		ret = create_ob_neigh_entry(lladdr, ndm->ndm_family, key, 0);

		num_keys = get_dst_addrs(dst, dst_len,
				   (struct in_addr *)key,
				   IPv4_NUM_KEYS);
		for (i = 0; i < num_keys; i++)
			ret = create_ob_neigh_entry(lladdr, ndm->ndm_family,
					    (u8 *)&dst[i].s_addr, dst_len[i]);
	}
	return ret;
}

static void *neigh_msg_loop(void *);

int setup_neigh_loop(pthread_t *tid)
{
	int ret;
	ret = pthread_create(tid, NULL, neigh_msg_loop, NULL);
	if (ret)
		fprintf(stderr, "error: failed to create NEIGH msg thread\n");

	return ret;
}

static void sig_handler(int signum)
{
}

static void *neigh_msg_loop(void *data)
{
	int rtm_sd;
	char buf[4096];
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct sockaddr_nl sa;
	int vif_idx, vof_idx;
	int len, ret;
	struct sigaction new_action, old_action;

	ret = init_neigh_tables(app_conf.fm, app_conf.ob_oh_post,
				fman_offline, cc_out_post_enc);
	if (ret < 0)
		goto out;

	ret = init_neigh_tables(app_conf.fm, app_conf.ib_oh,
				fman_offline, cc_in_post_dec);
	if (ret < 0)
		goto out1;

	ret = init_local_tables(app_conf.fm, app_conf.ob_oh_pre,
				fman_offline, cc_out_local);
	if (ret < 0)
		goto out2;

	ret = init_local_tables(app_conf.fm, app_conf.ib_eth,
				 fman_mac_1g, cc_in_local);
	if (ret < 0)
		goto out3;

	rtm_sd = create_nl_socket(NETLINK_ROUTE, RTMGRP_NEIGH);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* install a signal handler for SIGTERM */
	new_action.sa_handler = sig_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGTERM, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGTERM, &new_action, NULL);

	vif_idx = if_nametoindex(app_conf.vif);
	if (!vif_idx) {
		fprintf(stderr, " %s:%d: inbound interface"
				"%s not available\n",
				__func__, __LINE__, app_conf.vif);
		pthread_exit(NULL);
	}

	vof_idx = if_nametoindex(app_conf.vof);
	if (!vof_idx) {
		fprintf(stderr, " %s:%d: outbound virtual interface"
				"%s not available\n",
				__func__, __LINE__, app_conf.vof);
		pthread_exit(NULL);
	}

	ib_eth = get_fif(app_conf.fm,
			app_conf.ib_eth, fman_mac_1g);
	ob_oh_post = get_fif(app_conf.fm,
			app_conf.ob_oh_post, fman_offline);
	ob_eth = get_fif(app_conf.fm,
			app_conf.ob_eth, fman_mac_1g);
	ib_oh = get_fif(app_conf.fm,
			app_conf.ib_oh, fman_offline);

	while (1) {
		len = recvmsg(rtm_sd, &msg, 0);
		if (len < 0 && errno != EINTR) {
			fprintf(stderr,
				"error receiving from RTM socket, errno %d\n",
					errno);
			break;
		} else if (errno == EINTR) /* loop break requested */
			break;
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_ERROR) {
				fprintf(stderr,
					"Netlink error on RTM socket,"
					"errno %d\n",
					errno);
				break;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI ||
			    nh->nlmsg_type == NLMSG_DONE) {
					fprintf(stderr,
						"RTM multi-part messages "
						"not supported\n");
					break;
			}

			switch (nh->nlmsg_type) {
			case RTM_NEWNEIGH:
				process_new_neigh(nh, vif_idx, vof_idx);
				break;
			case RTM_DELNEIGH:
				process_del_neigh(nh, vif_idx, vof_idx);
				break;
			case RTM_NEWADDR:
			case RTM_DELADDR:
				process_add_del_addr(nh, vif_idx, vof_idx);
				break;
			default:
				break;
			}
		}
	}
	cleanup_local_tables(app_conf.fm, app_conf.ib_eth, fman_mac_1g);
out3:
	cleanup_local_tables(app_conf.fm, app_conf.ob_oh_pre, fman_offline);
out2:
	cleanup_neigh_tables(app_conf.fm, app_conf.ib_oh, fman_offline);
out1:
	cleanup_neigh_tables(app_conf.fm, app_conf.ob_oh_post, fman_offline);
out:
	pthread_exit(NULL);
}

