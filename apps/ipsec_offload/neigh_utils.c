/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include "usdpaa/fsl_dpa_classifier.h"
#include "usdpaa/fsl_dpa_ipsec.h"
#include "xfrm_km.h"
#include "app_config.h"
#include "app_common.h"

#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_NEXT(na) ((na) = ((struct nlattr *)((char *)(na) \
				+ NLA_ALIGN((na)->nla_len))))

static int neigh_cc_num_keys[] = NEIGH_TABLES_NUM_KEYS;
static int neigh_cc_key_size[] = NEIGH_TABLES_KEY_SIZE;

static int init_neigh_tables(int fm, int port_idx, int port_type,
			     t_Handle *cc_nodes)
{
	int i, j, cls_td;
	struct dpa_cls_tbl_params cls_tbl_params;
	struct dpa_cls_tbl_action def_action;
	int ret;
	struct ppac_interface *ppac_if = get_ppac_if(fm, port_idx, port_type);

	ppac_if->ppam_data.hhm_td = malloc(sizeof(int) *  MAX_ETHER_TYPES);
	if (!ppac_if->ppam_data.hhm_td)
		return -ENOMEM;

	for (i = 0; i < MAX_ETHER_TYPES; i++) {
		memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
		cls_tbl_params.cc_node = cc_nodes[i];
		cls_tbl_params.type = DPA_CLS_TBL_EXACT_MATCH;
		cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_KEY;
		cls_tbl_params.exact_match_params.entries_cnt =
			neigh_cc_num_keys[i];
		cls_tbl_params.exact_match_params.key_size =
			neigh_cc_key_size[i];
		ret = dpa_classif_table_create(&cls_tbl_params,
						&cls_td);
		if (ret < 0) {
			fprintf(stderr, "%s:%d: Error creating outbound "
				"neigh table (%d), err %d\n",
				__func__, __LINE__, i, ret);
			for (j = 0; j < i; j++) {
				cls_td = ppac_if->ppam_data.hhm_td[j];
				dpa_classif_table_free(cls_td);
			}
			free(ppac_if->ppam_data.hhm_td);
			return ret;
		}

		ppac_if->ppam_data.hhm_td[i] = cls_td;
	}
	return 0;
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
			int af, u8 *key)
{
	int hmd, td, ret;
	struct dpa_offload_lookup_key dpa_key;
	struct dpa_cls_tbl_action def_action;
	struct ppac_interface *ppac_if, *ppac_oif;

	/*TODO - no hm for local traffic */
	ret = create_neigh_hhm(&hmd, fwd_hm, &__oif->mac_addr, dst_addr);
	if (ret < 0)
		return ret;

	ppac_oif = get_ppac_if(__oif->fman_idx,
				__oif->mac_idx, __oif->mac_type);
	ppac_if = get_ppac_if(__if->fman_idx,
				__if->mac_idx, __if->mac_type);
	assert(ppac_if);

	dpa_key.byte = key;
	dpa_key.mask = NULL;
	if (af == AF_INET) {
		dpa_key.size = IPv4_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[0];
	} else if (af == AF_INET6) {
		dpa_key.size = IPv6_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[1];
	} else
		return -ENOTSUP;
	hexdump(dpa_key.byte, dpa_key.size);

	memset(&def_action, 0 , sizeof(def_action));
	def_action.type = DPA_CLS_TBL_ACTION_ENQ;
	def_action.enable_statistics = false;
	def_action.enq_params.new_fqid = ppac_oif->ppam_data.tx_fqids[0];
	def_action.enq_params.hmd = hmd;
	def_action.enq_params.override_fqid = true;

	ret = dpa_classif_table_insert_entry(td,
		&dpa_key, &def_action, 0, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s(%d) :Failed to create neighbour entry",
				__func__, __LINE__);
	}
	return ret;
}

int remove_neigh_entry(struct fman_if *__if, int af, u8 *key)
{
	struct dpa_offload_lookup_key dpa_key;
	struct ppac_interface *ppac_if;
	int td, ret;

	ppac_if = get_ppac_if(__if->fman_idx, __if->mac_idx, __if->mac_type);
	assert(ppac_if);

	dpa_key.byte = key;
	dpa_key.mask = NULL;

	if (af == AF_INET) {
		dpa_key.size = IPv4_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[0];
	} else if (af == AF_INET6) {
		dpa_key.size = IPv6_KEY_SIZE;
		td = ppac_if->ppam_data.hhm_td[1];
	} else
		return -ENOTSUP;

	ret = dpa_classif_table_delete_entry_by_key(td, &dpa_key);
	if (ret < 0) {
		fprintf(stderr, "%s(%d) :Failed to remove neighbour entry",
				__func__, __LINE__);
	}
	return ret;
}

static void *neigh_msg_loop(void *);

int setup_neigh_loop(void)
{
	pthread_t tid;
	int ret;
	ret = pthread_create(&tid, NULL, neigh_msg_loop, NULL);
	if (ret)
		fprintf(stderr, "error: failed to create NEIGH msg thread\n");

	return ret;
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
	struct fman_if *ib_eth, *ob_eth, *ob_oh_post, *ib_oh;

	ret = init_neigh_tables(app_conf.fm, app_conf.ob_oh_post,
				fman_offline, cc_out_post_enc);
	if (ret < 0)
		pthread_exit(NULL);

	ret = init_neigh_tables(app_conf.fm, app_conf.ib_oh,
				fman_offline, cc_in_post_dec);
	if (ret < 0)
		pthread_exit(NULL);

	rtm_sd = create_nl_socket(NETLINK_ROUTE, RTMGRP_NEIGH);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

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
		if (len < 0) {
			fprintf(stderr,
				"error receiving from RTM socket, errno %d\n",
					errno);
			break;
		}
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
			{
				struct ndmsg *ndm;
				struct nlattr *na;
				struct ether_addr *lladdr;
				u8 *key;
				ndm = (struct ndm *)NLMSG_DATA(nh);
				if (ndm->ndm_ifindex != vif_idx &&
					ndm->ndm_ifindex != vof_idx)
					break;
				TRACE("RTM_NEWNEIGH ifindex %d state %02x\n",
					ndm->ndm_ifindex, ndm->ndm_state);

				na = (struct nlattr *)(NLMSG_DATA(nh) +
					NLMSG_ALIGN(sizeof(*ndm)));
				if (na->nla_type == NDA_DST)
					key = NLA_DATA(na);
				NLA_NEXT(na);
				if (na->nla_type == NDA_LLADDR)
					lladdr = NLA_DATA(na);

				if (ndm->ndm_ifindex == vif_idx &&
					ndm->ndm_state == NUD_PERMANENT)
					ret = create_neigh_entry(ob_oh_post,
						ib_eth, ob_fwd_hm,
						lladdr, ndm->ndm_family, key);
				else if (ndm->ndm_ifindex == vif_idx &&
					ndm->ndm_state == NUD_FAILED)
					ret = remove_neigh_entry(ob_oh_post,
						ndm->ndm_family, key);
				else if (ndm->ndm_ifindex == vof_idx &&
					ndm->ndm_state == NUD_PERMANENT)
					ret = create_neigh_entry(ib_oh,
						ob_eth, ib_fwd_hm,
						lladdr, ndm->ndm_family, key);
				else if (ndm->ndm_ifindex == vof_idx &&
					ndm->ndm_state == NUD_FAILED)
					ret = remove_neigh_entry(ib_oh,
							ndm->ndm_family, key);
				break;
			}
			case RTM_DELNEIGH:
			default:
				break;
			}
		}
	}

	return NULL;
}

