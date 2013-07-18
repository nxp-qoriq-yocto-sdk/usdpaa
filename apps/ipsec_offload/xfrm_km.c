/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
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
#include <usdpaa/fsl_bman.h>
#include <usdpaa/fsl_qman.h>
#include "internal/compat.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <linux/pfkeyv2.h>
#include <assert.h>

#include "fsl_fman.h"
#include "usdpaa/fsl_dpa_ipsec.h"
#include "app_config.h"
#include "xfrm_km.h"
#include "app_common.h"

/* SADB */
static LIST_HEAD(dpa_sa_list);

/* pending SP list */
static LIST_HEAD(pending_sp);

#define DPA_IPSEC_ADDR_T_IPv4 4
#define DPA_IPSEC_ADDR_T_IPv6 6

/* returns fqid of inbound OH port Rx default queue
 frames not passing inbound policy verification are enqueued to it */
static uint32_t get_policy_miss_fqid(void)
{
	struct ppac_interface *ppac_if;
	list_for_each_entry(ppac_if, &ifs, node) {
		if ((app_conf.fm == ppac_if->port_cfg->fman_if->fman_idx) &&
			(ppac_if->port_cfg->fman_if->mac_type ==
			fman_offline) &&
			(app_conf.ib_oh ==
			ppac_if->port_cfg->fman_if->mac_idx)) {
				return qman_fq_fqid(&ppac_if->rx_default[0].fq);
			}
	}
	return 0;
}

static int create_post_flowid_table(void)
{
	int ret, cls_td = -1;
	struct dpa_cls_tbl_params cls_tbl_params;

	memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
	cls_tbl_params.cc_node = cc_post_flow_id;
	cls_tbl_params.type = DPA_CLS_TBL_EXACT_MATCH;
	cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
	cls_tbl_params.exact_match_params.entries_cnt = 1;
	cls_tbl_params.exact_match_params.key_size = 1;
	cls_tbl_params.prefilled_entries = 1;
	ret = dpa_classif_table_create(&cls_tbl_params,
				       &cls_td);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: Error creating inbound "
				"post flowid table, err %d\n",
				__func__, __LINE__, ret);
		return ret;
	}
	return cls_td;
}

static void *xfrm_msg_loop(void *);

struct thread_data {
	int dpa_ipsec_id;
	uint32_t pol_miss_fqid;
	int post_flow_id_td;
};

int create_nl_socket(int protocol, int groups)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = groups;
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		goto err;

	return fd;
err:
	close(fd);
	return -1;
}

int setup_xfrm_msgloop(int dpa_ipsec_id)
{
	pthread_t tid;
	int ret;
	uint32_t policy_miss_fqid;
	int post_flow_id_td;
	struct thread_data *data;

	/* get required fqids */
	policy_miss_fqid = get_policy_miss_fqid();
	post_flow_id_td = create_post_flowid_table();

	if (!policy_miss_fqid) {
		fprintf(stderr, "cannot get policy_miss_fqid\n");
		return -1;
	}

	if (post_flow_id_td < 0) {
		fprintf(stderr, "cannot create post flow id table\n");
		return -1;
	}

	data = malloc(sizeof(*data));
	if (!data) {
		fprintf(stderr, "cannot allocate XFRM msg thread data\n");
		return -1;
	}

	data->dpa_ipsec_id = dpa_ipsec_id;
	data->pol_miss_fqid = policy_miss_fqid;
	data->post_flow_id_td = post_flow_id_td;

	ret = pthread_create(&tid, NULL, xfrm_msg_loop, data);
	if (ret)
		fprintf(stderr, "error: failed to create XFRM msg thread\n");
	return ret;
}

static int offload_sa(int dpa_ipsec_id,
			struct dpa_ipsec_sa_params *sa_params,
			struct xfrm_usersa_info *sa_info,
			int next_table_td,
			int policy_miss_fqid,
			int dir, int *sa_id,
			struct xfrm_encap_tmpl *encap)
{
	struct iphdr outer_iphdr;
	struct udphdr	udp_hdr;
	struct ip6_hdr outer_ip6hdr;
	struct dpa_cls_tbl_action def_sa_action;
	int ret = 0;

	if (!sa_params->crypto_params.cipher_key ||
		!sa_params->crypto_params.auth_key)
		return -1;
	hexdump(sa_params->crypto_params.cipher_key,
		sa_params->crypto_params.cipher_key_len);

	hexdump(sa_params->crypto_params.auth_key,
		sa_params->crypto_params.auth_key_len);
	if (dir != XFRM_POLICY_OUT && dir != XFRM_POLICY_IN)
		return -1;
	if (sa_params->crypto_params.alg_suite < 0) {
		TRACE("Invalid algo suite selector %d\n",
			sa_params->crypto_params.alg_suite);
		return -EINVAL;
	}

	sa_params->spi = sa_info->id.spi;
	sa_params->sa_bpid = IF_BPID;
	sa_params->enable_stats = 1;
	sa_params->l2_hdr_size = ETH_HLEN;
	sa_params->hdr_upd_flags = 0;
	if (dir == XFRM_POLICY_OUT) {
		sa_params->sa_dir = DPA_IPSEC_OUTBOUND;
		sa_params->start_seq_num = 1;
		sa_params->sa_wqid = SEC_WQ_ID;
		if (sa_info->family == AF_INET) {
			memset(&outer_iphdr, 0, sizeof(outer_iphdr));
			outer_iphdr.version = IPVERSION;
			outer_iphdr.ihl = sizeof(outer_iphdr) / sizeof(u32);
			outer_iphdr.ttl = IPDEFTTL;
			outer_iphdr.tot_len = sizeof(outer_iphdr);
			if (encap->encap_sport && encap->encap_dport)
				outer_iphdr.tot_len += sizeof(udp_hdr);
			outer_iphdr.tos = app_conf.outer_tos;
			outer_iphdr.saddr = sa_info->saddr.a4;
			outer_iphdr.daddr = sa_info->id.daddr.a4;
			outer_iphdr.protocol = IPPROTO_ESP;
			sa_params->sa_out_params.outer_ip_header =
				&outer_iphdr;
			sa_params->sa_out_params.ip_hdr_size =
				sizeof(outer_iphdr);
			sa_params->sa_out_params.ip_ver = DPA_IPSEC_ADDR_T_IPv4;
			if (app_conf.ob_ecn) {
				TRACE("Outbound ECN tunneling set\n");
				sa_params->hdr_upd_flags =
						DPA_IPSEC_HDR_COPY_DSCP |
						DPA_IPSEC_HDR_COPY_ECN;
			}
		} else if (sa_info->family == AF_INET6) {
			memset(&outer_ip6hdr, 0, sizeof(outer_ip6hdr));
			memcpy(&outer_ip6hdr.ip6_src, sa_info->saddr.a6,
				sizeof(sa_info->saddr.a6));
			memcpy(&outer_ip6hdr.ip6_dst, sa_info->id.daddr.a6,
				sizeof(sa_info->id.daddr.a6));
			outer_ip6hdr.ip6_flow = 0x6<<28;
			outer_ip6hdr.ip6_nxt = IPPROTO_ESP;
			outer_ip6hdr.ip6_hlim = IPDEFTTL;
			sa_params->sa_out_params.outer_ip_header =
				&outer_ip6hdr;
			sa_params->sa_out_params.ip_hdr_size =
				sizeof(outer_ip6hdr);
			sa_params->sa_out_params.ip_ver = DPA_IPSEC_ADDR_T_IPv6;
		}

		if (encap->encap_sport && encap->encap_dport) {
			memset(&udp_hdr, 0, sizeof(udp_hdr));
			udp_hdr.source = encap->encap_sport;
			udp_hdr.dest = encap->encap_dport;
			sa_params->sa_out_params.outer_udp_header =
							       (void *)&udp_hdr;
		} else
			sa_params->sa_out_params.outer_udp_header = NULL;

		sa_params->sa_out_params.post_sec_flow_id = 0;
		sa_params->sa_out_params.init_vector = NULL;
	} else if (dir == XFRM_POLICY_IN) {
		sa_params->sa_dir = DPA_IPSEC_INBOUND;
		if (encap->encap_sport && encap->encap_dport) {
			sa_params->sa_in_params.use_udp_encap = true;
			sa_params->sa_in_params.src_port = encap->encap_sport;
			sa_params->sa_in_params.dest_port = encap->encap_dport;
		}
		if (sa_info->family == AF_INET) {
			sa_params->sa_in_params.src_addr.version =
				DPA_IPSEC_ADDR_T_IPv4;
			sa_params->sa_in_params.src_addr.addr.ipv4.word =
				sa_info->saddr.a4;
			sa_params->sa_in_params.dest_addr.version =
				DPA_IPSEC_ADDR_T_IPv4;
			sa_params->sa_in_params.dest_addr.addr.ipv4.word =
				sa_info->id.daddr.a4;
			if (app_conf.ib_ecn) {
				TRACE("Inbound ECN tunneling set\n");
				sa_params->hdr_upd_flags =
						DPA_IPSEC_HDR_COPY_DSCP |
						DPA_IPSEC_HDR_COPY_ECN;
			}
		} else if (sa_info->family == AF_INET6) {
			sa_params->sa_in_params.src_addr.version =
				DPA_IPSEC_ADDR_T_IPv6;
			memcpy(sa_params->sa_in_params.src_addr.addr.ipv6.byte,
				sa_info->saddr.a6, sizeof(sa_info->saddr.a6));
			sa_params->sa_in_params.dest_addr.version =
				DPA_IPSEC_ADDR_T_IPv6;
			memcpy(sa_params->sa_in_params.dest_addr.addr.ipv6.byte,
			    sa_info->id.daddr.a6, sizeof(sa_info->id.daddr.a6));
		}
		/* default SA action */
		memset(&def_sa_action, 0, sizeof(def_sa_action));
		def_sa_action.type = DPA_CLS_TBL_ACTION_NEXT_TABLE;
		def_sa_action.enable_statistics = false;
		def_sa_action.next_table_params.next_td = next_table_td;
		sa_params->sa_in_params.post_ipsec_action = def_sa_action;

		/* miss action */
		memset(&def_sa_action, 0, sizeof(def_sa_action));
		def_sa_action.type = DPA_CLS_TBL_ACTION_ENQ;
		def_sa_action.enable_statistics = false;
		def_sa_action.enq_params.new_fqid = policy_miss_fqid;
		def_sa_action.enq_params.hmd = DPA_OFFLD_DESC_NONE;
		def_sa_action.enq_params.override_fqid = true;
		sa_params->sa_in_params.policy_miss_action = def_sa_action;
		sa_params->sa_in_params.arw = DPA_IPSEC_ARSNONE;
	}

	ret =  dpa_ipsec_create_sa(dpa_ipsec_id, sa_params, sa_id);
	return ret;
}

static inline int offload_policy(struct dpa_ipsec_policy_params *pol_params,
				struct xfrm_selector *sel,
				int sa_id, int dir, int next_table_td,
				int *manip_desc)
{
	int ret = 0;
	struct dpa_cls_tbl_action policy_action;

	memset(pol_params, 0, sizeof(*pol_params));
	if ((dir == XFRM_POLICY_OUT) && (app_conf.mtu_pre_enc > 0)) {
		struct dpa_cls_hm_update_params update_params;
		int frag_desc;
		memset(&update_params, 0,
		       sizeof(struct dpa_cls_hm_update_params));
		frag_desc = DPA_OFFLD_DESC_NONE;
		update_params.fm_pcd = pcd_dev;
		update_params.ip_frag_params.df_action =
				DPA_CLS_HM_DF_ACTION_FRAG_ANYWAY;
		update_params.ip_frag_params.mtu = app_conf.mtu_pre_enc;
		update_params.ip_frag_params.scratch_bpid =
						app_conf.ipf_bpid;
		ret = dpa_classif_set_update_hm(&update_params,
					DPA_OFFLD_DESC_NONE,
					&frag_desc, true,  NULL);
		if (ret < 0) {
			fprintf(stderr, "Could not create "
				"fragmentation manip handle %d\n", ret);
			return ret;
		}

		*manip_desc = frag_desc;
		pol_params->dir_params.type =
				DPA_IPSEC_POL_DIR_PARAMS_MANIP;
		pol_params->dir_params.manip_desc = frag_desc;

	}

	if (sel->family == AF_INET) {
		pol_params->src_addr.version = DPA_IPSEC_ADDR_T_IPv4;
		pol_params->src_addr.addr.ipv4.word = sel->saddr.a4;
		pol_params->dest_addr.version = DPA_IPSEC_ADDR_T_IPv4;
		pol_params->dest_addr.addr.ipv4.word = sel->daddr.a4;
	} else if (sel->family == AF_INET6) {
		pol_params->src_addr.version = DPA_IPSEC_ADDR_T_IPv6;
		memcpy(pol_params->src_addr.addr.ipv6.byte,
			sel->saddr.a6, sizeof(sel->saddr.a6));
		pol_params->dest_addr.version = DPA_IPSEC_ADDR_T_IPv6;
		memcpy(pol_params->dest_addr.addr.ipv6.byte,
			sel->daddr.a6, sizeof(sel->daddr.a6));
	}

	pol_params->src_prefix_len = sel->prefixlen_s;
	pol_params->dest_prefix_len = sel->prefixlen_d;
	pol_params->protocol = sel->proto;
	pol_params->l4.src_port = sel->sport;
	pol_params->l4.src_port_mask = sel->sport_mask;
	pol_params->l4.dest_port = sel->dport;
	pol_params->l4.dest_port_mask = sel->dport_mask;

	if (sel->proto == IPPROTO_IP)
		pol_params->masked_proto = true;

	memset(&policy_action, 0, sizeof(policy_action));
	if (dir == XFRM_POLICY_IN) {
		policy_action.type = DPA_CLS_TBL_ACTION_NEXT_TABLE;
		policy_action.enable_statistics = false;
		policy_action.next_table_params.next_td = next_table_td;
		pol_params->dir_params.type = DPA_IPSEC_POL_DIR_PARAMS_ACT;
		pol_params->dir_params.in_action = policy_action;
	}

	ret = dpa_ipsec_sa_add_policy(sa_id, pol_params);
	return ret;
}

static void trace_xfrm_sa_info(struct xfrm_usersa_info *sa_info)
{
	struct in_addr saddr_in;
	struct in_addr daddr_in;
	struct in6_addr saddr_in6;
	struct in6_addr daddr_in6;
	__maybe_unused void *saddr, *daddr;
	char dst[INET6_ADDRSTRLEN];

	memset(dst, 0, sizeof(dst));
	if (sa_info->family == AF_INET) {
		saddr_in.s_addr = sa_info->saddr.a4;
		daddr_in.s_addr = sa_info->id.daddr.a4;
		saddr = &saddr_in.s_addr;
		daddr = &daddr_in.s_addr;
	} else if (sa_info->family == AF_INET6) {
		memcpy(&saddr_in6.s6_addr,
			&sa_info->saddr.a6,
			sizeof(saddr_in6.s6_addr));
		memcpy(&daddr_in6.s6_addr,
			&sa_info->id.daddr.a6,
			sizeof(daddr_in6.s6_addr));
		saddr = &saddr_in6.s6_addr;
		daddr = &daddr_in6.s6_addr;
	} else
		return;

	TRACE("xfrm sa spi %x", sa_info->id.spi);
	TRACE(" saddr %s", inet_ntop(sa_info->family,
				saddr, dst, sizeof(dst)));
	TRACE(" daddr %s\n", inet_ntop(sa_info->family,
				daddr, dst, sizeof(dst)));
}

void trace_xfrm_policy_info(struct xfrm_userpolicy_info *pol_info)
{
	__maybe_unused const char *dir;
	struct in_addr saddr_in;
	struct in_addr daddr_in;
	struct in6_addr saddr_in6;
	struct in6_addr daddr_in6;
	__maybe_unused void *saddr, *daddr;
	char dst[INET6_ADDRSTRLEN];

	memset(dst, 0, sizeof(dst));
	if (pol_info->sel.family == AF_INET) {
		saddr_in.s_addr = pol_info->sel.saddr.a4;
		daddr_in.s_addr = pol_info->sel.daddr.a4;
		saddr = &saddr_in.s_addr;
		daddr = &daddr_in.s_addr;
	} else if (pol_info->sel.family == AF_INET6) {
		memcpy(&saddr_in6.s6_addr,
			&pol_info->sel.saddr.a6,
			sizeof(saddr_in6.s6_addr));
		memcpy(&daddr_in6.s6_addr,
			&pol_info->sel.daddr.a6,
			sizeof(daddr_in6.s6_addr));
		saddr = &saddr_in6.s6_addr;
		daddr = &daddr_in6.s6_addr;
	} else
		return;


	dir = (pol_info->dir == XFRM_POLICY_OUT) ? "OUT" :
		((pol_info->dir == XFRM_POLICY_IN) ? "IN" : "FWD");

	TRACE("xfrm pol index %d dir %s\n",
		pol_info->index, dir);
	TRACE("\tsel saddr %s", inet_ntop(pol_info->sel.family,
				saddr, dst, sizeof(dst)));
	TRACE(" daddr %s\n", inet_ntop(pol_info->sel.family,
				daddr, dst, sizeof(dst)));
}

static void trace_dpa_policy(struct dpa_pol *dpa_pol)
{
	struct in_addr saddr_in;
	struct in_addr daddr_in;
	struct in6_addr saddr_in6;
	struct in6_addr daddr_in6;
	__maybe_unused void *saddr, *daddr;
	char dst[INET6_ADDRSTRLEN];

	memset(dst, 0, sizeof(dst));

	if (dpa_pol->sa_family == AF_INET) {
		saddr_in.s_addr = dpa_pol->sa_saddr.a4;
		daddr_in.s_addr = dpa_pol->sa_daddr.a4;
		saddr = &saddr_in.s_addr;
		daddr = &daddr_in.s_addr;
	} else if (dpa_pol->sa_family == AF_INET6) {
		memcpy(&saddr_in6.s6_addr,
			&dpa_pol->sa_saddr.a6,
			sizeof(saddr_in6.s6_addr));
		memcpy(&daddr_in6.s6_addr,
			&dpa_pol->sa_daddr.a6,
			sizeof(daddr_in6.s6_addr));
		saddr = &saddr_in6.s6_addr;
		daddr = &daddr_in6.s6_addr;
	} else
		return;

	trace_xfrm_policy_info(&dpa_pol->xfrm_pol_info);
	TRACE("\ttmpl saddr %s", inet_ntop(dpa_pol->sa_family,
				saddr, dst, sizeof(dst)));
	TRACE(" daddr %s\n", inet_ntop(dpa_pol->sa_family,
				daddr, dst, sizeof(dst)));
	TRACE("\tsa_id %d\n", dpa_pol->sa_id);
}

static inline void dpa_pol_free_manip(struct dpa_pol *dpa_pol)
{
	if (dpa_pol->manip_desc != DPA_OFFLD_INVALID_OBJECT_ID)
		dpa_classif_free_hm(dpa_pol->manip_desc);
}

static inline int do_offload(int dpa_ipsec_id,
			int *sa_id,
			int post_flow_id_td,
			uint32_t policy_miss_fqid,
			struct dpa_sa *dpa_sa,
			struct dpa_pol *dpa_pol)
{
	int ret = 0;
	if (*sa_id == DPA_OFFLD_INVALID_OBJECT_ID) {
		ret = offload_sa(dpa_ipsec_id, &dpa_sa->sa_params,
				&dpa_sa->xfrm_sa_info, post_flow_id_td,
				policy_miss_fqid, dpa_pol->xfrm_pol_info.dir,
				sa_id, &dpa_sa->encap);
		if (ret < 0) {
			fprintf(stderr, "offload_sa failed , ret %d\n", ret);
			return ret;
		}
		TRACE("dpa sa id %d dir %s\n", *sa_id,
			(dpa_pol->xfrm_pol_info.dir ==
			XFRM_POLICY_OUT) ? "OUT" : "IN");
		trace_xfrm_sa_info(&dpa_sa->xfrm_sa_info);
	}

	dpa_pol->sa_id = *sa_id;
	if (dpa_pol->xfrm_pol_info.dir == XFRM_POLICY_IN &&
		!app_conf.inb_pol_check)
		return ret;
	ret = offload_policy(&dpa_pol->pol_params,
			&dpa_pol->xfrm_pol_info.sel, *sa_id,
			dpa_pol->xfrm_pol_info.dir, post_flow_id_td,
			&dpa_pol->manip_desc);
	if (ret < 0) {
		fprintf(stderr, "offload_policy failed, ret %d\n", ret);
		dpa_pol_free_manip(dpa_pol);
		return ret;
	}
	trace_dpa_policy(dpa_pol);
	return ret;
}

static inline struct dpa_sa
*find_dpa_sa(struct xfrm_usersa_id *usersa_id)
{
	struct list_head *l, *tmp;
	struct dpa_sa *dpa_sa = NULL;
	list_for_each_safe(l, tmp, &dpa_sa_list) {
		dpa_sa = (struct dpa_sa *)l;
		if (dpa_sa->xfrm_sa_info.family == AF_INET &&
			dpa_sa->xfrm_sa_info.id.spi ==
			usersa_id->spi &&
			dpa_sa->xfrm_sa_info.id.daddr.a4 ==
			usersa_id->daddr.a4) {
			break;
		} else if (dpa_sa->xfrm_sa_info.family == AF_INET6 &&
			dpa_sa->xfrm_sa_info.id.spi ==
			usersa_id->spi &&
			!memcmp(&dpa_sa->xfrm_sa_info.id.daddr.a6,
				&usersa_id->daddr.a6,
				sizeof(dpa_sa->xfrm_sa_info.id.daddr.a6))) {
			break;
		}
	}
	return dpa_sa;
}

static inline struct dpa_sa
*find_dpa_sa_byaddr(xfrm_address_t *saddr, xfrm_address_t *daddr)
{
	struct list_head *l, *tmp;
	struct dpa_sa *dpa_sa = NULL;
	list_for_each_safe(l, tmp, &dpa_sa_list) {
		dpa_sa	= (struct dpa_sa *)l;
		if (dpa_sa->xfrm_sa_info.family == AF_INET &&
			dpa_sa->xfrm_sa_info.saddr.a4 == saddr->a4 &&
			dpa_sa->xfrm_sa_info.id.daddr.a4 == daddr->a4) {
			return dpa_sa;
		} else if (dpa_sa->xfrm_sa_info.family == AF_INET6 &&
			!memcmp(&dpa_sa->xfrm_sa_info.id.daddr.a6,
				&daddr->a6,
				sizeof(dpa_sa->xfrm_sa_info.id.daddr.a6)) &&
			!memcmp(&dpa_sa->xfrm_sa_info.saddr.a6,
				&saddr->a6,
				sizeof(dpa_sa->xfrm_sa_info.saddr.a6))) {
			return dpa_sa;
			}
	}
	return NULL;
}

static inline struct dpa_pol
*find_dpa_pol_bysel_list(struct xfrm_selector *sel, struct list_head *pol_list)
{
	struct list_head *p, *tmp;
	struct dpa_pol *dpa_pol = NULL;
	list_for_each_safe(p, tmp, pol_list) {
		dpa_pol = (struct dpa_pol *)p;
		if (!memcmp(&dpa_pol->xfrm_pol_info.sel, sel,
			sizeof(dpa_pol->xfrm_pol_info.sel))) {
			return dpa_pol;
		}
	}
	return NULL;
}

static inline void
set_offload_dir(struct dpa_sa *dpa_sa, int **sa_id, int dir,
	struct list_head **pol_list)
{
	if (dir == XFRM_POLICY_OUT) {
		*sa_id = &dpa_sa->out_sa_id;
		*pol_list = &dpa_sa->out_pols;
	} else if (dir == XFRM_POLICY_IN) {
		*sa_id = &dpa_sa->in_sa_id;
		*pol_list = &dpa_sa->in_pols;
	}
}

static inline struct dpa_pol
*find_dpa_pol_bysel(struct xfrm_selector *sel, int **sa_id, int dir)
{
	struct list_head *l, *pol_list;
	struct dpa_sa *dpa_sa;
	struct dpa_pol *dpa_pol;
	list_for_each(l, &dpa_sa_list) {
		dpa_sa = (struct dpa_sa *)l;
		set_offload_dir(dpa_sa, sa_id, dir, &pol_list);
		dpa_pol = find_dpa_pol_bysel_list(sel, pol_list);
		if (dpa_pol)
			return dpa_pol;
	}
	return NULL;
}

static inline int match_pol_tmpl(struct dpa_pol *dpa_pol,
				struct dpa_sa *dpa_sa)
{
	if (dpa_sa->xfrm_sa_info.family == AF_INET &&
		dpa_pol->sa_saddr.a4 == dpa_sa->xfrm_sa_info.saddr.a4 &&
		dpa_pol->sa_daddr.a4 == dpa_sa->xfrm_sa_info.id.daddr.a4)
		return 1;
	if (dpa_sa->xfrm_sa_info.family == AF_INET6 &&
		!memcmp(&dpa_pol->sa_saddr.a6,
			&dpa_sa->xfrm_sa_info.saddr.a6,
			sizeof(dpa_pol->sa_saddr.a6)) &&
		!memcmp(&dpa_pol->sa_daddr.a6,
			&dpa_sa->xfrm_sa_info.id.daddr.a6,
			sizeof(dpa_pol->sa_saddr.a6)))
		return 1;

	return 0;

}

static inline void move_pols_to_pending(struct list_head *pol_list)
{
	struct list_head *l, *tmp;
	struct dpa_pol *pol;
	list_for_each_safe(l, tmp, pol_list) {
		pol = (struct dpa_pol *)l;
		list_del(&pol->list);
		list_add(&pol->list, &pending_sp);
	}
}

static inline int flush_dpa_sa(void)
{
	struct list_head *l, *ltmp;
	struct list_head *p, *ptmp;
	struct dpa_sa *dpa_sa;
	struct dpa_pol *dpa_pol;
	int ret  = 0;
	list_for_each_safe(l, ltmp, &dpa_sa_list) {
		dpa_sa = (struct dpa_sa *)l;
		if (dpa_sa->in_sa_id != DPA_OFFLD_INVALID_OBJECT_ID)
			ret = dpa_ipsec_remove_sa(dpa_sa->in_sa_id);
		/* TODO - err handling */
		list_for_each_safe(p, ptmp, &dpa_sa->in_pols) {
			dpa_pol = (struct dpa_pol *)p;
			list_del(&dpa_pol->list);
			list_add_tail(&dpa_pol->list, &pending_sp);
		}

		if (dpa_sa->out_sa_id != DPA_OFFLD_INVALID_OBJECT_ID) {
			ret = dpa_ipsec_remove_sa(dpa_sa->out_sa_id);
			/* TODO - err handling*/
		}
		list_for_each_safe(p, ptmp, &dpa_sa->out_pols) {
			dpa_pol = (struct dpa_pol *)p;
			list_del(&dpa_pol->list);
			list_add_tail(&dpa_pol->list, &pending_sp);
		}
		list_del(&dpa_sa->list);
		free(dpa_sa);

	}
	return ret;
}

static inline int flush_dpa_policies(void)
{
	struct list_head *l, *ltmp;
	struct list_head *p, *ptmp;
	struct dpa_sa *dpa_sa;
	struct dpa_pol *dpa_pol;
	int ret  = 0;

	list_for_each_safe(l, ltmp, &dpa_sa_list) {
		dpa_sa = (struct dpa_sa *)l;
		/* TODO - err handling */
		list_for_each_safe(p, ptmp, &dpa_sa->in_pols) {
			dpa_pol = (struct dpa_pol *)p;
			assert(dpa_sa->in_sa_id !=
			       DPA_OFFLD_INVALID_OBJECT_ID);
			if (app_conf.inb_pol_check)
				ret = dpa_ipsec_sa_remove_policy(
					dpa_sa->in_sa_id,
					&dpa_pol->pol_params);

			list_del(&dpa_pol->list);
			free(dpa_pol);
		}

		/* TODO - err handling */
		list_for_each_safe(p, ptmp, &dpa_sa->out_pols) {
			dpa_pol = (struct dpa_pol *)p;
			assert(dpa_sa->out_sa_id !=
			      DPA_OFFLD_INVALID_OBJECT_ID);
			dpa_pol_free_manip(dpa_pol);
			ret = dpa_ipsec_sa_remove_policy(dpa_sa->out_sa_id,
				&dpa_pol->pol_params);
			list_del(&dpa_pol->list);
			free(dpa_pol);
		}
	}
	list_for_each_safe(p, ptmp, &pending_sp) {
		dpa_pol = (struct dpa_pol *)p;
		list_del(&dpa_pol->list);
		free(dpa_pol);
	}
	return ret;
}


static void *xfrm_msg_loop(void *data)
{
	int xfrm_sd;
	int ret;
	int len = 0;
	char buf[4096];	/* XFRM messages receive buf */
	struct iovec iov = { buf, sizeof(buf) };
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;
	uint32_t policy_miss_fqid;
	uint32_t post_flow_id_td;
	int dpa_ipsec_id;
	cpu_set_t cpuset;

	/* get ipsec instance we use */
	struct thread_data *thread_data = (struct thread_data *)data;
	dpa_ipsec_id = thread_data->dpa_ipsec_id;
	policy_miss_fqid = thread_data->pol_miss_fqid;
	post_flow_id_td = thread_data->post_flow_id_td;

	/* Set this cpu-affinity to CPU 0 */
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (ret != 0) {
		fprintf(stderr,
			"pthread_setaffinity_np(%d) failed, ret=%d\n", 0, ret);
		pthread_exit(NULL);
	}

	xfrm_sd = create_nl_socket(NETLINK_XFRM, XFRMGRP_ACQUIRE |
				   XFRMGRP_EXPIRE |
				   XFRMGRP_SA |
				   XFRMGRP_POLICY |
				   XFRMGRP_REPORT);
	if (xfrm_sd < 0) {
		fprintf(stderr,
			"opening NETLINK_XFRM socket failed, errno %d\n",
			errno);
		pthread_exit(NULL);
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* XFRM notification loop */
	while (1) {
		len = recvmsg(xfrm_sd, &msg, 0);
		if (len < 0) {
			fprintf(stderr,
				"error receiving from XFRM socket, errno %d\n",
				errno);
			break;
		}
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_ERROR) {
				fprintf(stderr,
					"Netlink error on XFRM socket,"
					" errno %d\n",
					errno);
				break;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI ||
				nh->nlmsg_type == NLMSG_DONE) {
				fprintf(stderr,
					"XFRM multi-part messages not supported\n");
				break;
			}

			switch (nh->nlmsg_type) {
			case XFRM_MSG_UPDSA:
				TRACE("XFRM_MSG_UPDSA\n");
			case XFRM_MSG_NEWSA:
			{
				struct xfrm_usersa_info *sa_info;
				struct xfrm_encap_tmpl encap;
				struct dpa_ipsec_sa_params sa_params;
				struct sadb_msg *m;
				struct dpa_sa *dpa_sa;
				struct list_head *l, *tmp, *pol_list = NULL;
				struct dpa_pol *dpa_pol;
				int *sa_id = NULL;

				if (nh->nlmsg_type == XFRM_MSG_NEWSA)
					TRACE("XFRM_MSG_NEWSA\n");

				sa_info = (struct xfrm_usersa_info *)
					NLMSG_DATA(nh);
				trace_xfrm_sa_info(sa_info);

				memset(&encap, 0, sizeof(encap));
				memset(&sa_params, 0, sizeof(sa_params));
				/* get SA */
				m = do_sadbget(sa_info->id.spi,
						sa_info->family,
						sa_info->saddr,
						sa_info->id.daddr,
						&sa_params,
						&encap);
				if (unlikely(!m)) {
					fprintf(stderr,
						"SA doesn't exist "
						"in kernel SADB\n");
					break;
				}

				/* create and store dpa_sa */
				dpa_sa = malloc(sizeof(*dpa_sa));
				if (!dpa_sa) {
					fprintf(stderr,
						"Cannot allocate memory for dpa_sa\n");
					break;
				}
				dpa_sa->xfrm_sa_info = *sa_info;
				dpa_sa->sa_params = sa_params;
				dpa_sa->encap = encap;
				dpa_sa->in_sa_id = DPA_OFFLD_INVALID_OBJECT_ID;
				dpa_sa->out_sa_id = DPA_OFFLD_INVALID_OBJECT_ID;
				INIT_LIST_HEAD(&dpa_sa->list);
				INIT_LIST_HEAD(&dpa_sa->in_pols);
				INIT_LIST_HEAD(&dpa_sa->out_pols);
				list_add_tail(&dpa_sa->list, &dpa_sa_list);

				/*for each matching policy perform offloading*/
				list_for_each_safe(l, tmp, &pending_sp) {
					dpa_pol = (struct dpa_pol *)l;
					if (!match_pol_tmpl(dpa_pol, dpa_sa))
						continue;
					/*Policy found,
					offload SA and add policy*/
					set_offload_dir(dpa_sa, &sa_id,
						dpa_pol->xfrm_pol_info.dir,
						&pol_list);
					assert(sa_id);
					assert(pol_list);

					ret = do_offload(dpa_ipsec_id, sa_id,
							post_flow_id_td,
							policy_miss_fqid,
							dpa_sa, dpa_pol);
					if (ret < 0) {
						free(dpa_pol);
						free(dpa_sa);
						break;
					}
					/* move policy from
					pending to dpa_sa list */
					list_del(&dpa_pol->list);
					list_add_tail(&dpa_pol->list, pol_list);
				}
				break;
			}
			case XFRM_MSG_DELSA:
			{
				struct xfrm_usersa_id *usersa_id;
				struct dpa_sa *dpa_sa;

				TRACE("XFRM_MSG_DELSA\n");
				usersa_id = (struct xfrm_usersa_id *)
					NLMSG_DATA(nh);

				dpa_sa = find_dpa_sa(usersa_id);
				if (unlikely(!dpa_sa))
					break;

				/* remove dpa policies and
				move all policies on pending */
				if (dpa_sa->in_sa_id >= 0)
					ret = dpa_ipsec_remove_sa(
						dpa_sa->in_sa_id);
				if (ret < 0) {
					/*TODO - handle error */
					fprintf(stderr,
						"Failed to remove dpa_sa,"
						" ret %d\n", ret);
				} else
					move_pols_to_pending(&dpa_sa->in_pols);

				if (dpa_sa->out_sa_id >= 0)
					ret = dpa_ipsec_remove_sa(
						dpa_sa->out_sa_id);
				if (ret < 0) {
					/*TODO - handle error */
					fprintf(stderr,
						"Failed to remove dpa_sa,"
						" ret %d\n", ret);
				} else {
					move_pols_to_pending(&dpa_sa->out_pols);
				}

				list_del(&dpa_sa->list);
				if (!ret)
					free(dpa_sa);

				break;
			}
			case XFRM_MSG_FLUSHSA:
				TRACE("XFRM_MSG_FLUSHSA\n");
				flush_dpa_sa();
				break;
			case XFRM_MSG_UPDPOLICY:
				TRACE("XFRM_MSG_UPDPOLICY\n");
			case XFRM_MSG_NEWPOLICY:
			{
				struct xfrm_userpolicy_info *pol_info;
				struct sadb_msg *m;
				struct list_head *pols;
				struct dpa_sa *dpa_sa;
				struct dpa_pol *dpa_pol;
				int af;
				xfrm_address_t saddr, daddr;
				int *sa_id = NULL;

				if (nh->nlmsg_type == XFRM_MSG_NEWPOLICY)
					TRACE("XFRM_MSG_NEWPOLICY\n");
				pol_info = (struct xfrm_userpolicy_info *)
					NLMSG_DATA(nh);

				/* we handle only in/out policies */
				if (pol_info->dir != XFRM_POLICY_OUT &&
					pol_info->dir != XFRM_POLICY_IN)
					break;
				trace_xfrm_policy_info(pol_info);

				/* get SA tmpl */
				m = do_spdget(pol_info->index, &saddr, &daddr,
						&af);
				if (unlikely(!m)) {
					fprintf(stderr,
						"Policy doesn't exist in kernel SPDB\n");
					break;
				}

				/* create dpa pol and fill in fields */
				dpa_pol = malloc(sizeof(*dpa_pol));
				if (!dpa_pol) {
					fprintf(stderr,
						"Cannot allocate memory for dpa_pol\n");
					break;
				}
				memset(dpa_pol, 0, sizeof(*dpa_pol));
				dpa_pol->xfrm_pol_info = *pol_info;
				INIT_LIST_HEAD(&dpa_pol->list);
				dpa_pol->sa_saddr = saddr;
				dpa_pol->sa_daddr = daddr;
				dpa_pol->sa_family = af;
				dpa_pol->sa_id = DPA_OFFLD_INVALID_OBJECT_ID;
				dpa_pol->manip_desc =
						DPA_OFFLD_INVALID_OBJECT_ID;

				dpa_sa = find_dpa_sa_byaddr(&saddr, &daddr);

				/* SA not found, add pol on pending */
				if (!dpa_sa) {
					list_add_tail(&dpa_pol->list,
						&pending_sp);
					break;
				}

				set_offload_dir(dpa_sa, &sa_id,
						pol_info->dir, &pols);
				assert(sa_id);

				ret = do_offload(dpa_ipsec_id, sa_id,
						post_flow_id_td,
						policy_miss_fqid,
						dpa_sa, dpa_pol);
				if (ret < 0) {
					free(dpa_sa);
					free(dpa_pol);
					break;
				}

				list_add(&dpa_pol->list, pols);
				break;
			}
			case XFRM_MSG_DELPOLICY:
			{
				struct xfrm_userpolicy_id *pol_id;
				struct dpa_pol *dpa_pol;
				int *sa_id = NULL;

				pol_id = (struct xfrm_userpolicy_id *)
					NLMSG_DATA(nh);
				TRACE("XFRM_MSG_DELPOLICY\n");

				/* we handle only in/out policies */
				if (pol_id->dir != XFRM_POLICY_OUT &&
					pol_id->dir != XFRM_POLICY_IN)
					break;

				/* search policy on all dpa_sa lists */
				dpa_pol = find_dpa_pol_bysel(&pol_id->sel,
							&sa_id, pol_id->dir);
				if (!dpa_pol) {
					/* search policy on pending */
					dpa_pol = find_dpa_pol_bysel_list(
								&pol_id->sel,
								&pending_sp);
					assert(dpa_pol);
					list_del(&dpa_pol->list);
					free(dpa_pol);
					break;
				}

				if (dpa_pol->xfrm_pol_info.dir ==
					XFRM_POLICY_IN &&
					!app_conf.inb_pol_check)
					goto no_remove;
				assert(sa_id);
				trace_dpa_policy(dpa_pol);
				dpa_pol_free_manip(dpa_pol);
				ret = dpa_ipsec_sa_remove_policy(*sa_id,
							&dpa_pol->pol_params);
				if (ret < 0) {
					fprintf(stderr,
						"Failed to remove policy "
						"index %d sa_id %d\n",
						dpa_pol->xfrm_pol_info.index,
						*sa_id);
					break;
				}
no_remove:
				list_del(&dpa_pol->list);
				free(dpa_pol);
				break;

			}
			case XFRM_MSG_GETPOLICY:
				TRACE("XFRM_MSG_GETPOLICY\n");
				break;
			case XFRM_MSG_POLEXPIRE:
				TRACE("XFRM_MSG_POLEXPIRE\n");
				break;
			case XFRM_MSG_FLUSHPOLICY:
				TRACE("XFRM_MSG_FLUSHPOLICY\n");
				flush_dpa_policies();
				break;
			}
		}
	}

	close(xfrm_sd);
	pthread_exit(NULL);
}
