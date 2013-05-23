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
#ifndef __APP_COMMON_H
#define __APP_COMMON_H

#include <ppac.h>
#include "std_ext.h"

static inline struct fman_if *get_fif(int fm,
				      int port_idx,
				      enum fman_mac_type type)
{
	struct ppac_interface *ppac_if;
	list_for_each_entry(ppac_if, &ifs, node) {
		if ((fm == ppac_if->port_cfg->fman_if->fman_idx) &&
			(type == ppac_if->port_cfg->fman_if->mac_type) &&
			(port_idx == ppac_if->port_cfg->fman_if->mac_idx))
			return ppac_if->port_cfg->fman_if;
	}
	return NULL;
}

static inline struct ppac_interface *get_ppac_if(int fm,
						 int port_idx,
						 enum fman_mac_type type)
{
	struct ppac_interface *ppac_if;
	list_for_each_entry(ppac_if, &ifs, node) {
		if ((fm == ppac_if->port_cfg->fman_if->fman_idx) &&
			(type == ppac_if->port_cfg->fman_if->mac_type) &&
			(port_idx == ppac_if->port_cfg->fman_if->mac_idx))
			return ppac_if;
	}
	return NULL;
}

/* VLAN header definition */
struct vlan_hdr {
	__u16 tci;
	__u16 type;
};

enum ether_types {
	ETHER_TYPE_IPv4 = 0,
	ETHER_TYPE_IPv6,
	MAX_ETHER_TYPES
};

/* key number and size for neigh tables */
#define IPv4_KEY_SIZE		4
#define IPv6_KEY_SIZE		16
#if defined P4080
#define IPv4_NUM_KEYS		16
#define IPv6_NUM_KEYS		16
/* number of outbound tcp/udp policies */
#define OUT_TCPUDP_POL_NUM	16

#elif defined B4860
#define IPv4_NUM_KEYS		64
#define IPv6_NUM_KEYS		64
/* number of outbound tcp/udp policies */
#define OUT_TCPUDP_POL_NUM	64
#elif defined B4420
#define IPv4_NUM_KEYS           64
#define IPv6_NUM_KEYS           64
/* number of outbound tcp/udp policies */
#define OUT_TCPUDP_POL_NUM      64
#else
	#error "Plaform not defined or not supported"
#endif

#define NEIGH_TABLES_KEY_SIZE { IPv4_KEY_SIZE, IPv6_KEY_SIZE }
#define NEIGH_TABLES_NUM_KEYS { IPv4_NUM_KEYS, IPv6_NUM_KEYS }

extern t_Handle pcd_dev;
/* inbound SA lookup */
extern t_Handle cc_in_rx[DPA_IPSEC_MAX_SA_TYPE];
/* flow_id lookup - optional in policy verification */
extern t_Handle cc_flow_id;
/* post flow_id classification */
extern t_Handle cc_post_flow_id;
/* outbound SP lookup */
extern t_Handle cc_out_pre_enc[DPA_IPSEC_MAX_SUPPORTED_PROTOS];
/* outbound post ipsec forwarding - ether header manip */
extern t_Handle cc_out_post_enc[MAX_ETHER_TYPES];
/* inbound post ipsec forwarding - ether header manip */
extern t_Handle cc_in_post_dec[MAX_ETHER_TYPES];
/* forwarding header manip resources */
extern t_Handle ob_fwd_hm, ib_fwd_hm;
/* outbound pre ipsec fragmentation */
extern int manip_desc[OUT_TCPUDP_POL_NUM];

int fmc_config(void);
void fmc_cleanup(void);
int ipsec_offload_init(int *dpa_ipsec_id);
int ipsec_offload_cleanup(int dpa_ipsec_id);
int setup_xfrm_msgloop(int dpa_ipsec_id);
int setup_neigh_loop(void);
int create_nl_socket(int protocol, int groups);

#endif
