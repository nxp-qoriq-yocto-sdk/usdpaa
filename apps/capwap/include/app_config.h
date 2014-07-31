/* Copyright (c) 2014 Freescale Semiconductor, Inc.
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
#ifndef __APP_CONFIG_H
#define __APP_CONFIG_H

#include <stdbool.h>
#include <net/if.h>
#include <netinet/in.h>
#include <usdpaa/fman.h>

#include "ncsw_ext.h"
#include "fm_ext.h"

#define APP_MAX_NUM_OF_CC_NODES             32
#define APP_MAX_NUM_OF_MANIPS               128

typedef struct {
	bool pcdSet;
	uint32_t numOfRxQs;
	uint32_t rxPcdQsBase;
	t_Handle h_NetEnv;
	uint8_t numOfScms;
	uint8_t scmsBase;
	t_Handle h_Schemes[FM_PCD_KG_NUM_OF_SCHEMES];
	t_Handle h_CcTree;
	uint8_t numOfCcNodes;
	t_Handle h_CcNodes[APP_MAX_NUM_OF_CC_NODES];
	t_Handle h_CcNodesOrder[APP_MAX_NUM_OF_CC_NODES];
	uint8_t numOfManips;
	t_Handle h_Manips[APP_MAX_NUM_OF_MANIPS];
	t_Handle h_ManipsOrder[APP_MAX_NUM_OF_MANIPS];
	int manipSizeOnOrigFrm;
	uint8_t manipSizeOnFeRxFrm;
} port_pcd_info;

struct capwap_port {
	t_Handle handle;
	struct fman_if *interface;
	port_pcd_info fm_pcd_info;
	e_FmPortType type;
};

struct dtls_alg_info {
	uint32_t algtype;
	uint8_t *key;
	uint32_t keylen;
};

struct tunnel_info {
	in_addr_t src_ip;
	in_addr_t dest_ip;
	uint8_t src_mac[6];
	uint8_t dest_mac[6];
	struct dtls_alg_info *cipherdata;
	struct dtls_alg_info *authdata;
};

/* application configuration data */
struct app_conf {
	/* CAPWAP Domain dev fd */
	int capwap_domain_dev_fd;
	/* FMAN index */
	int fm;
	/* CAPWAP Ethernet Port */
	struct capwap_port capwap_eth;
	/* CAPWAP outbound offline Port */
	struct capwap_port ob_op;
	/* CAPWAP inbound offline Port */
	struct capwap_port ib_op;
	/* Non-CAPWAP Ethernet Port1 for Mode II */
	struct capwap_port non_capwap_eth1;
	/* Non-CAPWAP Ethernet Port2 for Mode II */
	struct capwap_port non_capwap_eth2;
	/* IP fragmentation scratch bpid*/
	uint32_t bpid;
	/* Max 4 tunnel info in the list */
	struct tunnel_info *tunnel_list[4];
	/* CAPWAP Ethernet loopback */
	bool loop_back;
	/* Case mode, 1:default mode, 2:offload mode*/
	int mode;
};
extern struct app_conf app_conf;
#endif
