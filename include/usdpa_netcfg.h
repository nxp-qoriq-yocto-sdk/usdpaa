/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
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

#ifndef __CONFIG_H
#define	__CONFIG_H

#include <stdint.h>
#include <net/ethernet.h>

struct fm_ethport_fq {
	struct  {
		uint32_t start;
		uint32_t count;
	} pcd;					/* PCD FQIDs */
	uint32_t rx_def;			/* RX default FQID */
	uint32_t rx_err;			/* RX error FQID */
	uint32_t tx_err;			/* TX error FQID */
	uint32_t tx_confirm;			/* TX confirm FQID */
};

struct fm_mac_bpools {
	unsigned int num_bpools;
	struct bpool_data {
		uint32_t bpid; /* Buffer pool id */
		uint32_t count; /* Number of buffers */
		uint32_t size; /* Size of each buffer */
		off_t addr; /* Start address of the bpool */
	} bpool[0];	/* Variable structure array of size num_bpools.
			This have buffer pool configuration details of
			all bpools attched to ETH port */
};

/* Configuration information related to a specific ethernet port */
struct fm_eth_port_cfg {
	struct fm_ethport_fq fq;	/* FQs attached to ETH port */
	struct ether_addr fm_mac_addr;	/* MAC Address of the ETH port */
	uint8_t qm_tx_channel_id;	/* Tx qman channel id */
	struct fm_mac_bpools *mac_bpools; /* Points to the buffer pools
					     configurations attached to this
					     mac port */
};

/* This structure contains the network configuration information for USDPAA.
 * Currently this have configuration information related to
 * Ethernet ports only. More configuration informations, which is there in
 * device tree of XML file or command line arguments can be placed in this
 * structure if required by application. */
struct usdpa_netcfg_info {
	uint8_t num_cgrids;
	uint32_t *cgrids;
	uint8_t num_pool_channels;
	enum qm_channel *pool_channels;
	uint8_t num_ethports;	/* Number of ports */
	struct fm_eth_port_cfg port_cfg[0]; /* variable structure array of size
					num_ethports. */
};

/* pcd_file@ : netpcd xml file which have a PCD information.
 * cfg_file@ : cfgdata XML file
 * truct cfg * @: Returns the information in structure pointer.
 * Initialize the configuration layer and returns the port information.
 * */
struct usdpa_netcfg_info *usdpa_netcfg_acquire(char *pcd_file, char *cfg_file);

/* cfg_ptr@ configuration information pointer which was returned
 * in responce to usdpa_netcfg_acquire() api described above.
 * Frees the resources allocated for configuration layer */
void usdpa_netcfg_release(struct usdpa_netcfg_info *cfg_ptr);

/* cfg_ptr@ configuration information pointer. This should be pointer
 * returned in responce to usdpa_netcfg_acquire() api described above.
 * This function dumps configuration data pointed by cfg_ptr */
void dump_usdpa_netcfg(struct usdpa_netcfg_info *cfg_ptr);
#endif
