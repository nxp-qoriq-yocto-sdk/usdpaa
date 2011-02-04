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
#include <fman.h>
#include <net/ethernet.h>

/* Configuration information related to a specific ethernet port */
struct fm_eth_port_cfg {
	/* PCD and "Rx default" FQIDs, obtained from FMC configuration */
	struct  {
		uint32_t start;
		uint32_t count;
	} pcd;
	uint32_t rx_def;
	/* Other interface details are in the fman driver interface */
	struct fman_if *fman_if;
};

/* This structure contains the configuration information for the USDPAA app. */
struct usdpa_netcfg_info {
	uint8_t num_cgrids;
	uint32_t *cgrids;
	uint8_t num_pool_channels;
	enum qm_channel *pool_channels;
	uint8_t num_ethports;	/* Number of ports */
	struct fm_eth_port_cfg port_cfg[0]; /* variable structure array of size
					num_ethports. */
};

/* pcd_file: FMC netpcd XML ("policy") file, that contains PCD information.
 * cfg_file: FMC config XML file
 * Returns the configuration information in newly allocated memory.
 */
struct usdpa_netcfg_info *usdpa_netcfg_acquire(const char *pcd_file,
					const char *cfg_file);

/* cfg_ptr: configuration information pointer.
 * Frees the resources allocated by the configuration layer.
 */
void usdpa_netcfg_release(struct usdpa_netcfg_info *cfg_ptr);

/* cfg_ptr: configuration information pointer.
 * This function dumps configuration data to stdout.
 */
void dump_usdpa_netcfg(struct usdpa_netcfg_info *cfg_ptr);

#endif
