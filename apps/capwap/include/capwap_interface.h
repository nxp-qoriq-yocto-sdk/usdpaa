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
#ifndef CAPWAP_INTERFACE_H
#define CAPWAP_INTERFACE_H

#include "ncsw_ext.h"
#include "fm_ext.h"
#include <usdpaa/usdpaa_netcfg.h>

/*********************************/
/* Net interface data structures */
/*********************************/

/* Each Fman interface has one of these */
struct capwap_interface {
	struct list_head node;
	size_t size;
	const struct fm_eth_port_cfg *port_cfg;
	/* Note: the Tx FQs kept here are created to (a) initialise and schedule
	 * the FQIDs on startup, and (b) be able to clean them up on shutdown.
	 * They aren't used for enqueue operations though */
	unsigned int num_tx_fqs;
	struct qman_fq *tx_fqs;
	struct qman_fq rx_err_fq;
	struct qman_fq tx_err_fq;
	struct qman_fq tx_conf_fq;
	struct list_head list; /* list of "capwap_pcd_range"s */
	struct qman_fq rx_def_fq[0] ____cacheline_aligned;
} ____cacheline_aligned;

struct capwap_pcd_range {
	struct list_head list;
	uint32_t count;
	struct capwap_rx_hash {
		struct qman_fq fq;
#ifdef CAPWAP_ORDER_RESTORATION
		/* Rather than embedding a whole ORP object, we embed only the
		 * ORP FQ object so that it takes less (stashable) space. */
		struct qman_fq *orp_fq;
#endif
	} ____cacheline_aligned rx_hash[0];
} ____cacheline_aligned;

/* This helper simplifies the method for drilling into the interface
 * configuration to determine what flavour it is. */
static inline enum fman_mac_type capwap_interface_type(struct capwap_interface *i)
{
	return i->port_cfg->fman_if->mac_type;
}

#endif /* CAPWAP_INTERFACE_H */
