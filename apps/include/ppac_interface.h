/* Copyright (c) 2011 Freescale Semiconductor, Inc.
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

#ifndef __PPAC_INTERFACE_H
#define __PPAC_INTERFACE_H

#include <ppac.h>

/*********************************/
/* Net interface data structures */
/*********************************/

/* Each Fman interface has one of these */
struct ppac_interface {
	struct list_head node;
	size_t size;
	const struct fm_eth_port_cfg *port_cfg;
	/* Note: the Tx FQs kept here are created to (a) initialise and schedule
	 * the FQIDs on startup, and (b) be able to clean them up on shutdown.
	 * They aren't used for enqueue operations though, see "local_fq" in
	 * ppac.h for more info. */
	unsigned int num_tx_fqs;
	struct qman_fq *tx_fqs;
	struct ppam_interface ppam_data;
	struct ppac_rx_error {
		struct qman_fq fq;
		struct ppam_rx_error s;
	} rx_error;
	struct ppac_rx_default {
		struct qman_fq fq;
		struct ppam_rx_default s;
	} rx_default;
	struct ppac_tx_error {
		struct qman_fq fq;
		struct ppam_tx_error s;
	} tx_error;
	struct ppac_tx_confirm {
		struct qman_fq fq;
		struct ppam_tx_confirm s;
	} tx_confirm;
	struct ppac_rx_hash {
		struct qman_fq fq;
#ifdef PPAC_ORDER_RESTORATION
		/* Rather than embedding a whole ORP object, we embed only the
		 * ORPID so that it takes less (stashable) space. We can plug
		 * the ORPID into a temporary ORP object on the fly when
		 * performing ORP-enabled enqueues. */
		u32 orp_id;
#endif
		struct ppam_rx_hash s;
	} ____cacheline_aligned rx_hash[0];
} ____cacheline_aligned;

#endif	/* __PPAC_INTERFACE_H */
