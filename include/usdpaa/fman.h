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

#ifndef __FMAN_H
#define __FMAN_H

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>

/* This struct exports parameters about an Fman network interface, determined
 * from the device-tree. */
struct fman_if {
	/* Which Fman this interface belongs to */
	uint8_t fman_idx;
	/* The type/speed of the interface */
	enum {
		fman_mac_1g,
		fman_mac_10g
	} mac_type;
	/* The index of this MAC (within the Fman it belongs to) */
	uint8_t mac_idx;
	/* The MAC address */
	struct ether_addr mac_addr;
	/* The Qman channel to schedule Tx FQs to */
	enum qm_channel tx_channel_id;
	/* The hard-coded FQIDs for this interface. Note: this doesn't cover the
	 * PCD nor the "Rx default" FQIDs, which are configured via FMC and its
	 * XML-based configuration. */
	uint32_t fqid_rx_err;
	uint32_t fqid_tx_err;
	uint32_t fqid_tx_confirm;
	/* The base node for a per-"if" list of "struct fman_if_bpool" items */
	struct list_head bpool_list;
	/* The node for linking this interface into "fman_if_list" */
	struct list_head node;
};

/* This struct exposes parameters for buffer pools, extracted from the network
 * interface settings in the device tree. */
struct fman_if_bpool {
	uint32_t bpid;
	uint64_t count;
	uint64_t size;
	uint64_t addr;
	/* The node for linking this bpool into fman_if::bpool_list */
	struct list_head node;
};

/* And this is the base list node that the interfaces are added to. (See
 * fman_if_enable_all_rx() below for an example of its use.) */
const struct list_head *fman_if_list;

/* "init" discovers all Fman interfaces. "finish" tears down the driver. */
int fman_if_init(void);
void fman_if_finish(void);

/* Enable/disable Rx on specific interfaces */
void fman_if_enable_rx(const struct fman_if *);
void fman_if_disable_rx(const struct fman_if *);

/* Enable/disable Rx on all interfaces */
static inline void fman_if_enable_all_rx(void)
{
	const struct fman_if *__if;
	list_for_each_entry(__if, fman_if_list, node)
		fman_if_enable_rx(__if);
}
static inline void fman_if_disable_all_rx(void)
{
	const struct fman_if *__if;
	list_for_each_entry(__if, fman_if_list, node)
		fman_if_disable_rx(__if);
}

/* To display MAC addresses (of type "struct ether_addr") via printf()-style
 * interfaces, these macros may come in handy. Eg;
 *        struct fman_if *p = get_ptr_to_some_interface();
 *        printf("MAC address is " ETH_MAC_PRINTF_FMT "\n",
 *               ETH_MAC_PRINTF_ARGS(&p->mac_addr));
 */
#define ETH_MAC_PRINTF_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_MAC_PRINTF_ARGS(a) \
		(a)->ether_addr_octet[0], (a)->ether_addr_octet[1], \
		(a)->ether_addr_octet[2], (a)->ether_addr_octet[3], \
		(a)->ether_addr_octet[4], (a)->ether_addr_octet[5]

/* To iterate the "bpool_list" for an interface. Eg;
 *        struct fman_if *p = get_ptr_to_some_interface();
 *        struct fman_if_bpool *bp;
 *        printf("Interface uses following BPIDs;\n");
 *        fman_if_for_each_bpool(bp, p) {
 *            printf("    %d\n", bp->bpid);
 *            [...]
 *        }
 */
#define fman_if_for_each_bpool(bp, __if) \
	list_for_each_entry(bp, &(__if)->bpool_list, node)

#endif	/* __FMAN_H */