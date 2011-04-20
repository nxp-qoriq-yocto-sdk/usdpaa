/**
 \file eth.h
 \brief Ethernet related data structures, and defines
 */
/*
 * Copyright (C) 2010,2011 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __LIB_ETHERNET_ETH_H
#define __LIB_ETHERNET_ETH_H

#include "../../include/ppam_if.h"
#include <ppac_if.h>

#include "net/ll_cache.h"

/**
 \brief Fills in the Ethernet Header
 \param[in] dev Device Pointer
 \param[out] ll_payload Pointer to the Ethernet Payload Buffer
 \param[in] daddr Destination MAC Address
 \param[in] saddr Source MAC Address
 */
void *eth_set_header(struct ppac_if *dev,
		     void *ll_payload,
		     const struct ether_addr *daddr,
		     const struct ether_addr *saddr);

/**
 \brief Adds an ethernet address in link layer cache
 \param[in] llc link_layer cache pointer
 \param[in] ll_payload Ethernet header to be set
 */
void eth_cache_header(struct ll_cache_t *llc, const struct ether_header *eth);

/**
 \brief Swap 6-byte MAC headers "efficiently"
 \param[in] prot_eth
 */
static inline void eth_header_swap(struct ether_header *prot_eth)
{
	uint32_t a, b, c;
	uint32_t *overlay;

	overlay = (typeof(overlay))prot_eth;
	a = overlay[0];
	b = overlay[1];
	c = overlay[2];
	overlay[0] = (b << 16) | (c >> 16);
	overlay[1] = (c << 16) | (a >> 16);
	overlay[2] = (a << 16) | (b >> 16);
}

#endif /* __LIB_ETHERNET_ETH_H */
