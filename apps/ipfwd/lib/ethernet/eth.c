/**
 \file eth.c
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

#include "eth.h"

void *eth_set_header(struct ppac_if *dev,
		     void *ll_payload,
		     const struct ether_addr *saddr,
		     const struct ether_addr *daddr)
{
	struct ether_header *eth;

	eth = (typeof(eth))ll_payload - 1;

	if (saddr == NULL) {
		saddr = &dev->port_cfg->fman_if->mac_addr;
	}
	memcpy(eth->ether_shost, saddr, sizeof(eth->ether_shost));
	memcpy(eth->ether_dhost, daddr, sizeof(eth->ether_dhost));
	eth->ether_type = ETHERTYPE_IP;

	return eth;
}

void eth_cache_header(struct ll_cache_t *llc, const struct ether_header *eth)
{
	llc->ll_addr_len = sizeof(eth->ether_dhost);
	llc->ll_hdr_len = sizeof(*eth);
	memcpy(llc->ll_data, eth, sizeof(*eth));
}
