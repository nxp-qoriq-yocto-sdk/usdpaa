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
#include "ethernet/eth.h"
#include "net/net_dev.h"
#include "net/ll_cache.h"
#include <assert.h>

/**
 \brief Ethernet layer Setup function
 \param[in] Netdev Structure pointer
 */
void eth_net_dev_setup(struct net_dev_t *dev)
{
	dev->set_mtu = &eth_set_mtu;
	dev->set_ll_address = &eth_set_mac_addr;
	dev->set_header = &eth_set_header;
	dev->cache_header = &eth_cache_header;
	dev->mtu = ETH_MAX_MTU;
	dev->header_len = ETHER_HDR_LEN;
	dev->dev_addr_len = ETHER_ADDR_LEN;
}

/**
 \brief Set ethernet header in a ethernet pkt
 \param[in] dev Netdev Struture
 \param[in] ll_payload Link Layer Payload
 \param[in] saddr Source IPv4 Address
 \param[in] daddr Destination IPv4 Address
 */
void *eth_set_header(struct net_dev_t *dev, void *ll_payload, void *saddr,
		     void *daddr)
{
	struct ether_header *eth;

	assert(ll_payload != NULL);
	assert(dev != NULL);
	assert(daddr != NULL);

	eth = (typeof(eth))ll_payload - 1;

	if (saddr == NULL)
		saddr = dev->dev_addr;
	eth->ether_type = ETHERTYPE_IP;
	memcpy(&eth->ether_shost, saddr, dev->dev_addr_len);
	memcpy(&eth->ether_dhost, daddr, dev->dev_addr_len);

	return eth;
}

/**
 \brief Add Ethernet header in link layer cache
 \param[in] llc link layer cache pointer
 \param[in] eth_hdr Ethernet Header
 */
void eth_cache_header(struct ll_cache_t *llc, void *eth_hdr)
{
	struct ether_header *eth = eth_hdr;
	assert(eth_hdr != NULL);
	assert(llc != NULL);

	llc->ll_addr_len = ETHER_ADDR_LEN;
	llc->ll_hdr_len = ETHER_HDR_LEN;
	eth->ether_type = ETHERTYPE_IP;
	memcpy(llc->ll_data, eth_hdr, ETHER_HDR_LEN);
}

/**
 \brief Setup MTU of a link
 \param[in] dev Netdev structure associated to Link
 \param[in] new_mtu New MTU value to be set
 */
void eth_set_mtu(struct net_dev_t *dev, uint32_t new_mtu)
{
	assert(new_mtu >= ETH_MIN_MTU);
	assert(new_mtu <= ETH_MAX_MTU);

	dev->mtu = (uint16_t)new_mtu;
}

void eth_set_mac_addr(struct net_dev_t *dev, void *addr)
{
	assert(dev != NULL);
	assert(addr != NULL);

	memcpy(dev->dev_addr, addr, ETHER_ADDR_LEN);
}
