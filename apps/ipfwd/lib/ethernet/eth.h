/**
 \file eth.h
 \brief Ethernet related data structures, and defines
 */
/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc.
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

#include "compat.h"
#include <stdint.h>
#include <stdbool.h>
#include "net/net_dev.h"

/**
 \brief RFC-defined	 MTU for ethernet
 */
#define ETH_MIN_MTU                     (68)
/**< Minimum MTU for Ethernet Packet */
#define ETH_MAX_MTU	                (1500)
/**< Maximum MTU for Ethernet Packet */
#define ETH_HDR_LEN                     (4)
/**< Ethernet Header Length*/
#define ETH_ADDR_LEN                    (6)
/**< Ethernet Address Length*/

/**
 \brief A frame is multicast if the LSb of the MSB is a 1
 */
#define MULTICAST_ADDRESS_HI_MASK       (0x0100)
/**< Used to find if the Packet is Multicast */
#define ETHERNET_FRAME_TYPE_IP          (0x0800)
/**< Ethernet type - IP*/
#define ETHERNET_FRAME_CRC_SIZE         (4)
/**< Ethernet CRC size */

/**
 \brief This represents a 48-bit mac address
 */
union mac_address_t {
	uint8_t bytes[ETH_ADDR_LEN];
	struct {
		uint16_t address_hi;
		uint32_t address_lo;
	} __PACKED hilo;
} __PACKED;

/**
 \brief Floorplan for an ethernet frame header.
 */
struct ethernet_header_t {
	union mac_address_t destination;	/**< Destination MAC Address*/
	union mac_address_t source;		/**< Source MAC Address*/
	uint16_t proto;					/**< Ethernet Type*/
};

/**
 \brief Finds if 2 MAC Addresses are Equal or not
 \param[in] addr1 Pointer to First MAC Address
 \param[in] addr2 Pointer to Second MAC Address
 */
bool mac_address_equal(const union mac_address_t *addr1,
		       const union mac_address_t *addr2);

/**
 \brief Copies one MAC Address into another
 \param[out] dst Pointer to target MAC Address
 \param[in] src Pointer to Source MAC Address
 */
union mac_address_t *mac_address_copy(union mac_address_t *dst,
				      const union mac_address_t *src);

/**
 \brief Finds out if  a particular MAC Address is Unicast or not
 \param[in] addr Pointer to MAC Address
 */
bool is_mac_address_unicast(const union mac_address_t *addr);

/**
 \brief Net Device Function Pointer Implementations
 \param[inout] dev Device Pointer
 */
void eth_net_dev_setup(struct net_dev_t *dev);

/**
 \brief Fills in the Ethernet Header
 \param[in] dev Device Pointer
 \param[out] ll_payload Pointer to the Ethernet Payload Buffer
 \param[in] daddr Destination MAC Address
 \param[in] saddr Source MAC Address
 */
void *eth_set_header(struct net_dev_t *dev, void *ll_payload,
		     void *daddr, void *saddr);

/**
 \brief Adds an ethernet address in link layer cache
 \param[in] llc link_layer cache pointer
 \param[in] ll_payload Ethernet header to be set
 */
void eth_cache_header(struct ll_cache_t *llc, void *ll_payload);

/**
 \brief Sets the MTU for the Net Device
 \param[in] dev Device Pointer
 \param[in] new_mtu New MTU
 */
void eth_set_mtu(struct net_dev_t *dev, uint32_t new_mtu);

/**
 \brief Sets the MAC Address for the Net Device
 \param[in] dev Device Pointer
 \param[in] addr MAC Address
 */
void eth_set_mac_addr(struct net_dev_t *dev, void *addr);

/**
 \brief Swap 6-byte MAC headers "efficiently"
 \param[in] prot_eth
 */
static inline void ether_header_swap(struct ethernet_header_t *prot_eth)
{
	register u32 a, b, c;
	u32 *overlay = (u32 *)prot_eth;
	a = overlay[0];
	b = overlay[1];
	c = overlay[2];
	overlay[0] = (b << 16) | (c >> 16);
	overlay[1] = (c << 16) | (a >> 16);
	overlay[2] = (a << 16) | (b >> 16);
}

#endif /* __LIB_ETHERNET_ETH_H */
