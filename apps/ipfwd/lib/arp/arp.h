/**
 \file arp.h
 \brief This file contains functions for managing the arp table
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
#ifndef __LIB_ARP_ARP_H
#define __LIB_ARP_ARP_H

#include <stdint.h>
#include <stdbool.h>
#include "compiler.h"
#include "net/net_dev.h"
#include "net/neigh.h"
#include "net/annotations.h"
#include "ip/ip.h"

extern struct ip_stack_t stack;

#define	ARP_HDR_LEN	28	/**<ARP Header Length */
#define	ARP_HTYPE_ETH	1	/**<Link layer protocol type Ethenet */
#define	ARP_PTYPE_IP	0x800	/**<Upper layer protocol type IPv4 */
#define	ARP_HLEN_ETH	6	/**<Harware addr length */
#define	ARP_PLEN_IP	4	/**<IPv4 addr length */
#define	ARPOP_REQUEST	1	/**<ARP Request Opcode */
#define	ARPOP_REPLY	2	/**<ARP Reply Opcode */

#define ARP_RETRANSMIT_INTERVAL	5000
/**
 \brief ARP Header
 */
struct arp_header_t {
	uint16_t arp_hrd;	/**<ARP Hardware Type */
	uint16_t arp_proto;	/**<ARP Protocol Type */
	uint8_t arp_hrdlen;	/**<Hardware Address Length */
	uint8_t arp_protolen;	/**<Protocol Length */
	uint16_t arp_opcode;	/**<OpCode*/
	union mac_address_t arp_senderaddr;	/**<Sender Mac Address */
	uint32_t arp_senderip;	/**<Sender IP Address */
	union mac_address_t arp_targetaddr;	/**<Target Mac Address */
	uint32_t arp_targetip;	/**<Target IP Address */
} __attribute__ ((packed));

/**
 \brief Handles ARP Request on the Interface
 \param[in] eth_hdr pointer in ARP request frame
 \param[in] node Iface Node replying to the ARP Request
 \return    0 Arp request successfull
 -1 Arp request failed
 */
uint32_t arp_handle_request(struct ethernet_header_t *eth_hdr,
				   struct node_t *node);

/**
 \brief Creates the Arp Table
 \return Pointer to the created Table
 */
struct neigh_table_t *arp_table_create(void);

/**
 \brief Initializes the Arp Table
 \param[inout] n Pointer to the Arp Table
 \return none
 */
void arp_constructor(struct neigh_t *n);

/**
 \brief Increments the solicit Error for Arp Table
 \param[in] n Pointer to the Arp Table
 \param[in] notes Pointer to the prepended data used by BMI
 \param[in] ip_hdr Pointer to the IP Header
 \return none
 */
void arp_solicit(struct neigh_t *n, void *notes, void *ip_hdr);

/**
 \brief Increments the Protocol Errors for Arp Table
 \param[in] n Pointer to the Arp Table
 \param[in] notes Pointer to the prepended data used by BMI
 \param[in] ip_hdr Pointer to the IP Header
 \return none
 */
void arp_error_handler(struct neigh_t *n, void *notes, void *ip_hdr);

/**
 \brief Add dynamic arp entries
 \param[in] arp table ARP table pointer
 \param[in] node Link Node whose MAC has to be added in arp table
 \param[out] 0 on success, otherwise -ve value
 */
int add_arp_entry(struct neigh_table_t *arp_table, struct net_dev_t *dev,
			struct node_t *node);

/**
 \brief Handler function when arp packet received
 \param[in] notes pointer to Annotations structure
 \param[in] data  pointer to packet data
 \param[out] NULL
 */
void arp_handler(struct annotations_t *notes, void *data);

/**
 \brief Function to send arp request packet
 \param[in] dev pointer to interface structure
 \param[in] target_ip ip address of destination
 \param[out] 0 on success, otherwise -ve value
 */
int arp_send_request(struct net_dev_t *dev, uint32_t target_ip);

#endif /* __LIB_ARP_ARP_H */
