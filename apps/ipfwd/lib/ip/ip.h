/**
 \file ip.h
 \brief This file contains data structures, and defines related to IP Packet
 format
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
#ifndef __LIB_IP_IP_H
#define __LIB_IP_IP_H

#include "ethernet/eth.h"

#include <netinet/ip.h>

#define IP_ADDRESS_BYTES		(4)
/**< Number of Bytes in IP Address*/
#define IP_HEADER_LENGTH_NO_OPTIONS	(20)
/**< Length in bytes of the IP Header without the Optional fields*/
#define IP_HEADER_LENGTH_NO_OPTIONS_WORDS \
	(IP_HEADER_LENGTH_NO_OPTIONS / BYTES_PER_WORD)
#define IP_HEADER_DEFAULT_TOS		(0)
/**< default value of IP TOS*/
#define IP_HEADER_FRAG_NO_FRAG		(0)
/**< Value of Fragmentation Flag for No fragmentation*/
#define IP_HEADER_DEFAULT_TTL		(0x40)
/**< default value of IP TTL*/
#define IP_HEADER_PROTOCOL_ICMP		(0x01)
/**< value of ICMP protocol*/
#define IP_HEADER_PROTOCOL_TCP		(0x06)
/**< value of TCP protocol*/
#define IP_HEADER_PROTOCOL_UDP		(0x11)
/**< value of UDP protocol*/
#define IP_HEADER_PROTOCOL_GRE		(0x2F)
/**< value of GRE protocol*/
#define IP_HEADER_PROTOCOL_ESP		(0x32)
/**< value of ESP protocol*/
#define IP_HEADER_PROTOCOL_IPIP		(0x5E)
/**< value of IPIP protocol*/
#define IP_HEADER_NO_CHECKSUM		(0)
/**< IP no checksum value*/

/**
\brief IP Address
*/
union ip_address_t {
	uint8_t bytes[IP_ADDRESS_BYTES];
	/**< Specifies the IP Address*/
	uint32_t word;
};

/**
 \brief Network Node Structure
 */
struct node_t {
	struct ether_addr mac;	/**< MAC address */
	union ip_address_t ip;		/**< IP Address */
};

/**
\brief IP Options
*/
struct ip_option_t {
	union {
		uint8_t byte;
		struct {
			uint32_t copied:1;
			/**< The Bit is set to 1 if the options need to copied
			 into all the fragments of the datagram*/
			uint32_t tclass:2;
			/**< Specifies the category into which the option
			 belongs*/
			uint32_t number:5;
			/**< Specifies the kind of option*/
		} __PACKED bits;
	} type;
	uint8_t length;
	/**< For variable-length options, indicates the size of the
	 entire option, in bytes. */
	uint8_t data[];
	/**< For variable-length options, contains data to be sent
	 as part of the option */
};

 /**
 \brief Specifies if the IP Header contains Optional fields or not
 \param[in] ip_hdr Pointer to the IP Header Structure
 \return true - ip header has options
 false - ip header does not have options
 */
static inline bool has_options(struct iphdr *ip_hdr)
{
	return ((ip_hdr->ihl) > IP_HEADER_LENGTH_NO_OPTIONS);
}

 /**
 \brief Specifies if the IP Datagram is a fragment of a bigger datagram
 \param[in] ip_hdr Pointer to the IP Header Structure
 \return true - ip packet is a fragment of a bigger ip packet
 false - ip packet is non-fragmented
 */
static inline bool is_fragment(struct iphdr *ip_hdr)
{
	return (ip_hdr->frag_off != 1);
}

/**
 \brief Frame gets freed to bman pool
 \param[in] void * Buffer pointer to be freed
 \param[in] uint8_t Buffer PoolID
 \return none
 */
extern void discard_handler(void *notes, uint8_t bpid);
#endif /* __LIB_IP_IP_H */
