/**
 \file ip_forward.h
 \brief This file is designed to encapsulate the validation of all the
 forwarding attributes before sending out the packet
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
#ifndef LIB_IP_IP_FORWARD_H
#define LIB_IP_IP_FORWARD_H 1

#include "ip/ip.h"
#include "ip/ip_common.h"
#include "net/annotations.h"
#include "ip/ip_context.h"

/**
 \brief ip_checksum calculator
 \param[in] ip_hdr pointer to ip header checksum
 \param[out] len length of header on which checksum has to be
		calculated
 \return Returns calculated Checksum
 */
static inline uint16_t ip_checksum(struct ip_header_t *ip_hdr, uint8_t len)
{
	uint32_t sum;
	sum = 0;
	uint16_t *buff;

	buff = (uint16_t *) ip_hdr;

	while (len > 1) {
		sum += *buff;
		buff++;

		if (sum & 0x80000000)
			sum = (sum & 0xffff) + (sum >> 16);
		len = len - 2;
	}

	if (len)
		sum += *buff;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t) ~sum;
}

/**
 \brief Checks the packet forwarding attributes like TTL, MTU, No dest, and Drops it if any of these fail
 \param[in] ctxt IP Context
 \param[in] notes Annotaion
 \param[in] ip_hdr Pointer to the header of IPPacket that needs to be forwarded
 \return Status
 */
enum IP_STATUS ip_forward(struct ip_context_t *ctxt,
			  struct annotations_t *notes,
			  struct ip_header_t *ip_hdr);

/**
 \brief Handle any Optional field updation in the IP Header, Updates the Stats, and Sends the Packet
 \param[in] ctxt IP Context
 \param[in] notes Annotaion
 \param[in] ip_hdr Pointer to the header of the IP Packet
 \return Status
 */
enum IP_STATUS ip_forward_finish(struct ip_context_t *ctxt,
				 struct annotations_t *notes,
				 struct ip_header_t *ip_hdr);

#endif /* ifndef LIB_IP_IP_FORWARD_H */
