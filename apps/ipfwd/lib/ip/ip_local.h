/**
 \file ip_local.h
 \brief This file contains the functionality related to handling of
 self terminated packets
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
#ifndef LIB_IP_IP_LOCAL_H
#define LIB_IP_IP_LOCAL_H 1

#include "ip/ip.h"
#include "ip/ip_common.h"
#include "net/annotations.h"
#include "ip/ip_context.h"

/**
 \brief Handles Self terminated Packet. If the Packet is fragmented, and needs reassembly then it is discarded, else it is processed.
 \param[in] ctxt IP Context
 \param[in] notes Annotaion
 \param[in] ip_hdr Pointer to the header of the IP Packet
 \return Status
 */
enum IP_STATUS ip_local_deliver(struct ip_context_t *ctxt,
				struct annotations_t *notes,
				struct ip_header_t *ip_hdr);

/**
 \brief Handles Self terminated Packet. Updates the stats, and Processes the Packet.
 \param[in] ctxt IP Context
 \param[in] notes Annotation
 \param[in] ip_hdr Pointer to the header of the IP Packet
 \return Status
 */
enum IP_STATUS ip_local_deliver_finish(struct ip_context_t *ctxt,
				       struct annotations_t *notes,
				       struct ip_header_t *ip_hdr);

/**
 \brief Defragment a datagram
 \param[in] ctxt IP Context
 \param[in] notes Annotation
 \param[in] ip_hdr Pointer to the header of the IP Packet
 \return none
 */
void ip_defragment(struct ip_context_t *ctxt,
		   struct annotations_t *notes, struct ip_header_t *ip_hdr);

#endif /* ifndef LIB_IP_IP_LOCAL_H */
