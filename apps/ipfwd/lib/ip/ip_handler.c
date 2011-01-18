/**
 \file ip_handler.c
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
#include <compat.h>
#include <bigatomic.h>
#include "compiler.h"
#include "app_common.h"
#include "net/annotations.h"
#include "net/context.h"
#include "net/frame_handler.h"
#include "net/net_dev.h"
#include "ip/ip_common.h"
#include "ip/ip_accept.h"
#include "ethernet/eth.h"

void ip_handler(struct fq_context_t *ctxt, struct annotations_t *notes,
		void *data)
{
	struct ip_header_t *ip_hdr;
#ifdef STATS_TBD
	struct ip_context_t *ip_ctxt = (struct ip_context_t *)ctxt;
#endif

	markpoint(6);
#ifdef STATS_TBD
	decorated_notify_inc_32(&(ip_ctxt->stats->ip_in_received));
#endif
	ip_hdr =
	    (struct ip_header_t *)((uint8_t *) data +
				   sizeof(struct ethernet_header_t));
	notes->dest = NULL;
	ip_accept_preparsed((struct ip_context_t *)ctxt, notes, ip_hdr,
			SOURCE_POST_FMAN);
}
