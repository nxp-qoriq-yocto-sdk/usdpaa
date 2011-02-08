/**
 \file ip_route.c
 \brief IPv4 Route lookup is done for forwarding decision.
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

#include "compat.h"
#include <stdint.h>
#include <stdbool.h>
#include "app_common.h"
#include "ip/ip_route.h"
#include "ip/ip_forward.h"
#include "ip/ip_local.h"
#include "ip/ip_rc.h"
#include "ip/ip_protos.h"
#include "net/rt.h"
#include "net/annotations.h"
#include "net/frame_handler.h"
#include "bigatomic.h"

enum IP_STATUS ip_route_input(struct ip_context_t *ctxt,
			      struct annotations_t *notes,
			      struct iphdr *ip_hdr, enum state source)
{
	enum IP_STATUS retval = IP_STATUS_DROP;

	switch (source) {
	case SOURCE_POST_FMAN:
	{
		struct rc_entry_t *entry;
		entry = rc_entry_fast_lookup(ctxt->rc,
					ip_hdr->saddr,
					ip_hdr->daddr,
					ip_hdr->tos,
					RC_BUCKET_INDEX(notes));
		pr_dbg("Hash index= %x\n", RC_BUCKET_INDEX(notes));

		if (entry == NULL) {
			entry = rc_entry_lookup(ctxt->rc,
					ip_hdr->saddr,
					ip_hdr->daddr,
					ip_hdr->tos);
			if (entry == NULL) {
				pr_dbg("Fast Lookup Failed, going slow \
				   for Src = 0x%x; Dest = 0x%x; TOS = 0x%x\n",
				   ip_hdr->saddr,
				   ip_hdr->daddr, ip_hdr->tos);
				retval =
				ip_route_input_slow(ctxt, notes, ip_hdr);
				return retval;
			}
		}

		notes->dest = entry->dest;
#ifdef STATS_TBD
		decorated_notify_inc_64(&(entry->stats->hits));
#endif
		retval = ip_route_finish(ctxt, notes, ip_hdr);
	}
		break;
	default:
		pr_err("Invalid Case of routing\n");
		break;
	}

	return retval;
}

enum IP_STATUS ip_route_input_slow(struct ip_context_t *ctxt,
				   struct annotations_t *notes,
				   struct iphdr *ip_hdr __UNUSED)
{
#ifdef STATS_TBD
	decorated_notify_inc_64(&(ctxt->stats->ip_route_input_slow));
#endif
	free_buff(notes->fd);
	return IP_STATUS_DROP;
}

enum IP_STATUS ip_route_finish(struct ip_context_t *ctxt,
				struct annotations_t *notes,
				struct iphdr *ip_hdr)
{
	struct rt_dest_t *dest;


	dest = notes->dest;
	switch (dest->scope) {
	case ROUTE_SCOPE_GLOBAL:
		if (likely(dest->dev)) {
			return ip_forward(ctxt, notes, ip_hdr);
		} else {
#ifdef STATS_TBD
			decorated_notify_inc_64(&
				(ctxt->
				stats->ip_xmit_icmp_unreach_no_egress));
#endif
		}
		break;
	case ROUTE_SCOPE_LOCAL:
		return ip_local_deliver(ctxt, notes, ip_hdr);
	}
	free_buff(notes->fd);
	return IP_STATUS_DROP;
}
