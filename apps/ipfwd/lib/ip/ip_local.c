/**
 \file ip_local.c
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
#include "net/annotations.h"
#include "compiler.h"
#include "ip/ip_local.h"
#include "ip/ip_common.h"
#include "ip/ip_hooks.h"
#include "ip/ip_protos.h"

enum IP_STATUS ip_local_deliver(struct ip_context_t *ctxt,
				struct annotations_t *notes,
				struct iphdr *ip_hdr)
{
	enum IP_STATUS retval;

	if (unlikely(is_fragment(ip_hdr))) {
		ip_defragment(ctxt, notes, ip_hdr);
		retval = IP_STATUS_STOLEN;
	} else {
		/* Call INPUT hooks */
		retval = exec_hook(ctxt->hooks, IP_HOOK_INPUT, ctxt, notes,
				ip_hdr, &ip_local_deliver_finish,
				SOURCE_POST_FMAN);
	}

	return retval;
}

enum IP_STATUS ip_local_deliver_finish(struct ip_context_t *ctxt,
				       struct annotations_t *notes,
				       struct iphdr *ip_hdr,
				       enum state source)
{
#ifdef STATS_TBD
	decorated_notify_inc_32(&(ctxt->stats->ip_local_delivery));
#endif
	return ip_protos_exec(ctxt->protos, (enum IP_PROTO)ip_hdr->protocol,
				ctxt, notes, ip_hdr);
}

void ip_defragment(struct ip_context_t *ctxt,
		   struct annotations_t *notes,
		   struct iphdr *ip_hdr __UNUSED)
{
#ifdef STATS_TBD
	decorated_notify_inc_32(&(ctxt->stats->ip_local_frag_reassem_started));
#endif
	/* For now, do not reassemble fragments - discard them */
	free_buff(notes->fd);
}