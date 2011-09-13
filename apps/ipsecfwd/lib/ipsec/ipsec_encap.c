/*
 * Copyright (C) 2011 Freescale Semiconductor, Inc.
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

#include <usdpaa/dma_mem.h>
#include <stdbool.h>
#include "app_common.h"
#include "ipsec_sec.h"
#include "net/frame_desc.h"
#include "mm/mem_cache.h"
#include "ip/ip_rc.h"
#include "ip/ip_protos.h"
#include "ip/ip_hooks.h"
#include "ethernet/eth.h"
#include "net/net_dev.h"
#include "ip/ip_output.h"
#include "ip/ip_accept.h"
#include "ip/ip_forward.h"

#define FM_FD_CMD_RPD  0x40000000	/* Read Prepended Data */
#define FM_FD_CMD_DTC  0x10000000	/* Do TCP Checksum */
#define FM_L3_PARSE_RESULT_IPV4	0x8000

enum IP_STATUS ipsec_encap_send(const struct ppam_rx_hash *ctxt,
				struct annotations_t *notes, void *ip_hdr_ptr)
{
	struct iphdr *ip_hdr = ip_hdr_ptr;
	struct ipsec_tunnel_t *entry = notes->dest->tunnel;
	struct qm_fd *fd = notes->fd, fd2;
	uint32_t ret;
	uint32_t sec_fq;

	ipsec_create_compound_fd(&fd2, fd, ip_hdr, ENCRYPT);
	fd = &fd2;
#ifdef STATS_TBD
#ifdef INFINITE_IPSECFWD
	decorated_notify_inc_32(&(ctxt->stats->encap_pre_sec));
#endif
#endif
	if (unlikely(entry->fq_state == PARKED)) {
		spin_lock(&entry->tlock);
		if (entry->fq_state == PARKED) {
			sec_fq = SEC_FQ_BASE + (entry->tunnel_id * 2);
			if (init_sec_fqs(entry, ENCRYPT, entry->ctxtA,
					sec_fq)) {
				fprintf(stderr, "error: %s: Failed to Init"
					" encap Context\n", __func__);
				return IP_STATUS_DROP;
			}
			entry->fq_state = SCHEDULED;
		}
		spin_unlock(&entry->tlock);
	}

loop:
	ret = qman_enqueue(entry->qm_fq_to_sec, fd, 0);

	if (unlikely(ret)) {
		uint64_t now, then = mfatb();
		do {
			now = mfatb();
		} while (now < (then + 1000));
		goto loop;
	}

	return IP_STATUS_STOLEN;
}

void ipsec_encap_cb(const struct ipsec_context_t *ipsec_ctxt,
		    const struct qm_fd *fd, void *data __always_unused)
{
	struct qm_fd simple_fd;
	struct iphdr *ip_hdr;
	struct annotations_t *ip_notes;
	const struct qm_fd *compound_fd = fd;

	if (unlikely(compound_fd->status)) {
		fprintf(stderr, "error: %s: Non-Zero Status from"
			" SEC Block %x\n", __func__, compound_fd->status);
/* TBD
		ipsec_free_fd(buff_allocator, compound_fd);
*/
		return;
	}
	ipsec_create_simple_fd(&simple_fd, compound_fd, ENCRYPT);
	ip_notes = dma_mem_ptov(qm_fd_addr(&simple_fd));

	ip_hdr = (void *)((uint8_t *) ip_notes + simple_fd.offset);
	ip_notes->fd->offset -= ETHER_HDR_LEN;
	ip_notes->fd->length20 += ETHER_HDR_LEN;
#ifdef STATS_TBD
	decorated_notify_inc_32(&(ipsec_ctxt->stats->encap_post_sec));
#endif
	ip_accept_preparsed(&(ipsec_ctxt->ppam_ctxt), ip_notes, ip_hdr,
		SOURCE_POST_ENCAP);
}

void ipsec_encap_init(struct ipsec_tunnel_t *entry,
		struct iphdr *ip_hdr,
		struct app_ctrl_sa_algo *ealg,
		struct app_ctrl_sa_algo *aalg)
{
	void *ctxtA;
	ctxtA = create_encapsulation_sec_descriptor(entry, ip_hdr,
			IP_PROTO_TCP, ealg, aalg);
	if (NULL == ctxtA) {
		fprintf(stderr, "error: %s: Error creating descriptor\n",
			__func__);
		return;
	}

	entry->ctxtA = ctxtA;
	entry->fq_state = PARKED;
}
