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
#include <stdint.h>
#include <stdbool.h>
#include "app_common.h"
#include "ipsec/ipsec.h"
#include "ipsec_sec.h"
#include "net/frame_desc.h"
#include "mm/mem_cache.h"
#include "ip/ip.h"
#include "ip/ip_protos.h"
#include "ip/ip_rc.h"
#include "ip/ip_hooks.h"
#include "ethernet/eth.h"
#include "net/net_dev.h"
#include "ip/ip_output.h"
#include "ip/ip_accept.h"
#include "ipsec/ipsec_init.h"

enum IP_STATUS ipsec_decap_send(const struct ppam_rx_hash *ctxt,
				struct annotations_t *notes, void *ip_hdr_ptr)
{
	struct ipsec_tunnel_t *entry;
	bool retval = false;
	struct ipsec_esp_hdr_t *esp_hdr;
	struct iphdr *ip_hdr = ip_hdr_ptr;
	const struct qm_fd *fd;
	struct qm_fd fd2;
	uint32_t ret;
	uint32_t sec_fq;

	esp_hdr =
	    (struct ipsec_esp_hdr_t *)((char *) ip_hdr +
				       sizeof(struct iphdr));
	pr_debug("%s: Pkt src = %x, dst = %x and spi = %x\n", __func__,
		  ip_hdr->saddr, ip_hdr->daddr, esp_hdr->spi);
	retval = ipsec_tunnel_fast_lookup(&entry,
					  (struct ipsec_tunnel_table_t *)
					  ctxt->itt,
					  ip_hdr->saddr,
					  ip_hdr->daddr, esp_hdr->spi,
					  RC_BUCKET_INDEX(notes));
	if (unlikely(retval == false)) {
		fprintf(stdout, "info: %s: Packet not in fast tunnel_list\n",
			__func__);
		retval = ipsec_lookup_tunnel_entry(&entry,
						   (struct ipsec_tunnel_table_t
						    *)
						   ctxt->itt,
						   ip_hdr->saddr,
						   ip_hdr->daddr,
						   esp_hdr->spi);
		if (unlikely(retval == false)) {
			fprintf(stderr, "error: %s: Couldn't find tunnel\n",
				__func__);
#ifdef STATS_TBD
			decorated_notify_inc_32(&(ctxt->stats->dropped));
#endif
			return IP_STATUS_HOLD;
		}
	}
	fd = &notes->dqrr->fd;

	ipsec_create_compound_fd(&fd2, fd, ip_hdr, DECRYPT);
#ifdef STATS_TBD
	/* update statistics that enqueue to sec is done for decap */
	decorated_notify_inc_32(&(ctxt->stats->decap_pre_sec));
#endif

	if (unlikely(entry->fq_state == PARKED)) {
		spin_lock(&entry->tlock);
		if (entry->fq_state == PARKED) {
			sec_fq = SEC_FQ_BASE + (entry->tunnel_id * 2);
			if (init_sec_fqs(entry, DECRYPT, entry->ctxtA,
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
	/* enqueue frame to SEC4.0 for Encap*/
	ret = qman_enqueue(entry->qm_fq_to_sec, &fd2, 0);

	if (unlikely(ret)) {
		uint64_t now, then = mfatb();
		do {
			now = mfatb();
		} while (now < (then + 1000));
		goto loop;
	}

	return IP_STATUS_ACCEPT;
}

void ipsec_decap_cb(const struct ipsec_context_t *ipsec_ctxt,
		    const struct qm_fd *fd, void *data __always_unused)
{
	struct qm_dqrr_entry dqrr;
	struct qm_fd *simple_fd = &dqrr.fd;
	struct qm_sg_entry *sg;
	struct iphdr *ip_hdr;
	struct annotations_t *ip_notes;
	const struct qm_fd *compound_fd = fd;
	uint8_t padlen = 0;

	/* Error Returned by SEC Block, Refer to Section 1.5.2.9 of BG */
	if (unlikely(compound_fd->status)) {
		fprintf(stderr, "error: %s: SEC Block returned Status = %x\n",
			__func__, compound_fd->status);
		return;
	}

	ipsec_create_simple_fd(simple_fd, compound_fd, DECRYPT);

	ip_notes = dma_mem_ptov(qm_fd_addr(simple_fd));
#ifdef STATS_TBD
	decorated_notify_inc_32(&(ipsec_ctxt->stats->decap_post_sec));
#endif

	/* get notes and context information so that we can hand
	   over the processing to the remainder of IPv4 processing
	   chain
	 */
	if (unlikely(qm_fd_contig == simple_fd->format)) {
		ip_hdr = (void *)((uint8_t *) ip_notes + simple_fd->offset);

		padlen = *(uint8_t *)((uint8_t *)ip_hdr +
				simple_fd->length20 - PADLEN_OFFSET)
				 + PADLEN_OFFSET;
		if (unlikely(padlen > IPSEC_MAX_HMAC_KEY_SIZE_BYTES)) {
			fprintf(stderr, "error: %s: Bad Padlen = %d\n",
				__func__, padlen);
			if (simple_fd->bpid)
				;
/* TBD
				ipsec_free_fd(buff_allocator, &simple_fd);
*/
			else
				fprintf(stderr, "error: %s: Bad BPID\n",
					__func__);
			return;
		}
	} else {
		sg = dma_mem_ptov(qm_fd_addr(simple_fd) + simple_fd->offset);
		ip_hdr = dma_mem_ptov(qm_fd_addr(simple_fd) + sg->offset);
		do {
			sg++;
		} while (!sg->final);
		padlen = *(uint8_t *)(dma_mem_ptov(qm_fd_addr(simple_fd) +
			sg->offset) + sg->length - PADLEN_OFFSET) +
			PADLEN_OFFSET;
		if (padlen == sg->length) {
			sg--;
			sg->final = 1;
		} else
			sg->length -= padlen;
	}
	simple_fd->length20 -= padlen;

	if (likely(qm_fd_contig == simple_fd->format))
		simple_fd->offset -= ETHER_HDR_LEN;
	else if (qm_fd_sg == simple_fd->format) {
		sg = dma_mem_ptov(qm_fd_addr(simple_fd) + simple_fd->offset);
		sg->offset -= ETHER_HDR_LEN;
		sg->length += ETHER_HDR_LEN;
	}
	simple_fd->length20 += ETHER_HDR_LEN;
	ip_notes->dqrr = &dqrr;

	/* hand over the packet to IP layer for egress transmission */
	ip_accept_preparsed(&(ipsec_ctxt->ppam_ctxt), ip_notes, ip_hdr,
		 SOURCE_POST_DECAP);
}

void ipsec_decap_init(struct ipsec_tunnel_t *entry,
		struct app_ctrl_sa_algo *ealg,
		struct app_ctrl_sa_algo *aalg)
{
	void *ctxtA;

	ctxtA = create_decapsulation_sec_descriptor(entry, ealg, aalg);
	if (NULL == ctxtA) {
		fprintf(stderr, "error: %s: Unable to allocate buffer"
			" for descriptor\n", __func__);
		return;
	}

	entry->ctxtA = ctxtA;
	entry->fq_state = PARKED;
}
