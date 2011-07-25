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
#include "ipsec/ipsec_sec.h"
#include "ipsec/ipsec_decap.h"
#include "net/frame_desc.h"
#include "mm/mem_cache.h"
#include "ip/ip_accept.h"
#include "ip/ip_protos.h"
#include "ip/ip_hooks.h"
#include "ethernet/eth.h"
#include "net/net_dev.h"
#include "ip/ip_output.h"
#include "ip/ip_forward.h"

void free_buffer(void *virt_addr, uint8_t bpid)
{
	struct bm_buffer bman_buf;

	bman_buf.hi = 0;
	bman_buf.lo = (uint32_t) dma_mem_vtop(virt_addr);
	bman_buf.bpid = bpid;

	if (bman_release(pool[bpid], &bman_buf, 1, 0))
		fprintf(stderr, "error: %s: Failed to free buffer to"
			" bpid %d\n", __func__, bpid);
}

/* TBD */
#if 0
/**
\brief		Drop a compound frame descriptor
\details	Parse and free scatter/gather list of compound frame
		and individual buffers
\param[in]
\return
*/
static int ipsec_free_compound_fd()
{
	/* TBD */
}

/**
\brief		Drop a simple single buffer frame descriptor
\details	Free memory associated with a simple frame descriptor.
\param[in]
\return
*/
static int ipsec_free_simple_fd()
{
	/* TBD */
}

int ipsec_free_fd()
{
	/* TBD */
}

#endif

int32_t ipsec_create_compound_fd(struct qm_fd *fd, struct qm_fd *old_fd,
				 struct iphdr *ip_hdr, uint8_t mode)
{
	/* we are passing in the input frame & data */
	struct qm_sg_entry *sg;
	struct qm_sg_entry *next_sg;
	void *out_buf = NULL;
	uint8_t out_bpid = 0;
	struct bm_buffer bman_buf, bman_buf_sg;
	uint32_t size = 0;
	dma_addr_t addr;

	if (mode == ENCRYPT) {
		size = ip_hdr->tot_len + sizeof(struct iphdr) +
			IP_HDR_OFFSET * 2;
/* TBD Remove hardcoded buffer pool aquiring */
		if (unlikely(1 != bman_acquire(pool[9], &bman_buf, 1, 0)))
			return -ENOMEM;
		out_buf = (void *)bman_buf.lo;
		out_bpid = bman_buf.bpid;

	} else {
		size = ip_hdr->tot_len;
		out_buf = (void *)old_fd->addr_lo;
		out_bpid = old_fd->bpid;
	}

/* TBD Remove hardcoded buffer pool aquiring */
	if (unlikely(1 != bman_acquire(pool[8], &bman_buf_sg, 1, 0)))
		return -ENOMEM;
	sg = dma_mem_ptov(bman_buf_sg.lo);
	memset(sg, 0, sizeof(struct qm_sg_entry));

	/* output buffer */
	sg->addr_hi = 0;
	sg->addr_lo = (uint32_t) out_buf;
	sg->length = size;
	if (DECRYPT == mode) {
		if (qm_fd_contig == old_fd->format) {
			sg->offset = old_fd->offset + ETHER_HDR_LEN;
		} else if (qm_fd_sg == old_fd->format) {
			sg->offset = old_fd->offset;
			/* next_sg is same as input buffer */
			sg->extension = 1;
		}
	} else {
		sg->offset = old_fd->offset + ETHER_HDR_LEN;
	}
	sg->bpid = out_bpid;

	/* input buffer */
	sg++;
	sg->addr_hi = old_fd->addr_hi;
	sg->addr_lo = old_fd->addr_lo;
	sg->length = ip_hdr->tot_len;
	if (qm_fd_contig == old_fd->format) {
		sg->offset = old_fd->offset + ETHER_HDR_LEN;
		sg->extension = 0;
	} else if (qm_fd_sg == old_fd->format) {
		sg->offset = old_fd->offset;
		addr = sg->addr_hi;
		addr = (addr << 32) | sg->addr_lo;
		next_sg = dma_mem_ptov(addr + sg->offset);
		next_sg->length -= ETHER_HDR_LEN;
		next_sg->offset += ETHER_HDR_LEN;
		sg->extension = 1;
	}
	sg->bpid = old_fd->bpid;
	sg->final = 1;
	sg--;
	addr = dma_mem_vtop(sg);
	fd->addr_hi = (uint8_t) (addr >> 32);
	fd->addr_lo = (uint32_t) (addr);
	fd->bpid = bman_buf_sg.bpid;
	fd->_format1 = qm_fd_compound;
	fd->cong_weight = 0;
	fd->cmd = 0;
	return 0;
}

void ipsec_create_simple_fd(struct qm_fd *simple_fd,
			    struct qm_fd *compound_fd, uint8_t mode)
{
	struct qm_sg_entry *sg;
	struct annotations_t *new_notes;
	struct annotations_t *old_notes;

	sg = dma_mem_ptov(compound_fd->addr_lo);
	simple_fd->addr_hi = 0;
	simple_fd->addr_lo = sg->addr_lo;
	if (0 == sg->extension)
		simple_fd->format = qm_fd_contig;
	else
		simple_fd->format = qm_fd_sg;

	simple_fd->offset = (uint16_t)sg->offset;
	simple_fd->length20 = (uint16_t)sg->length;
	simple_fd->bpid = sg->bpid;
	simple_fd->cmd = 0;

	/* SEC40 updates the length field when it writes
	   output.
	 */
	pr_debug
	    ("Offset Post CAAM is %x sg->addr_lo is %x, bpid = %x",
	     sg->offset, sg->addr_lo, simple_fd->bpid);

	new_notes = dma_mem_ptov(simple_fd->addr_lo);

	if (mode == ENCRYPT) {
		sg++;
		old_notes = dma_mem_ptov(sg->addr_lo);
		free_buffer(old_notes, sg->bpid);
		sg--;
	}
	new_notes->fd = simple_fd;
	free_buffer(sg, compound_fd->bpid);
}

void ipsec_build_outer_ip_hdr(struct iphdr *ip_hdr,
			      uint32_t *saddr, uint32_t *daddr)
{
	ip_hdr->version = IP_HEADER_VERSION_4;
	ip_hdr->ihl = IP_HEADER_LENGTH_NO_OPTIONS_WORDS;
	ip_hdr->tos = IP_HEADER_DEFAULT_TOS;
	ip_hdr->tot_len = IP_HEADER_LENGTH_NO_OPTIONS;
	ip_hdr->id = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = IP_HEADER_DEFAULT_TTL;
	ip_hdr->protocol = IP_HEADER_PROTOCOL_ESP;
	/* we do not know what the length is going to be for
	   encapsulated packet. so for now initialize the
	   checksum field. compute checksum after we get the
	   packet back from SEC40.
	 */
	ip_hdr->saddr = *saddr;
	ip_hdr->daddr = *daddr;
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
}
