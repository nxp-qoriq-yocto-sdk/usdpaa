/* Copyright 2008-2011 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pme2_private.h"

static const struct pme_flow default_sw_flow = {
	.sos = 1,
	.srvm = 0,
	.esee = 1,
	.ren = 0,
	.rlen = 0,
	.seqnum_hi = 0,
	.seqnum_lo = 0,
	.sessionid = 0x7ffffff,
	.rptr_hi = 0,
	.rptr_lo = 0,
	.clim = 0xffff,
	.mlim = 0xffff
};

void pme_sw_flow_init(struct pme_flow *flow)
{
	memcpy(flow, &default_sw_flow, sizeof(*flow));
}
EXPORT_SYMBOL(pme_sw_flow_init);

void pme_initfq(struct qm_mcc_initfq *initfq, struct pme_hw_flow *flow, u8 qos,
		u8 rbpid, u32 rfqid)
{
	struct pme_context_a *pme_a =
		(struct pme_context_a *)&initfq->fqd.context_a;
	struct pme_context_b *pme_b =
		(struct pme_context_b *)&initfq->fqd.context_b;

	initfq->we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA |
				QM_INITFQ_WE_CONTEXTB;
	initfq->fqd.dest.channel = qm_channel_pme;
	initfq->fqd.dest.wq = qos;
	if (flow) {
		dma_addr_t fcp = flow_map((struct pme_flow *)flow);
		pme_a->mode = pme_mode_flow;
		pme_context_a_set64(pme_a, fcp);
	} else {
		pme_a->mode = pme_mode_direct;
		pme_context_a_set64(pme_a, 0);
	}
	pme_b->rbpid = rbpid;
	pme_b->rfqid = rfqid;
}
EXPORT_SYMBOL(pme_initfq);

void pme_fd_cmd_nop(struct qm_fd *fd)
{
	struct pme_cmd_nop *nop = (struct pme_cmd_nop *)&fd->cmd;
	nop->cmd = pme_cmd_nop;
}
EXPORT_SYMBOL(pme_fd_cmd_nop);

void pme_fd_cmd_fcw(struct qm_fd *fd, u8 flags, struct pme_flow *flow,
		struct pme_hw_residue *residue)
{
	dma_addr_t f;
	struct pme_cmd_flow_write *fcw = (struct pme_cmd_flow_write *)&fd->cmd;

	BUG_ON(!flow);
	BUG_ON((unsigned long)flow & 31);
	fcw->cmd = pme_cmd_flow_write;
	fcw->flags = flags;
	if (flags & PME_CMD_FCW_RES) {
		if (residue) {
			dma_addr_t rptr = residue_map(residue);
			BUG_ON(!residue);
			BUG_ON((unsigned long)residue & 63);
			pme_flow_rptr_set64(flow, rptr);
		} else
			pme_flow_rptr_set64(flow, 0);
	}
	f = flow_map(flow);
	qm_fd_addr_set64(fd, f);
	fd->format = qm_fd_contig;
	fd->offset = 0;
	fd->length20 = sizeof(*flow);
}
EXPORT_SYMBOL(pme_fd_cmd_fcw);

void pme_fd_cmd_fcr(struct qm_fd *fd, struct pme_flow *flow)
{
	dma_addr_t f;
	struct pme_cmd_flow_read *fcr = (struct pme_cmd_flow_read *)&fd->cmd;

	BUG_ON(!flow);
	BUG_ON((unsigned long)flow & 31);
	fcr->cmd = pme_cmd_flow_read;
	f = flow_map(flow);
	qm_fd_addr_set64(fd, f);
	fd->format = qm_fd_contig;
	fd->offset = 0;
	fd->length20 = sizeof(*flow);
}
EXPORT_SYMBOL(pme_fd_cmd_fcr);

void pme_fd_cmd_pmtcc(struct qm_fd *fd)
{
	struct pme_cmd_pmtcc *pmtcc = (struct pme_cmd_pmtcc *)&fd->cmd;
	pmtcc->cmd = pme_cmd_pmtcc;
}
EXPORT_SYMBOL(pme_fd_cmd_pmtcc);

void pme_fd_cmd_scan(struct qm_fd *fd, u32 args)
{
	struct pme_cmd_scan *scan = (struct pme_cmd_scan *)&fd->cmd;
	fd->cmd = args;
	scan->cmd = pme_cmd_scan;
}
EXPORT_SYMBOL(pme_fd_cmd_scan);
