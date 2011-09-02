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

#include "ipsecfwd.h"
#include <usdpaa/fsl_qman.h>
#include "ip/ip_forward.h"
#include "ip/ip_local.h"
#include "arp/arp.h"
#include "ipsec/ipsec_sec.h"
#include "net/annotations.h"

extern int32_t g_key_split_flag;

static inline void ipsec_encap_decap(struct ipsec_context_t *ipsec_ctxt,
				   const struct qm_dqrr_entry *dqrr)
{
	struct annotations_t *notes;
	void *data;
	struct qm_sg_entry *sg;
	struct qm_fd *fd;

	switch (dqrr->fd.format) {
	case qm_fd_contig:
		notes = dma_mem_ptov(qm_fd_addr(&dqrr->fd));
		data = (void *)notes + dqrr->fd.offset;
		break;
	case qm_fd_compound:
		sg = dma_mem_ptov(qm_fd_addr(&dqrr->fd));
		notes = dma_mem_ptov(qm_sg_entry_get64(sg));
		data = (void *)notes + sg->offset;
		break;
	case qm_fd_sg:
		sg = dma_mem_ptov(qm_fd_addr(&dqrr->fd) + dqrr->fd.offset);
		data = dma_mem_ptov(qm_sg_entry_get64(sg) + sg->offset);
		break;
	default:
		fprintf(stderr, "error: %s: Unsupported format packet came\n",
			__func__);
		return;
	}
	fd = (struct qm_fd *)&dqrr->fd;

	ipsec_ctxt->ipsec_handler(ipsec_ctxt, fd, data);
}

enum qman_cb_dqrr_result
ipsec_dqrr_entry_handler(struct qman_portal *qm __always_unused,
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr)
{
	struct ipsec_context_t *ipsec_ctxt =
		container_of(fq, struct ipsec_context_t, fq_from_sec);
	ipsec_encap_decap(ipsec_ctxt, dqrr);
	return qman_cb_dqrr_consume;
}

/**
 \brief Enqueue Rejection Notification Handler for SEC Tx FQ
 \param[in] msg Message Ring entry to be processed
 \param[out] NULL
 */
static void ipsecfwd_ern_handler(struct qman_portal *qm, struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	fprintf(stderr, "error: %s: RC = %x, seqnum = %x\n", __func__,
		msg->ern.rc, msg->ern.seqnum);
/* TBD
	ipsec_free_fd(buff_allocator, &msg->ern.fd);
*/
	return;
}

/**
 \brief Handler for Split Key generated by SEC Block
 */
static enum qman_cb_dqrr_result dqrr_split_key_handler(struct qman_portal *qm,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	g_key_split_flag = 1;
	return qman_cb_dqrr_consume;
}

/**
 \brief Dummy function for unsupported handlers
 */
static void my_cb_notimplemented(struct qman_portal *qm, struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	fprintf(stdout, "info: In %s\n", __func__);
}

/**
 \brief IPSec Transmit FQ Callback Handler
 */
const struct qman_fq_cb ipsecfwd_rx_cb_pcd = {
	.dqrr = ipsec_dqrr_entry_handler,
	.ern = ipsecfwd_ern_handler,
	.dc_ern = my_cb_notimplemented,
	.fqs = my_cb_notimplemented
};

const struct qman_fq_cb ipsecfwd_tx_cb = {
	.dqrr = NULL,
	.ern = ipsecfwd_ern_handler,
	.dc_ern = my_cb_notimplemented,
	.fqs = my_cb_notimplemented
};

/**
 \brief Handler for SEC Generated Split Key
 */
const struct qman_fq_cb ipfwd_split_key_cb = {
	.dqrr = dqrr_split_key_handler,
	.ern = my_cb_notimplemented,
	.dc_ern = my_cb_notimplemented,
	.fqs = my_cb_notimplemented
};

