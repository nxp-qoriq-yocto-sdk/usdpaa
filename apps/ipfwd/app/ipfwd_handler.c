/**
 \ipfwd_handler.c
 \brief IPSec Forwarding Application Handlers
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
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ipfwd.h"
#include "ip/ip_forward.h"
#include "ip/ip_local.h"
#include "net/annotations.h"

#include <usdpaa/dma_mem.h>

extern __PERCPU uint32_t rx_errors;

void ip_fq_state_chg(struct qman_portal *qm, struct qman_fq *fq,
			const struct qm_mr_entry *msg);
/**
 \brief Enqueue Rejection Notification Handler for FMAN Rx FQs
 \param[in] msg Message Ring entry to be processed
 \param[out] NULL
 */
static void ipfwd_dc_ern_handler(struct qman_portal *qm, struct qman_fq *fq,
				const struct qm_mr_entry *msg)
{
	pr_err("%s: RC = %x, FQID = %x\n", __func__,
		 msg->dcern.rc, msg->dcern.fqid);
	free_buff(&msg->dcern.fd);
	return;
}

/**
 \brief Enqueue Rejection Notification Handler for FMAN Tx FQs
 \param[in] msg Message Ring entry to be processed
 \param[out] NULL
 */
static void ipfwd_ern_handler(struct qman_portal *qm, struct qman_fq *fq,
				const struct qm_mr_entry *msg)
{
	pr_err("%s: RC = %x, seqnum = %x\n", __func__,\
		 msg->ern.rc, msg->ern.seqnum);
	free_buff(&msg->ern.fd);
	return;
}

/**
 \brief Error Frame Dequeue Handler for IPSEC FWD Application
 \param[in] dqrr Dequeue Receive Ring entry to be processed
 \param[out] NULL
 */
static enum qman_cb_dqrr_result dqrr_handler_tx_err(struct qman_portal *qm,
						   struct qman_fq *fq,
						   const struct qm_dqrr_entry
						   *dqrr)
{
	pr_err("In %s: Status Returned is %x on FQID %x\n", __func__, \
			dqrr->fd.status, dqrr->fqid);

	free_buff((struct qm_fd *)(&dqrr->fd));
	return qman_cb_dqrr_consume;
}

/**
 \brief Error Frame Dequeue Handler for IPSEC FWD Application
 \param[in] dqrr Dequeue Receive Ring entry to be processed
 \param[out] NULL
 */
static enum qman_cb_dqrr_result dqrr_handler_tx_confirm(struct qman_portal *qm,
						struct qman_fq *fq,
						const struct qm_dqrr_entry
						*dqrr)
{
	pr_info("In %s: Status Returned is %x on FQID %x\n", __func__,
			dqrr->fd.status, dqrr->fqid);

	free_buff((struct qm_fd *)(&dqrr->fd));
	return qman_cb_dqrr_consume;
}

/**
 \brief Error Frame Dequeue Handler for IPSEC FWD Application
 \param[in] dqrr Dequeue Receive Ring entry to be processed
 \param[out] NULL
 */

static enum qman_cb_dqrr_result dqrr_entry_handler_err(struct qman_portal *qm,
						   struct qman_fq *fq,
						   const struct qm_dqrr_entry
						   *dqrr)
{
	pr_debug("In %s: Status Returned is %x, on FQID = %x\n", __func__, \
		dqrr->fd.status, dqrr->fqid);
	free_buff((struct qm_fd *)(&dqrr->fd));
	rx_errors++;

	return qman_cb_dqrr_consume;
}

/**
 \brief Dequeue Handler for IPSEC FWD Application
 \param[in] struct qm_dqrr_entry * Dequeue Receive Ring entry to be processed
 \param[out] NULL
 */
static enum qman_cb_dqrr_result dqrr_entry_handler_pcd(struct qman_portal *qm,
						   struct qman_fq *fq,
						   const struct qm_dqrr_entry
						   *dqrr)
{
	struct annotations_t *notes;
	struct ip_fq_context_t *ip_fq_ctxt = (struct ip_fq_context_t *)fq;
	struct fq_context_t *context =
	    (struct fq_context_t *)(ip_fq_ctxt->ip_ctxt);
	uint8_t *data;

	switch (dqrr->fd.format) {
	case qm_fd_contig:
		notes = dma_mem_ptov(qm_fd_addr(&dqrr->fd));
		data = (uint8_t *)notes + dqrr->fd.offset;
		break;
	default:
		pr_err("Unsupported format packet came\n");
		goto done;
	}
	notes->fd = (struct qm_fd *)(&(dqrr->fd));

	context->handler(context, notes, data);
done:

	return qman_cb_dqrr_consume;
}

/**
 \brief Dequeue Handler for IPSEC FWD Application default FQ
 \param[in] struct qm_dqrr_entry * Dequeue Receive Ring entry to be processed
 \param[out] NULL
 */
static enum qman_cb_dqrr_result dqrr_entry_handler(struct qman_portal *qm,
						   struct qman_fq *fq,
						   const struct qm_dqrr_entry
						   *dqrr)
{
	struct annotations_t *notes;
	struct ip_fq_context_t *ip_fq_ctxt = (struct ip_fq_context_t *)fq;
	struct fq_context_t *context =
	    (struct fq_context_t *)(ip_fq_ctxt->ip_ctxt);
	uint8_t *data;
	struct ether_header *eth_hdr;

	/** Following qman_fq is my context */
	switch (dqrr->fd.format) {
	case qm_fd_contig:
		notes = dma_mem_ptov(qm_fd_addr(&dqrr->fd));
		data = (uint8_t *)notes + dqrr->fd.offset;
		break;
	default:
		pr_err("Unsupported format packet came\n");
		goto done;
	}
	notes->fd = (struct qm_fd *)(&(dqrr->fd));

	eth_hdr =  (struct ether_header *) data;
	if (eth_hdr->ether_type == ETHERTYPE_ARP)
		arp_handler(notes, data);
	else
		context->handler(context, notes, data);
done:

	return qman_cb_dqrr_consume;
}

/**
 \brief Dummy function for unsupported handlers
 */
static void my_cb_notimplemented(struct qman_portal *qm,
				struct qman_fq *fq,
				const struct qm_mr_entry *msg)
{
	pr_info("In %s\n", __func__);
}

static enum qman_cb_dqrr_result dqrr_cb_notimplemented(struct qman_portal *qm,
						   struct qman_fq *fq,
						   const struct qm_dqrr_entry
						   *dqrr)
{
	pr_info("In %s\n", __func__);
	return 0;
}

/**
 \brief RX Error Callback Handler
 */
const struct qman_fq_cb ipfwd_rx_cb_err = {
	.dqrr = dqrr_entry_handler_err,
	.ern = my_cb_notimplemented,
	.dc_ern = ipfwd_dc_ern_handler,
	.fqs = ip_fq_state_chg
};

/**
 \brief TX Error Callback Handler
 */
const struct qman_fq_cb ipfwd_tx_cb_err = {
	.dqrr = dqrr_handler_tx_err,
	.ern = my_cb_notimplemented,
	.dc_ern = my_cb_notimplemented,
	.fqs = ip_fq_state_chg
};

/**
 \brief TX confirm Callback Handler
 */
const struct qman_fq_cb ipfwd_tx_cb_confirm = {
	.dqrr = dqrr_handler_tx_confirm,
	.ern = my_cb_notimplemented,
	.dc_ern = my_cb_notimplemented,
	.fqs = ip_fq_state_chg
};

/**
 \brief IPFwd PCD FQ Callback Handler
 */
const struct qman_fq_cb ipfwd_rx_cb_pcd = {
	.dqrr = dqrr_entry_handler_pcd,
	.ern = my_cb_notimplemented,
	.dc_ern = ipfwd_dc_ern_handler,
	.fqs = ip_fq_state_chg
};

/**
 \brief IPFwd Callback Handler
 */
const struct qman_fq_cb ipfwd_rx_cb = {
	.dqrr = dqrr_entry_handler,
	.ern = my_cb_notimplemented,
	.dc_ern = ipfwd_dc_ern_handler,
	.fqs = ip_fq_state_chg
};

/**
 \brief IPFwd Transmit FQ Callback Handler
 */
const struct qman_fq_cb ipfwd_tx_cb = {
	.dqrr = dqrr_cb_notimplemented,
	.ern = ipfwd_ern_handler,
	.dc_ern = my_cb_notimplemented,
	.fqs = ip_fq_state_chg
};
