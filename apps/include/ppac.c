/* Copyright (c) 2010,2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

/* This file should be included by exactly one of the files compiled into the
 * application, after declaring all the required definitions. */

#include <ppac.h>

/*********************************/
/* Net interface data structures */
/*********************************/

/* Each Fman i/face has one of these */
struct ppac_if {
	struct list_head node;
	size_t sz;
	const struct fm_eth_port_cfg *port_cfg;
	/* NB: the Tx FQs kept here are created to (a) initialise and schedule
	 * the FQIDs on startup, and (b) be able to clean them up on shutdown.
	 * They aren't used for enqueues, as that's not in keeping with how a
	 * "generic network processing application" would work. See "local_fq"
	 * below for more info. */
	unsigned int num_tx_fqs;
	struct qman_fq *tx_fqs;
	struct ppam_if module_if;
	struct ppac_rx_error {
		struct qman_fq fq;
		struct ppam_rx_error s;
	} rx_error;
	struct ppac_rx_default {
		struct qman_fq fq;
		struct ppam_rx_default s;
	} rx_default;
	struct ppac_tx_error {
		struct qman_fq fq;
		struct ppam_tx_error s;
	} tx_error;
	struct ppac_tx_confirm {
		struct qman_fq fq;
		struct ppam_tx_confirm s;
	} tx_confirm;
	struct ppac_rx_hash {
		struct qman_fq fq;
		struct ppam_rx_hash s;
	} ____cacheline_aligned rx_hash[0];
} ____cacheline_aligned;

/*******************/
/* Packet handling */
/*******************/

static enum qman_cb_dqrr_result
cb_dqrr_rx_error(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	struct ppac_rx_error *rxe = container_of(fq, struct ppac_rx_error,
							fq);
	struct ppac_if *_if = container_of(rxe, struct ppac_if, rx_error);
	TRACE("Rx_error: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	ppam_rx_error_cb(&rxe->s, &_if->module_if, dqrr);
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
cb_dqrr_rx_default(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	struct ppac_rx_default *rxe = container_of(fq, struct ppac_rx_default,
							fq);
	struct ppac_if *_if = container_of(rxe, struct ppac_if, rx_default);
	TRACE("Rx_default: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	ppam_rx_default_cb(&rxe->s, &_if->module_if, dqrr);
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_error(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	struct ppac_tx_error *rxe = container_of(fq, struct ppac_tx_error,
							fq);
	struct ppac_if *_if = container_of(rxe, struct ppac_if, tx_error);
	TRACE("Tx_error: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	ppam_tx_error_cb(&rxe->s, &_if->module_if, dqrr);
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_confirm(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	struct ppac_tx_confirm *rxe = container_of(fq, struct ppac_tx_confirm,
							fq);
	struct ppac_if *_if = container_of(rxe, struct ppac_if, tx_confirm);
	TRACE("Tx_confirm: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	ppam_tx_confirm_cb(&rxe->s, &_if->module_if, dqrr);
	return qman_cb_dqrr_consume;
}

enum qman_cb_dqrr_result
cb_dqrr_rx_hash(struct qman_portal *qm __always_unused,
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr)
{
	struct ppac_rx_hash *p = container_of(fq, struct ppac_rx_hash, fq);
	TRACE("Rx_hash: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	ppam_rx_hash_cb(&p->s, dqrr);
	return qman_cb_dqrr_consume;
}

void cb_ern(struct qman_portal *qm __always_unused,
	    struct qman_fq *fq,
	    const struct qm_mr_entry *msg)
{
	TRACE("Tx_ern: fqid=%d\tfd_status = 0x%08x\n", msg->ern.fqid,
	      msg->ern.fd.status);
	ppac_drop_frame(&msg->ern.fd);
}

static enum qman_cb_dqrr_result
cb_tx_drain(struct qman_portal *qm __always_unused,
	    struct qman_fq *fq __always_unused,
	    const struct qm_dqrr_entry *dqrr)
{
	TRACE("Tx_drain: fqid=%d\tfd_status = 0x%08x\n", fq->fqid,
		dqrr->fd.status);
	ppac_drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

/*************************/
/* Buffer-pool depletion */
/*************************/

#ifdef PPAC_DEPLETION
void bp_depletion(struct bman_portal *bm __always_unused,
		  struct bman_pool *p,
		  void *cb_ctx __maybe_unused,
		  int depleted)
{
	u8 bpid = bman_get_params(p)->bpid;
	BUG_ON(p != *(typeof(&p))cb_ctxt);

	pr_info("%s: BP%u -> %s\n", __func__, bpid,
		depleted ? "entry" : "exit");
}
#endif

/*********************************/
/* CGR state-change notification */
/*********************************/

#ifdef PPAC_CGR
static void cgr_rx_cb(struct qman_portal *qm, struct qman_cgr *c, int congested)
{
	BUG_ON(c != &cgr_rx);

	pr_info("%s: rx CGR -> congestion %s\n", __func__,
		congested ? "entry" : "exit");
}
static void cgr_tx_cb(struct qman_portal *qm, struct qman_cgr *c, int congested)
{
	BUG_ON(c != &cgr_tx);

	pr_info("%s: tx CGR -> congestion %s\n", __func__,
		congested ? "entry" : "exit");
}
#endif

/* Initialization code preserved here due to its dependency on ppam_* types.
 * \todo	Move this out of here at some point...
 */
int ppac_if_init(unsigned idx)
{
	struct ppac_if *i;
	const struct fman_if_bpool *bp;
	int err, loop;
	const struct fm_eth_port_cfg *port = &netcfg->port_cfg[idx];
	const struct fman_if *fif = port->fman_if;
	size_t sz = sizeof(struct ppac_if) +
		(port->pcd.count * sizeof(struct ppac_rx_hash));

	/* Handle any pools used by this i/f that are not already handled. */
	fman_if_for_each_bpool(bp, fif) {
		err = lazy_init_bpool(bp->bpid);
		if (err)
			return err;
	}
	/* allocate stashable memory for the interface object */
	i = dma_mem_memalign(L1_CACHE_BYTES, sz);
	if (!i)
		return -ENOMEM;
	memset(i, 0, sz);
	i->sz = sz;
	i->port_cfg = port;
	/* allocate and initialise Tx FQs for this interface */
	i->num_tx_fqs = (fif->mac_type == fman_mac_10g) ?
			PPAC_TX_FQS_10G : PPAC_TX_FQS_1G;
	i->tx_fqs = malloc(sizeof(*i->tx_fqs) * i->num_tx_fqs);
	if (!i->tx_fqs) {
		dma_mem_free(i, sz);
		return -ENOMEM;
	}
	err = ppam_if_init(&i->module_if, port, i->num_tx_fqs);
	if (err) {
		free(i->tx_fqs);
		dma_mem_free(i, sz);
		return err;
	}
	memset(i->tx_fqs, 0, sizeof(*i->tx_fqs) * i->num_tx_fqs);
	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qm_mcc_initfq opts;
		struct qman_fq *fq = &i->tx_fqs[loop];
		/* These FQ objects need to be able to handle DQRR callbacks,
		 * when cleaning up. */
		fq->cb.dqrr = cb_tx_drain;
		err = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID |
					QMAN_FQ_FLAG_TO_DCPORTAL, fq);
		/* TODO: handle errors here, BUG_ON()s are compiled out in
		 * performance builds (ie. the default) and this code isn't even
		 * performance-sensitive. */
		BUG_ON(err);
		opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
		opts.fqd.dest.channel = fif->tx_channel_id;
		opts.fqd.dest.wq = PPAC_PRIO_2TX;
		opts.fqd.fq_ctrl =
#ifdef PPAC_2FWD_TX_PREFERINCACHE
			QM_FQCTRL_PREFERINCACHE |
#endif
#ifdef PPAC_2FWD_TX_FORCESFDR
			QM_FQCTRL_FORCESFDR |
#endif
			0;
#if defined(PPAC_CGR)
		opts.we_mask |= QM_INITFQ_WE_CGID;
		opts.fqd.cgid = cgr_tx.cgrid;
		opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
		opts.fqd.context_b = 0;
		opts.fqd.context_a.hi = 0x80000000;
		opts.fqd.context_a.lo = 0;
		err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
		BUG_ON(err);
		TRACE("I/F %d, using Tx FQID %d\n", idx, fq->fqid);
		ppam_if_tx_fqid(&i->module_if, loop, fq->fqid);
	}
	/* TODO: as above, we should handle errors and unwind */
	err = ppam_rx_error_init(&i->rx_error.s, &i->module_if);
	BUG_ON(err);
	ppac_fq_nonpcd_init(&i->rx_error.fq, fif->fqid_rx_err, get_rxc(),
				cb_dqrr_rx_error);
	err = ppam_rx_default_init(&i->rx_default.s, &i->module_if);
	BUG_ON(err);
	ppac_fq_nonpcd_init(&i->rx_default.fq, fif->fqid_rx_err, get_rxc(),
				cb_dqrr_rx_default);
	err = ppam_tx_error_init(&i->tx_error.s, &i->module_if);
	BUG_ON(err);
	ppac_fq_nonpcd_init(&i->tx_error.fq, fif->fqid_rx_err, get_rxc(),
				cb_dqrr_tx_error);
	err = ppam_tx_confirm_init(&i->tx_confirm.s, &i->module_if);
	BUG_ON(err);
	ppac_fq_nonpcd_init(&i->tx_confirm.fq, fif->fqid_rx_err, get_rxc(),
				cb_dqrr_tx_confirm);
	for (loop = 0; loop < port->pcd.count; loop++) {
		err = ppam_rx_hash_init(&i->rx_hash[loop].s, &i->module_if,
			loop);
		BUG_ON(err);
		ppac_fq_pcd_init(&i->rx_hash[loop].fq, port->pcd.start + loop,
				get_rxc());
	}
	ppac_if_enable_rx(i);
	list_add_tail(&i->node, &ifs);
	return 0;
}

void ppac_if_enable_rx(const struct ppac_if *i)
{
	TRACE("Interface %d:%d, enabling RX\n",
	      i->port_cfg->fman_if->fman_idx,
	      i->port_cfg->fman_if->mac_idx);
	fman_if_enable_rx(i->port_cfg->fman_if);
}

void ppac_if_disable_rx(const struct ppac_if *i)
{
	fman_if_disable_rx(i->port_cfg->fman_if);
	TRACE("Interface %d:%d, disabled RX\n",
	      i->port_cfg->fman_if->fman_idx,
	      i->port_cfg->fman_if->mac_idx);
}

void ppac_if_finish(struct ppac_if *i)
{
	int loop;

	list_del(&i->node);
	ppac_if_disable_rx(i);
	ppam_rx_error_finish(&i->rx_error.s, &i->module_if);
	teardown_fq(&i->rx_error.fq);
	ppam_rx_default_finish(&i->rx_default.s, &i->module_if);
	teardown_fq(&i->rx_default.fq);
	ppam_tx_error_finish(&i->tx_error.s, &i->module_if);
	teardown_fq(&i->tx_error.fq);
	ppam_tx_confirm_finish(&i->tx_confirm.s, &i->module_if);
	teardown_fq(&i->tx_confirm.fq);
	for (loop = 0; loop < i->port_cfg->pcd.count; loop++) {
		ppam_rx_hash_finish(&i->rx_hash[loop].s, &i->module_if, loop);
		teardown_fq(&i->rx_hash[loop].fq);
	}
	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qman_fq *fq = &i->tx_fqs[loop];
		TRACE("I/F %d, destroying Tx FQID %d\n",
		      i->port_cfg->fman_if->fman_idx, fq->fqid);
		teardown_fq(fq);
	}
	ppam_if_finish(&i->module_if);
	free(i->tx_fqs);
	dma_mem_free(i, i->sz);
}