/* Copyright (c) 2011 Freescale Semiconductor, Inc.
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

#include <ppac.h>
#include "fra_network_interface.h"
#include <ppac_interface.h>
#include "fra.h"

void ppac_fq_nonpcd_init(struct qman_fq *fq, uint32_t fqid,
			 enum qm_channel channel,
			 const struct qm_fqd_stashing *stashing,
			 qman_cb_dqrr cb)
{
	struct qm_mcc_initfq opts;
	__maybe_unused int ret;

	fq->cb.dqrr = cb;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2drop" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = PPAC_PRIORITY_2DROP;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing = *stashing;
	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

void ppac_fq_pcd_init(struct qman_fq *fq, uint32_t fqid,
		      enum qm_channel channel,
		      const struct qm_fqd_stashing *stashing,
		      int prefer_in_cache)
{
	struct qm_mcc_initfq opts;
	__maybe_unused int ret;
	fq->cb.dqrr = cb_dqrr_rx_hash;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2fwd" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = PPAC_PRIORITY_2FWD;
	opts.fqd.fq_ctrl =
#ifdef PPAC_HOLDACTIVE
		QM_FQCTRL_HOLDACTIVE |
#endif
#ifdef PPAC_AVOIDBLOCK
		QM_FQCTRL_AVOIDBLOCK |
#endif
		QM_FQCTRL_CTXASTASHING;
	if (prefer_in_cache)
		opts.fqd.fq_ctrl |= QM_FQCTRL_PREFERINCACHE;
#ifdef PPAC_CGR
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_rx.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	opts.fqd.context_a.stashing = *stashing;
	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

#ifdef PPAC_ORDER_RESTORATION
void ppac_orp_init(uint32_t *orp_id)
{
	struct qm_mcc_initfq opts;
	struct qman_fq tmp_fq;
	int ret = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, &tmp_fq);
	BUG_ON(ret);
	opts.we_mask = QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_ORPC;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_ORP;
	opts.fqd.orprws = PPAC_ORP_WINDOW_SIZE;
	opts.fqd.oa = PPAC_ORP_AUTO_ADVANCE;
	opts.fqd.olws = PPAC_ORP_ACCEPT_LATE;
	ret = qman_init_fq(&tmp_fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
	*orp_id = tmp_fq.fqid;
}
#endif

static enum qman_cb_dqrr_result
cb_tx_drain(struct qman_portal *qm __always_unused,
	    struct qman_fq *fq __always_unused,
	    const struct qm_dqrr_entry *dqrr)
{
	FRA_DBG("Tx_drain: fqid=%d\tfd_status = 0x%08x", fq->fqid,
		dqrr->fd.status);
	ppac_drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

void ppac_fq_tx_init(struct qman_fq *fq, enum qm_channel channel,
		     uint32_t tx_confirm_fqid __maybe_unused)
{
	struct qm_mcc_initfq opts;
	__maybe_unused int err;
	/* These FQ objects need to be able to handle DQRR callbacks, when
	 * cleaning up. */
	fq->cb.dqrr = cb_tx_drain;
	err = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID |
			     QMAN_FQ_FLAG_TO_DCPORTAL, fq);
	/* Note: handle errors here, BUG_ON()s are compiled out in performance
	 * builds (ie. the default) and this code isn't even
	 * performance-sensitive. */
	BUG_ON(err);
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = PPAC_PRIORITY_2TX;
	opts.fqd.fq_ctrl = 0;
#ifdef PPAC_TX_PREFERINCACHE
	opts.fqd.fq_ctrl |= QM_FQCTRL_PREFERINCACHE;
#endif
#ifdef PPAC_TX_FORCESFDR
	opts.fqd.fq_ctrl |= QM_FQCTRL_FORCESFDR;
#endif
#if defined(PPAC_CGR)
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_tx.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
#ifdef PPAC_TX_CONFIRM
	opts.fqd.context_b = tx_confirm_fqid;
	opts.fqd.context_a.hi = 0;
#else
	opts.fqd.context_b = 0;
	opts.fqd.context_a.hi = 0x80000000;
#endif
	opts.fqd.context_a.lo = 0;
	err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(err);
}

/*********************************/
/* CGR state-change notification */
/*********************************/

#ifdef PPAC_CGR
static void cgr_rx_cb(struct qman_portal *qm, struct qman_cgr *c, int congested)
{
	BUG_ON(c != &cgr_rx);

	error(0, 0, "%s(): RX CGR -> congestion %s", __func__,
	      congested ? "entry" : "exit");
}
static void cgr_tx_cb(struct qman_portal *qm, struct qman_cgr *c, int congested)
{
	BUG_ON(c != &cgr_tx);

	error(0, 0, "%s(): TX CGR -> congestion %s", __func__,
	      congested ? "entry" : "exit");
}
int ppac_cgr_init(struct usdpaa_netcfg_info *cfg)
{
	int err;
	uint32_t loop, numrxfqs = 0, numtxfqs = 0;
	struct qm_mcc_initcgr opts = {
		.we_mask = QM_CGR_WE_CS_THRES |
#ifdef PPAC_CSCN
		QM_CGR_WE_CSCN_EN |
#endif
#ifdef PPAC_CSTD
		QM_CGR_WE_CSTD_EN |
#endif
		QM_CGR_WE_MODE,
		.cgr = {
#ifdef PPAC_CSCN
			.cscn_en = QM_CGR_EN,
#endif
#ifdef PPAC_CSTD
			.cstd_en = QM_CGR_EN,
#endif
			.mode = QMAN_CGR_MODE_FRAME
		}
	};
	if (cfg->num_cgrids < 2)
		error(EXIT_FAILURE, 0, "%s(): insufficient CGRIDs available", __func__);

	/* Set up Rx CGR */
	for (loop = 0; loop < cfg->num_ethports; loop++) {
		const struct fm_eth_port_cfg *p = &cfg->port_cfg[loop];
		const struct fmc_netcfg_fqrange *fqr;
		list_for_each_entry(fqr, p->list, list) {
			numrxfqs += fqr->count;
			numtxfqs += (p->fman_if->mac_type == fman_mac_10g) ?
				PPAC_TX_FQS_10G :
				(p->fman_if->mac_type == fman_offline) ?
				PPAC_TX_FQS_OFFLINE : PPAC_TX_FQS_1G;
		}
	}
		qm_cgr_cs_thres_set64(&opts.cgr.cs_thres,
				      numrxfqs * PPAC_CGR_RX_PERFQ_THRESH, 0);
		cgr_rx.cgrid = cfg->cgrids[0];
		cgr_rx.cb = cgr_rx_cb;
		err = qman_create_cgr(&cgr_rx, QMAN_CGR_FLAG_USE_INIT, &opts);
		if (err < 0)
			error(0, -err, "%s(): qman_create_cgr(RX), continuing", __func__);

		/* Set up Tx CGR */
		qm_cgr_cs_thres_set64(&opts.cgr.cs_thres,
				      numtxfqs * PPAC_CGR_TX_PERFQ_THRESH, 0);
		cgr_tx.cgrid = cfg->cgrids[1];
		cgr_tx.cb = cgr_tx_cb;
		err = qman_create_cgr(&cgr_tx, QMAN_CGR_FLAG_USE_INIT, &opts);
		if (err < 0)
			error(0, -err, "%s(): qman_create_cgr(TX), continuing", __func__);

		return err;
	}
#endif

	void teardown_fq(struct qman_fq *fq)
	{
		uint32_t flags;
		int s = qman_retire_fq(fq, &flags);
		if (s == 1) {
			/* Retire is non-blocking, poll for completion */
			enum qman_fq_state state;
			do {
				qman_poll();
				qman_fq_state(fq, &state, &flags);
			} while (state != qman_fq_state_retired);
			if (flags & QMAN_FQ_STATE_NE) {
				/* FQ isn't empty, drain it */
				s = qman_volatile_dequeue(fq, 0,
							  QM_VDQCR_NUMFRAMES_TILLEMPTY);
				BUG_ON(s);
				/* Poll for completion */
				do {
					qman_poll();
					qman_fq_state(fq, &state, &flags);
				} while (flags & QMAN_FQ_STATE_VDQCR);
			}
		}
		s = qman_oos_fq(fq);
		BUG_ON(s);
		qman_destroy_fq(fq, 0);
	}


/* There is no configuration that specifies how many Tx FQs to use
 * per-interface, it's an internal choice for ppac.c and may depend on
 * optimisations, link-speeds, command-line options, etc. Also the Tx FQIDs are
 * dynamically allocated, so they're not known until ppac.c has already
 * initialised them. So firstly, the # of Tx FQs is passed in as a parameter
 * here because there's no other place where it could be meaningfully captured.
 * (Note, an interesting alternative would be to have this hook *choose* how
 * many Tx FQs to use!) Secondly, the Tx FQIDs are "notified" to us
 * post-allocation but prior to Rx initialisation. */
	static int ppam_interface_init(struct ppam_interface *p,
				       const struct fm_eth_port_cfg *cfg,
				       uint32_t num_tx_fqs)
	{
		p->num_tx_fqids = num_tx_fqs;
		p->tx_fqids = malloc(p->num_tx_fqids * sizeof(*p->tx_fqids));
		if (!p->tx_fqids)
			return -ENOMEM;
		return 0;
	}
	static void ppam_interface_finish(struct ppam_interface *p)
	{
		free(p->tx_fqids);
	}
	static void ppam_interface_tx_fqid(struct ppam_interface *p, uint8_t idx,
					   uint32_t fqid)
	{
		p->tx_fqids[idx] = fqid;
	}

	static int ppam_rx_error_init(struct ppam_rx_error *p,
				      struct ppam_interface *_if,
				      struct qm_fqd_stashing *stash_opts)
	{
		return 0;
	}
	static void ppam_rx_error_finish(struct ppam_rx_error *p,
					 struct ppam_interface *_if)
	{
	}
	static inline void ppam_rx_error_cb(struct ppam_rx_error *p,
					    struct ppam_interface *_if,
					    const struct qm_dqrr_entry *dqrr)
	{
		const struct qm_fd *fd = &dqrr->fd;
		ppac_drop_frame(fd);
	}

	static int ppam_rx_default_init(struct ppam_rx_default *p,
					struct ppam_interface *_if,
					struct qm_fqd_stashing *stash_opts)
	{
		return 0;
	}
	static void ppam_rx_default_finish(struct ppam_rx_default *p,
					   struct ppam_interface *_if)
	{
	}
	static inline void ppam_rx_default_cb(struct ppam_rx_default *p,
					      struct ppam_interface *_if,
					      const struct qm_dqrr_entry *dqrr)
	{
		const struct qm_fd *fd = &dqrr->fd;
		ppac_drop_frame(fd);
	}

	static int ppam_tx_error_init(struct ppam_tx_error *p,
				      struct ppam_interface *_if,
				      struct qm_fqd_stashing *stash_opts)
	{
		return 0;
	}
	static void ppam_tx_error_finish(struct ppam_tx_error *p,
					 struct ppam_interface *_if)
	{
	}
	static inline void ppam_tx_error_cb(struct ppam_tx_error *p,
					    struct ppam_interface *_if,
					    const struct qm_dqrr_entry *dqrr)
	{
		const struct qm_fd *fd = &dqrr->fd;
		ppac_drop_frame(fd);
	}

	static int ppam_tx_confirm_init(struct ppam_tx_confirm *p,
					struct ppam_interface *_if,
					struct qm_fqd_stashing *stash_opts)
	{
		return 0;
	}
	static void ppam_tx_confirm_finish(struct ppam_tx_confirm *p,
					   struct ppam_interface *_if)
	{
	}
	static inline void ppam_tx_confirm_cb(struct ppam_tx_confirm *p,
					      struct ppam_interface *_if,
					      const struct qm_dqrr_entry *dqrr)
	{
		const struct qm_fd *fd = &dqrr->fd;
		ppac_drop_frame(fd);
	}

	static int ppam_rx_hash_init(struct ppam_rx_hash *p, struct ppam_interface *_if,
				     uint8_t idx, struct qm_fqd_stashing *stash_opts)
	{
		return 0;
	}

	static void ppam_rx_hash_finish(struct ppam_rx_hash *p,
					struct ppam_interface *_if,
					uint8_t idx)
	{
	}

	static inline void ppam_rx_hash_cb(struct ppam_rx_hash *p,
					   const struct qm_dqrr_entry *dqrr)
	{
		dist_fwd_from_handler(p, &dqrr->fd);
	}

/* Inline the PPAC machinery */
#include <ppac.c>
