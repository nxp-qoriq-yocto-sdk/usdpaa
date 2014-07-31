/* Copyright (c) 2014 Freescale Semiconductor, Inc.
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

#include <flib/rta.h>

#include <capwap_debug.h>
#include <capwap_cfg.h>
#include <app_config.h>
#include <capwap_interface.h>
#include "fm_port_ext.h"

#if defined(CAPWAP_ORDER_PRESERVATION) || \
	defined(CAPWAP_ORDER_RESTORATION)
__thread const struct qm_dqrr_entry *local_dqrr;
#endif
#ifdef CAPWAP_ORDER_RESTORATION
__thread struct qman_fq *local_orp_fq;
__thread u32 local_seqnum;
#endif

/* This struct holds the default stashing opts for Rx FQ configuration. */
static const struct qm_fqd_stashing default_stash_opts = {
	.annotation_cl = CAPWAP_STASH_ANNOTATION_CL,
	.data_cl = CAPWAP_STASH_DATA_CL,
	.context_cl = CAPWAP_STASH_CONTEXT_CL
};

extern const struct qman_fq_cb capwap_tx_cb;

uint32_t statistic_packets=1;

const struct fm_eth_port_cfg *capwap_interface_pcfg(struct capwap_interface *i)
{
	return i->port_cfg;
}

extern int capwap_port_id;
extern int plain_port_id1;
extern int plain_port_id2;

/*******************/
/* Packet handling */
/*******************/

#if defined(CAPWAP_ORDER_PRESERVATION) || \
	defined(CAPWAP_ORDER_RESTORATION)
#define PRE_DQRR()  local_dqrr = dqrr
#define POST_DQRR() (local_dqrr ? qman_cb_dqrr_consume : qman_cb_dqrr_defer)
#else
#define PRE_DQRR()  do { ; } while (0)
#define POST_DQRR() qman_cb_dqrr_consume
#endif

#ifdef CAPWAP_ORDER_RESTORATION
#define PRE_ORP(orpid, seqnum) \
	do { \
		local_orp_fq = orpid; \
		local_seqnum = seqnum; \
	} while (0)

#define POST_ORP() \
	do { \
		local_orp_fq = NULL; \
	} while (0)
#else
#define PRE_ORP(orpid, seqnum) do { ; } while (0)
#define POST_ORP()             do { ; } while (0)
#endif

#undef DUMP_FRAME

void dump_hex(volatile uint8_t *data, uint32_t count)
{
	uint32_t i;

	for (i = 0; i < count; i++) {
		if(!(i%16))
			printf("\n%04x  ", i);
		else if(!(i%8))
			TRACE(" ");
		printf("%02x ", *data++);
	}
	printf("\n");
}

void dump_fd(const struct qm_fd *fd)
{
	dma_addr_t addr;
	struct qm_sg_entry * sg_entry;
	uint32_t len;
	uint32_t final = 0;
	volatile uint8_t *data;

	if (fd->format == qm_fd_sg) {/*short sg */
		addr = qm_fd_addr(fd);
		len = fd->length20;
		TRACE("FD: addr = 0x%llx\n", addr);
		TRACE("    offset=%d\n", fd->offset);
		TRACE("    len  = %d\n", len);
		data = __dma_mem_ptov(addr);
		data += fd->offset;
		sg_entry = (struct qm_sg_entry *) data;
		do {
			addr = qm_sg_addr(sg_entry);
			len = sg_entry->length;
			final = sg_entry->final;
			TRACE("SG ENTRY: addr = 0x%llx\n", addr);
			TRACE("          len  = %d\n", len);
			TRACE("          bpid = %d\n", sg_entry->bpid);
			TRACE("          extension = %d\n", sg_entry->extension);
			data = __dma_mem_ptov(addr);
			TRACE("          v-addr=%p\n", data);
			data += sg_entry->offset;
			dump_hex(data, len);
			if(final)
				break;
			sg_entry ++;
		} while (1);
	} else if (fd->format == qm_fd_contig) { /* short single */
		addr = qm_fd_addr(fd);
		len = fd->length20;
		TRACE("FD: addr = 0x%llx\n", addr);
		TRACE("    offset=%d\n", fd->offset);
		TRACE("    len  = %d\n", len);
		data = __dma_mem_ptov(addr);
		TRACE("    v-addr=%p\n", data);
		dump_hex(data, len + fd->offset);
	}
}

static enum qman_cb_dqrr_result
cb_dqrr_rx_error(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
#if 0
	TRACE("Rx_error: fqid=0x%x\tfd_status = 0x%08x\n",
	      fq->fqid, fd->status);
	TRACE("format is 0x%x\n", fd->format);
	TRACE("bpid = %d\n", fd->bpid);
#endif
#ifdef DUMP_FRAME
	dump_fd(fd);
#endif /* DUMP_FRAME */

	PRE_DQRR();
	/* The bpid of error fq from SEC is zero */
	if (fd->bpid != 0)
		capwap_drop_frame(fd);
	return POST_DQRR();
}

enum qman_cb_dqrr_result
cb_dqrr_rx_default(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;

	TRACE("\n***************************%d***************************\n",
			statistic_packets++);
	TRACE("Rx_default: fqid=0x%x\tfd_status = 0x%08x\n", fq->fqid,
			fd->status);
	TRACE("format is 0x%x\n", fd->format);
	TRACE("bpid = %d\n", fd->bpid);

#ifdef DUMP_FRAME
	dump_fd(fd);
#endif /* DUMP_FRAME */
	PRE_DQRR();
	capwap_drop_frame(fd);
	return POST_DQRR();
}

static enum qman_cb_dqrr_result
cb_dqrr_rx_timeout(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	TRACE("Reassble_timeout\n");
	PRE_DQRR();
	capwap_drop_frame(&dqrr->fd);
	return POST_DQRR();
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_error(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	TRACE("Tx_error: fqid=%d\tfd_status = 0x%08x\n", fq->fqid,
			dqrr->fd.status);
	PRE_DQRR();
	capwap_drop_frame(&dqrr->fd);
	return POST_DQRR();
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_confirm(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	TRACE("Tx_confirm: fqid=%d\tfd_status = 0x%08x\n", fq->fqid,
			dqrr->fd.status);
	PRE_DQRR();
	capwap_drop_frame(&dqrr->fd);
	return POST_DQRR();
}

void cb_ern(struct qman_portal *qm __always_unused,
	    struct qman_fq *fq,
	    const struct qm_mr_entry *msg)
{
	TRACE("Tx_ern: fqid=%d\tfd_status = 0x%08x\n", msg->ern.fqid,
	      msg->ern.fd.status);
	PRE_ORP(p->orp_fq, msg->ern.seqnum);
	capwap_drop_frame(&msg->ern.fd);
	POST_ORP();
}

int capwap_interface_init(unsigned idx)
{
	struct capwap_interface *i;
	struct qm_fqd_stashing stash_opts;
	const struct fm_eth_port_cfg *port = &netcfg->port_cfg[idx];
	const struct fman_if *fif = port->fman_if;
	size_t size;

	if (fif->mac_type == fman_mac_less) {
		size = sizeof(struct capwap_interface) +
			(fif->macless_info.tx_count *
			sizeof(struct qman_fq));
	} else {
		size = sizeof(struct capwap_interface) +
			sizeof(struct qman_fq);
	}
	/* allocate stashable memory for the interface object */
	i = __dma_mem_memalign(L1_CACHE_BYTES, size);
	if (!i)
		return -ENOMEM;
	memset(i, 0, size);
	INIT_LIST_HEAD(&i->list);
	i->size = size;
	i->port_cfg = port;

	/* Offline ports don't have Tx Error or Tx Confirm FQs */
	if (fif->mac_type == fman_offline || fif->mac_type == fman_onic) {
		list_add_tail(&i->node, &ifs);
		return 0;
	}
	/* Note: we should handle errors and unwind */
	stash_opts = default_stash_opts;
	/* For shared MAC, Tx Error and Tx Confirm FQs are created by linux */
	if (fif->shared_mac_info.is_shared_mac != 1) {
		stash_opts = default_stash_opts;
		capwap_fq_nonpcd_init(&i->tx_err_fq, fif->fqid_tx_err,
				get_rxc(), &stash_opts, cb_dqrr_tx_error);
		stash_opts = default_stash_opts;
		capwap_fq_nonpcd_init(&i->tx_conf_fq, fif->fqid_tx_confirm,
				get_rxc(), &stash_opts, cb_dqrr_tx_confirm);
	}

	list_add_tail(&i->node, &ifs);
	return 0;
}

int capwap_interface_init_rx(struct capwap_interface *i)
{
	__maybe_unused int err;
	int loop;
	struct qm_fqd_stashing stash_opts;
	const struct fman_if *fif = i->port_cfg->fman_if;

	/* Note: we should handle errors and unwind */
	stash_opts = default_stash_opts;
	if (fif->mac_type == fman_mac_less) {
		uint32_t fqid = fif->macless_info.tx_start;
		for (loop = 0; loop < fif->macless_info.tx_count; loop++) {
			capwap_fq_nonpcd_init(&i->rx_def_fq[loop],
				fqid++, get_rxc(), &stash_opts,
				cb_dqrr_rx_default);
		}
		capwap_interface_enable_shared_rx(i);
		return 0;
	}
	TRACE("rx_def fq is 0x%x, rx_err fq is 0x%x\n", i->port_cfg->rx_def,
			fif->fqid_rx_err);
	if (fif->shared_mac_info.is_shared_mac == 1) {
		struct qm_mcr_queryfq_np np;
		struct qman_fq fq;
		fq.fqid = i->port_cfg->rx_def;
		err = qman_query_fq_np(&fq, &np);
		if (err) {
			error(0, err, "%s(): shared MAC query FQ", __func__);
			return err;
		}
		/* For shared MAC, initialize default FQ only if state is OOS */
		if (np.state == qman_fq_state_oos) {
			capwap_fq_nonpcd_init(&i->rx_def_fq[0],
				i->port_cfg->rx_def, get_rxc(), &stash_opts,
				cb_dqrr_rx_default);
		}
	} else {
		capwap_fq_nonpcd_init(&i->rx_err_fq, fif->fqid_rx_err,
				    get_rxc(), &stash_opts, cb_dqrr_rx_error);
		stash_opts = default_stash_opts;
		capwap_fq_nonpcd_init(&i->rx_def_fq[0], i->port_cfg->rx_def,
					get_rxc(), &stash_opts,
					cb_dqrr_rx_default);
	}

	capwap_interface_enable_rx(i);
	if (fif->shared_mac_info.is_shared_mac == 1)
		capwap_interface_enable_shared_rx(i);

	return 0;
}

void capwap_interface_enable_rx(const struct capwap_interface *i)
{
	fman_if_enable_rx(i->port_cfg->fman_if);
	TRACE("Interface %d:%d, enabled RX\n",
	      i->port_cfg->fman_if->fman_idx,
	      i->port_cfg->fman_if->mac_idx);
}

void capwap_interface_disable_rx(const struct capwap_interface *i)
{
	fman_if_disable_rx(i->port_cfg->fman_if);
	TRACE("Interface %d:%d, disabled RX\n",
	      i->port_cfg->fman_if->fman_idx,
	      i->port_cfg->fman_if->mac_idx);
}

void capwap_interface_enable_shared_rx(const struct capwap_interface *i)
{
	bool if_up = true;
	const struct fman_if *fif = i->port_cfg->fman_if;

	usdpaa_netcfg_enable_disable_shared_rx(i->port_cfg->fman_if,
						if_up);
	if (fif->mac_type == fman_mac_less)
		TRACE("Interface name %s:, enabled RX\n",
			fif->macless_info.macless_name);
	else
		TRACE("Interface name %s:, enabled RX\n",
			fif->shared_mac_info.shared_mac_name);
}

void capwap_interface_disable_shared_rx(const struct capwap_interface *i)
{
	bool if_down = false;
	const struct fman_if *fif = i->port_cfg->fman_if;

	usdpaa_netcfg_enable_disable_shared_rx(i->port_cfg->fman_if,
						if_down);
	if (fif->mac_type == fman_mac_less)
		TRACE("Interface name %s:, disabled RX\n",
			fif->macless_info.macless_name);
	else
		TRACE("Interface name %s:, disabled RX\n",
			fif->shared_mac_info.shared_mac_name);
}

void capwap_interface_finish(struct capwap_interface *i)
{
	int loop;

	/* Cleanup in the opposite order of capwap_interface_init() */
	list_del(&i->node);
	if (capwap_interface_type(i) == fman_mac_less) {
		__dma_mem_free(i);
		return;
	}

	/* Offline ports don't have Tx Error or Confirm FQs */
	if (capwap_interface_type(i) != fman_offline) {
		teardown_fq(&i->tx_conf_fq);
		teardown_fq(&i->tx_err_fq);
	}

	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qman_fq *fq = &i->tx_fqs[loop];
		TRACE("I/F %d, destroying Tx FQID %d\n",
			i->port_cfg->fman_if->fman_idx, fq->fqid);
		teardown_fq(fq);
	}

	free(i->tx_fqs);
	__dma_mem_free(i);
}

void capwap_interface_finish_rx(struct capwap_interface *i)
{
	int loop;
	struct capwap_pcd_range *pcd_range;
	const struct fman_if *fif = i->port_cfg->fman_if;

	if (fif->mac_type == fman_mac_less) {
		capwap_interface_disable_shared_rx(i);
		for (loop = 0; loop < fif->macless_info.tx_count; loop++) {
			teardown_fq(&i->rx_def_fq[loop]);
		}
		return;
	}
	/* Cleanup in the opposite order of capwap_interface_init_rx() */
	if (fif->shared_mac_info.is_shared_mac == 1)
		capwap_interface_disable_shared_rx(i);
	capwap_interface_disable_rx(i);
	teardown_fq(&i->rx_def_fq[0]);
	teardown_fq(&i->rx_err_fq);
	list_for_each_entry(pcd_range, &i->list, list) {
		for (loop = 0; loop < pcd_range->count; loop++) {
			teardown_fq(&pcd_range->rx_hash[loop].fq);
#ifdef CAPWAP_ORDER_RESTORATION
			teardown_fq(pcd_range->rx_hash[loop].orp_fq);
			__dma_mem_free(pcd_range->rx_hash[loop].orp_fq);
#endif
		}
	}
}

void teardown_fq(struct qman_fq *fq)
{
	u32 flags;
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

/*******************/
/* packet handling */
/*******************/

void capwap_fq_nonpcd_init(struct qman_fq *fq, u32 fqid,
			 u16 channel,
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
	opts.fqd.dest.wq = CAPWAP_PRIORITY_2DROP;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing = *stashing;
	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

#ifdef CAPWAP_ORDER_RESTORATION
struct qman_fq *capwap_orp_init(void)
{
	struct qm_mcc_initfq opts;
	struct qman_fq *orp_fq;
	int ret;

	orp_fq = __dma_mem_memalign(L1_CACHE_BYTES, sizeof(*orp_fq));
	BUG_ON(!orp_fq);
	memset(&orp_fq->cb, NULL, sizeof(orp_fq->cb));
	ret = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, orp_fq);
	BUG_ON(ret);
	opts.we_mask = QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_ORPC;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_ORP;
	opts.fqd.orprws = CAPWAP_ORP_WINDOW_SIZE;
	opts.fqd.oa = CAPWAP_ORP_AUTO_ADVANCE;
	opts.fqd.olws = CAPWAP_ORP_ACCEPT_LATE;
	ret = qman_init_fq(orp_fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
	return orp_fq;
}
#endif

static enum qman_cb_dqrr_result
cb_tx_drain(struct qman_portal *qm __always_unused,
	    struct qman_fq *fq __always_unused,
	    const struct qm_dqrr_entry *dqrr)
{
	TRACE("Tx_drain: fqid=%d\tfd_status = 0x%08x\n", fq->fqid,
		dqrr->fd.status);
	capwap_drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

void capwap_fq_tx_init(struct qman_fq *fq, u16 channel,
			dma_addr_t context_a, uint32_t context_b)
{
	struct qm_mcc_initfq opts;
	__maybe_unused int err;
	uint32_t flags = QMAN_FQ_FLAG_TO_DCPORTAL;

	/* These FQ objects need to be able to handle DQRR callbacks, when
	 * cleaning up. */
	//fq->cb.dqrr = cb_tx_drain;
	fq->cb = capwap_tx_cb;
	if (!fq->fqid)
		flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;
	err = qman_create_fq(fq->fqid, flags, fq);
	/* Note: handle errors here, BUG_ON()s are compiled out in performance
	 * builds (ie. the default) and this code isn't even
	 * performance-sensitive. */
	BUG_ON(err);
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	if(context_a)
		opts.we_mask |= QM_INITFQ_WE_CONTEXTA;
	if(context_b)
		opts.we_mask |= QM_INITFQ_WE_CONTEXTB;
	if (!channel)
		opts.fqd.dest.channel = get_rxc();
	else
		opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = CAPWAP_PRIORITY_2TX;
	opts.fqd.fq_ctrl = 0;
#ifdef CAPWAP_TX_PREFERINCACHE
	opts.fqd.fq_ctrl |= QM_FQCTRL_PREFERINCACHE;
#endif
#ifdef CAPWAP_TX_FORCESFDR
	opts.fqd.fq_ctrl |= QM_FQCTRL_FORCESFDR;
#endif
#if defined(CAPWAP_CGR)
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_tx.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	opts.fqd.context_b = context_b;
	qm_fqd_context_a_set64(&opts.fqd, context_a);
	err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(err);
}

static uint32_t pchannel_idx;

u16 get_rxc(void)
{
	u16 ret = pchannels[pchannel_idx];
	pchannel_idx = (pchannel_idx + 1) % CAPWAP_NUM_POOL_CHANNELS;
	return ret;
}

/****************/
/* Buffer-pools */
/****************/

#ifdef CAPWAP_DEPLETION
static void bp_depletion(struct bman_portal *bm __always_unused,
			  struct bman_pool *p,
			  void *cb_ctx __maybe_unused,
			  int depleted)
{
	u8 bpid = bman_get_params(p)->bpid;
	BUG_ON(p != *(typeof(&p))cb_ctx);

	pr_info("%s: BP%u -> %s\n", __func__, bpid,
		depleted ? "entry" : "exit");
}
#endif

int capwap_prepare_bpid(u8 bpid, unsigned int count, uint64_t sz,
		      unsigned int align,
		      int to_drain,
		      void (*notify_cb)(struct bman_portal *,
					struct bman_pool *,
					void *cb_ctx,
					int depleted),
		      void *cb_ctx)
{
	struct bman_pool_params params = {
		.bpid	= bpid,
#ifdef CAPWAP_DEPLETION
		.flags	= notify_cb ? BMAN_POOL_FLAG_DEPLETION : 0,
		.cb	= notify_cb,
		.cb_ctx	= cb_ctx
#endif
	};
	struct bm_buffer bufs[8];
	unsigned int num_bufs = 0;
	int ret = 0;

	BUG_ON(bpid >= CAPWAP_MAX_BPID);
	if (pool[bpid])
		/* this BPID is already handled */
		return 0;
	pool[bpid] = bman_new_pool(&params);
	if (!pool[bpid]) {
		fprintf(stderr, "error: bman_new_pool(%d) failed\n", bpid);
		return -ENOMEM;
	}
	/* Drain the pool of anything already in it. */
	if (to_drain)
	do {
		/* Acquire is all-or-nothing, so we drain in 8s, then in 1s for
		 * the remainder. */
		if (ret != 1)
			ret = bman_acquire(pool[bpid], bufs, 8, 0);
		if (ret < 8)
			ret = bman_acquire(pool[bpid], bufs, 1, 0);
		if (ret > 0)
			num_bufs += ret;
	} while (ret > 0);
	if (num_bufs)
		fprintf(stderr, "Warn: drained %u bufs from BPID %d\n",
			num_bufs, bpid);
	/* Fill the pool */
	for (num_bufs = 0; num_bufs < count; ) {
		unsigned int loop, rel = (count - num_bufs) > 8 ? 8 :
					(count - num_bufs);
		for (loop = 0; loop < rel; loop++) {
			void *ptr;
			if (!align)
				align = 64;
			ptr = __dma_mem_memalign(align, sz);
			if (!ptr) {
				fprintf(stderr, "error: no buffer space\n");
				abort();
			}
			bm_buffer_set64(&bufs[loop], __dma_mem_vtop(ptr));
		}
		do {
			ret = bman_release(pool[bpid], bufs, rel, 0);
		} while (ret == -EBUSY);
		if (ret)
			fprintf(stderr, "Fail: %s\n", "bman_release()");
		num_bufs += rel;
	}
	printf("Released %u bufs to BPID %d\n", num_bufs, bpid);
	return 0;
}

int interface_init(void)
{

	int err;
	struct list_head *interface;
	unsigned int loop;

	/* Initialise interface objects. We initialise the interface objects and
	 * their Tx FQs in one loop */
	for (loop = 0; loop < netcfg->num_ethports; loop++) {
		TRACE("Initialising interface %d\n", loop);
		err = capwap_interface_init(loop);
		if (err) {
			fprintf(stderr, "error: interface %d failed\n", loop);
			do_global_finish();
			return err;
		}
	}

	/* Init Rx-err and Rx-def fq for each port */
	list_for_each(interface, &ifs) {
		/* Same comment applies as the cast in do_global_finish() */
		err = capwap_interface_init_rx((struct capwap_interface *)interface);
		if (err) {
			fprintf(stderr, "error: interface %p failed\n", interface);
			do_global_finish();
			return err;
		}
	}

	/* Initialise buffer pools as required by the interfaces */
	list_for_each(interface, &ifs) {
		struct fman_if_bpool *bp;
		struct capwap_interface *_if = (struct capwap_interface *)interface;
		const struct fm_eth_port_cfg *pcfg = capwap_interface_pcfg(_if);
		int bp_idx = 0;
		TRACE("Initialising interface buffer pools %p\n", interface);
		list_for_each_entry(bp, &pcfg->fman_if->bpool_list, node) {
			if (bp_idx > 2) {
				fprintf(stderr, "warning: more than 3 pools "
					"for interface %d\n", loop);
				break;
			}
			err = capwap_prepare_bpid(bp->bpid, bp->count,
						bp->size, 0, 1,
#ifdef PPAC_DEPLETION
						bp->count ?
							bp_depletion : NULL,
#else
						NULL,
#endif
						&pool[bp->bpid]);
			if (err) {
				fprintf(stderr, "error: bpid %d failed\n",
					bp->bpid);
				do_global_finish();
				return err;
			}
			bp_idx++;
		}
	}

	return 0;
}

int init_rx_fq(u32 fqid)
{
	struct qman_fq *fq;
	struct qm_fqd_stashing stash_opts;

	stash_opts = default_stash_opts;
	fq = __dma_mem_memalign(L1_CACHE_BYTES, sizeof(struct qman_fq));
	if (unlikely(NULL == fq)) {
		fprintf(stderr, "error: dma_mem_memalign failed in create_fqs"
				" for debug fq\n");
		return -ENOMEM;
	}
	memset(fq, 0, sizeof(struct qman_fq));
	fq->fqid = fqid;
	capwap_fq_nonpcd_init(fq, fq->fqid, get_rxc(), &stash_opts,
			cb_dqrr_rx_default);

	return 0;
}

struct qman_fq *get_def_fq(struct capwap_port *port)
{
	struct list_head *i;

	list_for_each(i, &ifs) {
		struct capwap_interface *_if = (struct capwap_interface *)i;
		if (_if->port_cfg->fman_if == port->interface)
			return &_if->rx_def_fq[0];
	}

	return NULL;
}
