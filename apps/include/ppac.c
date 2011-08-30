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
#include <ppac_interface.h>

/* This struct holds the default stashing opts for Rx FQ configuration. PPAM
 * hooks can override (copies of) it before the configuration occurs. */
static const struct qm_fqd_stashing default_stash_opts = {
	.annotation_cl = PPAC_STASH_ANNOTATION_CL,
	.data_cl = PPAC_STASH_DATA_CL,
	.context_cl = PPAC_STASH_CONTEXT_CL
};

struct fmc_netcfg_fqrange {
	struct list_head list;
	uint32_t start;
	uint32_t count;
};

/*******************/
/* Packet handling */
/*******************/

#if defined(PPAC_ORDER_PRESERVATION) || \
	defined(PPAC_ORDER_RESTORATION)
#define PRE_DQRR()  local_dqrr = dqrr
#define POST_DQRR() (local_dqrr ? qman_cb_dqrr_consume : qman_cb_dqrr_defer)
#else
#define PRE_DQRR()  do { ; } while (0)
#define POST_DQRR() qman_cb_dqrr_consume
#endif

#ifdef PPAC_ORDER_RESTORATION
#define PRE_ORP(orpid, seqnum) \
	do { \
		local_orp_id = orpid; \
		local_seqnum = seqnum; \
	} while (0)

#define POST_ORP() \
	do { \
		local_orp_id = 0; \
	} while (0)
#else
#define PRE_ORP(orpid, seqnum) do { ; } while (0)
#define POST_ORP()             do { ; } while (0)
#endif

static enum qman_cb_dqrr_result
cb_dqrr_rx_error(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	struct ppac_rx_error *r = container_of(fq, struct ppac_rx_error, fq);
	struct ppac_interface *_if = container_of(r, struct ppac_interface,
						  rx_error);
	TRACE("Rx_error: fqid=%d\tfd_status = 0x%08x\n",
	      fq->fqid, dqrr->fd.status);
	PRE_DQRR();
	ppam_rx_error_cb(&r->s, &_if->ppam_data, dqrr);
	return POST_DQRR();
}

static enum qman_cb_dqrr_result
cb_dqrr_rx_default(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	struct ppac_rx_default *r = container_of(fq, struct ppac_rx_default,
						 fq);
	struct ppac_interface *_if = container_of(r, struct ppac_interface,
						  rx_default);
	TRACE("Rx_default: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	PRE_DQRR();
	ppam_rx_default_cb(&r->s, &_if->ppam_data, dqrr);
	return POST_DQRR();
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_error(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	struct ppac_tx_error *t = container_of(fq, struct ppac_tx_error, fq);
	struct ppac_interface *_if = container_of(t, struct ppac_interface,
						  tx_error);
	TRACE("Tx_error: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	PRE_DQRR();
	ppam_tx_error_cb(&t->s, &_if->ppam_data, dqrr);
	return POST_DQRR();
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_confirm(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	struct ppac_tx_confirm *t = container_of(fq, struct ppac_tx_confirm,
						 fq);
	struct ppac_interface *_if = container_of(t, struct ppac_interface,
						  tx_confirm);
	TRACE("Tx_confirm: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	PRE_DQRR();
	ppam_tx_confirm_cb(&t->s, &_if->ppam_data, dqrr);
	return POST_DQRR();
}

enum qman_cb_dqrr_result
cb_dqrr_rx_hash(struct qman_portal *qm __always_unused,
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr)
{
	struct ppac_rx_hash *p = container_of(fq, struct ppac_rx_hash, fq);
	TRACE("Rx_hash: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	PRE_DQRR();
	PRE_ORP(p->orp_id, dqrr->seqnum);
	ppam_rx_hash_cb(&p->s, dqrr);
	POST_ORP();
	return POST_DQRR();
}

void cb_ern(struct qman_portal *qm __always_unused,
	    struct qman_fq *fq,
	    const struct qm_mr_entry *msg)
{
	TRACE("Tx_ern: fqid=%d\tfd_status = 0x%08x\n", msg->ern.fqid,
	      msg->ern.fd.status);
	PRE_ORP((msg->ern.orp & QM_MR_ORPID_MASK), msg->ern.seqnum);
	ppac_drop_frame(&msg->ern.fd);
	POST_ORP();
}

#ifdef PPAC_RX_1G_PREFERINCACHE
#define RX_1G_PIC 1
#else
#define RX_1G_PIC 0
#endif
#ifdef PPAC_RX_10G_PREFERINCACHE
#define RX_10G_PIC 1
#else
#define RX_10G_PIC 0
#endif
#ifdef PPAC_2FWD_RX_OFFLINE_PREFERINCACHE
#define RX_OFFLINE_PIC 1
#else
#define RX_OFFLINE_PIC 0
#endif

/* This is part of the inlined code due to its dependency on ppam_* types. */
int ppac_interface_init(unsigned idx)
{
	struct ppac_interface *i;
	const struct fman_if_bpool *bp;
	int err, loop;
	struct qm_fqd_stashing stash_opts;
	const struct fm_eth_port_cfg *port = &netcfg->port_cfg[idx];
	const struct fman_if *fif = port->fman_if;
	size_t size = sizeof(struct ppac_interface);
	struct fmc_netcfg_fqrange *fqr;

	/* Make sure we are able to handle drops by initialising pool objects
	 * for all buffer pools used by the network interface. */
	fman_if_for_each_bpool(bp, fif) {
		err = lazy_init_bpool(bp->bpid);
		if (err)
			return err;
	}
	/* allocate stashable memory for the interface object */
	i = dma_mem_memalign(L1_CACHE_BYTES, size);
	if (!i)
		return -ENOMEM;
	memset(i, 0, size);
	INIT_LIST_HEAD(&i->list);
	i->size = size;
	i->port_cfg = port;
	/* allocate and initialise Tx FQs for this interface */
	i->num_tx_fqs = (fif->mac_type == fman_mac_10g) ?
			PPAC_TX_FQS_10G :
			(fif->mac_type == fman_offline) ?
			PPAC_TX_FQS_OFFLINE : PPAC_TX_FQS_1G;
	i->tx_fqs = malloc(sizeof(*i->tx_fqs) * i->num_tx_fqs);
	if (!i->tx_fqs) {
		dma_mem_free(i, size);
		return -ENOMEM;
	}
	err = ppam_interface_init(&i->ppam_data, port, i->num_tx_fqs);
	if (err) {
		free(i->tx_fqs);
		dma_mem_free(i, size);
		return err;
	}
	memset(i->tx_fqs, 0, sizeof(*i->tx_fqs) * i->num_tx_fqs);
	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qman_fq *fq = &i->tx_fqs[loop];
		ppac_fq_tx_init(fq, fif->tx_channel_id, fif->fqid_tx_confirm);
		TRACE("I/F %d, using Tx FQID %d\n", idx, fq->fqid);
		ppam_interface_tx_fqid(&i->ppam_data, loop, fq->fqid);
	}
	/* Note: we should handle errors and unwind */
	stash_opts = default_stash_opts;
	err = ppam_rx_error_init(&i->rx_error.s, &i->ppam_data, &stash_opts);
	BUG_ON(err);
	ppac_fq_nonpcd_init(&i->rx_error.fq, fif->fqid_rx_err, get_rxc(),
			    &stash_opts, cb_dqrr_rx_error);
	stash_opts = default_stash_opts;
	err = ppam_rx_default_init(&i->rx_default.s, &i->ppam_data,
				   &stash_opts);
	BUG_ON(err);
	ppac_fq_nonpcd_init(&i->rx_default.fq, port->rx_def, get_rxc(),
			    &stash_opts, cb_dqrr_rx_default);

	/* Offline ports don't have Tx Error or Tx Confirm FQs */
	if (fif->mac_type != fman_offline) {
		stash_opts = default_stash_opts;
		err = ppam_tx_error_init(&i->tx_error.s, &i->ppam_data, &stash_opts);
		BUG_ON(err);
		ppac_fq_nonpcd_init(&i->tx_error.fq, fif->fqid_tx_err, get_rxc(),
			    &stash_opts, cb_dqrr_tx_error);
		stash_opts = default_stash_opts;
		err = ppam_tx_confirm_init(&i->tx_confirm.s, &i->ppam_data,
				   &stash_opts);
		BUG_ON(err);
		ppac_fq_nonpcd_init(&i->tx_confirm.fq, fif->fqid_tx_confirm, get_rxc(),
			    &stash_opts, cb_dqrr_tx_confirm);
	}

	list_for_each_entry(fqr, port->list, list) {
		uint32_t fqid = fqr->start;
		struct ppac_pcd_range *pcd_range;

		size = sizeof(struct ppac_pcd_range) +
			fqr->count*sizeof(struct ppac_rx_hash);
		pcd_range = dma_mem_memalign(L1_CACHE_BYTES, size);
		if (!pcd_range)
			return -ENOMEM;

		memset(pcd_range, 0, size);
		INIT_LIST_HEAD(&pcd_range->list);
		pcd_range->count = fqr->count;

		for (loop = 0; loop < fqr->count; loop++) {
			stash_opts = default_stash_opts;
			err = ppam_rx_hash_init(&pcd_range->rx_hash[loop].s,
				 &i->ppam_data, loop, &stash_opts);
			BUG_ON(err);
#ifdef PPAC_ORDER_RESTORATION
			ppac_orp_init(&pcd_range->rx_hash[loop].orp_id);
			TRACE("I/F %d, Rx FQID %d associated with ORP ID %d\n",
				idx, pcd_range->rx_hash[loop].fq.fqid,
				pcd_range->rx_hash[loop].orp_id);
#endif
			ppac_fq_pcd_init(&pcd_range->rx_hash[loop].fq, fqid++,
				get_rxc(), &stash_opts,
				(fif->mac_type == fman_mac_1g) ? RX_1G_PIC :
				(fif->mac_type == fman_mac_10g) ? RX_10G_PIC :
				(fif->mac_type == fman_offline) ? RX_OFFLINE_PIC:
				0);
		}
		list_add_tail(&pcd_range->list, &i->list);
	}

	ppac_interface_enable_rx(i);
	list_add_tail(&i->node, &ifs);

	return 0;
}

void ppac_interface_enable_rx(const struct ppac_interface *i)
{
	fman_if_enable_rx(i->port_cfg->fman_if);
	TRACE("Interface %d:%d, enabled RX\n",
	      i->port_cfg->fman_if->fman_idx,
	      i->port_cfg->fman_if->mac_idx);
}

void ppac_interface_disable_rx(const struct ppac_interface *i)
{
	fman_if_disable_rx(i->port_cfg->fman_if);
	TRACE("Interface %d:%d, disabled RX\n",
	      i->port_cfg->fman_if->fman_idx,
	      i->port_cfg->fman_if->mac_idx);
}

void ppac_interface_finish(struct ppac_interface *i)
{
	int loop;
	struct ppac_pcd_range *pcd_range;

	/* Cleanup in the opposite order of ppac_interface_init() */
	ppac_interface_disable_rx(i);
	list_del(&i->node);
	list_for_each_entry(pcd_range, &i->list, list) {
		for (loop = 0; loop < pcd_range->count; loop++) {
			ppam_rx_hash_finish(&pcd_range->rx_hash[loop].s,
				 &i->ppam_data, loop);
			teardown_fq(&pcd_range->rx_hash[loop].fq);
		}
	}

	/* Offline ports don't have Tx Error or Confirm FQs */
	if (ppac_interface_type(i) != fman_offline) {
		ppam_tx_confirm_finish(&i->tx_confirm.s, &i->ppam_data);
		teardown_fq(&i->tx_confirm.fq);
		ppam_tx_error_finish(&i->tx_error.s, &i->ppam_data);
		teardown_fq(&i->tx_error.fq);
	}
	ppam_rx_default_finish(&i->rx_default.s, &i->ppam_data);
	teardown_fq(&i->rx_default.fq);
	ppam_rx_error_finish(&i->rx_error.s, &i->ppam_data);
	teardown_fq(&i->rx_error.fq);
	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qman_fq *fq = &i->tx_fqs[loop];
		TRACE("I/F %d, destroying Tx FQID %d\n",
		      i->port_cfg->fman_if->fman_idx, fq->fqid);
		teardown_fq(fq);
	}

	ppam_interface_finish(&i->ppam_data);
	free(i->tx_fqs);
	dma_mem_free(i, i->size);
}
