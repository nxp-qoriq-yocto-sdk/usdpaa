/**
 \helper.c
 \brief helper functions
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

#include <usdpaa/compat.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/dma_mem.h>
#include <usdpaa/fman.h>

#include <internal/compat.h>

#include "helper.h"
#include "app_common.h"

struct ipfwd_eth_t ipfwd_fq_range[MAX_NUM_PORTS]; /* num of ports */
#define SIZE_TO_STASH_LINES(s) ((s >> 6) + ((s & 0x3F) ? 1 : 0))
#define GET_STASH_LINES(l) (SIZE_TO_STASH_LINES(l) > 3 ? 3 : \
 SIZE_TO_STASH_LINES(l))
#undef CGR_SUPPORT
static uint32_t pchannel_idx;
static struct usdpaa_netcfg_info cfg;

static enum qm_channel get_rxc(void)
{
	enum qm_channel ret = cfg.pool_channels[pchannel_idx];
	pchannel_idx = (pchannel_idx + 1) % cfg.num_pool_channels;
	return ret;
}

/**
\brief	Frame queues initialisation function

\details Inits a number of frame queues as requested.

\return -1 - Failure
0 - Success
*/

static int init_fqs(struct ipfwd_fq_range_t *fq_range,
	     uint32_t flags, struct qm_mcc_initfq *opts, const char *fq_type)
{
	uint32_t count;
	uint32_t fq_id;

	opts->fqd.dest.channel = (uint16_t)fq_range->channel;
	opts->fqd.dest.wq = (uint16_t)fq_range->work_queue;
	for (count = 0; count < fq_range->fq_count; count++) {
		if (unlikely(0 != qman_init_fq(fq_range->fq[count],
						 flags, opts))) {
			fq_id = fq_range->fq_start + count;
			pr_err("qm_init_fq failed for fq_id: %u\n", fq_id);
			return -1;
		}
	}

	pr_info("Init %s FQs Base: %u, Count: %u, "
		 "Channel: %u, WQ: %u\n", fq_type,
		 fq_range->fq_start, fq_range->fq_count,
		 fq_range->channel, fq_range->work_queue);

	return 0;
}

/**
\brief	Frame queues creation function

\details Creates a number of frame queues as requested.

\return Negative - Failure
Non-Negative - Success
*/
static int create_fqs(struct ipfwd_fq_range_t *fq_range, const uint32_t flags,
		struct qman_fq_cb *cb, const char *fq_type,
		uint32_t priv_data_size)
{
	struct qman_fq *fq;
	uint32_t fq_id;
	uint32_t count;
	fq_id = fq_range->fq_start;

	for (count = 0; count < fq_range->fq_count; count++) {
		fq = (struct qman_fq *)dma_mem_memalign(L1_CACHE_BYTES,
				 sizeof(struct qman_fq) + priv_data_size);
		if (unlikely(NULL == fq)) {
			pr_err("malloc failed in create_fqs for FQ ID: %u\n",
			     fq_id);
			return -1;
		}
		fq->cb = *cb;

		if (unlikely(0 != qman_create_fq(fq_id, flags, fq))) {
			pr_err("qman_create_fq failed for FQ ID: %u\n",
					fq_id);
			return -1;
		}

		fq_range->fq[count] = fq;
		fq_id++;
	}

	pr_info("Created %s Base: %u, Count: %u\n", fq_type,
		 fq_range->fq_start, fq_range->fq_count);

	return 0;
}

static int ipfwd_fq_create(struct usdpaa_netcfg_info *cfg_ptr,
		      struct qman_fq_cb *rx_default_cb,
		      struct qman_fq_cb *rx_pcd_cb,
		      struct qman_fq_cb *rx_err_cb,
		      struct qman_fq_cb *tx_cb,
		      struct qman_fq_cb *tx_confirm_cb,
		      struct qman_fq_cb *tx_err_cb, uint32_t priv_data_size)
{
	uint32_t port_id;
	struct fm_eth_port_cfg *p_cfg;
	const struct fman_if *fif;
	uint32_t flags;
	int ret;

	pr_debug("IPFWD FQ CREATE: Enter\n");
	for (port_id = 0; port_id < g_num_dpa_eth_ports; port_id++) {
		p_cfg = &cfg_ptr->port_cfg[port_id];
		fif = p_cfg->fman_if;
		/* Using dynamic FQID allocator for TX FQ */
		ipfwd_fq_range[port_id].tx.fq_start = 0;
		ipfwd_fq_range[port_id].tx.fq_count = 1;
		ipfwd_fq_range[port_id].tx.work_queue = 1;
		ipfwd_fq_range[port_id].tx.channel = fif->tx_channel_id;
		flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_TO_DCPORTAL |
			QMAN_FQ_FLAG_DYNAMIC_FQID;
		ret = create_fqs(&ipfwd_fq_range[port_id].tx, flags,
				 tx_cb, "Tx default", priv_data_size);
		if (unlikely(0 != ret)) {
			pr_err("create_fqs failed for Tx\n");
			return -1;
		}

		/* This would come from config */
		ipfwd_fq_range[port_id].rx_def.fq_start = p_cfg->rx_def;
		ipfwd_fq_range[port_id].rx_def.fq_count = 1;
		ipfwd_fq_range[port_id].rx_def.work_queue = 3;
		ipfwd_fq_range[port_id].rx_def.channel = get_rxc();
		flags = QMAN_FQ_FLAG_NO_ENQUEUE | QMAN_FQ_FLAG_LOCKED;
		ret = create_fqs(&ipfwd_fq_range[port_id].rx_def, flags,
				 rx_default_cb, "Rx default", priv_data_size);
		if (unlikely(0 != ret)) {
			pr_err("create_fqs failed for Rx default\n");
			return -1;
		}

		ipfwd_fq_range[port_id].rx_err.fq_start = fif->fqid_rx_err;
		ipfwd_fq_range[port_id].rx_err.fq_count = 1;
		ipfwd_fq_range[port_id].rx_err.work_queue = 1;
		ipfwd_fq_range[port_id].rx_err.channel = get_rxc();
		ret = create_fqs(&ipfwd_fq_range[port_id].rx_err, flags,
				 rx_err_cb, "Rx err", priv_data_size);
		if (unlikely(0 != ret)) {
			pr_err("create_fqs failed for Rx err\n");
			return -1;
		}

		ipfwd_fq_range[port_id].pcd.fq_start = p_cfg->pcd.start;
		ipfwd_fq_range[port_id].pcd.fq_count = p_cfg->pcd.count;
		ipfwd_fq_range[port_id].pcd.work_queue = 3;
		ipfwd_fq_range[port_id].pcd.channel = get_rxc();
		ret = create_fqs(&ipfwd_fq_range[port_id].pcd, flags,
				 rx_pcd_cb, "Rx PCD", priv_data_size);
		if (unlikely(0 != ret)) {
			pr_err("create_fqs failed for Rx PCD\n");
			return -1;
		}

		ipfwd_fq_range[port_id].tx_err.fq_start =
					fif->fqid_tx_err;
		ipfwd_fq_range[port_id].tx_err.fq_count = 1;
		ipfwd_fq_range[port_id].tx_err.work_queue = 1;
		ipfwd_fq_range[port_id].tx_err.channel = get_rxc();
		ret = create_fqs(&ipfwd_fq_range[port_id].tx_err, flags,
				 tx_err_cb, "Tx err", priv_data_size);
		if (unlikely(0 != ret)) {
			pr_err("create_fqs failed for Tx err\n");
			return -1;
		}

		ipfwd_fq_range[port_id].tx_confirm.fq_start =
					fif->fqid_tx_confirm;
		ipfwd_fq_range[port_id].tx_confirm.fq_count = 1;
		ipfwd_fq_range[port_id].tx_confirm.work_queue = 1;
		ipfwd_fq_range[port_id].tx_confirm.channel = get_rxc();
		ret = create_fqs(&ipfwd_fq_range[port_id].tx_confirm, flags,
				 tx_confirm_cb, "Tx confirm", priv_data_size);
		if (unlikely(0 != ret)) {
			pr_err("create_fqs failed Tx confirm\n");
			return -1;
		}
	}
	pr_debug("IPFWD FQ CREATE: Exit\n");
	return 0;
}


static int ipfwd_fq_init(uint32_t data_stash_size,
		uint32_t ann_stash_size, uint32_t ctx_stash_size,
		struct qman_orp_pcd *pcd_orp, struct td_param *pcd_td)
{
	uint32_t port_id;
	uint32_t flags;
	uint32_t ctx_lines;
	uint32_t ann_lines;
	uint32_t data_lines;
	uint32_t ctx_a_excl;

	struct qm_mcc_initfq opts;

	for (port_id = 0; port_id < g_num_dpa_eth_ports; port_id++) {
		pr_info("Initializing FQs for port id: %u\n", port_id);

		flags = QMAN_INITFQ_FLAG_SCHED;
		opts.we_mask = QM_INITFQ_WE_DESTWQ |
		    QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_FQCTRL;
		opts.fqd.fq_ctrl =
			 QM_FQCTRL_CTXASTASHING | QM_FQCTRL_LOCKINCACHE |
				QM_FQCTRL_CPCSTASH;
		if (NULL != pcd_orp) {
			opts.we_mask |= QM_INITFQ_WE_ORPC ;
			opts.fqd.fq_ctrl |= QM_FQCTRL_ORP;
			opts.fqd.orprws = pcd_orp->orprws;
			opts.fqd.oa = pcd_orp->oa;
			opts.fqd.olws = pcd_orp->olws;
		}

		ctx_a_excl =
			QM_STASHING_EXCL_ANNOTATION | QM_STASHING_EXCL_DATA;

		ctx_lines = GET_STASH_LINES(ctx_stash_size);
		data_lines = GET_STASH_LINES(data_stash_size);
		ann_lines = GET_STASH_LINES(ann_stash_size);

		opts.fqd.context_a.stashing.exclusive = ctx_a_excl;
		opts.fqd.context_a.stashing.annotation_cl = ann_lines;
		opts.fqd.context_a.stashing.data_cl = data_lines;
		opts.fqd.context_a.stashing.context_cl = ctx_lines;

		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].rx_def,
				 flags, &opts, "Rx default"))) {
			pr_err("init_fqs failed for Rx default FQs\n");
			return -1;
		}

		/*Check if tail drop is required on PCD FQs*/
		if (NULL != pcd_td) {
			if (pcd_td->flag == QM_FQCTRL_TDE) {
				opts.fqd.fq_ctrl |= QM_FQCTRL_TDE;
				opts.we_mask |= QM_INITFQ_WE_TDTHRESH;
				opts.fqd.td.exp = pcd_td->exp;
				opts.fqd.td.mant = pcd_td->mant;
				pr_info("Init PCDFQs TD mant = %hu exp = %hu\n",
					pcd_td->mant, pcd_td->exp);
			}
		else if (pcd_td->flag == QM_FQCTRL_CGE) {
				opts.we_mask |= QM_INITFQ_WE_CGID;
				opts.fqd.fq_ctrl = QM_FQCTRL_CGE;
				/* Currently hardcoding all ingress pcd FQs
				 to single CGR */
				opts.fqd.cgid = pcd_td->cgr_id;
				pr_info("Enabling Congestion Group %x\n",
					 opts.fqd.cgid);
			}
		}

		opts.fqd.fq_ctrl |= QM_FQCTRL_HOLDACTIVE;
		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].pcd, flags,
				  &opts, "Rx PCD"))) {
			pr_err("init_fqs failed for Rx PCD FQs\n");
			return -1;
		}

		/*We do not need stashing for following FQs */
		opts.fqd.fq_ctrl = 0;
		opts.we_mask = QM_INITFQ_WE_DESTWQ;
		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].rx_err,
			 flags, &opts, "Rx err"))) {
			pr_err("init_fqs failed for Rx err FQs\n");
			return -1;
		}

		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].tx_err,
				 flags, &opts, "Tx err"))) {
			pr_err("init_fqs failed for Tx err FQs\n");
			return -1;
		}

		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].tx_confirm,
				 flags, &opts, "Tx confirm"))) {
			pr_err("init_fqs failed for Tx confirm FQs\n");
			return -1;
		}

		opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
		opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA |
		    QM_INITFQ_WE_CONTEXTB;

		opts.fqd.context_a.hi = 0x80000000;
		opts.fqd.context_a.lo = 0x0;
		opts.fqd.context_b = 0;	/*By default no confirmation needed */
		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].tx, flags,
				  &opts, "Tx"))) {
			pr_err("init_fqs failed for Tx FQs\n");
			return -1;
		}
	}

	return 0;
}

#ifdef CGR_SUPPORT
/**
 \brief Initialize Congestion Group Record
 \param[in] Congestion parameters for Congestion group initialization
 \param[in] Congestion Group ID
 \param[out] Congestion group Record
 */
static struct qman_cgr *init_cgr(struct td_param *cgr_param)
{
	struct qm_mcc_initcgr cgr_state;
	struct qman_cgr *cgr = NULL;
	uint32_t res = 0;

	cgr = (struct qman_cgr *)dma_mem_memalign(L1_CACHE_BYTES,
			 sizeof(struct qman_cgr));
	if (cgr == NULL) {
		pr_err("%s: Memory for CGR not available\n", __func__);
		return NULL;
	}
	memset(cgr, 0, sizeof(struct qman_cgr));

	cgr->cgrid = cgr_param->cgr_id;
	memset(&cgr_state, 0, sizeof(struct qm_mcc_initcgr));
	pr_info("%s: Congestion Record ID being created is %x\n", __func__,
		 cgr_param->cgr_id);
	cgr_state.we_mask = QM_CGR_WE_CS_THRES | QM_CGR_WE_CSTD_EN |
			 QM_CGR_WE_MODE;
#ifdef CGR_NOTIFY_REQUIRED
	cgr->cb = cgr_param->cgr_cb;
	cgr_state.we_mask |= QM_CGR_WE_CSCN_EN;
	cgr_state.cgr.cscn_en = 1;
#endif
	cgr_state.cgr.mode = QMAN_CGR_MODE_FRAME;
	cgr_state.cgr.cstd_en = 1;
	cgr_state.cgr.cs_thres.TA = cgr_param->mant;
	cgr_state.cgr.cs_thres.Tn = cgr_param->exp;
	res = qman_create_cgr(cgr, QMAN_CGR_FLAG_USE_INIT, &cgr_state);
	if (res) {
		pr_err("%s: Error Creating CGR\n", __func__);
		dma_mem_free(cgr, sizeof(struct qman_cgr));
		return NULL;
	}

	return cgr;
}
#endif
/**
 \brief Initialize ethernet interfaces
 \param[in]
 \param[out] NULL
 */
int init_interface(struct usdpaa_netcfg_info *cfg_ptr,
		      uint32_t *recv_channel_map,
		      struct qman_fq_cb *rx_default_cb,
		      struct qman_fq_cb *rx_pcd_cb,
		      struct qman_fq_cb *rx_err_cb,
		      struct qman_fq_cb *tx_cb,
		      struct qman_fq_cb *tx_confirm_cb,
		      struct qman_fq_cb *tx_err_cb, uint32_t priv_data_size)
{
	uint32_t port_id;
	struct fm_eth_port_cfg *p_cfg;
	const struct fman_if *fif;
#ifdef CGR_SUPPORT
	struct td_param pcd_td_param;
#endif
	struct td_param *pcd_td_ptr = NULL;
	const struct fman_if_bpool *bp;
	int loop, err;

	pr_debug("Init interface: Enter\n");

	*recv_channel_map = 0;
	cfg = *cfg_ptr;
	g_num_dpa_eth_ports = cfg_ptr->num_ethports;
	for (port_id = 0; port_id < g_num_dpa_eth_ports; port_id++) {
		p_cfg = &cfg_ptr->port_cfg[port_id];
		fif = p_cfg->fman_if;
		ipfwd_fq_range[port_id].mac_addr = fif->mac_addr;
		/* Handle any pools used by this i/f
		 that are not already handled */
		fman_if_for_each_bpool(bp, fif) {
			err = lazy_init_bpool(bp->bpid);
			if (err)
				return err;
		}
	}
	for (loop = 0; loop < cfg_ptr->num_pool_channels; loop++) {
		*recv_channel_map |= QM_SDQCR_CHANNELS_POOL_CONV(
					cfg_ptr->pool_channels[loop]);
		pr_info("Adding 0x%08x to SDQCR -> 0x%08x\n",
				QM_SDQCR_CHANNELS_POOL_CONV(
				cfg_ptr->pool_channels[loop]),
				*recv_channel_map);
	}
	if (0 !=
		ipfwd_fq_create(cfg_ptr, rx_default_cb, rx_pcd_cb, rx_err_cb,
			tx_cb, tx_confirm_cb, tx_err_cb, priv_data_size)) {
		pr_err("Unable to Create FQs\n");
		return -EINVAL;
	}
#ifdef CGR_SUPPORT
	pcd_td_param.mant = 1; /**< Mantissa is 1 */
	pcd_td_param.exp = 10; /**< Exponent is 12 */
	pcd_td_ptr = &pcd_td_param;
	/* Allow 4k Frames in CG */
	pcd_td_param.flag = QM_FQCTRL_CGE;
	pcd_td_param.cgr_cb = NULL;
	pcd_td_param.cgr_id = 1;
	if (!init_cgr(pcd_td_ptr)) {
		pr_err("Unabled to create Congestion Group\n");
		return -EINVAL;
	}
#endif

	if (0 != ipfwd_fq_init(L1_CACHE_BYTES, L1_CACHE_BYTES, L1_CACHE_BYTES, NULL, pcd_td_ptr)) {
		pr_err("Unable to initialize FQs\n");
		return -EINVAL;
	}
	pr_debug("Init interface: Exit\n");
	return 0;
}
