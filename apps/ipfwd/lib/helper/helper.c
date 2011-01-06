/**
 \helper.c
 \brief helper functions
 */
/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc.
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

#include "compat.h"
#include "helper.h"
#include <linux/fsl_qman.h>
#include <app_common.h>
#include <dma_mem.h>
#include <usdpa_netcfg.h>

struct ipfwd_eth_t ipfwd_fq_range[MAX_NUM_PORTS]; /* num of ports */
#define SIZE_TO_STASH_LINES(s) ((s >> 6) + ((s & 0x3F) ? 1 : 0))
#define GET_STASH_LINES(l) (SIZE_TO_STASH_LINES(l) > 3 ? 3 : \
 SIZE_TO_STASH_LINES(l))
#define IPFWD_FQID_TX(n)        (0x3000 + n)
#define CGR_SUPPORT

/**
\brief  Frame queues initialisation function

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
			APP_ERROR("qm_init_fq failed for fq_id: %u", fq_id);
			return -1;
		}
	}

	APP_INFO("Init %s FQs Base: %u, Count: %u, "
		 "Channel: %u, WQ: %u", fq_type,
		 fq_range->fq_start, fq_range->fq_count,
		 fq_range->channel, fq_range->work_queue);

	return 0;
}

/**
\brief  Frame queues creation function

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
		fq = (struct qman_fq *)dma_mem_memalign(CACHE_LINE_SIZE,
				 sizeof(struct qman_fq) + priv_data_size);
		if (unlikely(NULL == fq)) {
			APP_ERROR("malloc failed in create_fqs for FQ ID: %u",
			     fq_id);
			return -1;
		}
		fq->cb = *cb;

		if (unlikely(0 != qman_create_fq(fq_id, flags, fq))) {
			APP_ERROR("qman_create_fq failed for FQ ID: %u",
					fq_id);
			return -1;
		}

		fq_range->fq[count] = fq;
		fq_id++;
	}

	APP_INFO("Created %s Base: %u, Count: %u", fq_type,
		 fq_range->fq_start, fq_range->fq_count);

	return 0;
}

static int ipfwd_fq_create(struct usdpa_netcfg_info *cfg_ptr,
		      struct qman_fq_cb *rx_default_cb,
		      struct qman_fq_cb *rx_pcd_cb,
		      struct qman_fq_cb *rx_err_cb,
		      struct qman_fq_cb *tx_cb,
		      struct qman_fq_cb *tx_confirm_cb,
		      struct qman_fq_cb *tx_err_cb, uint32_t priv_data_size)
{
	uint32_t port_id;
	struct fm_eth_port_cfg *p_cfg;
	struct fm_ethport_fq *pfq;
	uint32_t flags;
	int ret;

	APP_DEBUG("IPFWD FQ CREATE: Enter");
	for (port_id = 0; port_id < g_num_dpa_eth_ports; port_id++) {
		p_cfg = &cfg_ptr->port_cfg[port_id];
		pfq = &p_cfg->fq;
		/* Assigning fqid as not using FQID allocator for TX FQ */
		ipfwd_fq_range[port_id].tx.fq_start = IPFWD_FQID_TX(port_id);
		ipfwd_fq_range[port_id].tx.fq_count = 1;
		ipfwd_fq_range[port_id].tx.work_queue = 1;
		ipfwd_fq_range[port_id].tx.channel = p_cfg->qm_tx_channel_id;
		flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_TO_DCPORTAL;
		ret = create_fqs(&ipfwd_fq_range[port_id].tx, flags,
				 tx_cb, "Tx default", priv_data_size);
		if (unlikely(0 != ret)) {
			APP_ERROR("create_fqs failed for Tx");
			return -1;
		}

		/* This would come from config */
		ipfwd_fq_range[port_id].rx_def.fq_start = pfq->rx_def.start;
		ipfwd_fq_range[port_id].rx_def.fq_count = pfq->rx_err.count;
		ipfwd_fq_range[port_id].rx_def.work_queue = 3;
		ipfwd_fq_range[port_id].rx_def.channel =
					p_cfg->qm_rx_channel_id;
		flags = QMAN_FQ_FLAG_NO_ENQUEUE | QMAN_FQ_FLAG_LOCKED;
		ret = create_fqs(&ipfwd_fq_range[port_id].rx_def, flags,
				 rx_default_cb, "Rx default", priv_data_size);
		if (unlikely(0 != ret)) {
			APP_ERROR("create_fqs failed for Rx default");
			return -1;
		}

		ipfwd_fq_range[port_id].rx_err.fq_start = pfq->rx_err.start;
		ipfwd_fq_range[port_id].rx_err.fq_count = pfq->rx_err.count;
		ipfwd_fq_range[port_id].rx_err.work_queue = 1;
		ipfwd_fq_range[port_id].rx_err.channel =
					p_cfg->qm_rx_channel_id;
		ret = create_fqs(&ipfwd_fq_range[port_id].rx_err, flags,
				 rx_err_cb, "Rx err", priv_data_size);
		if (unlikely(0 != ret)) {
			APP_ERROR("create_fqs failed for Rx err");
			return -1;
		}

		ipfwd_fq_range[port_id].pcd.fq_start = pfq->pcd.start;
		ipfwd_fq_range[port_id].pcd.fq_count = pfq->pcd.count;
		ipfwd_fq_range[port_id].pcd.work_queue = 3;
		ipfwd_fq_range[port_id].pcd.channel = p_cfg->qm_rx_channel_id;
		ret = create_fqs(&ipfwd_fq_range[port_id].pcd, flags,
				 rx_pcd_cb, "Rx PCD", priv_data_size);
		if (unlikely(0 != ret)) {
			APP_ERROR("create_fqs failed for Rx PCD");
			return -1;
		}

		ipfwd_fq_range[port_id].tx_err.fq_start =
					pfq->tx_err.start;
		ipfwd_fq_range[port_id].tx_err.fq_count =
					pfq->tx_err.count;
		ipfwd_fq_range[port_id].tx_err.work_queue = 1;
		ipfwd_fq_range[port_id].tx_err.channel =
					p_cfg->qm_rx_channel_id;
		ret = create_fqs(&ipfwd_fq_range[port_id].tx_err, flags,
				 tx_err_cb, "Tx err", priv_data_size);
		if (unlikely(0 != ret)) {
			APP_ERROR("create_fqs failed for Tx err");
			return -1;
		}

		ipfwd_fq_range[port_id].tx_confirm.fq_start =
					pfq->tx_confirm.start;
		ipfwd_fq_range[port_id].tx_confirm.fq_count =
					pfq->tx_confirm.count;
		ipfwd_fq_range[port_id].tx_confirm.work_queue = 1;
		ipfwd_fq_range[port_id].tx_confirm.channel =
					p_cfg->qm_rx_channel_id;
		ret = create_fqs(&ipfwd_fq_range[port_id].tx_confirm, flags,
				 tx_confirm_cb, "Tx confirm", priv_data_size);
		if (unlikely(0 != ret)) {
			APP_ERROR("create_fqs failed Tx confirm");
			return -1;
		}
	}
	APP_DEBUG("IPFWD FQ CREATE: Exit");
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
		APP_INFO("Initializing FQs for port id: %u", port_id);

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
			APP_ERROR("init_fqs failed for Rx default FQs");
			return -1;
		}

		/*Check if tail drop is required on PCD FQs*/
		if (NULL != pcd_td) {
			if (pcd_td->flag == QM_FQCTRL_TDE) {
				opts.fqd.fq_ctrl |= QM_FQCTRL_TDE;
				opts.we_mask |= QM_INITFQ_WE_TDTHRESH;
				opts.fqd.td.exp = pcd_td->exp;
				opts.fqd.td.mant = pcd_td->mant;
				APP_INFO("Init PCDFQs TD mant = %hu exp = %hu",
					pcd_td->mant, pcd_td->exp);
			}
		else if (pcd_td->flag == QM_FQCTRL_CGE) {
				opts.we_mask |= QM_INITFQ_WE_CGID;
				opts.fqd.fq_ctrl = QM_FQCTRL_CGE;
				/* Currently hardcoding all ingress pcd FQs
				 to single CGR */
				opts.fqd.cgid = pcd_td->cgr_id;
				APP_INFO("Enabling Congestion Group %x",
					 opts.fqd.cgid);
			}
		}

		opts.fqd.fq_ctrl |= QM_FQCTRL_HOLDACTIVE;
		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].pcd, flags,
				  &opts, "Rx PCD"))) {
			APP_ERROR("init_fqs failed for Rx PCD FQs");
			return -1;
		}

		/*We do not need stashing for following FQs */
		opts.fqd.fq_ctrl = 0;
		opts.we_mask = QM_INITFQ_WE_DESTWQ;
		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].rx_err,
			 flags, &opts, "Rx err"))) {
			APP_ERROR("init_fqs failed for Rx err FQs");
			return -1;
		}

		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].tx_err,
				 flags, &opts, "Tx err"))) {
			APP_ERROR("init_fqs failed for Tx err FQs");
			return -1;
		}

		if (unlikely(0 != init_fqs(&ipfwd_fq_range[port_id].tx_confirm,
				 flags, &opts, "Tx confirm"))) {
			APP_ERROR("init_fqs failed for Tx confirm FQs");
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
			APP_ERROR("init_fqs failed for Tx FQs");
			return -1;
		}
	}

	return 0;
}

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

	cgr = (struct qman_cgr *)dma_mem_memalign(CACHE_LINE_SIZE,
			 sizeof(struct qman_cgr));
	if (cgr == NULL) {
		APP_ERROR("%s: Memory for CGR not available", __func__);
		return NULL;
	}
	memset(cgr, 0, sizeof(struct qman_cgr));

	cgr->cgrid = cgr_param->cgr_id;
	memset(&cgr_state, 0, sizeof(struct qm_mcc_initcgr));
	APP_INFO("%s: Congestion Record ID being created is %x", __func__,\
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
		APP_ERROR("%s: Error Creating CGR", __func__);
		dma_mem_free(cgr, sizeof(struct qman_cgr));
		return NULL;
	}

	return cgr;
}

/**
 \brief Initialize ethernet interfaces
 \param[in]
 \param[out] NULL
 */
int init_interface(struct usdpa_netcfg_info *cfg_ptr,
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
	int32_t recv_channel_id;
	struct fm_ethport_fq *pfq;
	struct td_param pcd_td_param;
	struct td_param *pcd_td_ptr = NULL;

	APP_DEBUG("Init interface: Enter");

	*recv_channel_map = 0;
	g_num_dpa_eth_ports = cfg_ptr->num_ethports;
	for (port_id = 0; port_id < g_num_dpa_eth_ports; port_id++) {
		p_cfg = &cfg_ptr->port_cfg[port_id];
		pfq = &p_cfg->fq;
		memcpy(&ipfwd_fq_range[port_id].mac_addr,
				p_cfg->fm_mac_addr, ETHER_ADDR_LEN);
		recv_channel_id = p_cfg->qm_rx_channel_id;
		if (recv_channel_id >= qm_channel_swportal0 &&
		    recv_channel_id <= qm_channel_swportal9) {
			recv_channel_id = 0;	/*Dedicated channel case */
		} else if (recv_channel_id >= qm_channel_pool1 &&
			   recv_channel_id <= qm_channel_pool15) {
			/*Pool channels start from 1 */
			recv_channel_id = recv_channel_id -
			    qm_channel_pool1 + 1;
		} else {
			APP_ERROR("Invalid recv channel id: %d",
				  recv_channel_id);
			return -1;
		}

		*recv_channel_map = *recv_channel_map |
		    QM_SDQCR_CHANNELS_POOL(recv_channel_id);
	}
	if (0 !=
		ipfwd_fq_create(cfg_ptr, rx_default_cb, rx_pcd_cb, rx_err_cb,
			tx_cb, tx_confirm_cb, tx_err_cb, priv_data_size)) {
		APP_ERROR("Unable to Create FQs");
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
		APP_ERROR("Unabled to create Congestion Group");
		return -EINVAL;
	}
#endif

	if (0 != ipfwd_fq_init(64, 64, 64, NULL, pcd_td_ptr)) {
		APP_ERROR("Unable to initialize FQs");
		return -EINVAL;
	}
	APP_DEBUG("Init interface: Exit");
	return 0;
}
