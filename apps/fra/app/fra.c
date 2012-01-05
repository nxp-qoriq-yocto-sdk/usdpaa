/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
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
#include "rman_interface.h"
#include "fra_cfg_parser.h"
#include "fra.h"

struct fra *fra;

#ifdef ENABLE_FRA_DEBUG
uint64_t fwd_from_count;
uint64_t fwd_to_count;
uint64_t tx_count;
uint64_t rx_count;
uint64_t tx_release_count;

int debug_off;

static int debug_setting(int argc, char *argv[])
{
	if (argc != 2) {
		error(EXIT_SUCCESS, 0,
			"debug correct format:\n\tdebug [on/off]");
		return -EINVAL;
	}

	if (!strcmp(argv[1], "on"))
		debug_off = 0;
	else if (!strcmp(argv[1], "off"))
		debug_off = 1;
	else
		return -EINVAL;

	return 0;
}
cli_cmd(debug, debug_setting);
#endif

static inline void tran_status(struct rio_tran *tran)
{
	fprintf(stderr, "\t\trio_tran:%s type:%s\n",
		tran->name, RIO_TYPE_TO_STR[tran->type]);
}

static int fra_cli_status(int argc, char *argv[])
{
	const struct fra_cfg *fra_cfg;
	struct dist_order *dist_order;
	struct distribution *dist;
	struct dist_cfg *cfg;
	int i = 1;

	if (argc > 2)
		return -EINVAL;

	if (!fra || !fra->cfg) {
		error(EXIT_SUCCESS, 0, "Fra is not been configured");
		return -EINVAL;
	}

	fra_cfg = fra->cfg;
	fprintf(stderr, "RMan configuration:\n"
		"\tRMan uses 0x%x qman channel to receive messages\n"
		"\tCreate inbound message descriptor: %s\n"
		"\tThe algorithmic frame queue bits info:\n"
		"\t\tdata streaming:%d mailbox:%d\n"
		"\tBPID info:\n"
		"\t\tdata streaming:%d mailbox:%d doorbell:%d sg:%d\n",
		fra_cfg->rman_cfg.rx_channel_id,
		MD_CREATE_MODE_STR[fra_cfg->rman_cfg.md_create],
		fra_cfg->rman_cfg.fq_bits[RIO_TYPE_DSTR],
		fra_cfg->rman_cfg.fq_bits[RIO_TYPE_MBOX],
		fra_cfg->rman_cfg.bpid[RIO_TYPE_DSTR],
		fra_cfg->rman_cfg.bpid[RIO_TYPE_MBOX],
		fra_cfg->rman_cfg.bpid[RIO_TYPE_DBELL],
		fra_cfg->rman_cfg.sgbpid);

#ifdef ENABLE_FRA_DEBUG
	fprintf(stderr, "\tfwd_from_network packets:0x%llx\n"
		"\ttx packets:0x%llx\n"
		"\ttx_release packets:0x%llx\n"
		"\trx packets:0x%llx\n"
		"\tfwd_to_network packtes:0x%llx\n",
		fwd_from_count, tx_count, tx_release_count,
		rx_count, fwd_to_count);
#endif

	list_for_each_entry(dist_order, &fra->dist_order_list, node) {
		if (i > 1)
			fprintf(stderr, "\n");
		fprintf(stderr, "distribution order-%d:\n", i++);

		dist = dist_order->dist;
		while (dist) {
			cfg = dist->cfg;
			fprintf(stderr, "\tdistribution-%d-%s: %s\n",
				cfg->number, DIST_TYPE_STR[cfg->type],
				cfg->name);
			switch (cfg->type) {
			case DIST_TYPE_RX:
				fprintf(stderr, "\t\tport:%d sid:%d"
					" mask:%d queue:0x%x mode:%s\n",
					cfg->dist_rx_cfg.port,
					cfg->dist_rx_cfg.sid,
					cfg->dist_rx_cfg.sid_mask,
					cfg->dist_rx_cfg.fqid,
				FQ_MODE_STR[cfg->dist_rx_cfg.fq_mode]);
				tran_status(cfg->dist_rx_cfg.tran);
				fprintf(stderr, "\t\tbase FQID:0x%x count:%d"
					" configured to IBCU %d\n",
					cfg->dist_rx_cfg.fqid,
					cfg->dist_rx_cfg.fq_count,
					fqid_to_ibcu(cfg->dist_rx_cfg.fqid));
				break;
			case DIST_TYPE_TX:
				fprintf(stderr, "\t\tport:%d did:%d"
					" session:%d\n "
					"\t\tFQID:0x%x count:%d\n",
					cfg->dist_tx_cfg.port,
					cfg->dist_tx_cfg.did,
					dist->tx[0].session_count,
					cfg->dist_tx_cfg.fqid,
					cfg->dist_tx_cfg.fq_count);
				tran_status(cfg->dist_tx_cfg.tran);
				break;
			case DIST_TYPE_FWD:
				fprintf(stderr,
					"\t\tport:%d fm:%d type:%dg\n",
					cfg->dist_fwd_cfg.port_num,
					cfg->dist_fwd_cfg.fman_num,
					cfg->dist_fwd_cfg.port_type);
				break;
			default:
				fprintf(stderr, "a invalid type\n");
			}
			dist = dist->next;
		}
	}
	return 0;
}

cli_cmd(status, fra_cli_status);

static enum handler_status
dist_tx_handler(struct distribution *dist, struct tx_opt *opt,
		const struct qm_fd *fd)
{
#ifdef ENABLE_FRA_DEBUG
	FRA_DBG("Fra TX(%s) will transmit a msg", dist->cfg->name);
	tx_count++;
#endif

	if (rman_send_fd(&dist->tx[0].md, opt, (struct qm_fd *)fd)) {
		bpool_fd_free(fd);
		error(EXIT_SUCCESS, 0,
			"FRA: dist(%s)failed to send fd", dist->cfg->name);
	}
	return HANDLER_DONE;
}

static enum handler_status
dist_fwd_to_handler(struct distribution *dist, struct tx_opt *opt,
		const struct qm_fd *fd)
{
#ifdef ENABLE_FRA_DEBUG
	FRA_DBG("Fra: FWD to dist %s using FQID 0x%x",
		dist->cfg->name, opt->txfqid);
	fwd_to_count++;
#endif

	ppac_send_frame(opt->txfqid, fd);
	return HANDLER_DONE;
}

static inline void dist_order_handler(struct distribution *dist,
				      struct tx_opt *opt,
				      const struct qm_fd *fd)
{
	enum handler_status status = HANDLER_CONTINUE;

	while (dist && status != HANDLER_DONE) {
		if (dist->handler)
			status = dist->handler(dist, opt, fd);
		dist = dist->next;
	}

	if (status != HANDLER_DONE)
		bpool_fd_free(fd);
}

void dist_rx_handler(struct dist_rx *rx, const struct qm_fd *fd)
{
	struct distribution *dist = rx->dist;

#ifdef ENABLE_FRA_DEBUG
	struct msg_buf *msg;
	rx_count++;
	if (FD_GET_STATUS(fd)) {
		FRA_DBG("Rx(%s) get a wrong frame stauts(0x%x)",
			dist->cfg->name, fd->status);
		bpool_fd_free(fd);
		return;
	}
	msg = fd_to_msg((struct qm_fd *)fd);
	if (msg)
		FRA_DBG("Fra: RX type(%d) length(%d) sid(%d) did(%d)",
			msg_get_type(msg), msg_get_len(msg), msg_get_sid(msg),
			msg_get_did(msg));
#endif

	if (fd->format != qm_fd_contig && fd->format != qm_fd_sg) {
		error(EXIT_SUCCESS, 0,
			"Rx(%s) get a wrong frame format(%d)",
			dist->cfg->name, fd->format);
		bpool_fd_free(fd);
	}

	if (FD_GET_STATUS(fd)) {
		/*
		error(EXIT_SUCCESS, 0, "Rx(%s) get a wrong frame stauts(0x%x)",
			dist->cfg->name, fd->status);
		if (fd->status & 0x1) {
			error(EXIT_SUCCESS, 0, "bpool buffers are depleted");
			return ;
		}
		*/
		bpool_fd_free(fd);
		return;
	}

	dist_order_handler(dist, &rx->opt, fd);
	return;
}

void dist_tx_status_handler(struct dist_tx *tx, const struct qm_fd *fd)
{
#ifdef ENABLE_FRA_DEBUG
	struct distribution *dist = tx->dist;
	FRA_DBG("Fra Tx(%s) get tx status(0x%x)", dist->cfg->name,
		fd->status);
	tx_release_count++;
#endif

	bpool_fd_free(fd);
}

void dist_fwd_from_handler(struct ppam_rx_hash *rx, const struct qm_fd *fd)
{
	struct distribution *dist = rx->dist;

#ifdef ENABLE_FRA_DEBUG
	FRA_DBG("Fra: FWD from network dist %s", dist->cfg->name);
	fwd_from_count++;
#endif

	dist_order_handler(dist, &rx->opt, fd);
	return;
}

static void dist_finish(struct distribution *dist)
{
	struct dist_cfg *cfg;
	int i;

	if (!dist)
		return;

	cfg = dist->cfg;
	FRA_DBG("Fra: release dist %s", dist->cfg->name);
	switch (cfg->type) {
	case DIST_TYPE_RX:
		for (i = 0; i < cfg->dist_rx_cfg.fq_count; i++)
			rman_fq_free(&dist->rx_hash[i].fq);
		rman_rxfq_finish(cfg->dist_rx_cfg.fqid);
		dma_mem_free(dist, dist->sz);
		break;
	case DIST_TYPE_TX:
		rman_fq_free(&dist->tx[0].stfq);
		for (i = 0; i < cfg->dist_tx_cfg.fq_count; i++)
			rman_fq_free(&dist->tx[0].fq[i]);
		dma_mem_free(dist, dist->sz);
		break;
	case DIST_TYPE_FWD:
		dma_mem_free(dist, dist->sz);
		break;
	}
}

static void dist_order_finish(struct dist_order *dist_order)
{
	struct distribution *dist, *dist_temp;

	if (!dist_order)
		return;

	dist = dist_order->dist;
	while (dist) {
		dist_temp = dist;
		dist = dist->next;
		dist_finish(dist_temp);
	}
	if (dist_order->node.prev && dist_order->node.next)
		list_del(&dist_order->node);
	free(dist_order);
}

void fra_finish(void)
{
	struct dist_order  *dist_order, *temp;

	if (!fra)
		return;
	list_for_each_entry_safe(dist_order, temp,
			&fra->dist_order_list, node) {
		dist_order_finish(dist_order);
	}
	rman_if_finish();
	free(fra);
	fra = NULL;
}

static struct distribution *dist_rx_init(struct dist_cfg *cfg)
{
	struct dist_rx_cfg *rxcfg;
	struct distribution *dist;
	struct dist_rx *rx;
	int i;
	size_t sz;

	if (!cfg || cfg->type != DIST_TYPE_RX)
		return NULL;

	rxcfg = &cfg->dist_rx_cfg;

	if (!rman_get_port_status(rxcfg->port)) {
		error(0, 0, "SRIO port%d is not connected",
		      rxcfg->port);
		return NULL;
	}

	rxcfg->fq_count = rman_get_rxfq_count(rxcfg->fq_mode, rxcfg->tran);

	if (rxcfg->fq_count < 0)
		return NULL;

	sz = sizeof(*dist) + rxcfg->fq_count * sizeof(struct dist_rx);

	/* allocate stashable memory for the interface object */
	dist = dma_mem_memalign(L1_CACHE_BYTES, sz);
	if (!dist)
		return NULL;
	memset(dist, 0, sz);

	dist->cfg = cfg;
	dist->sz = sz;

	for (i = 0; i < rxcfg->fq_count; i++) {
		rx = &dist->rx_hash[i];
		rman_rxfq_init(&rx->fq, rxcfg->fqid + i,
				rxcfg->wq,
				rxcfg->channel[i%rxcfg->chan_count]);
		rx->dist = dist;
	}

	if (rman_rxfq_start(rxcfg->fqid, rxcfg->fq_mode,
			rxcfg->port, rxcfg->port_mask,
			rxcfg->sid, rxcfg->sid_mask, rxcfg->tran)) {
		error(EXIT_SUCCESS, 0, "Fra: can not start rxfq");
		dist_finish(dist);
		return NULL;
	}
	dist->handler = NULL;
	return dist;
}

static struct distribution *dist_tx_init(struct dist_cfg *cfg)
{
	struct dist_tx_cfg *txcfg;
	struct distribution *dist;
	struct dist_tx *tx;
	struct rman_outb_md *md;
	struct rio_tran *tran;
	size_t sz;
	int i;

	txcfg = &cfg->dist_tx_cfg;

	if (!rman_get_port_status(txcfg->port)) {
		error(0, 0, "SRIO port%d is not connected",
		      txcfg->port);
		return NULL;
	}

	sz = sizeof(*dist) + 1 * sizeof(struct dist_tx);

	dist = dma_mem_memalign(L1_CACHE_BYTES, sz);
	if (!dist)
		return NULL;
	memset(dist, 0, sz);

	dist->sz = sz;
	dist->cfg = cfg;
	tx = &dist->tx[0];
	tx->dist = dist;
	tran = txcfg->tran;

	if (rman_stfq_init(&tx->stfq, 0, 0, 0)) {
		error(EXIT_SUCCESS, 0, "Fra: failed to create rman stfq");
		dma_mem_free(dist, dist->sz);
		return NULL;
	}

	tx->fq = malloc(txcfg->fq_count * sizeof(struct qman_fq));
	if (!tx->fq) {
		rman_fq_free(&tx->stfq);
		dma_mem_free(dist, dist->sz);
		return NULL;
	}
	memset(tx->fq, 0, txcfg->fq_count * sizeof(struct qman_fq));

	for (i = 0; i < txcfg->fq_count; i++)
		rman_txfq_init(&tx->fq[i], txcfg->fqid + i,
			txcfg->wq, txcfg->port);

	md = &tx->md;
	md->ftype = tran->type;
#ifdef ENABLE_FRA_DEBUG
	md->br = 0;
	md->cs = 1;
#else
	md->br = 1;
	md->cs = 0;
#endif
	md->es = 1;
	md->status_fqid = qman_fq_fqid(&tx->stfq);
	md->did = txcfg->did;
	md->count = 0;
	md->flowlvl = tran->flowlvl;
	md->tint = txcfg->port - 1;
	switch (tran->type) {
	case RIO_TYPE_MBOX:
		md->retry = 255;
		tx->session_count = tran->mbox.ltr_mask + 1;
		md->dest = tran->mbox.ltr << 6 | tran->mbox.mbox;
		break;
	case RIO_TYPE_DSTR:
		tx->session_count = tran->dstr.streamid_mask + 1;
		md->dest = tran->dstr.streamid ;
		md->other_attr = tran->dstr.cos;
		break;
	default:
		tx->session_count = 1;
	}

	dist->handler = dist_tx_handler;
	return dist;
}

static struct distribution *dist_fwd_init(struct dist_cfg *cfg)
{
	struct distribution *dist;
	struct dist_fwd *fwd;
	struct dist_fwd_cfg *fwdcfg;
	struct ppac_interface *ppac_if;
	struct list_head *i = NULL;
	const struct fman_if *fif;
	size_t sz;

	if (!cfg || cfg->type != DIST_TYPE_FWD)
		return NULL;

	sz = sizeof(*dist) + 1 * sizeof(struct dist_fwd);

	dist = dma_mem_memalign(L1_CACHE_BYTES, sz);
	if (!dist)
		return NULL;
	memset(dist, 0, sz);

	dist->sz = sz;
	dist->cfg = cfg;
	fwd = &dist->fwd[0];
	fwdcfg = &cfg->dist_fwd_cfg;
	/* Tear down interfaces */
	list_for_each(i, &ifs) {
		ppac_if = (struct ppac_interface *)i;
		fif = ppac_if->port_cfg->fman_if;
		if (fif->fman_idx == fwdcfg->fman_num &&
		    (fif->mac_type == fman_mac_1g ? 1 : 10) ==
		     fwdcfg->port_type &&
		    fif->mac_idx == fwdcfg->port_num)
			break;
	}
	if (i == &ifs) { /* not find valid ppac_if */
		dma_mem_free(dist, dist->sz);
		return NULL;
	}

	fwd->ppac_if = (struct ppac_interface *)i;
	if (cfg->number > 1) /* fwd to */
		dist->handler = dist_fwd_to_handler;
	else
		dist->handler = NULL;
	return dist;
}

static int dist_rx_tx_mapping(struct dist_order *dist_order)
{
	struct distribution *first;
	struct distribution *second;
	struct dist_rx_cfg *rxcfg;
	struct dist_tx_cfg *txcfg;
	struct ppac_interface *ppac_if;
	struct ppam_interface *_if;
	int i;

	if (!dist_order || !dist_order->dist || !dist_order->dist->next)
		return 0;

	first = dist_order->dist;
	second = first->next;

	FRA_DBG("mapping %s--%s", first->cfg->name, second->cfg->name);
	if (first->cfg->type == DIST_TYPE_RX) {
		rxcfg = &first->cfg->dist_rx_cfg;
		if (second->cfg->type == DIST_TYPE_TX) {
			txcfg = &second->cfg->dist_tx_cfg;
			for (i = 0; i < rxcfg->fq_count; i++) {
				first->rx_hash[i].opt.session =
					i % second->tx[0].session_count;
				first->rx_hash[i].opt.txfqid =
					txcfg->fqid + i % txcfg->fq_count;
				FRA_DBG("Mapping RX FQID-0x%x --> "
					"session-%d TX FQID-0x%x",
					qman_fq_fqid(&first->rx_hash[i].fq),
					first->rx_hash[i].opt.session,
					first->rx_hash[i].opt.txfqid);
			}
		} else if (second->cfg->type == DIST_TYPE_FWD) {
			_if = &second->fwd[0].ppac_if->ppam_data;
			for (i = 0; i < rxcfg->fq_count; i++) {
				first->rx_hash[i].opt.session = 0 ;
				first->rx_hash[i].opt.txfqid =
					 _if->tx_fqids[i % _if->num_tx_fqids];
				FRA_DBG("Mapping RX FQID-0x%x --> "
					"session-%d Fwd FQID-0x%x",
					qman_fq_fqid(&first->rx_hash[i].fq),
					first->rx_hash[i].opt.session,
					first->rx_hash[i].opt.txfqid);
			}
		} else
			return -EINVAL;
	} else if (first->cfg->type == DIST_TYPE_FWD) {
		ppac_if = first->fwd[0].ppac_if;
		if (second->cfg->type == DIST_TYPE_TX) {
			struct ppac_pcd_range *pcd_range;
			struct ppac_rx_hash *rx;
			txcfg = &second->cfg->dist_tx_cfg;
			list_for_each_entry(pcd_range, &ppac_if->list, list) {
				if (!pcd_range)
					break;
				for (i = 0; i < pcd_range->count ; i++) {
					rx =  &pcd_range->rx_hash[i];
					rx->s.dist = first;
					rx->s.opt.session = i %
						second->tx[0].session_count;
					rx->s.opt.txfqid = txcfg->fqid +
						i % txcfg->fq_count;
					FRA_DBG("Mapping Fwd FQID-0x%x --> "
						"session-%d TX FQID-0x%x",
						qman_fq_fqid(&rx->fq),
						rx->s.opt.session,
						rx->s.opt.txfqid);
				}
			}
		} else if (second->cfg->type == DIST_TYPE_FWD) {
			struct ppac_pcd_range *pcd_range;
			struct ppac_rx_hash *rx;
			_if = &second->fwd[0].ppac_if->ppam_data;
			list_for_each_entry(pcd_range, &ppac_if->list, list) {
				if (!pcd_range)
					break;
				for (i = 0; i < pcd_range->count ; i++) {
					rx =  &pcd_range->rx_hash[i];
					rx->s.dist = first;
					rx->s.opt.session = 0;
					rx->s.opt.txfqid = _if->tx_fqids[i %
						_if->num_tx_fqids];
					FRA_DBG("Mapping Fwd FQID-0x%x --> "
						"session-%d TX FQID-0x%x",
						qman_fq_fqid(&rx->fq),
						rx->s.opt.session,
						rx->s.opt.txfqid);
				}
			}
		} else
			return -EINVAL;
	} else
		return -EINVAL;
	return 0;
}

int fra_init(const struct fra_cfg *fra_cfg)
{
	struct dist_order_cfg  *dist_order_cfg;
	struct dist_cfg *dist_cfg;
	struct dist_order  *dist_order;
	struct distribution *dist, *next_dist;
	int err;

#ifdef ENABLE_FRA_DEBUG
	tx_count = 0;
	rx_count = 0;
	fwd_to_count = 0;
	fwd_from_count = 0;
	tx_release_count = 0;
#endif

	if (!fra_cfg) {
		error(EXIT_SUCCESS, 0, "Fra: is not been configured");
		return -EINVAL;
	}

	fra = malloc(sizeof(struct fra));
	if (!fra) {
		error(EXIT_SUCCESS, errno, "failed to allocate fra");
		return -errno;
	}
	memset(fra, 0, sizeof(*fra));
	INIT_LIST_HEAD(&fra->dist_order_list);
	fra->cfg = fra_cfg;

	if (rman_if_init(&fra_cfg->rman_cfg)) {
		error(EXIT_SUCCESS, 0, "Fra: failed to initialize rman if");
		err = -EINVAL;
		goto _err;
	}

	list_for_each_entry(dist_order_cfg,
		&fra_cfg->dist_order_cfg_list, node) {
		dist_order = malloc(sizeof(*dist_order));
		if (!dist_order) {
			error(EXIT_SUCCESS, errno,
			"failed to allocate dist_order memory");
			err = -errno;
			goto _err;
		}
		memset(dist_order, 0, sizeof(*dist_order));
		dist_cfg = dist_order_cfg->dist_cfg;
		dist = dist_order->dist;
		err = 0;
		while (dist_cfg && !err) {
			FRA_DBG("Fra: initialize distribution(%s)",
				dist_cfg->name);
			next_dist = NULL;
			switch (dist_cfg->type) {
			case DIST_TYPE_RX:
				next_dist = dist_rx_init(dist_cfg);
				break;
			case DIST_TYPE_TX:
				next_dist = dist_tx_init(dist_cfg);
				break;
			case DIST_TYPE_FWD:
				next_dist = dist_fwd_init(dist_cfg);
				break;
			default:
				break;
			}
			if (!next_dist) {
				error(EXIT_SUCCESS, 0, "dist(%s) is not been"
					" initialized", dist_cfg->name);
				err = 1;
				break;
			}
			if (!dist)
				dist_order->dist = next_dist;
			else
				dist->next = next_dist;
			dist = next_dist;
			dist_cfg = dist_cfg->next;
		}
		if (err || !dist_order->dist) {
			dist_order_finish(dist_order);
			continue;
		}

		err = dist_rx_tx_mapping(dist_order);
		if (err)
			goto _err;

		list_add_tail(&dist_order->node,
				&fra->dist_order_list);
	}
	return 0;
_err:
	fra_finish();
	return err;
}
