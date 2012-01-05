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

#include <usdpaa/compat.h>
#include <usdpaa/fsl_srio.h>
#include "rman_interface.h"
#include "fra.h"

struct rman_if {
	struct rman_dev *rmdev;
	struct rman_cfg cfg;
	struct srio_dev *sriodev;
	int port_status;
	enum qm_channel tx_channel_id[RMAN_MAX_NUM_OF_CHANNELS];
	uint32_t msg_size[RIO_TYPE_NUM];
	int sg_size;
};

static struct rman_if *rmif;

int rman_get_port_status(int port_number)
{
	if (!rmif)
		return 0;
	return rmif->port_status & (1 << (port_number - 1));
}

int fqid_to_ibcu(int fqid)
{
	return rman_get_ibcu(rmif->rmdev, fqid);
}

int rman_get_rxfq_count(enum RMAN_FQ_MODE fq_mode, const struct rio_tran *tran)
{
	int fq_count, bit_mask;

	if (!rmif || !tran)
		return 0;

	bit_mask = (1 << rmif->cfg.fq_bits[tran->type]) - 1;
	if (fq_mode == ALGORITHMIC) {
		switch (tran->type) {
		case RIO_TYPE_MBOX:
			fq_count = (tran->mbox.ltr_mask & bit_mask) + 1;
			break;
		case RIO_TYPE_DSTR:
			fq_count = (tran->dstr.streamid_mask & bit_mask) + 1;
			break;
		default:
			fq_count = 1;
			break;
		}
	} else
		fq_count = 1;

	return fq_count;
}

static inline void msg_set_fd(struct msg_buf *msg, struct qm_fd *fd)
{
	msg->flag = USING_FD;
	msg->fd = fd;
}

static inline void msg_set_bmb(struct msg_buf *msg, const struct bm_buffer *bmb)
{
	msg->flag = USING_BMB;
	msg->bmb = *bmb;
}

uint32_t msg_max_size(enum RIO_TYPE type)
{
	return rmif->msg_size[type];
}

struct msg_buf *msg_alloc(enum RIO_TYPE type)
{
	struct msg_buf *msg;
	struct bm_buffer bmb;
	uint8_t bpid;
	bpid = rmif->cfg.bpid[type];

	if (bpool_buffer_acquire(bpid, &bmb, 1, 0) <= 0) {
		FRA_DBG("RMan:failed to acquire bpool buffer");
		return NULL;
	}
	msg = dma_mem_ptov(bm_buf_addr(&bmb));
	msg_set_bmb(msg, &bmb);
	FRA_DBG("RMan: get a bman buffer bpid(%d) phy-addr(%llx),"
		"vitraddr(%p)", bmb.bpid, bm_buf_addr(&msg->bmb), msg);

	msg->data = (uint8_t *)msg + RM_DATA_OFFSET;
	msg->len = 0;
	return msg;
}

struct msg_buf *fd_to_msg(struct qm_fd *fd)
{
	struct msg_buf		*msg;
	struct qm_sg_entry	*sgt;

	switch (fd->format) {
	case qm_fd_contig:
		if (fd->offset < RM_DATA_OFFSET)
			return NULL;
		msg = dma_mem_ptov(qm_fd_addr(fd));
		msg->data = (uint8_t *)msg + fd->offset;
		msg->len = fd->length20;
		msg_set_fd(msg, fd);
		break;
	case qm_fd_sg:
		sgt = (dma_mem_ptov(qm_fd_addr(fd)) + fd->offset);
		FRA_DBG("RMan: get a sg msg bpid(%d), e(%d)  f(%d)",
			sgt->bpid, sgt->extension, sgt->final);
		if (sgt->final != 1 || sgt->offset < RM_DATA_OFFSET) {
			error(0, 0,
			      "Unsupported fd sg.final(%d)", sgt->final);
			return NULL;
		}
		msg = dma_mem_ptov(qm_sg_addr(sgt));
		msg->data = (uint8_t *)msg + sgt->offset;
		msg->len = fd->length20;
		msg_set_fd(msg, fd);
		break;
	default:
		error(0, EINVAL, "Unsupported fd format(%d)",
		      fd->format);
		return NULL;
	}
	return msg;
}

static inline int msg_to_fd(struct qm_fd *fd, const struct msg_buf *msg)
{

	if (!fd || !msg)
		return -EINVAL;

	if (msg->flag == USING_FD) {
		*fd = *msg->fd;
		return 0;
	}

	memset(fd, 0, sizeof(*fd));
	fd->format = qm_fd_contig;
	fd->length20 = msg->len;
	fd->bpid = msg->bmb.bpid;
	qm_fd_addr_set64(fd, bm_buffer_get64(&msg->bmb));
	fd->offset = (void *)msg->data - (void *)msg;
	return 0;
}

/************************* FQ handler ***************************/
static enum qman_cb_dqrr_result
rman_status_dqrr(struct qman_portal *portal,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dq)
{
	struct dist_tx *tx;

	FRA_DBG("rman_rx_dqrr receive a msg frame fqid(0x%x) type(%d) "
		"msg format(%d) bpid(%d) len(%d) offset(%d) "
		"addr(0x%llx) status(0x%x)",
		fq->fqid, FD_GET_FTYPE(&dq->fd), dq->fd.format,
		dq->fd.bpid, dq->fd.length20, dq->fd.offset,
		qm_fd_addr_get64(&dq->fd), dq->fd.status);

	tx = container_of(fq, struct dist_tx, stfq);
	dist_tx_status_handler(tx, &dq->fd);
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
rman_rx_dqrr(struct qman_portal *portal, struct qman_fq *fq,
	     const struct qm_dqrr_entry *dq)
{
	struct dist_rx *rx;

	FRA_DBG("rman_rx_dqrr receive a msg frame fqid(0x%x) type(%d) "
		"msg format(%d) bpid(%d) len(%d) offset(%d) "
		"addr(0x%llx) status(0x%x)",
		fq->fqid, FD_GET_FTYPE(&dq->fd), dq->fd.format,
		dq->fd.bpid, dq->fd.length20, dq->fd.offset,
		qm_fd_addr_get64(&dq->fd), dq->fd.status);

	rx = container_of(fq, struct dist_rx, fq);
	dist_rx_handler(rx,  &dq->fd);
	return qman_cb_dqrr_consume;
}

int rman_rxfq_init(struct qman_fq *fq, int fqid, uint8_t wq,
		   enum qm_channel channel)
{
	struct qm_mcc_initfq initfq;
	int err;

	fq->cb.dqrr = rman_rx_dqrr;
	err = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	if (err) {
		error(0, -err, "cqman_create_fq(%u)", fqid);
		return err;
	}

	initfq.fqd.dest.channel = channel;
	initfq.fqd.dest.wq = wq;
	initfq.we_mask = QM_INITFQ_WE_DESTWQ |
		QM_INITFQ_WE_FQCTRL |
		QM_INITFQ_WE_CONTEXTA;
	initfq.fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK |
		QM_FQCTRL_PREFERINCACHE |
		QM_FQCTRL_CTXASTASHING;
	initfq.fqd.context_a.stashing.data_cl = 1;
	initfq.fqd.context_a.stashing.context_cl = 0;

	err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (err < 0) {
		error(0, -err, "qman_init_fq(%u)",
		      qman_fq_fqid(fq));
		qman_destroy_fq(fq, 0);
		return err;
	}
	FRA_DBG("Create a rx fq(0x%x) channel(0x%x) wq(0x%x)",
		qman_fq_fqid(fq), channel, wq);
	return 0;
}

int rman_rxfq_start(int fqid, int fq_mode, uint8_t port, uint8_t port_mask,
		    uint16_t sid, uint16_t sid_mask, struct rio_tran *tran)
{
	struct ibcu_cfg cfg;
	int ibcu, err;

	if (!fqid)
		return -EINVAL;

	ibcu = rman_request_ibcu(rmif->rmdev, fqid);
	if (ibcu < 0) {
		error(0, -ibcu,
		      "RMan: fqid(0x%x) failed to request ibcu resource",
		      fqid);
		return -EINVAL;
	}
	FRA_DBG("Bind FQID 0x%x to IBCU %d", fqid, ibcu);

	memset(&cfg, 0, sizeof(cfg));
	cfg.tran = tran;
	cfg.ibcu = ibcu;
	cfg.port = port;
	cfg.port_mask = port_mask;
	cfg.sid = sid;
	cfg.sid_mask = sid_mask;
	cfg.did = 0;
	cfg.did_mask = 0xffff;
	cfg.fqid = fqid;
	cfg.fq_mode = fq_mode;
	cfg.bpid = rmif->cfg.bpid[cfg.tran->type];
	cfg.sgbpid = rmif->cfg.sgbpid;
	cfg.msgsize = rmif->msg_size[cfg.tran->type];
	cfg.sgsize = rmif->sg_size;
	cfg.data_offset = RM_DATA_OFFSET;
	err = rman_enable_ibcu(rmif->rmdev, &cfg);
	return err;
}

int rman_rxfq_finish(int fqid)
{
	int ibcu;
	ibcu =	rman_get_ibcu(rmif->rmdev, fqid);
	if (ibcu < 0)
		return ibcu;
	rman_release_ibcu(rmif->rmdev, ibcu);
	return 0;
}

int rman_stfq_init(struct qman_fq *fq, int fqid, uint8_t wq,
		   enum qm_channel channel)
{
	struct qm_mcc_initfq initfq;
	uint32_t flags;
	int err;

	if (!rmif)
		return -EINVAL;

	fq->cb.dqrr = rman_status_dqrr;

	flags = QMAN_FQ_FLAG_NO_ENQUEUE;
	if (!fqid)
		flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;

	err = qman_create_fq(fqid, flags, fq);
	if (err) {
		error(0, -err, "qman_create_fq(0x%x)", fqid);
		return err;
	}

	if (!channel)
		initfq.fqd.dest.channel = rmif->cfg.rx_channel_id;
	else
		initfq.fqd.dest.channel = channel;

	initfq.fqd.dest.wq = wq;
	initfq.we_mask = QM_INITFQ_WE_DESTWQ |
		QM_INITFQ_WE_FQCTRL |
		QM_INITFQ_WE_CONTEXTA;
	initfq.fqd.fq_ctrl = QM_FQCTRL_AVOIDBLOCK |
		QM_FQCTRL_PREFERINCACHE |
		QM_FQCTRL_CTXASTASHING;
	initfq.fqd.context_a.stashing.data_cl = 1;
	initfq.fqd.context_a.stashing.context_cl = 0;

	err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (err < 0) {
		error(0, -err, "qman_init_fq(0x%x)",
		      qman_fq_fqid(fq));
		qman_destroy_fq(fq, 0);
		return err;
	}

	FRA_DBG("Create a stfq(0x%x) channel(0x%x) wq(0x%x)",
		qman_fq_fqid(fq), initfq.fqd.dest.channel, wq);
	return 0;
}

int rman_txfq_init(struct qman_fq *fq, int fqid, uint8_t wq, uint8_t rmchan)
{
	struct qm_mcc_initfq initfq;
	uint32_t flags;
	int err;

	flags = QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_LOCKED;
	if (!fqid)
		flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;

	err = qman_create_fq(fqid, flags, fq);
	if (err) {
		error(0, -err, "qman_create_fq(0x%x)", fqid);
		return err;
	}

	initfq.fqd.dest.channel = rmif->tx_channel_id[rmchan-1];
	initfq.fqd.dest.wq = wq;
	initfq.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	initfq.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	initfq.fqd.context_b = 0;
	qm_fqd_context_a_set64(&initfq.fqd, 0);

	err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (err) {
		error(0, -err, "qman_init_fq(0x%x)",
		      qman_fq_fqid(fq));
		qman_destroy_fq(fq, 0);
		return err;
	}
	FRA_DBG("Create a txfq(0x%x) channel(0x%x) wq(0x%x)",
		fqid, rmif->tx_channel_id[rmchan-1], wq);
	return 0;
}

void rman_fq_free(struct qman_fq *fq)
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
			if (s) {
				error(0, -s, "Fail: %s: %d",
				      "qman_volatile_dequeue()", s);
				return;
			}
			/* Poll for completion */
			do {
				qman_poll();
				qman_fq_state(fq, &state, &flags);
			} while (flags & QMAN_FQ_STATE_VDQCR);
		}
	}
	s = qman_oos_fq(fq);
	if (s)
		error(0, -s, "Fail: %s: %d", "qman_oos_fq()", s);
	else
		qman_destroy_fq(fq, 0);
}

static inline void rman_send_frame(uint32_t fqid, const struct qm_fd *fd)
{
	local_fq.fqid = fqid;

	while (qman_enqueue(&local_fq, fd, 0))
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
}

int rman_send_fd(struct rman_outb_md *std_md, struct tx_opt *opt,
		 struct qm_fd *fd)
{
	struct rman_outb_md *md;

	if (fd->format == qm_fd_contig) {
		if (fd->offset < RM_DATA_OFFSET)
			return -EINVAL;
		md = dma_mem_ptov(qm_fd_addr(fd));
	} else if (fd->format == qm_fd_sg) {
		const struct qm_sg_entry *sgt;
		sgt = dma_mem_ptov(qm_fd_addr(fd)) + fd->offset;
		if (sgt->offset < RM_DATA_OFFSET)
			return -EINVAL;
		md = dma_mem_ptov(qm_sg_addr(sgt));
	} else
		return -EINVAL;

	memcpy(md, std_md, sizeof(*std_md));
	md->count = fd->length20;
	FD_SET_TYPE(fd, std_md->ftype);

#ifdef SUPPORT_MULTIE_SESSION
	switch (std_md->ftype) {
	case RIO_TYPE_MBOX:
		md->dest += opt->session << 6;
		break;
	case RIO_TYPE_DSTR:
		md->dest += opt->session;
		break;
	default:
		break;
	}
#endif

#ifdef ENABLE_FRA_DEBUG
	switch (std_md->ftype) {
	case RIO_TYPE_MBOX:
		FRA_DBG("send to device(%d) a msg using mailbox"
			" mbox(%d) ltr(%d) fq(0x%x)",
			md->did, md->dest & 3, (md->dest >> 6) & 3,
			opt->txfqid);
		break;
	case RIO_TYPE_DSTR:
		FRA_DBG("send to device(%d) a msg using data-streaming"
			" cos(0x%x) streamid(0x%x) fq(0x%x)",
			md->did, md->other_attr, md->dest, opt->txfqid);
		break;
	default:
		FRA_DBG("send to device(%d) a msg using %s"
			" dest(0x%x) oter_attr(0x%x) fq(0x%x)",
			md->did, rio_type_to_str[std_md->ftype],
			md->dest, md->other_attr, opt->txfqid);
		break;
	}
#endif
	rman_send_frame(opt->txfqid, fd);
	return 0;
}

int rman_send_msg(struct rman_outb_md *std_md, struct tx_opt *opt,
		  struct msg_buf *msg)
{
	struct qm_fd fd;

	if (msg_to_fd(&fd, msg))
		return -EINVAL;

	memcpy(&msg->omd, std_md, sizeof(*std_md));
	msg->omd.count = msg->len;
	FD_SET_TYPE(&fd, std_md->ftype);

#ifdef SUPPORT_MULTIE_SESSION
	switch (std_md->ftype) {
	case RIO_TYPE_MBOX:
		msg->omd.dest += opt->session << 6;
		break;
	case RIO_TYPE_DSTR:
		msg->omd.dest += opt->session;
		break;
	default:
		break;
	}
#endif

#ifdef ENABLE_FRA_DEBUG
	switch (std_md->ftype) {
	case RIO_TYPE_MBOX:
		FRA_DBG("send to device(%d) a msg using mailbox"
			" mbox(%d) ltr(%d) fq(0x%x)",
			msg->omd.did, msg->omd.dest & 3,
			(msg->omd.dest >> 6) & 3, opt->txfqid);
		break;
	case RIO_TYPE_DSTR:
		FRA_DBG("send to device(%d) a msg using data-streaming"
			" cos(0x%x) streamid(0x%x) fq(0x%x)",
			msg->omd.did, msg->omd.other_attr,
			msg->omd.dest, opt->txfqid);
		break;
	default:
		FRA_DBG("send to device(%d) a msg using %s"
			" dest(0x%x) oter_attr(0x%x) fq(0x%x)",
			msg->omd.did, rio_type_to_str[msg->omd.ftype],
			msg->omd.dest, msg->omd.other_attr, opt->txfqid);
		break;
	}
#endif

	rman_send_frame(opt->txfqid, &fd);
	return 0;
}

int rman_if_init(const struct rman_cfg *cfg)
{
	int err, port_num, i;

	if (!cfg)
		return -EINVAL;

	rmif = malloc(sizeof(*rmif));
	if (!rmif) {
		error(0, errno, "malloc()");
		return -errno;
	}
	memset(rmif, 0, sizeof(*rmif));

	rmif->cfg = *cfg;

	err = fsl_srio_uio_init(&rmif->sriodev);
	if (err < 0) {
		error(0, -err, "srio_uio_init()");
		return err;
	}

	port_num = fsl_srio_get_port_num(rmif->sriodev);
	for (i = 0; i < port_num; i++)
		fsl_srio_connection(rmif->sriodev, i);

	rmif->port_status = fsl_srio_port_connected(rmif->sriodev);
	if (rmif->port_status < 0)
		err = rmif->port_status;
	else if (!rmif->port_status)
		err = -ENODEV;
	if (err < 0) {
		error(0, -err, "%s(): fsl_srio_port_connected()", __func__);
		goto _err;
	}

	rmif->rmdev = rman_dev_init(cfg);
	if (!rmif->rmdev) {
		error(0, ENODEV, "rman_dev_init()");
		err = -EINVAL;
		goto _err;
	}

	for (i = RIO_TYPE0; i < RIO_TYPE_NUM; i++)
		rmif->msg_size[i] = bpool_get_size(rmif->cfg.bpid[i]);
	rmif->sg_size = bpool_get_size(rmif->cfg.sgbpid);

	for (i = 0; i < RMAN_MAX_NUM_OF_CHANNELS; i++)
		rmif->tx_channel_id[i] = rman_get_channel_id(rmif->rmdev, i);

	return 0;
_err:
	rman_if_finish();
	return err;
}

void rman_if_finish(void)
{
	if (!rmif)
		return;

	if (rmif->sriodev)
		fsl_srio_uio_finish(rmif->sriodev);

	if (rmif->rmdev)
		rman_dev_finish(rmif->rmdev);

	free(rmif);
	rmif = NULL;
}
