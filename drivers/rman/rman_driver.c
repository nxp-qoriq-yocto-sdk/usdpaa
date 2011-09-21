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
#include <usdpaa/fsl_rman.h>
#include <internal/compat.h>
#include <error.h>

#define RMAN_CU_NUM_PER_IB		8
#define RMAN_IB_OFFSET			0x1000
#define RMAN_CU_OFFSET			0x100
#define RMAN_IPBRR0			0xBF8
#define RMAN_IPBRR1			0xBFC

#define RMAN_REG_WIN_SIZE		0x20000
#define RMAN_GOLABEL_REG_OFFSET		0xF00

#define MMIER_ENABLE_ALL		0x800000FF
#define MMEDR_CLEAR			0x800000FF

#define IBCU_IDLE_FQID			0

/* Inbound Block TypeX Classification Registers */
struct rman_ibcu_regs {
	uint32_t  mr;		/* 0xmn00 - Mode Register */
	uint32_t res1;
	uint32_t fqr;		/* 0xmn08 - Frame Queue Register */
	uint32_t res2;
	uint32_t rvr[2];	/* 0xmn10 - Rule Value Register 0/1 */
	uint32_t rmr[2];	/* 0xmn18 - Rule Mask Register 0/1 */
	uint32_t t9fcdr;	/* 0xmn20 -
				   Type9 Flow Control Destination Register */
	uint32_t res3[3];
	uint32_t dbpr;		/* 0xmn30 - Data Buffer Pool Register */
	uint32_t dor;		/* 0xmn34 - Data Offset Register */
	uint32_t t9sgbpr;	/* 0xmn38 -
				   Type9 Scatter/Gather Buffer Poll Register */
};

struct rman_global_reg {
	uint32_t mmmr;		/* 0x1E_0F00 - Message manager Mode Register */
	uint32_t mmsr;		/* 0x1E_0F04 -
				   Message manager Status Register */
	uint32_t res1[2];
	uint32_t mmt8fqar;	/* 0x1E_0F10 - Message manager
				   T8 Frame Queue Assembly Register */
	uint32_t mmt9fqar;	/* 0x1E_0F14 - Message manager
				   T9 Frame Queue Assembly Register */
	uint32_t mmt10fqar;	/* 0x1E_0F18 - Message manager
				   T10 Frame Queue Assembly Register */
	uint32_t mmt11fqar;	/* 0x1E_0F1c - Message manager
				   T11 Frame Queue Assembly Register */
	uint32_t mmier;		/* 0x1E_0F20 - Message Unmanager
				   Interrupt Enable Register */
	uint32_t mmedr;		/* 0x1E_0F24 - Message manager
				   Error Detect Register */
	uint32_t mmicr;		/* 0x1E_0F28 - Message manager
				   Interrupt Coalescing Registers */
	uint32_t mmt8dcr;	/* 0x1E_0F2C - Message manager
				   T8 Drop Counter Register */
	uint32_t mmt9dcr;	/* 0x1E_0F30 - Message manager
				   T9 Drop Counter Register */
	uint32_t mmecqfqr;	/* 0x1E_0F34 - Message manager
				   Error Capture Frame Queue Register */
	uint32_t mmecfdr[4];	/* 0x1E_0F38 - Message manager
				   Error Capture FD Register 0/1/2/3 */
	uint32_t mmecar[2];	/* 0x1E_0F48 - Message manager
				   Error Capture Address Register 0/1 */
	uint32_t mmawr;		/* 0x1E_0F50 - Message manager
				   Arbitration Weight Register */
	uint32_t mmiomr;	/* 0x1E_0F54 - Message manager
				   Outbound Interleaving Mask Register */
	uint32_t res2[3];
	uint32_t mmliodnbr;	/* 0x1E_0F64 - Message manager
				   logical I/O device number base Register */
	uint32_t mmitar;	/* 0x1E_0F68- Message manager
				   Inbound Translation Address Register*/
	uint32_t mmitdr;	/* 0x1E_0F6c- Message manager
				   Inbound Translation Data Register*/
	uint32_t mmsepr0;	/* 0x1E_0F70- Message Unit Segmentation
				   Execution Privilege Register 0 */
	uint32_t res3[3];
	uint32_t mmrcar[3];	/* 0x1E_0F80- Message manager
				   Reassembly Context Assignment Register 0/1/2 */
	uint32_t res4[21];
	uint32_t mmsmr;		/* 0x1E_0FE0- Message manager
				   support mode register */
};

struct rman_dev {
	int irq;
	uint32_t ib_num;
	uint32_t ibcu_num;
	volatile void *regs_win;
	volatile struct rman_global_reg *global_regs;
	struct ibcu {
		volatile struct rman_ibcu_regs *regs_win;
		int fqid;
	} ibcu[0];
};

static inline void write_reg(volatile uint32_t *p, int v)
{
	*(volatile uint32_t *)(p) = v;
	__sync_synchronize();
}

static inline uint32_t read_reg(const volatile uint32_t *p)
{
	uint32_t ret;
	ret = *(volatile uint32_t *)(p);
	__sync_synchronize();
	return ret;
}

static int uiofd = -1;

/************************* ibcu handler ***************************/
void rman_release_ibcu(struct rman_dev *rmdev, int idx)
{
	/* disable ibcu */
	write_reg(&rmdev->ibcu[idx].regs_win->mr, 0);
	rmdev->ibcu[idx].fqid = IBCU_IDLE_FQID;
}

int rman_request_ibcu(struct rman_dev *rmdev, int fqid)
{
	int i;

	if (!fqid)
		return -EINVAL;

	for (i = 0; i < rmdev->ibcu_num; i++) {
		if (rmdev->ibcu[i].fqid == fqid)
			return i;
	}

	for (i = 0; i < rmdev->ibcu_num; i++) {
		if (rmdev->ibcu[i].fqid == IBCU_IDLE_FQID) {
			rmdev->ibcu[i].fqid = fqid;
			return i;
		}
	}
	return -EINVAL;
}

int rman_get_ibcu(const struct rman_dev *rmdev, int fqid)
{
	int i;

	if (!fqid)
		return -EINVAL;

	for (i = 0; i < rmdev->ibcu_num; i++) {
		if (rmdev->ibcu[i].fqid == fqid)
			return i;
	}

	return -EINVAL;
}

int rman_enable_ibcu(struct rman_dev *rmdev, const struct ibcu_cfg *cfg)
{
	if (rmdev->ibcu[cfg->ibcu].fqid != cfg->fqid) {
		error(0, EINVAL, "RMan: please firstly request a ibcu");
		return -EINVAL;
	}

	write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->fqr, cfg->fqid);
	write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rvr[0],
		  cfg->sid << 16 | cfg->did);
	write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rmr[0],
		  cfg->sid_mask << 16 | cfg->did_mask);
	switch (cfg->tran->type) {
	case RIO_TYPE_DBELL:
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rmr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port_mask << 24);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->dor,
			  cfg->data_offset);
		break;
	case RIO_TYPE_MBOX:
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24 |
			  cfg->tran->mbox.msglen << 8 |
			  cfg->tran->mbox.ltr << 6 |
			  cfg->tran->mbox.mbox);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24 |
			  cfg->tran->mbox.msglen_mask << 8 |
			  cfg->tran->mbox.ltr_mask << 6 |
			  cfg->tran->mbox.mbox_mask);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->dor,
			  cfg->data_offset);
		break;
	case RIO_TYPE_DSTR:
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24 |
			  cfg->tran->dstr.cos << 16 |
			  cfg->tran->dstr.streamid);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24 |
			  cfg->tran->dstr.cos_mask << 16 |
			  cfg->tran->dstr.streamid_mask);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->t9sgbpr,
			  (cfg->sgsize << 16) | cfg->sgbpid);
		write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->dor,
			  cfg->data_offset);
		break;
	default:
		return -EINVAL;
	}
	write_reg(&rmdev->ibcu[cfg->ibcu].regs_win->mr,
		  0x80000000 | cfg->fq_mode << 28 | (cfg->tran->type << 24));
	return 0;
}

static struct rman_dev *rman_uio_init(const char *filename)
{

	uint32_t revision, conf_version, rman_size;
	void *win;
	uint8_t ib_num, ibcu_num;
	struct rman_dev *rmdev;

	if (uiofd >= 0)	 {
		error(0, EBUSY, "%s()", __func__);
		return NULL;
	}

	uiofd = open(filename, O_RDWR);
	if (uiofd < 0) {
		error(0, errno, "%s()", __func__);
		return NULL;
	}

	win = mmap(NULL, RMAN_REG_WIN_SIZE,
			PROT_READ | PROT_WRITE, MAP_SHARED, uiofd, 0);
	if (MAP_FAILED == win) {
		error(0, errno, "%s()", __func__);
		close(uiofd);
		uiofd = -1;
		return NULL;
	}

	revision = read_reg(win + RMAN_IPBRR0);
	conf_version = read_reg(win + RMAN_IPBRR1);
	ib_num = ((conf_version >> 6) & 0x3) * 4 + 4;
	ibcu_num = ib_num * RMAN_CU_NUM_PER_IB;
	fprintf(stderr, "RMan: major revision is %d, "
		"minor revision is %d, has %d blocks\n",
		(revision >> 8) & 0xff, revision & 0xff, ib_num);

	rman_size = sizeof(*rmdev) + ibcu_num * sizeof(struct ibcu);
	rmdev = malloc(rman_size);
	if (!rmdev) {
		error(0, errno, "%s()", __func__);
		return NULL;
	}
	memset(rmdev, 0, rman_size);

	rmdev->regs_win = win;
	rmdev->ibcu_num = ibcu_num;
	rmdev->ib_num = ib_num;

	return rmdev;
}

static int rman_dev_setup(struct rman_dev *rmdev, const struct rman_cfg *cfg)
{
	uint8_t ib_num, cu_num, idx = 0;

	if (!rmdev)
		return -EINVAL;

	rmdev->global_regs = (typeof(rmdev->global_regs))
		(rmdev->regs_win + RMAN_GOLABEL_REG_OFFSET);
	for (ib_num = 0; ib_num < rmdev->ib_num; ib_num++)
		for (cu_num = 0; cu_num < RMAN_CU_NUM_PER_IB; cu_num++)
			rmdev->ibcu[idx++].regs_win = rmdev->regs_win +
				ib_num * RMAN_IB_OFFSET +
				cu_num * RMAN_CU_OFFSET;

	/* reset */
	write_reg(&rmdev->global_regs->mmmr, 1);
	/* set inbound message descriptor write status */
	write_reg(&rmdev->global_regs->mmmr, cfg->md_create << 31);
	/* Enable Error Interrupt */
	write_reg(&rmdev->global_regs->mmedr, MMEDR_CLEAR);
	write_reg(&rmdev->global_regs->mmier, MMIER_ENABLE_ALL);
	/* to do  initialize LIODN */
	/* initialize the frame queue assembly register */
	/* data streaming supports max 32 receive frame queue */
	write_reg(&rmdev->global_regs->mmt9fqar,
		  cfg->fq_bits[RIO_TYPE9] << 7);
	/* doorbell supports max 1 receive frame queue */
	write_reg(&rmdev->global_regs->mmt10fqar, 0);
	/* mailbox supports max 4 receive frame queue */
	write_reg(&rmdev->global_regs->mmt11fqar,
		  cfg->fq_bits[RIO_TYPE11] << 8);

	return 0;
}

struct rman_dev *rman_dev_init(const char *filename, const struct rman_cfg *cfg)
{
	int err;
	struct rman_dev *rmdev;

	rmdev = rman_uio_init(filename);
	if (!rmdev) {
		error(0, EINVAL, "RMan: failed to initialize");
		return NULL;
	}

	err = rman_dev_setup(rmdev, cfg);
	if (err < 0) {
		error(0, -err, "RMan: failed to setup");
		rman_dev_finish(rmdev);
		return NULL;
	}

	return rmdev;
}

void rman_dev_finish(struct rman_dev *rmdev)
{
	if (!rmdev)
		return;

	if (rmdev->regs_win)
		munmap((void *)rmdev->regs_win, RMAN_REG_WIN_SIZE);
	if (uiofd > 0)
		close(uiofd);

	free(rmdev);
}
