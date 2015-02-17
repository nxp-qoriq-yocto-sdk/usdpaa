/* Copyright 2012 Freescale Semiconductor, Inc.
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

#include <internal/of.h>
#include <usdpaa/fsl_rman_ib.h>
#include <error.h>

#define RMAN_IB_FILE		"/dev/rman-inbound-block"
#define RMAN_CU_NUM_PER_IB	8
#define RMAN_CU_OFFSET		0x100
#define RMAN_IB_INDEX_OFFSET	12
#define RMAN_IBCU_ENABLE_MASK	0x80000000

enum IBCU_STATUS {
	IBCU_STATUS_IDLE,
	IBCU_STATUS_READY,
	IBCU_STATUS_RUNNING
};

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
	uint32_t res4;
	uint32_t efqr;		/* 0xm040 - error frame queue register */
};

/**
 * A RMan classification unit contains a set of run-time registers to filter
 * and reassembles transaction then put onto a specified queue for processing
 * by software.
 */
struct rman_classification_unit {
	volatile struct rman_ibcu_regs *cu_regs;
	int status;
};

/**
 * A RMan device contains multiple inbound blocks.
 * Each block contains eight classification units.
 */
struct rman_inbound_block {
	int index;
	int uiofd;
	uint32_t efq;
	volatile void *ib_regs;
	uint64_t regs_size;
	struct rman_classification_unit cu[RMAN_CU_NUM_PER_IB];
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

int rman_ib_idx(struct rman_inbound_block *ib)
{
	return ib->index;
}

void rman_enable_ibcu(struct rman_inbound_block *ib, int idx)
{
	int mr;

	if (!ib || idx >= RMAN_CU_NUM_PER_IB)
		return;

	mr = read_reg(&ib->cu[idx].cu_regs->mr);
	mr |= RMAN_IBCU_ENABLE_MASK;
	write_reg(&ib->cu[idx].cu_regs->mr, mr);
	ib->cu[idx].status = IBCU_STATUS_RUNNING;
}

void rman_disable_ibcu(struct rman_inbound_block *ib, int idx)
{
	int mr;

	if (!ib || idx >= RMAN_CU_NUM_PER_IB)
		return;

	mr = read_reg(&ib->cu[idx].cu_regs->mr);
	mr &= ~RMAN_IBCU_ENABLE_MASK;
	write_reg(&ib->cu[idx].cu_regs->mr, mr);
	ib->cu[idx].status = IBCU_STATUS_READY;
}

void rman_release_ibcu(struct rman_inbound_block *ib, int idx)
{

	if (!ib || idx >= RMAN_CU_NUM_PER_IB)
		return;

	rman_disable_ibcu(ib, idx);
	ib->cu[idx].status = IBCU_STATUS_IDLE;
}

int rman_request_ibcu(struct rman_inbound_block *ib)
{
	int idx;

	for (idx = 0; idx < RMAN_CU_NUM_PER_IB; idx++) {
		if (ib->cu[idx].status == IBCU_STATUS_IDLE) {
			ib->cu[idx].status = IBCU_STATUS_READY;
			return idx;
		}
	}

	return -EINVAL;
}

int rman_config_ibcu(struct rman_inbound_block *ib,
			  const struct ibcu_cfg *cfg)
{
	int cu_index = cfg->ibcu;

	if (ib->cu[cu_index].status != IBCU_STATUS_READY) {
		error(0, EINVAL, "RMan: please firstly request an ibcu");
		return -EINVAL;
	}

	write_reg(&ib->cu[cu_index].cu_regs->fqr, cfg->fqid);
	write_reg(&ib->cu[cu_index].cu_regs->rvr[0],
		  cfg->sid << 16 | cfg->did);
	write_reg(&ib->cu[cu_index].cu_regs->rmr[0],
		  cfg->sid_mask << 16 | cfg->did_mask);
	switch (cfg->tran->type) {
	case RIO_TYPE_DBELL:
	case RIO_TYPE_PW:
		write_reg(&ib->cu[cu_index].cu_regs->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24);
		write_reg(&ib->cu[cu_index].cu_regs->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24);
		write_reg(&ib->cu[cu_index].cu_regs->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&ib->cu[cu_index].cu_regs->dor,
			  cfg->data_offset);
		break;
	case RIO_TYPE_MBOX:
		write_reg(&ib->cu[cu_index].cu_regs->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24 |
			  cfg->tran->mbox.msglen << 8 |
			  cfg->tran->mbox.ltr << 6 |
			  cfg->tran->mbox.mbox);
		write_reg(&ib->cu[cu_index].cu_regs->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24 |
			  cfg->tran->mbox.msglen_mask << 8 |
			  cfg->tran->mbox.ltr_mask << 6 |
			  cfg->tran->mbox.mbox_mask);
		write_reg(&ib->cu[cu_index].cu_regs->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&ib->cu[cu_index].cu_regs->dor,
			  cfg->data_offset);
		break;
	case RIO_TYPE_DSTR:
		write_reg(&ib->cu[cu_index].cu_regs->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24 |
			  cfg->tran->dstr.cos << 16 |
			  cfg->tran->dstr.streamid);
		write_reg(&ib->cu[cu_index].cu_regs->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24 |
			  cfg->tran->dstr.cos_mask << 16 |
			  cfg->tran->dstr.streamid_mask);
		write_reg(&ib->cu[cu_index].cu_regs->t9fcdr,
			  cfg->fcdr << 16 |
			  cfg->fcdr);
		write_reg(&ib->cu[cu_index].cu_regs->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&ib->cu[cu_index].cu_regs->t9sgbpr,
			  (cfg->sgsize << 16) | cfg->sgbpid);
		write_reg(&ib->cu[cu_index].cu_regs->dor,
			  cfg->data_offset);
		break;
	default:
		return -EINVAL;
	}
	write_reg(&ib->cu[cu_index].cu_regs->mr,
		  cfg->fq_mode << 28 |
		  cfg->tran->type << 24 |
		  cfg->ext << 23 |
		  cfg->cgn);

	return 0;
}

void rman_set_ibef(struct rman_inbound_block *ib, uint32_t fqid)
{
	ib->efq = fqid;
	write_reg(&ib->cu[0].cu_regs->efqr, fqid);
}

int rman_get_ibef(struct rman_inbound_block *ib)
{
	return ib->efq;
}

struct rman_inbound_block *rman_ib_init(int idx)
{
	const struct device_node *rman_node, *ib_node;
	struct rman_inbound_block *ib;
	const uint32_t *regs_addr;
	uint64_t regs_size;
	uint64_t phys_addr;
	int ib_index, cu_index, found;
	char uio_file[PATH_MAX];

	rman_node = of_find_compatible_node(NULL, NULL, "fsl,rman");
	if (of_device_is_available(rman_node) == false)
		return NULL;

	found = 0;
	for_each_child_node(rman_node, ib_node) {
		if (of_device_is_compatible(ib_node,
					    "fsl,rman-inbound-block")) {
			regs_addr = of_get_address(ib_node, 0,
						   &regs_size, NULL);
			if (!regs_addr) {
				error(0, 0, "%s missed reg property",
				      ib_node->full_name);
				return NULL;
			}

			phys_addr = of_translate_address(ib_node, regs_addr);
			if (!phys_addr) {
				error(0, 0, "%s of_translate_address failed",
				      ib_node->full_name);
				return NULL;
			}

			ib_index = (phys_addr >> RMAN_IB_INDEX_OFFSET) & 0xf;
			if (ib_index == idx) {
				found = 1;
				break;
			}
		}
	}

	if (!found)
		return NULL;

	ib = malloc(sizeof(*ib));
	if (!ib) {
		error(0, errno, "%s", __func__);
		return NULL;
	}
	memset(ib, 0, sizeof(*ib));

	ib->index = idx;
	ib->regs_size = regs_size;

	sprintf(uio_file, RMAN_IB_FILE"%d", ib->index);
	ib->uiofd = open(uio_file, O_RDWR);
	if (ib->uiofd < 0)
		goto _err;

	ib->ib_regs = mmap(NULL, (size_t)ib->regs_size,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED, ib->uiofd, 0);
	if (MAP_FAILED == ib->ib_regs)
		goto _err;

	for (cu_index = 0; cu_index < RMAN_CU_NUM_PER_IB; cu_index++) {
		ib->cu[cu_index].cu_regs = ib->ib_regs +
					   cu_index * RMAN_CU_OFFSET;
		ib->cu[cu_index].status = IBCU_STATUS_IDLE;
	}

	fprintf(stderr, "RMan inbound block%d is initialized\n", ib->index);

	return ib;
_err:
	rman_ib_finish(ib);
	return NULL;
}

void rman_ib_finish(struct rman_inbound_block *ib)
{
	if (!ib)
		return;

	if (ib->ib_regs)
		munmap((void *)ib->ib_regs, (size_t)ib->regs_size);

	if (ib->uiofd > 0)
		close(ib->uiofd);
	free(ib);
}
