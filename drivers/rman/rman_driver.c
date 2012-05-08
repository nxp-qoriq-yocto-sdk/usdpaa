/* Copyright (c) 2011-2012 Freescale Semiconductor, Inc.
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

#include <internal/of.h>
#include <usdpaa/fsl_rman.h>
#include <error.h>

#define RMAN_UIO_FILE		"/dev/rman-uio"
#define RMAN_IB_FILE		"/dev/rman-inbound-block"
#define RMAN_IB_INDEX_OFFSET	12
#define RMAN_CU_NUM_PER_IB	8
#define RMAN_CU_OFFSET		0x100
#define MMIER_ENABLE_ALL	0x800000FF
#define MMEDR_CLEAR		0x800000FF
#define IBCU_IDLE_FQID		0
#define RMAN_RESET_VALUE	1
#define RMAN_IBCU_ENABLE_MASK	0x80000000
#define RMAN_MMSR_IMUB_SHIFT	31
#define RMAN_MMSR_OMUB_SHIFT	30
#define RMAN_MMMR_MDD_SHIFT	31
#define RMAN_FQAR_STID_SHIFT	7
#define RMAN_FQAR_LTR_SHIFT	8

/* The magic is a workaround for mailbox transaction.
 * The MMSEPR0 setting assigns AG0 to only execute on SU0
 * AG1 on SU1, AG2 on SU2, AG3 on SU3.
 */
#define MMSEPR0_MAILBOX 0x010234F8
#define MMSEPR0_DEFAULT 0x030F3FFF

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
	uint32_t res0[766];	/* 0x1E_0000 - Add for 4K aligned */
	uint32_t ipbrr[2];	/* 0x1E_0BFB - IP block revision register 0/1 */
	uint32_t res1[192];
	uint32_t mmmr;		/* 0x1E_0F00 - Message manager Mode Register */
	uint32_t mmsr;		/* 0x1E_0F04 -
				   Message manager Status Register */
	uint32_t res2[2];
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
	uint32_t res3[3];
	uint32_t mmliodnbr;	/* 0x1E_0F64 - Message manager
				   logical I/O device number base Register */
	uint32_t mmitar;	/* 0x1E_0F68- Message manager
				   Inbound Translation Address Register*/
	uint32_t mmitdr;	/* 0x1E_0F6c- Message manager
				   Inbound Translation Data Register*/
	uint32_t mmsepr0;	/* 0x1E_0F70- Message Unit Segmentation
				   Execution Privilege Register 0 */
	uint32_t res4[3];
	uint32_t mmrcar[3];	/* 0x1E_0F80- Message manager
				   Reassembly Context Assignment Register 0/1/2 */
	uint32_t res5[21];
	uint32_t mmsmr;		/* 0x1E_0FE0- Message manager
				   support mode register */
};

/**
 * A RMan classification unit contains a set of run-time registers to filter
 * and reassembles transaction then put onto a specified queue for processing
 * by software.
 */
struct rman_classification_unit {
	volatile struct rman_ibcu_regs *cu_regs;
	int fqid;
};

/**
 * A RMan device contains multiple inbound blocks.
 * Each block contains eight classification units.
 */
struct rman_inbound_block {
	int index;
	int uiofd;
	volatile void *ib_regs;
	uint64_t regs_size;
	struct rman_classification_unit cu[RMAN_CU_NUM_PER_IB];
};

struct rman_dev {
	int uiofd;
	int irq;
	int ib_num;
	int channel_id[RMAN_MAX_NUM_OF_CHANNELS];
	volatile struct rman_global_reg *global_regs;
	uint64_t regs_size;
	struct rman_inbound_block *ib;
	int fix_mbox_flag;
};

static struct rman_dev *__rmdev;

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

int rman_global_fd(void)
{
	return __rmdev->uiofd;
}

void rman_interrupt_enable(void)
{
	write_reg(&__rmdev->global_regs->mmier, MMIER_ENABLE_ALL);
}

int rman_interrupt_status(void)
{
	return read_reg(&__rmdev->global_regs->mmedr);
}

void rman_interrupt_clear(void)
{
	write_reg(&__rmdev->global_regs->mmedr, MMEDR_CLEAR);
}

int rman_rx_busy(void)
{
	int status;

	status = read_reg(&__rmdev->global_regs->mmsr);
	return (status >> RMAN_MMSR_IMUB_SHIFT) & 0x01;
}

int rman_tx_busy(void)
{
	int status;

	status = read_reg(&__rmdev->global_regs->mmsr);
	return (status >> RMAN_MMSR_OMUB_SHIFT) & 0x01;
}

void rman_reset(void)
{
	write_reg(&__rmdev->global_regs->mmmr, RMAN_RESET_VALUE);
}

int rman_get_channel_id(const struct rman_dev *rmdev, int idx)
{
	if (!rmdev || idx > RMAN_MAX_NUM_OF_CHANNELS)
		return -EINVAL;

	return rmdev->channel_id[idx];
}

/************************* ibcu handler ***************************/
void rman_enable_ibcu(struct rman_dev *rmdev, int idx)
{
	int ib_index, cu_index, mr;

	if (idx >= rmdev->ib_num)
		return;

	ib_index = idx / RMAN_CU_NUM_PER_IB;
	cu_index = idx % RMAN_CU_NUM_PER_IB;

	mr = read_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->mr);
	mr |= RMAN_IBCU_ENABLE_MASK;
	write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->mr, mr);
}

void rman_disable_ibcu(struct rman_dev *rmdev, int idx)
{
	int ib_index, cu_index, mr;

	ib_index = idx / RMAN_CU_NUM_PER_IB;
	cu_index = idx % RMAN_CU_NUM_PER_IB;

	if (idx >= rmdev->ib_num)
		return;

	mr = read_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->mr);
	mr &= ~RMAN_IBCU_ENABLE_MASK;
	write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->mr, mr);
}

void rman_release_ibcu(struct rman_dev *rmdev, int idx)
{
	int ib_index, cu_index;

	if (idx >= rmdev->ib_num)
		return;

	ib_index = idx / RMAN_CU_NUM_PER_IB;
	cu_index = idx % RMAN_CU_NUM_PER_IB;
	rman_disable_ibcu(rmdev, idx);
	rmdev->ib[ib_index].cu[cu_index].fqid = IBCU_IDLE_FQID;
}

int rman_request_ibcu(struct rman_dev *rmdev, int fqid)
{
	int ib_index, cu_index, ibcu_index;

	if (!fqid)
		return -EINVAL;

	ibcu_index = rman_get_ibcu(rmdev, fqid);
	if (ibcu_index >= 0)
		return ibcu_index;

	for (ib_index = 0; ib_index < rmdev->ib_num; ib_index++) {
		if (!rmdev->ib[ib_index].ib_regs)
			continue;
		for (cu_index = 0; cu_index < RMAN_CU_NUM_PER_IB; cu_index++) {
			if (rmdev->ib[ib_index].cu[cu_index].fqid ==
				IBCU_IDLE_FQID) {
				rmdev->ib[ib_index].cu[cu_index].fqid = fqid;
				return ib_index * RMAN_CU_NUM_PER_IB +
					cu_index;
			}
		}
	}
	return -EINVAL;
}

int rman_get_ibcu(const struct rman_dev *rmdev, int fqid)
{
	int ib_index, cu_index;

	if (!fqid)
		return -EINVAL;

	for (ib_index = 0; ib_index < rmdev->ib_num; ib_index++) {
		if (!rmdev->ib[ib_index].ib_regs)
			continue;
		for (cu_index = 0; cu_index < RMAN_CU_NUM_PER_IB; cu_index++)
			if (rmdev->ib[ib_index].cu[cu_index].fqid == fqid)
				return ib_index * RMAN_CU_NUM_PER_IB +
					cu_index;
	}

	return -EINVAL;
}

int rman_config_ibcu(struct rman_dev *rmdev, const struct ibcu_cfg *cfg)
{
	int ib_index, cu_index;

	ib_index = cfg->ibcu / RMAN_CU_NUM_PER_IB;
	cu_index = cfg->ibcu % RMAN_CU_NUM_PER_IB;

	if (rmdev->ib[ib_index].cu[cu_index].fqid != cfg->fqid) {
		error(0, EINVAL, "RMan: please firstly request a ibcu");
		return -EINVAL;
	}

	write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->fqr, cfg->fqid);
	write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rvr[0],
		  cfg->sid << 16 | cfg->did);
	write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rmr[0],
		  cfg->sid_mask << 16 | cfg->did_mask);
	switch (cfg->tran->type) {
	case RIO_TYPE_DBELL:
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->dor,
			  cfg->data_offset);
		break;
	case RIO_TYPE_MBOX:
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24 |
			  cfg->tran->mbox.msglen << 8 |
			  cfg->tran->mbox.ltr << 6 |
			  cfg->tran->mbox.mbox);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24 |
			  cfg->tran->mbox.msglen_mask << 8 |
			  cfg->tran->mbox.ltr_mask << 6 |
			  cfg->tran->mbox.mbox_mask);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->dor,
			  cfg->data_offset);

		/* RMan can't handle type 11 (message) packets after long
		 * time traffic. To fix this, assign an arbitration group to
		 * only execute on one segmentation unit
		 */
		if (!rmdev->fix_mbox_flag) {
			write_reg(&rmdev->global_regs->mmsepr0,
				  MMSEPR0_MAILBOX);
			rmdev->fix_mbox_flag = 1;
		}
		break;
	case RIO_TYPE_DSTR:
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rvr[1],
			  cfg->tran->flowlvl << 28 |
			  cfg->port << 24 |
			  cfg->tran->dstr.cos << 16 |
			  cfg->tran->dstr.streamid);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->rmr[1],
			  cfg->tran->flowlvl_mask << 28 |
			  cfg->port_mask << 24 |
			  cfg->tran->dstr.cos_mask << 16 |
			  cfg->tran->dstr.streamid_mask);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->dbpr,
			  (cfg->msgsize << 16) | cfg->bpid);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->t9sgbpr,
			  (cfg->sgsize << 16) | cfg->sgbpid);
		write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->dor,
			  cfg->data_offset);
		break;
	default:
		return -EINVAL;
	}
	write_reg(&rmdev->ib[ib_index].cu[cu_index].cu_regs->mr,
		  cfg->fq_mode << 28 | (cfg->tran->type << 24));
	return 0;
}

static int rman_get_ib_number(struct rman_dev *rmdev)
{
	uint32_t ip_cfg;

	if (!rmdev || !rmdev->global_regs)
		return -EINVAL;

	ip_cfg = read_reg(&rmdev->global_regs->ipbrr[1]);
	return 2 << (((ip_cfg >> 6) & 0x3) + 1);
}

static int rman_ib_init(const struct device_node *ib_node,
			struct rman_dev *rmdev)
{
	struct rman_inbound_block *ib;
	const uint32_t *regs_addr;
	uint64_t regs_size;
	uint64_t phys_addr;
	int ib_index;
	char ib_name[PATH_MAX];
	int cu_index;

	if (!ib_node || !rmdev)
		return -EINVAL;

	regs_addr = of_get_address(ib_node, 0, &regs_size, NULL);
	if (!regs_addr) {
		error(0, 0, "%s missed reg property", ib_node->full_name);
		return -EINVAL;
	}

	phys_addr = of_translate_address(ib_node, regs_addr);
	if (!phys_addr) {
		error(0, 0, "%s of_translate_address failed",
		      ib_node->full_name);
		return -EINVAL;
	}
	ib_index = (phys_addr >> RMAN_IB_INDEX_OFFSET) & 0xf;
	if (ib_index >= rmdev->ib_num)
		return -EFAULT;

	ib = &rmdev->ib[ib_index];
	ib->index = ib_index;
	ib->regs_size = regs_size;
	sprintf(ib_name, RMAN_IB_FILE"%d", ib->index);

	ib->uiofd = open(ib_name, O_RDWR);
	if (ib->uiofd < 0) {
		error(0, errno, "%s", __func__);
		return -errno;
	}

	ib->ib_regs = mmap(NULL, ib->regs_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, ib->uiofd, 0);
	if (MAP_FAILED == ib->ib_regs) {
		error(0, errno, "%s", __func__);
		return -errno;
	}

	for (cu_index = 0; cu_index < RMAN_CU_NUM_PER_IB; cu_index++)
		ib->cu[cu_index].cu_regs = ib->ib_regs +
					   cu_index * RMAN_CU_OFFSET;
	error(0, 0, "RMan inbound block%d initialized", ib->index);
	return 0;
}

int rman_dev_config(struct rman_dev *rmdev, const struct rman_cfg *cfg)
{
	if (!rmdev || !cfg)
		return -EINVAL;

	/* Set inbound message descriptor write status */
	if (cfg->md_create)
		write_reg(&rmdev->global_regs->mmmr,
			  read_reg(&rmdev->global_regs->mmmr) |
			  cfg->md_create << RMAN_MMMR_MDD_SHIFT);
	else
		write_reg(&rmdev->global_regs->mmmr,
			  read_reg(&rmdev->global_regs->mmmr) &
			  ~(cfg->md_create << RMAN_MMMR_MDD_SHIFT));

	/* Initialize the frame queue assembly register */
	/* Data streaming supports max 32 inbound frame queues */
	write_reg(&rmdev->global_regs->mmt9fqar,
		  cfg->fq_bits[RIO_TYPE9] << RMAN_FQAR_STID_SHIFT);
	/* Doorbell supports max 1 inbound frame queues */
	write_reg(&rmdev->global_regs->mmt10fqar, 0);
	/* Mailbox supports max 4 inbound frame queues */
	write_reg(&rmdev->global_regs->mmt11fqar,
		  cfg->fq_bits[RIO_TYPE11] << RMAN_FQAR_LTR_SHIFT);

	/* Set MMSEPR0 default value to avoid mailbox workaround impact */
	write_reg(&rmdev->global_regs->mmsepr0, MMSEPR0_DEFAULT);

	return 0;
}

static int
rman_global_node_init(const struct device_node *global_regs_node,
		      struct rman_dev *rmdev)
{
	if (!global_regs_node || !rmdev || rmdev->uiofd < 0)
		return -EINVAL;

	if (!of_get_address(global_regs_node, 0, &rmdev->regs_size, NULL))
		return -EINVAL;

	rmdev->global_regs = mmap(NULL, rmdev->regs_size,
				  PROT_READ | PROT_WRITE, MAP_SHARED,
				  rmdev->uiofd, 0);

	if (MAP_FAILED == rmdev->global_regs) {
		error(0, errno, "%s", __func__);
		return -errno;
	}

	return 0;
}

struct rman_dev *rman_dev_init(void)
{
	struct rman_dev *rmdev;
	int uiofd = -1, channel_num, i;
	const struct device_node *rman_node, *child;
	size_t lenp;
	const phandle *prop;

	uiofd = open(RMAN_UIO_FILE, O_RDWR);
	if (uiofd < 0) {
		error(0, errno, "%s", __func__);
		return NULL;
	}

	rman_node = of_find_compatible_node(NULL, NULL, "fsl,rman");
	if (of_device_is_available(rman_node) == false)
		return NULL;

	rmdev = malloc(sizeof(*rmdev));
	if (!rmdev) {
		error(0, errno, "%s", __func__);
		return NULL;
	}
	memset(rmdev, 0, sizeof(*rmdev));

	rmdev->uiofd = uiofd;

	/* Setup channels */
	prop = of_get_property(rman_node, "fsl,qman-channels-id", &lenp);
	if (!prop) {
		error(0, 0, "missed fsl,qman-channels-id property");
		goto _err;
	}
	channel_num = lenp/sizeof(*prop);
	if (channel_num > RMAN_MAX_NUM_OF_CHANNELS)
		channel_num = RMAN_MAX_NUM_OF_CHANNELS;
	for (i = 0; i < channel_num; i++)
		rmdev->channel_id[i] = prop[i];

	/* Setup global regs */
	for_each_child_node(rman_node, child) {
		if (of_device_is_compatible(child, "fsl,rman-global-cfg"))
			if (rman_global_node_init(child, rmdev))
				goto _err;
	}

	/* Setup inbound blocks */
	rmdev->ib_num = rman_get_ib_number(rmdev);
	if (rmdev->ib_num < 1) {
		error(0, 0, "%s has no inbound block", __func__);
		goto _err;
	}
	rmdev->ib = malloc(rmdev->ib_num * sizeof(*rmdev->ib));
	if (!rmdev->ib) {
		error(0, errno, "%s", __func__);
		goto _err;
	}
	memset(rmdev->ib, 0, rmdev->ib_num * sizeof(*rmdev->ib));

	for_each_child_node(rman_node, child) {
		if (of_device_is_compatible(child, "fsl,rman-inbound-block"))
			if (rman_ib_init(child, rmdev))
				goto _err;
	}

	__rmdev = rmdev;
	return rmdev;
_err:
	rman_dev_finish(rmdev);
	return NULL;
}

void rman_dev_finish(struct rman_dev *rmdev)
{
	int ib_index;

	if (!rmdev)
		return;

	if (rmdev->ib) {
		for (ib_index = 0; ib_index < rmdev->ib_num; ib_index++) {
			if (rmdev->ib[ib_index].ib_regs)
				munmap((void *)rmdev->ib[ib_index].ib_regs,
					rmdev->ib[ib_index].regs_size);
			if (rmdev->ib[ib_index].uiofd > 0)
				close(rmdev->ib[ib_index].uiofd);
		}
		free(rmdev->ib);
	}

	if (rmdev->global_regs)
		munmap((void *)rmdev->global_regs, rmdev->regs_size);
	if (rmdev->uiofd > 0)
		close(rmdev->uiofd);

	free(rmdev);
}
