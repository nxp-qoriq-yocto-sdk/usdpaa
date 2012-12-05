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
#define MMIER_ENABLE_ALL	0x800000FF
#define MMEDR_CLEAR		0x800000FF
#define RMAN_RESET_VALUE	1
#define RMAN_MMSR_IMUB_SHIFT	31
#define RMAN_MMSR_OMUB_SHIFT	30
#define RMAN_MMMR_MDD_SHIFT	31
#define RMAN_MMMR_OSID_SHIFT	28
#define RMAN_MMMR_EFQ_SHIFT	27
#define RMAN_FQAR_STID_SHIFT	7
#define RMAN_FQAR_LTR_SHIFT	8

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

struct rman_dev {
	int uiofd;
	int irq;
	int ib_num;
	int channel_id[RMAN_MAX_NUM_OF_CHANNELS];
	volatile struct rman_global_reg *global_regs;
	uint64_t regs_size;
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

int rman_get_ib_number(struct rman_dev *rmdev)
{
	return rmdev->ib_num;
}

int rman_dev_config(struct rman_dev *rmdev, const struct rman_cfg *cfg)
{
	uint32_t mmmr;

	if (!rmdev || !rmdev->global_regs || !cfg)
		return -EINVAL;

	mmmr = read_reg(&rmdev->global_regs->mmmr);
	/* Set inbound message descriptor write status */
	mmmr &= ~(1 << RMAN_MMMR_MDD_SHIFT);
	mmmr |= cfg->md_create << RMAN_MMMR_MDD_SHIFT;
	/* Set OSID */
	mmmr &= ~(1 << RMAN_MMMR_OSID_SHIFT);
	mmmr |= cfg->osid << RMAN_MMMR_OSID_SHIFT;
	/* Set EFQ */
	mmmr &= ~(1 << RMAN_MMMR_EFQ_SHIFT);
	mmmr |= cfg->efq << RMAN_MMMR_EFQ_SHIFT;
	write_reg(&rmdev->global_regs->mmmr, mmmr);

	/* Initialize the frame queue assembly register */
	/* Data streaming supports max 32 inbound frame queues */
	write_reg(&rmdev->global_regs->mmt9fqar,
		  cfg->fq_bits[RIO_TYPE9] << RMAN_FQAR_STID_SHIFT);
	/* Doorbell supports max 1 inbound frame queues */
	write_reg(&rmdev->global_regs->mmt10fqar, 0);
	/* Mailbox supports max 4 inbound frame queues */
	write_reg(&rmdev->global_regs->mmt11fqar,
		  cfg->fq_bits[RIO_TYPE11] << RMAN_FQAR_LTR_SHIFT);

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
	if (uiofd < 0)
		error(0, 0, "Can not open RMan device file"
			"It may have been opened by other app");

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
	for_each_child_node(rman_node, child)
		if (of_device_is_compatible(child, "fsl,rman-global-cfg"))
			rman_global_node_init(child, rmdev);

	/* get inbound blocks number according to dts nodes */
	for_each_child_node(rman_node, child)
		if (of_device_is_compatible(child, "fsl,rman-inbound-block"))
			rmdev->ib_num++;

	if (rmdev->ib_num < 1) {
		error(0, 0, "%s has no inbound block", __func__);
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
	if (!rmdev)
		return;

	if (rmdev->global_regs)
		munmap((void *)rmdev->global_regs, rmdev->regs_size);
	if (rmdev->uiofd > 0)
		close(rmdev->uiofd);

	free(rmdev);
}
