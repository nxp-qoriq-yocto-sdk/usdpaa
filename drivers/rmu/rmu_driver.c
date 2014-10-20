/* Copyright (c) 2012 Freescale Semiconductor, Inc.
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
#include <usdpaa/of.h>
#include <usdpaa/fsl_rmu.h>
#include <error.h>
#include <math.h>
#include "rmu_driver.h"

/* This function maps RMU unit registers */
int fsl_rmu_unit_uio_init(struct rmu_unit **unit, uint8_t unit_id)
{
	int err = 0;
	struct rmu_unit *unit_uio;
	char unit_uio_name[PATH_MAX];
	const struct device_node *rmu_node, *child;
	const uint32_t *regs_addr;
	uint64_t phys_addr = 0;
	uint64_t regs_size = 0;
	uint32_t offset;

	rmu_node = of_find_compatible_node(NULL, NULL, "fsl,srio-rmu");
	if (!rmu_node) {
		err = -ENODEV;
		error(0, -err, "%s(): compatible", __func__);
		return err;
	}

	/* Get RMU unit node register physical address */
	for_each_child_node(rmu_node, child) {
		regs_addr = of_get_address(child, 0,
					&regs_size, NULL);
		if (!regs_addr) {
			err = -ENODEV;
			error(0, -err, "%s(): of_get_address()",
					    __func__);
			return err;
		}

		if (((*regs_addr >> 8) & 0xf) != unit_id)
			continue;

		phys_addr = of_translate_address(child,
						regs_addr);
		if (!phys_addr) {
			err = -ENODEV;
			error(0, -err,
					"%s(): of_translate_address()",
					__func__);
			return err;
		}
		break;
	}

	/* Calculate RMU unit offset in a page */
	offset =  phys_addr & PAGE_MASK;

	unit_uio = (typeof(unit_uio))malloc(sizeof(struct rmu_unit));
	if (!unit_uio)
		return -errno;

	memset(unit_uio, 0, sizeof(*unit_uio));

	/* RMU uio name is rmu-uio-xxxx */
	if (unit_id == 4)
		snprintf(unit_uio_name, PATH_MAX - 1, "/dev/rmu-uio-doorbell");
	else
		snprintf(unit_uio_name, PATH_MAX - 1,
				"/dev/rmu-uio-msg%d", unit_id);

	unit_uio->fd = open(unit_uio_name, O_RDWR);
	if (unit_uio->fd < 0) {
		error(0, errno, "%s(): %s", __func__, unit_uio_name);
		err = -errno;
		goto err_rmu_open;
	}
	unit_uio->regs = mmap(0, regs_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, unit_uio->fd, 0);
	if (!unit_uio->regs) {
		error(0, errno, "%s(): dma register", __func__);
		err = -errno;
		goto err_rmu_mmap;
	}
	unit_uio->regs = (typeof(unit_uio->regs))
			((uint8_t *)unit_uio->regs + offset);
	*unit = unit_uio;

	return 0;

err_rmu_mmap:
	close(unit_uio->fd);
err_rmu_open:
	free(unit_uio);

	return err;
}

/* This function releases RMU unit related resource. */
int fsl_rmu_unit_uio_finish(struct rmu_unit *unit)
{
	if (!unit)
		return -EINVAL;

	if (unit->regs != NULL) {
		munmap(unit->regs, PAGE_SIZE);
		close(unit->fd);
	}

	free(unit);
	return 0;
}

int fsl_msg_send_err_clean(struct rmu_unit *unit)
{
	struct msg_regs *regs;

	if (!unit)
		return -EINVAL;

	regs = (struct msg_regs *)unit->regs;
	out_be32(&regs->omsr, 0xffffffff);

	return 0;
}

int fsl_dbell_send_err_clean(struct rmu_unit *unit)
{
	struct dbell_regs *regs;

	if (!unit)
		return -EINVAL;

	regs = (struct dbell_regs *)unit->regs;
	out_be32(&regs->odsr, 0xffffffff);

	return 0;
}

/* This function waits for message operation completion or error */
int fsl_msg_send_wait(struct rmu_unit *unit)
{
	struct msg_regs *regs;
	uint32_t omsr;
	int err = 0;

	if (!unit)
		return -EINVAL;

	regs = (struct msg_regs *)unit->regs;

	while (!(in_be32(&regs->omsr) & MSG_OMSR_EOMI)) {
		omsr = in_be32(&regs->omsr);
		if (omsr & MSG_OMSR_MER) {
			error(0, 0,
				"%s(): message send error--MER!", __func__);
			err = -EINVAL;
			break;
		} else if (omsr & MSG_OMSR_RETE) {
			error(0, 0,
				"%s(): message send error--RETE!", __func__);
			err = -EINVAL;
			break;
		} else if (omsr & MSG_OMSR_PRT) {
			error(0, 0,
				"%s(): message send error--PRT!", __func__);
			err = -EINVAL;
			break;
		} else if (omsr & MSG_OMSR_TE) {
			error(0, 0,
				"%s(): message send error--TE!", __func__);
			err = -EINVAL;
			break;
		}
	}
	out_be32(&regs->omsr, 0xffffffff);

	return err;
}

/* This function waits for doorbell operation completion or error */
int fsl_dbell_send_wait(struct rmu_unit *unit)
{
	struct dbell_regs *regs;
	uint32_t odsr;
	int err = 0;

	if (!unit)
		return -EINVAL;

	regs = (struct dbell_regs *)unit->regs;

	while (!(in_be32(&regs->odsr) & DBELL_ODSR_EODI)) {
		odsr = in_be32(&regs->odsr);
		if (odsr & DBELL_ODSR_MER) {
			error(0, 0,
				"%s(): doorbell send error--MER!", __func__);
			err = -EINVAL;
			break;
		} else if (odsr & DBELL_ODSR_RETE) {
			error(0, 0,
				"%s(): doorbell send error--RETE!", __func__);
			err = -EINVAL;
			break;
		} else if (odsr & DBELL_ODSR_PRT) {
			error(0, 0,
				"%s(): doorbell send error--PRT!", __func__);
			err = -EINVAL;
			break;
		}
	}
	out_be32(&regs->odsr, 0xffffffff);

	return err;
}

int fsl_rmu_msg_inb_handler(struct rmu_unit *unit,
				void *info, struct rmu_ring *rx_ring)
{
	struct msg_regs *regs;
	void *currfqdpa;
	uint32_t imsr;
	uint32_t immr;

	if ((!unit) || (!info) || (!rx_ring))
		return -EINVAL;

	regs = (struct msg_regs *)unit->regs;

	imsr = in_be32(&regs->imsr);

	if (imsr & MSG_IMSR_MRT) {
		error(0, 0, "%s(): message rx error--MRT!", __func__);
		out_be32(&regs->imsr, MSG_IMSR_MRT);
		return -EINVAL;
	}

	if (imsr & MSG_IMSR_TE) {
		error(0, 0, "%s(): message rx error--TE!", __func__);
		out_be32(&regs->imsr, MSG_IMSR_TE);
		return -EINVAL;
	}

	if (imsr & MSG_IMSR_QF) {
		printf("MSG: message queue full! imsr = 0x%x\n", imsr);
		out_be32(&regs->imsr, MSG_IMSR_QFI);
	}

	if (imsr & MSG_IMSR_QE)
		return -EINVAL;

	/* XXX Need to check/dispatch until queue empty */
	if (imsr & MSG_IMSR_MIQI) {
		currfqdpa = rx_ring->virt
			+ (in_be32(&regs->imfqdpar)
			& ((rx_ring->entries) * (rx_ring->cell_size) - 1));
		memcpy(info, currfqdpa, rx_ring->cell_size);

		immr = in_be32(&regs->immr) | MSG_IMMR_MI;
		out_be32(&regs->immr, immr);
		out_be32(&regs->imsr, MSG_IMSR_MIQI);
	}

	return 0;
}

int fsl_rmu_dbell_inb_handler(struct rmu_unit *unit,
				void *info, struct rmu_ring *rx_ring)
{
	struct dbell_regs *regs;
	struct dbell_info *currdqdpa;
	uint32_t idsr;
	uint32_t idmr;

	if ((!unit) || (!info) || (!rx_ring))
		return -EINVAL;

	regs = (struct dbell_regs *)unit->regs;

	idsr = in_be32(&regs->idsr);

	if (idsr & DBELL_IDSR_TE) {
		error(0, 0, "%s(): doorbell rx error--TE!", __func__);
		out_be32(&regs->idsr, DBELL_IDSR_TE);
		return -EINVAL;
	}

	if (idsr & DBELL_IDSR_QF) {
		printf("DBELL: doorbell queue full! idsr = 0x%x\n", idsr);
		out_be32(&regs->idsr, DBELL_IDSR_QFI);
	}

	if (idsr & DBELL_IDSR_QE)
		return -EINVAL;

	/* XXX Need to check/dispatch until queue empty */
	if (idsr & DBELL_IDSR_DIQI) {
		currdqdpa = (struct dbell_info *)(rx_ring->virt
				+ (in_be32(&regs->idqdpar)
				& ((rx_ring->entries) *
				(rx_ring->cell_size) - 1)));
		memcpy(info, currdqdpa, rx_ring->cell_size);

		idmr = in_be32(&regs->idmr) | DBELL_IDMR_DI;
		out_be32(&regs->idmr, idmr);
		out_be32(&regs->idsr, DBELL_IDSR_DIQI);
	}

	return 0;
}

int fsl_rmu_dbell_send(struct rmu_unit *unit,
		uint8_t port, uint32_t destid, uint8_t priority, uint16_t data)
{
	struct dbell_regs *regs;

	if ((!unit) || (port > SRIO_MAX_PORT) || (destid > SRIO_MAX_DEVID))
		return -EINVAL;

	regs = (struct dbell_regs *)unit->regs;

	/*
	 * In the serial version silicons, such as MPC8548, MPC8641,
	 * below operations is must be.
	 */
	out_be32(&regs->odmr, 0x0);
	out_be32(&regs->odretcr, 0x00000004);
	out_be32(&regs->oddpr, destid << 16);
	out_be32(&regs->oddatr, 0x20000000 | (priority << 26)
						| (port << 20) | data);
	out_be32(&regs->odmr, DBELL_ODMR_DUS);

	return 0;
}

int fsl_add_outb_msg(struct rmu_unit *unit, struct rmu_ring *desc_ring,
				struct msg_tx_info *tx_info)
{
	struct msg_regs *regs;
	struct msg_tx_desc *desc;
	uint32_t omsr;
	uint32_t ommr;
	uint32_t omdqepar;
	int i;

	if ((!unit) || (!desc_ring) || (!tx_info))
		return -EINVAL;

	if ((tx_info->len < 8) || (tx_info->len > MSG_MAX_FRAME_SIZE))
		return -EINVAL;

	regs = (struct msg_regs *)unit->regs;

	omsr = in_be32(&regs->omsr);
	if (omsr & MSG_OMSR_QF) {
		error(0, 0, "%s(): message tx error--QF!", __func__);
		return -EINVAL;
	}

	omdqepar =  in_be32(&regs->omdqepar);
	desc = (struct msg_tx_desc *)(desc_ring->virt
			+ (omdqepar - (uint32_t)desc_ring->phys));

	/* Set mbox field for message, and set destid */
	desc->dport = (tx_info->destid << 16) | (tx_info->mbox & 0x3);

	/* Enable EOMI interrupt and priority */
	desc->dattr = ((tx_info->priority << 26) & MSG_OMDATR_DTFLOWLVL)
			| ((tx_info->port) << 20) | MSG_OMDATR_EOMIE;

	/* Set transfer size aligned to next power of 2 (in double words) */
	for (i = 3; i < 13; i++) {
		if ((1 << i) >= tx_info->len) {
			desc->dwcnt = 1 << i;
			break;
		}
	}

	/* Set snooping and source buffer address */
	desc->saddr = MSG_OMSAR_SEN | tx_info->phys_buffer;

	ommr = in_be32(&regs->ommr) | MSG_OMMR_MUI;
	/* Increment enqueue pointer */
	out_be32(&regs->ommr, ommr);

	return 0;
}

int fsl_rmu_msg_outb_init(struct rmu_unit *unit, struct rmu_ring *desc_ring)
{
	struct msg_regs *regs;
	uint32_t regval;
	uint32_t ommr;

	if ((!unit) || (!desc_ring))
		return -EINVAL;

	if ((desc_ring->entries < MSG_MIN_TX_RING_ENTRY) ||
		(desc_ring->entries > MSG_MAX_TX_RING_ENTRY) ||
		(!is_power_of_2(desc_ring->entries)))
		return -EINVAL;

	/*
	 * the phy must be aligned on a boundary
	 * equal to number of queue entries x desc size
	 */
	if (desc_ring->phys % (desc_ring->entries * desc_ring->cell_size))
		return -EINVAL;

	regs = (struct msg_regs *)unit->regs;

	/* First disable the unit */
	out_be32(&regs->ommr, 0);

	/* Point dequeue/enqueue desc pointers at first entry in ring */
	out_be32(&regs->omdqdpar, (u32)desc_ring->phys);
	out_be32(&regs->omdqepar, (u32)desc_ring->phys);

	/* Clear interrupt status */
	out_be32(&regs->omsr, MSG_OMSR_CLEAR);

	/*
	 * Configure outbound message unit:
	 *      Snooping
	 *      Unmask all interrupt sources
	 *      Disable
	 *	   Chaining mode
	 */
	 regval = ((((uint32_t)log2(desc_ring->entries) - 1) << 12)
		& MSG_OMMR_CIRQ_SIZ)
		| MSG_OMMR_DES_SEN;
	out_be32(&regs->ommr, regval);

	ommr = in_be32(&regs->ommr) | MSG_OMMR_MUS;
	/* Now enable the unit */
	out_be32(&regs->ommr, ommr);

	return 0;
}

int fsl_rmu_msg_inb_init(struct rmu_unit *unit, struct rmu_ring *rx_ring)
{
	struct msg_regs *regs;
	uint32_t regval;
	uint32_t immr;

	if ((!unit) || (!rx_ring))
		return -EINVAL;

	if ((rx_ring->entries < MSG_MIN_RX_RING_ENTRY) ||
		(rx_ring->entries > MSG_MAX_RX_RING_ENTRY) ||
		(!is_power_of_2(rx_ring->entries)))
		return -EINVAL;

	if ((rx_ring->cell_size < 8) ||
		(rx_ring->cell_size > MSG_MAX_FRAME_SIZE) ||
		(!is_power_of_2(rx_ring->cell_size)))
		return -EINVAL;

	/*
	 * the phy must be aligned on a boundary
	 * equal to number of queue entries x frame size
	 */
	if (rx_ring->phys % (rx_ring->entries * rx_ring->cell_size))
		return -EINVAL;

	regs = (struct msg_regs *)unit->regs;

	/* First disable the unit */
	out_be32(&regs->immr, 0);

	/* Point dequeue/enqueue pointers at first entry in ring */
	out_be32(&regs->imfqdpar, (u32)rx_ring->phys);
	out_be32(&regs->imfqepar, (u32)rx_ring->phys);

	/* Clear interrupt status */
	out_be32(&regs->imsr, MSG_IMSR_CLEAR);

	/*
	 * Configure inbound message unit:
	 *      Snooping
	 *      4KB max message size
	 *      Unmask all interrupt sources
	 *      Disable
	 */
	 regval = ((((uint32_t)log2(rx_ring->cell_size) - 1) << 16)
		& MSG_IMMR_FRA_SIZ)
		| ((((uint32_t)log2(rx_ring->entries) - 1) << 12)
		& MSG_IMMR_CIRQ_SIZ)
		| MSG_IMMR_SEN | MSG_IMMR_MIQIE;
	out_be32(&regs->immr, regval);

	immr = in_be32(&regs->immr) | MSG_IMMR_ME;
	/* Now enable the unit */
	out_be32(&regs->immr, immr);

	return 0;
}

int fsl_rmu_dbell_inb_init(struct rmu_unit *unit, struct rmu_ring *rx_ring)
{
	struct dbell_regs *regs;
	uint32_t regval;

	if ((!unit) || (!rx_ring))
		return -EINVAL;

	if ((rx_ring->entries < DBELL_MIN_RX_RING_ENTRY) ||
		(rx_ring->entries > DBELL_MAX_RX_RING_ENTRY) ||
		(!is_power_of_2(rx_ring->entries)))
		return -EINVAL;

	/*
	 * the phy must be aligned on a boundary
	 * equal to number of queue entries x frame size
	 */
	if (rx_ring->phys % (rx_ring->entries * rx_ring->cell_size))
		return -EINVAL;

	regs = (struct dbell_regs *)unit->regs;

	/* First disable the unit */
	out_be32(&regs->idmr, 0);

	/* Point dequeue/enqueue pointers at first entry in ring */
	out_be32(&regs->idqdpar, (u32)rx_ring->phys);
	out_be32(&regs->idqepar, (u32)rx_ring->phys);

	/* Clear interrupt status */
	out_be32(&regs->idsr, DBELL_IDSR_CLEAR);

	/* Configure inbound doorbell for snooping, entries, and enable */
	regval = ((((uint32_t)log2(rx_ring->entries) - 1) << 12)
			& DBELL_IDMR_CIRQ_SIZ) | DBELL_IDMR_SEN
			| DBELL_IDMR_DIQIE | DBELL_IDMR_DE;
	out_be32(&regs->idmr, regval);

	return 0;
}
