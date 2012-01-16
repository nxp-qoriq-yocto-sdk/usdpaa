/* Copyright (c) 2011 - 2012 Freescale Semiconductor, Inc.
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
#include "dma_driver.h"
#include <error.h>

/* This function maps DMA registers by channels */
int fsl_dma_chan_init(struct dma_ch **dma_ch, uint8_t dma_id, uint8_t ch_id)
{
	int err = 0;
	struct dma_ch *dma_uio;
	char dma_uio_name[PATH_MAX];
	const struct device_node *dma_node, *child;
	const uint32_t *cell_index;
	const uint32_t *regs_addr;
	uint64_t phys_addr = 0;
	uint64_t regs_size;
	uint32_t offset;
	size_t lenp;

	for_each_compatible_node(dma_node, NULL, "fsl,eloplus-dma") {
		cell_index = (typeof(cell_index))of_get_property(dma_node,
							"cell-index", &lenp);
		if (!cell_index) {
			err = -ENODEV;
			error(0, err, "%s(): cell-index", __func__);
			return err;
		}

		if (*cell_index != dma_id)
			continue;

		/* Get DMA channel node register physical address */
		for_each_child_node(dma_node, child) {
			cell_index = of_get_property(child, "cell-index", NULL);
			if (!cell_index) {
				err = -ENODEV;
				error(0, -err, "%s(): of_get_property()",
				      __func__);
				return err;
			}

			if (*cell_index == ch_id) {
				regs_addr = of_get_address(child, 0,
							   &regs_size, NULL);
				if (!regs_addr) {
					err = -ENODEV;
					error(0, -err, "%s(): of_get_address()",
					      __func__);
					return err;
				}
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
			} else
				continue;
		}

		break;
	}

	/* Calculate DMA channel offset in a page */
	offset =  phys_addr & PAGE_MASK;

	dma_uio = (typeof(dma_uio))malloc(sizeof(struct dma_ch));
	if (!dma_uio)
		return -errno;

	memset(dma_uio, 0, sizeof(*dma_uio));

	/* DMA uio name is dma-uio[0~1]-[0~4] */
	snprintf(dma_uio_name, PATH_MAX - 1, "/dev/dma-uio%d-%d",
			dma_id, ch_id);

	dma_uio->fd = open(dma_uio_name, O_RDWR);
	if (dma_uio->fd < 0) {
		error(0, errno, "%s(): %s", __func__, dma_uio_name);
		err = -errno;
		goto err_dma_open;
	}
	dma_uio->regs = mmap(0, regs_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, dma_uio->fd, 0);
	if (!dma_uio->regs) {
		error(0, errno, "%s(): dma register", __func__);
		err = -errno;
		goto err_dma_mmap;
	}
	dma_uio->regs = (typeof(dma_uio->regs))
			((uint8_t *)dma_uio->regs + offset);
	*dma_ch = dma_uio;

	return 0;

err_dma_mmap:
	close(dma_uio->fd);
err_dma_open:
	free(dma_uio);

	return err;
}

/* This function releases DMA related resource. */
int fsl_dma_chan_finish(struct dma_ch *dma_ch)
{
	if (!dma_ch)
		return -EINVAL;

	if (dma_ch->regs != NULL) {
		munmap(dma_ch->regs, PAGE_SIZE);
		close(dma_ch->fd);
	}

	free(dma_ch);
	return 0;
}
/* This function initializes DMA controller in direct mode */
int fsl_dma_chan_basic_direct_init(struct dma_ch *dma_ch)
{
	if (!dma_ch)
		return -EINVAL;

	/* Write: Snoop local processor */
	out_be32(&dma_ch->regs->datr, DMA_DATR_WR_SNOOP);
	/* Read: Snoop local processor*/
	out_be32(&dma_ch->regs->satr, DMA_SATR_RD_SNOOP);
	/* direct mode, single reg write, write dest start dma */
	out_be32(&dma_ch->regs->mr,
		DMA_MR_BWC_DIS | DMA_MR_SRW_EN | DMA_MR_CTM_EN);

	return 0;
}

/* Using this function can set BWC of DMA channel */
int fsl_dma_chan_bwc(struct dma_ch *dma_ch, uint8_t bwc)
{
	if (!dma_ch)
		return -EINVAL;

	out_be32(&dma_ch->regs->mr, (in_be32(&dma_ch->regs->mr) &
		~DMA_BWC_MASK) | (bwc << DMA_BWC_OFFSET));

	return 0;
}

/* This function waits for DMA operation completion or error */
int fsl_dma_wait(struct dma_ch *dma_ch)
{
	if (!dma_ch)
		return -EINVAL;

	while (in_be32(&dma_ch->regs->sr) & DMA_SR_CH_BUSY)
		;

	if (in_be32(&dma_ch->regs->sr) & DMA_SR_ERR) {
		error(0, EBUSY, "%s(): dma transfer", __func__);
		out_be32(&dma_ch->regs->sr, ~0);
		return -EBUSY;
	}

	return 0;
}

/* This function starts DMA transmission in direct mode */
int fsl_dma_direct_start(struct dma_ch *dma_ch, dma_addr_t src_phys,
			dma_addr_t dest_phys, uint32_t len)
{
	if (!dma_ch)
		return -EINVAL;

	/* Wait for DMA channel free */
	fsl_dma_wait(dma_ch);
	/* Data len */
	out_be32(&dma_ch->regs->bcr, len);
	/* Prepare the high 4 bit of the 36 bit DMA address */
	out_be32(&dma_ch->regs->satr,
		(in_be32(&dma_ch->regs->satr)
		& ~0xf) | (uint32_t)(src_phys >> 32));
	out_be32(&dma_ch->regs->datr,
		(in_be32(&dma_ch->regs->datr) & ~0xf) |
		(uint32_t)(dest_phys >> 32));
	/* Set the low 32 bit address */
	out_be32(&dma_ch->regs->sar, (uint32_t)src_phys);
	/* Make sure the early data is set */
	__sync_synchronize();
	out_be32(&dma_ch->regs->dar, (uint32_t)dest_phys);
	/* Make sure DMA start */
	__sync_synchronize();

	return 0;
}
