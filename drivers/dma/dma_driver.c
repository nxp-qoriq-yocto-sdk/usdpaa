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

#include <internal/of.h>
#include <usdpaa/of.h>
#include "dma_driver.h"
#include <error.h>

/* This function maps DMA registers */
int fsl_dma_uio_init(struct dma_dev **dmadev)
{
	int dma_fd;
	int i, j;
	int err = 0;
	size_t lenp;
	const uint32_t *cell_index;
	uint32_t dma_id;
	struct dma_dev *dma_uio;
	char dma_uio_name[PATH_MAX];
	const struct device_node *dt_node;

	dma_uio = malloc(sizeof(*dma_uio));
	if (!dma_uio)
		return -errno;

	memset(dma_uio, 0, sizeof(*dma_uio));

	for_each_compatible_node(dt_node, NULL, "fsl,eloplus-dma") {
		cell_index = (typeof(cell_index))of_get_property(
			dt_node, "cell-index", &lenp);

		if (*cell_index > ARRAY_SIZE(dma_uio->dma_ctrl)) {
			error(0, ENODEV, "%s(): cell-index", __func__);
			err = -ENODEV;
			continue;
		}
		dma_uio->dma_num++;
		dma_id = *cell_index;
		/* DMA UIO name is dma-uio[0~1]-[0~4] */
		snprintf(dma_uio_name, PATH_MAX - 1, "/dev/dma-uio%d-0",
			 dma_id);
		/* dma-uio0-[0~3] registers map base are the same,
		 * so just open one device for register map.
		 * So are dma-uio1-[0~3] registers.
		 */
		dma_fd = open(dma_uio_name, O_RDWR);
		if (dma_fd < 0) {
			error(0, errno, "%s(): %s", __func__, dma_uio_name);
			err = -errno;
			goto err_dma_open;
		}
		dma_uio->dma_ctrl[dma_id].dma_fd = dma_fd;
		dma_uio->dma_ctrl[dma_id].ch[0].ch_regs =
			mmap(0, DMA_REG_MAP_SIZE, PROT_READ | PROT_WRITE,
			     MAP_SHARED, dma_fd, 0);

		if (!dma_uio->dma_ctrl[dma_id].ch[0].ch_regs) {
			error(0, errno, "%s()", __func__);
			err = -errno;
			goto err_dma_mmap;
		}

		dma_uio->dma_ctrl[dma_id].ch[0].ch_regs =
			(typeof(dma_uio->dma_ctrl[dma_id].ch[0].ch_regs))
			((uintptr_t)dma_uio->dma_ctrl[dma_id].ch[0].ch_regs +
			 DMA_BASE_OFFSET);
		for (j = 0; j < ARRAY_SIZE(dma_uio->dma_ctrl[dma_id].ch); j++) {
			dma_uio->dma_ctrl[dma_id].ch[j].ch_regs =
				(typeof(dma_uio->dma_ctrl[dma_id].ch[j].ch_regs))
				((uintptr_t)dma_uio->dma_ctrl[dma_id].ch[0].ch_regs +
				 DMA_REG_SIZE * j);
		}
	}

	if (err < 0)
		goto err_dma_uio_malloc;

	*dmadev = dma_uio;

	return 0;

err_dma_mmap:
	for (i = 0; i < dma_uio->dma_num; i++)
		if (dma_uio->dma_ctrl[i].ch[0].ch_regs) {
			err = munmap(dma_uio->dma_ctrl[i].ch[0].ch_regs,
				     DMA_REG_SIZE);
			if (err < 0)
				error(0, errno, "%s()", __func__);
		}
err_dma_open:
	for (i = 0; i < dma_uio->dma_num; i++)
		if (dma_uio->dma_ctrl[i].dma_fd) {
			err = close(dma_uio->dma_ctrl[i].dma_fd);
			if (err < 0)
				error(0, errno, "%s()", __func__);
		}
err_dma_uio_malloc:
	free(dma_uio);

	return err;
}


/* This function releases DMA related resource */
int fsl_dma_uio_finish(struct dma_dev *dmadev)
{
	int i;

	if (!dmadev)
		return -EINVAL;

	for (i = 0; i < dmadev->dma_num; i++) {
		if (dmadev->dma_ctrl[i].ch[0].ch_regs)
			munmap(dmadev->dma_ctrl[i].ch[0].ch_regs, DMA_REG_SIZE);
		if (dmadev->dma_ctrl[i].dma_fd)
			close(dmadev->dma_ctrl[i].dma_fd);
	}

	free(dmadev);

	return 0;
}

/* This function initializes DMA controller in direct mode */
int fsl_dma_chan_basic_direct_init(struct dma_dev *dmadev,
				   uint8_t dma_id, uint8_t chan_id)
{
	if (!dmadev || dma_id > dmadev->dma_num || chan_id > DMA_CHAN_NUM)
		return -EINVAL;

	/* Write: Snoop local processor */
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->datr,
		 DMA_DATR_WR_SNOOP);
	/* Read: Snoop local processor */
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->satr,
		 DMA_SATR_RD_SNOOP);
	/* Direct mode, single reg write, write dest start DMA */
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->mr,
		 DMA_MR_BWC_DIS | DMA_MR_SRW_EN | DMA_MR_CTM_EN);

	return 0;
}

/* Using this function can set BWC of DMA channel */
int fsl_dma_chan_bwc(struct dma_dev *dmadev, uint8_t dma_id,
		     uint8_t chan_id, uint8_t bwc)
{
	if (!dmadev || dma_id > dmadev->dma_num || chan_id > DMA_CHAN_NUM)
		return -EINVAL;

	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->mr,
		 (in_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->mr)
		  & ~DMA_BWC_MASK) | (bwc << DMA_BWC_OFFSET));

	return 0;
}

/* This function waits for DMA operation completion or error */
int fsl_dma_wait(struct dma_dev *dmadev, uint8_t dma_id, uint8_t chan_id)
{
	if (!dmadev || dma_id > dmadev->dma_num || chan_id > DMA_CHAN_NUM)
		return -EINVAL;

	while (in_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->sr)
	       & DMA_SR_CH_BUSY);

	if (in_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->sr) &
	    DMA_SR_ERR) {
		error(0, EBUSY, "%s(): DMA transfer", __func__);
		out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->sr, ~0);
		return -EBUSY;
	}

	return 0;
}

/* This function starts DMA transmission in direct mode */
int fsl_dma_direct_start(struct dma_dev *dmadev, uint8_t dma_id,
			 uint8_t chan_id, dma_addr_t src_phys,
			 dma_addr_t dest_phys, size_t len)
{
	if (!dmadev || dma_id > dmadev->dma_num || chan_id > DMA_CHAN_NUM)
		return -EINVAL;

	/* Wait for DMA channel free */
	fsl_dma_wait(dmadev, dma_id, chan_id);
	/* Data len */
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->bcr, len);
	/* Prepare the high 4 bit of the 36 bit DMA address */
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->satr,
		 (in_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->satr)
		  & ~0xf) | (uint32_t)(src_phys >> 32));
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->datr,
		 (in_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->datr)
		  & ~0xf) | (uint32_t)(dest_phys >> 32));
	/* Set the low 32 bit address */
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->sar, src_phys);
	/* Make sure the early data is set */
	__sync_synchronize();
	out_be32(&dmadev->dma_ctrl[dma_id].ch[chan_id].ch_regs->dar, dest_phys);
	/* Make sure DMA start */
	__sync_synchronize();

	return 0;
}
