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
#ifndef FSL_DMA_H
#define FSL_DMA_H

enum {
	DMA_BWC_1,
	DMA_BWC_2,
	DMA_BWC_4,
	DMA_BWC_8,
	DMA_BWC_16,
	DMA_BWC_32,
	DMA_BWC_64,
	DMA_BWC_128,
	DMA_BWC_256,
	DMA_BWC_512,
	DMA_BWC_1024,
	DMA_BWC_NUM,
	DMA_BWC_DIS = 0xf
};

struct dma_dev;

int fsl_dma_uio_init(struct dma_dev **dmadev);
int fsl_dma_uio_finish(struct dma_dev *dmadev);
int fsl_dma_chan_basic_direct_init(struct dma_dev *dmadev,
				   uint8_t dma_id, uint8_t chan_id);
int fsl_dma_chan_bwc(struct dma_dev *dmadev, uint8_t dma_id,
		     uint8_t chan_id, uint8_t bwc);
int fsl_dma_wait(struct dma_dev *dmadev, uint8_t dma_id, uint8_t chan_id);
int fsl_dma_direct_start(struct dma_dev *dmadev, uint8_t dma_id,
			 uint8_t chan_id, dma_addr_t src_phys,
			 dma_addr_t dest_phys, size_t len);
#endif
