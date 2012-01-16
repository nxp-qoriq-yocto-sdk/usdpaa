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

#define PAGE_SIZE	0x1000
#define PAGE_MASK	(PAGE_SIZE - 1)
#define DMA_DATR_WR_SNOOP	0x50000
#define DMA_SATR_RD_SNOOP	0x50000
#define DMA_MR_BWC_DIS		(0xf << 24)
#define DMA_MR_SRW_EN		(0x1 << 10)
#define DMA_MR_CTM_EN		(0x1 << 2)
#define DMA_SR_CH_BUSY		(0x1 << 2)
#define DMA_SR_ERR		(0xf << 4)
#define DMA_BWC_MASK		(0xf << 24)
#define DMA_BWC_OFFSET		24

struct dma_ch_regs {
	uint32_t	mr;
	uint32_t	sr;
	uint32_t	eclndar;
	uint32_t	clndar;
	uint32_t	satr;
	uint32_t	sar;
	uint32_t	datr;
	uint32_t	dar;
	uint32_t	bcr;
	uint32_t	enlndar;
	uint32_t	nlndar;
	uint32_t	res;
	uint32_t	eclsdar;
	uint32_t	clsdar;
	uint32_t	enlsdar;
	uint32_t	nlsdar;
	uint32_t	ssr;
	uint32_t	dsr;
	uint32_t	res1[14];
};

struct dma_ch {
	struct dma_ch_regs *regs;	/* channel register map */
	int32_t fd;			/* dma channel uio device fd */
};
