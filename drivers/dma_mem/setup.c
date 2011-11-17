/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
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

#include "private.h"

/* For an efficient conversion between user-space virtual address map(s) and bus
 * addresses required by hardware for DMA, we use a single contiguous mmap() on
 * the /dev/fsl-usdpaa device, and extract the corresponding physical base
 * address. */

/* This global is exported for use in ptov/vtop inlines. It is the delta between
 * virtual and physical addresses, pre-cast to dma_addr_t. */
dma_addr_t __dma_virt2phys;
/* The mapped virtual address */
static void *virt;
/* The length of the DMA region */
static uint64_t len;

/* This is the physical address range reserved for bpool usage */
static dma_addr_t bpool_base;
static size_t bpool_range;

int dma_mem_setup(void)
{
	uint64_t phys;
	int ret = process_dma_map(&virt, &phys, &len);
	if (ret)
		return ret;
	/* Present "carve up" is to use the first DMA_MEM_BPOOL bytes of dma_mem
	 * for buffer pools and the rest of dma_mem for ad-hoc allocations. */
	ret = dma_mem_alloc_init(virt + DMA_MEM_BPOOL, len - DMA_MEM_BPOOL);
	if (ret) {
		process_dma_unmap();
		return ret;
	}
	__dma_virt2phys = phys - (dma_addr_t)(unsigned long)virt;
	bpool_base = phys;
	bpool_range = DMA_MEM_BPOOL;
	printf("FSL dma_mem device mapped (phys=0x%"PRIx64",virt=%p,sz=0x%"PRIx64")\n",
		phys, virt, len);
	return 0;
}

dma_addr_t dma_mem_bpool_base(void)
{
	return bpool_base;
}

size_t dma_mem_bpool_range(void)
{
	return bpool_range;
}

int dma_mem_bpool_set_range(size_t sz)
{
	int ret = dma_mem_alloc_reinit(virt + sz, len - sz,
				       virt + bpool_range,
				       len - bpool_range);
	if (!ret)
		bpool_range = sz;
	return ret;
}
