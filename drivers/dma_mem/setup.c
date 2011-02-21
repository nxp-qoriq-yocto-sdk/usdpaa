/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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
 * the /dev/fsl-shmem device, a pre-arranged physical base address (and
 * similarly reserved from regular linux use by a "mem=<...>" kernel boot
 * parameter). See conf.h for the hard-coded constants that are used. */

static int fd;

/* This global is exported for use in ptov/vtop inlines. It is the result of the
 * mmap(), but pre-cast to dma_addr_t, so if we have 64-bit physical addresses
 * the ptov/vtop inlines will have less conversion to do. */
dma_addr_t __dma_virt;
/* This is the same value, but it's the pointer type */
static void *virt;

int dma_mem_setup(void)
{
	void *trial;
	int ret = -ENODEV;
	fd = open(DMA_MEM_PATH, O_RDWR);
	if (fd < 0) {
		perror("can't open dma_mem device");
		return ret;
	}
	/* TODO: this needs to be improved but may not be possible until
	 * hugetlbfs is available. If we let the kernel choose the virt address,
	 * it will only guarantee page-alignment, yet our TLB1 hack in the
	 * kernel requires that this mapping be *size*-aligned. With this in
	 * mind, we'll do a trial-and-error proposing addresses to the kernel
	 * until we find one that works or give up. */
	for (trial = (void *)0x70000000; (unsigned long)trial < 0xc0000000;
				trial += DMA_MEM_SIZE) {
		virt = mmap(trial, DMA_MEM_SIZE, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_FIXED, fd, DMA_MEM_PHYS);
		if (virt != MAP_FAILED)
			break;
	}
	if (virt == MAP_FAILED) {
		perror("can't mmap() dma_mem device");
		goto err;
	}
	/* Present "carve up" is to use the first DMA_MEM_BPOOL bytes of dma_mem
	 * for buffer pools and the rest of dma_mem for ad-hoc allocations. */
	ret = dma_mem_alloc_init(virt + DMA_MEM_BPOOL,
				DMA_MEM_SIZE - DMA_MEM_BPOOL);
	if (ret)
		goto err;
	__dma_virt = (dma_addr_t)virt;
	printf("FSL dma_mem device mapped (phys=0x%x,virt=%p,sz=0x%x)\n",
		DMA_MEM_PHYS, virt, DMA_MEM_SIZE);
	return 0;
err:
	fprintf(stderr, "ERROR: dma_mem setup failed, ret = %d\n", ret);
	close(fd);
	return ret;
}
