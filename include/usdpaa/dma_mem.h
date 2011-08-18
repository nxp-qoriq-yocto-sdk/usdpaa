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

#ifndef __DMA_MEM_H
#define __DMA_MEM_H

#include <usdpaa/compat.h>

/* These types are for linux-compatibility, eg. they're used by single-source
 * qbman drivers. Only dma_addr_t is in compat.h, because it is required by
 * fsl_qman.h. The remaining definitions are here because they're only required
 * by the the "dma_mem" driver interface. */
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};
#define DMA_BIT_MASK(n) (((uint64_t)1 << (n)) - 1)
int dma_set_mask(void *dev __always_unused, uint64_t v __always_unused);
dma_addr_t dma_map_single(void *dev __always_unused, void *cpu_addr,
			size_t size __maybe_unused,
			enum dma_data_direction direction __always_unused);
int dma_mapping_error(void *dev __always_unused,
			dma_addr_t dma_addr __always_unused);

/* The following definitions and interfaces are USDPAA-specific */

/* For an efficient conversion between user-space virtual address map(s) and bus
 * addresses required by hardware for DMA, we use a single contiguous mmap() on
 * the /dev/mem device, a pre-arranged physical base address (and
 * similarly reserved from regular linux use by a "mem=<...>" kernel boot
 * parameter). See conf.h for the hard-coded constants that are used. */

/* initialise ad-hoc DMA allocation memory.
 *    -> returns non-zero on failure.
 */
int dma_mem_setup(void);

/* Ad-hoc DMA allocation (not optimised for speed...). NB, the size must be
 * provided to 'free'. */
void *dma_mem_memalign(size_t boundary, size_t size);
void dma_mem_free(void *ptr, size_t size);

/* Internal base-address delta, this is exported only to allow the ptov/vtop
 * functions (below) to be implemented as inlines. */
extern dma_addr_t __dma_virt2phys;

/* Conversion between user-virtual ("v") and physical ("p") address. NB, the
 * double-casts avoid the "cast to pointer from integer of different size" and
 * "cast from pointer to integer of different size" warnings. */
static inline void *dma_mem_ptov(dma_addr_t p)
{
	return (void *)(unsigned long)(p - __dma_virt2phys);
}
static inline dma_addr_t dma_mem_vtop(void *v)
{
	return (dma_addr_t)(unsigned long)v + __dma_virt2phys;
}

/* The physical address range used for seeding Bman pools */
dma_addr_t dma_mem_bpool_base(void);
size_t dma_mem_bpool_range(void);

/* This API allows the application to change the size of the dma_mem reservation
 * for use by buffer pools. It will only succeed if no ad-hoc allocations from
 * dma_mem_memalign() are outstanding. The application is responsible for seeding
 * buffer pools so it should ensure it does not conflict with this setting. */
int dma_mem_bpool_set_range(size_t sz);

#endif	/* __DMA_MEM_H */
