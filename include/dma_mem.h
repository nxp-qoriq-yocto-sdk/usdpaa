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

/* These types are for linux-compatibility, eg. they're used by single-source
 * qbman drivers. These aren't in compat.h because that would lead to
 * dependencies being back-to-front. */
typedef uint32_t dma_addr_t;
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

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

/* Internal base-address pointer, it's exported only to allow the ptov/vtop
 * functions (below) to be implemented as inlines. Note, this is dma_addr_t
 * rather than void*, so that 32/64 type conversions aren't required for
 * ptov/vtop when sizeof(dma_addr_t)>sizeof(void*). */
extern dma_addr_t __dma_virt;

/* Conversion between user-virtual ("v") and physical ("p") address */
static inline void *dma_mem_ptov(dma_addr_t p)
{
	return (void *)(p + __dma_virt - DMA_MEM_PHYS);
}
static inline dma_addr_t dma_mem_vtop(void *v)
{
	return (dma_addr_t)v + DMA_MEM_PHYS - __dma_virt;
}

/* These interfaces are also for linux-compatibility, but are declared down here
 * because the implementations are dependent on dma_mem-specific interfaces
 * above. */
#define DMA_BIT_MASK(n) (((uint64_t)1 << (n)) - 1)
static inline int dma_set_mask(void *dev __always_unused,
			uint64_t v __always_unused)
{
	return 0;
}
static inline dma_addr_t dma_map_single(void *dev __always_unused,
			void *cpu_addr, size_t size __maybe_unused,
			enum dma_data_direction direction __always_unused)
{
	BUG_ON((u32)cpu_addr < DMA_MEM_VIRT);
	BUG_ON(((u32)cpu_addr + size) > (DMA_MEM_VIRT + DMA_MEM_SIZE));
	return dma_mem_vtop(cpu_addr);
}
static inline int dma_mapping_error(void *dev __always_unused,
				dma_addr_t dma_addr __always_unused)
{
	return 0;
}

#endif	/* __DMA_MEM_H */
