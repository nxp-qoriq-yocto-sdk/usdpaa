/* Copyright (c) 2011 Freescale Semiconductor, Inc.
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

#include "pme2_private.h"

#define PME_RESIDUE_SIZE	128
#define PME_RESIDUE_ALIGN	64
#define PME_FLOW_SIZE		sizeof(struct pme_flow)
#define PME_FLOW_ALIGN		32

/***********************/
/* low-level functions */
/***********************/
struct pme_hw_residue *pme_hw_residue_new(void)
{
	return __dma_mem_memalign(PME_RESIDUE_ALIGN, PME_RESIDUE_SIZE);
}

void pme_hw_residue_free(struct pme_hw_residue *p)
{
	__dma_mem_free(p);
}

struct pme_hw_flow *pme_hw_flow_new(void)
{
	struct pme_flow *flow = __dma_mem_memalign(PME_FLOW_ALIGN,
						   PME_FLOW_SIZE);
	if (flow)
		memset(flow, 0, PME_FLOW_SIZE);
	return (struct pme_hw_flow *)flow;
}

void pme_hw_flow_free(struct pme_hw_flow *p)
{
	__dma_mem_free(p);
}

dma_addr_t pme_map(void *ptr)
{
	return dma_map_single(NULL, ptr, 1, DMA_BIDIRECTIONAL);
}
EXPORT_SYMBOL(pme_map);

int pme_map_error(dma_addr_t dma_addr)
{
	return dma_mapping_error(NULL, dma_addr);
}
EXPORT_SYMBOL(pme_map_error);
