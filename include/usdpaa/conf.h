/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef HEADER_USDPAA_CONF_H
#define HEADER_USDPAA_CONF_H

/* This header is included by <usdpaa/compat.h>, and thus by all other
 * <usdpaa/xxx.h> headers. It should provide the minimal set of configuration
 * primitives required by these headers, and thus by any code (internal,
 * application, or 3rd party) that includes them. */


/* The contiguous memory map for 'dma_mem' uses the DMA_MEM_*** constants, the
 * _PHYS and _SIZE values *must* agree with the "mem=<...>" kernel boot
 * parameter as well as the device-tree's "fsl-shmem" node.
 *
 * Also, the first part of that memory map is used to seed buffer pools, as
 * indicated by DMA_MEM_BPOOL. The ad-hoc buffer allocation will be confined to
 * the area following that range, in order to not conflict with buffer pool
 * usage.
 *
 * NB: these settings are required in the exported conf.h because of the inlined
 * dma_mem_ptov() and dma_mem_vtop() functions.
 */
#define DMA_MEM_PATH	"/dev/fsl-shmem"
#define DMA_MEM_PHYS	0x70000000 /* 1.75G */
#define DMA_MEM_SIZE	0x10000000 /* 256M */
#define DMA_MEM_BPOOL	0x05b80000 /* ~92M */


#endif /* HEADER_USDPAA_CONF_H */
