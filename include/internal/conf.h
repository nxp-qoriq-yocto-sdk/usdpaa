/* Copyright (c) 2008-2011 Freescale Semiconductor, Inc.
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

#ifndef __CONF_H
#define __CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header should define all configuration symbols that have no API
 * impact. For those that affect the API (and especially the ABI!), put them in
 * <usdpaa/conf.h> instead.
 */

/* The contiguous memory map for 'dma_mem' uses the DMA_MEM_*** constants. The
 * first part of the memory map is used to seed buffer pools, as indicated by
 * these constants, and the ad-hoc buffer allocation will be confined to the
 * area following that range, which will be limited only be the size of the DMA
 * memory region allocated by the kernel. Note, we include the BPID here too
 * (even though it has nothing to do with the DMA driver), because it means the
 * app code has all the definitions it needs for seeding buffer pools.
 */
#define DMA_MEM_PATH		"/dev/fsl-usdpaa-shmem"
#define DMA_MEM_BP1_BPID	7
#define DMA_MEM_BP1_SIZE	192
#define DMA_MEM_BP1_NUM		0x4000 /* 0x4000*192==3145728 (3MB) */
#define DMA_MEM_BP2_BPID	8
#define DMA_MEM_BP2_SIZE	576
#define DMA_MEM_BP2_NUM		0x1000 /* 0x1000*576==2359296 (2.25MB) */
#define DMA_MEM_BP3_BPID	9
#define DMA_MEM_BP3_SIZE	1600
#define DMA_MEM_BP3_NUM		0x1000 /* 0x1000*1600==6553600 (6.25MB) */
#define DMA_MEM_BPOOL \
	(DMA_MEM_BP1_SIZE * DMA_MEM_BP1_NUM + \
	DMA_MEM_BP2_SIZE * DMA_MEM_BP2_NUM + \
	DMA_MEM_BP3_SIZE * DMA_MEM_BP3_NUM) /* 12058624 (11.5MB) */

/* Until device-trees (or device-tree replacements) are available, another thing
 * to hard-code is the FQID and BPID range allocation. */
#define FSL_FQID_RANGE_START	0x200	/* 512 */
#define FSL_FQID_RANGE_LENGTH	0x200	/* 512 */
#define FSL_BPID_RANGE_START	56
#define FSL_BPID_RANGE_LENGTH	8

/* When copying aligned words or shorts, try to avoid memcpy() */
#define CONFIG_TRY_BETTER_MEMCPY

/* disable support for run-time parameter checking, assertions, etc */
#undef CONFIG_FSL_DPA_CHECKING

/* support IRQs */
#define CONFIG_FSL_DPA_HAVE_IRQ

/* USDPAA has no concept of portal-sharing, so don't build it */
#undef CONFIG_FSL_DPA_PORTAL_SHARE

/* We need these, though they are "options" due to code-sharing with other
 * driver targets (kernel, etc). */
#define CONFIG_FSL_BMAN_PORTAL
#define CONFIG_FSL_QMAN_PORTAL

/* workarounds for errata and missing features in p4080 rev1 */
#define CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1

/* don't disable DCA on auto-initialised portals */
#undef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO_DCA

/* Interrupt-gating settings */
#define CONFIG_FSL_QMAN_PIRQ_DQRR_ITHRESH 0
#define CONFIG_FSL_QMAN_PIRQ_MR_ITHRESH 0
#define CONFIG_FSL_QMAN_PIRQ_IPERIOD 0

/* maximum number of DQRR entries to process in qman_poll() */
#define CONFIG_FSL_QMAN_POLL_LIMIT 8

/* don't compile support for DQRR prefetching (so stashing is required) */
#undef CONFIG_FSL_QMAN_DQRR_PREFETCHING

#ifdef __cplusplus
}
#endif
#endif
