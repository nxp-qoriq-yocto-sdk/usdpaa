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
 * The contiguous memory map for 'dma_mem' uses the DMA_MEM_*** constants, the
 * _PHYS and _SIZE values *must* agree with the "mem=<...>" kernel boot
 * parameter as well as the device-tree's "fsl-shmem" node.
 *
 * Also, the first part of that memory map is used to seed buffer pools, as
 * indicated by DMA_MEM_BPOOL. The ad-hoc buffer allocation will be confined to
 * the area following that range, in order to not conflict with buffer pool
 * usage.
 */
#define DMA_MEM_PATH	"/dev/fsl-shmem"
#define DMA_MEM_PHYS	0x70000000 /* 1.75G */
#define DMA_MEM_SIZE	0x10000000 /* 256M */
#define DMA_MEM_BPOOL	0x05b80000 /* ~92M */

/* Until device-trees (or device-tree replacements) are available, another thing
 * to hard-code is the FQID and BPID range allocation. */
#define FSL_FQID_RANGE_START	0x200	/* 512 */
#define FSL_FQID_RANGE_LENGTH	0x080	/* 128 */
#define FSL_BPID_RANGE_START	56
#define FSL_BPID_RANGE_LENGTH	8

/* support for BUG_ON()s, might_sleep()s, etc */
#undef CONFIG_BUGON

/* When copying aligned words or shorts, try to avoid memcpy() */
#define CONFIG_TRY_BETTER_MEMCPY

/* don't support blocking (so, WAIT flags won't be #define'd) */
#undef CONFIG_FSL_DPA_CAN_WAIT

#ifdef CONFIG_FSL_DPA_CAN_WAIT
/* if we can "WAIT" - can we "WAIT_SYNC" too? */
#undef CONFIG_FSL_DPA_CAN_WAIT_SYNC
#endif

/* disable support for run-time parameter checking, assertions, etc */
#undef CONFIG_FSL_DPA_CHECKING

/* support IRQs */
#define CONFIG_FSL_DPA_HAVE_IRQ

/* workarounds for errata and missing features in p4080 rev1 */
#define CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1

/* don't use rev1-specific adaptive "backoff" for EQCR:CI updates */
#undef CONFIG_FSL_QMAN_ADAPTIVE_EQCR_THROTTLE

/* support FQ allocator built on top of BPID 0 */
#define CONFIG_FSL_QMAN_FQALLOCATOR

/* don't disable DCA on auto-initialised portals */
#undef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO_DCA

/* Interrupt-gating settings */
#define CONFIG_FSL_QMAN_PIRQ_DQRR_ITHRESH 0
#define CONFIG_FSL_QMAN_PIRQ_MR_ITHRESH 0
#define CONFIG_FSL_QMAN_PIRQ_IPERIOD 0

/* maximum number of DQRR entries to process in qman_poll() */
#define CONFIG_FSL_QMAN_POLL_LIMIT 8

/* don't compile support for NULL FQ handling */
#undef CONFIG_FSL_QMAN_NULL_FQ_DEMUX

/* don't compile support for DQRR prefetching (so stashing is required) */
#undef CONFIG_FSL_QMAN_DQRR_PREFETCHING

#ifdef __cplusplus
}
#endif
#endif
