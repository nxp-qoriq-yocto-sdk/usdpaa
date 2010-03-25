/*
 * Copyright (c) 2008-2010 Freescale Semiconductor, Inc.
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

/***********/
/* General */
/***********/

/* support for BUG_ON()s, might_sleep()s, etc */
#undef CONFIG_BUGON

/* When copying aligned words or shorts, try to avoid memcpy() */
#define CONFIG_TRY_BETTER_MEMCPY

/* The driver requires that CENA spaces be 16KB-aligned, whereas mmap() only
 * guarantees 4KB-alignment. Hmm. Workaround is to require *these*
 * [BQ]MAN_*** addresses for now.

 * The contiguous memory map for 'shmem' uses the FSL_SHMEM_*** constants, the
 * _PHYS and _SIZE values *must* agree with the "mem=<...>" kernel boot
 * parameter as well as the device-tree's "fsl-shmem" node.
 *
 * So the virt-address space we use for all of this is;
 *  BM_CENA     0x6ff00000 - 0x6f3fffff    at (1.75G - 1M); sz=256K
 *  QM_CENA     0x6ff40000 - 0x6f7fffff                     sz=256K
 *  BM_CINH     0x6ff80000 - 0x6fbfffff                     sz=256K
 *  QM_CINH     0x6ffc0000 - 0x6fffffff                     sz=256K
 *  shmem       0x70000000 - 0x7fffffff    at 1.75G; sz=256M
 */
#define BMAN_CENA(n)	(void *)(0x6ff00000 + (n)*16*1024)
#define QMAN_CENA(n)	(void *)(0x6ff40000 + (n)*16*1024)
#define BMAN_CINH(n)	(void *)(0x6ff80000 + (n)*4*1024)
#define QMAN_CINH(n)	(void *)(0x6ffc0000 + (n)*4*1024)

#define FSL_SHMEM_PATH	"/dev/fsl-shmem"
#define FSL_SHMEM_VIRT	(u32)0x70000000
#define FSL_SHMEM_PHYS	(u32)0x70000000 /* 1.75G */
#define FSL_SHMEM_SIZE	(u32)0x10000000 /* 256M */
#define __shmem_ptov(p) (void *)(p + (FSL_SHMEM_VIRT - FSL_SHMEM_PHYS))
#define __shmem_vtop(v) ((dma_addr_t)v - (FSL_SHMEM_VIRT - FSL_SHMEM_PHYS))

/********/
/* Bman */
/********/

/* support for run-time parameter checking, assertions, etc */
#undef CONFIG_FSL_BMAN_CHECKING

/* do not do slow-path processing via IRQ */
#undef CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_SLOW

/* do not do fast-path processing via IRQ */
#undef CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_FAST

/* portals do not initialise in recovery mode */
#undef CONFIG_FSL_BMAN_PORTAL_FLAG_RECOVER

#if defined(CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_SLOW) || \
		defined(CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_FAST)
#define CONFIG_FSL_BMAN_HAVE_IRQ
#else
#undef CONFIG_FSL_BMAN_HAVE_IRQ
#endif

#if !defined(CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_SLOW) || \
		!defined(CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_FAST)
#define CONFIG_FSL_BMAN_HAVE_POLL
#else
#undef CONFIG_FSL_BMAN_HAVE_POLL
#endif

/********/
/* Qman */
/********/

/* workarounds for errata and missing features in p4080 rev1 */
#define CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1

/* support for run-time parameter checking, assertions, etc */
#undef CONFIG_FSL_QMAN_CHECKING

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

/* do not do slow-path processing via IRQ */
#undef CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_SLOW

/* do not do fast-path processing via IRQ */
#undef CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_FAST

/* portals aren't SMP-locked, they're core-affine */
#undef CONFIG_FSL_QMAN_PORTAL_FLAG_LOCKED

/* portals do not initialise in recovery mode */
#undef CONFIG_FSL_QMAN_PORTAL_FLAG_RECOVER

#if defined(CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_SLOW) || \
		defined(CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_FAST)
#define CONFIG_FSL_QMAN_HAVE_IRQ
#else
#undef CONFIG_FSL_QMAN_HAVE_IRQ
#endif

#if !defined(CONFIG_FSL_QMAN_PIRQ_SLOW) || \
		!defined(CONFIG_FSL_QMAN_PIRQ_FAST)
#define CONFIG_FSL_QMAN_HAVE_POLL
#else
#undef CONFIG_FSL_QMAN_HAVE_POLL
#endif

#ifdef __cplusplus
}
#endif
#endif
