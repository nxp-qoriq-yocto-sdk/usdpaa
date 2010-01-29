/* Copyright (c) 2008, 2009 Freescale Semiconductor, Inc.
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

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/of_platform.h>
#include <linux/kthread.h>
#include <linux/lmb.h>
#include <linux/completion.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

/* CONFIG_FSL_BMAN_HAVE_POLL is defined via Kconfig, because the API header is
 * conditional upon it. CONFIG_FSL_BMAN_CHECKING is also defined via Kconfig,
 * but because it's a knob for users. Everything else affects only
 * implementation (not interface), so we define it here, internally. */

/* do slow-path processing via IRQ */
#define CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_SLOW

/* do fast-path processing via IRQ */
#define CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_FAST

/* portals do not initialise in recovery mode */
#undef CONFIG_FSL_BMAN_PORTAL_FLAG_RECOVER

#if defined(CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_SLOW) || \
		defined(CONFIG_FSL_BMAN_PORTAL_FLAG_IRQ_FAST)
#define CONFIG_FSL_BMAN_HAVE_IRQ
#else
#undef CONFIG_FSL_BMAN_HAVE_IRQ
#endif

/* TODO: NB, we currently assume that hwsync() and lwsync() imply compiler
 * barriers and that dcb*() won't fall victim to compiler or execution
 * reordering with respect to other code/instructions that manipulate the same
 * cacheline. */
#define hwsync() \
	do { \
		__asm__ __volatile__ ("sync" : : : "memory"); \
	} while(0)
#define lwsync() \
	do { \
		__asm__ __volatile__ ("lwsync" : : : "memory"); \
	} while(0)
#define dcbzl(p) \
	do { \
		__asm__ __volatile__ ("dcbzl 0,%0" : : "r" (p)); \
	} while(0)
#define dcbf(p) \
	do { \
		__asm__ __volatile__ ("dcbf 0,%0" : : "r" (p)); \
	} while(0)
#define dcbt_ro(p) \
	do { \
		__asm__ __volatile__ ("dcbt 0,%0" : : "r" (p)); \
	} while(0)
#define dcbt_rw(p) \
	do { \
		__asm__ __volatile__ ("dcbtst 0,%0" : : "r" (p)); \
	} while(0)
#define dcbi(p) dcbf(p)

#ifdef CONFIG_FSL_BMAN_CHECKING
#define BM_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			dump_stack(); \
			panic("assertion failure"); \
		} \
	} while(0)
#else
#define BM_ASSERT(x)
#endif

