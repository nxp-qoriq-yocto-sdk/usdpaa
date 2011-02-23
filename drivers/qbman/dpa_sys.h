/* Copyright (c) 2008-2011 Freescale Semiconductor, Inc.
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

#include <usdpaa/dma_mem.h>
#include <internal/compat.h>

#ifdef CONFIG_FSL_DPA_CHECKING
#define DPA_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			exit(EXIT_FAILURE); \
		} \
	} while(0)
#else
#define DPA_ASSERT(x)		do { ; } while(0)
#endif

/* Commonly used combo */
static inline void dcbit_ro(void *p)
{
	dcbi(p);
	dcbt_ro(p);
}

/* For trees that contain such support, these stubs are re-mapped to
 * hypervisor+failover features. */
struct device_node {
	int offset;
	const char *full_name;
};
#define for_each_child_of_node(n1,n2) while (0)
static inline int pamu_enable_liodn(struct device_node *n __always_unused,
					int i __always_unused)
{
	return 0;
}

#ifdef CONFIG_FSL_DPA_HAVE_IRQ
struct qbman_uio_irq {
	int irq;
	irqreturn_t (*isr)(int irq, void *arg);
	unsigned long flags;
	const char *name;
	void *arg;
	struct list_head node;
};
/* This is the interface from the platform-agnostic driver code to (de)register
 * interrupt handlers. We simply create/destroy corresponding structs. */
int qbman_request_irq(int irq, irqreturn_t (*isr)(int irq, void *arg),
			unsigned long flags, const char *name, void *arg);
int qbman_free_irq(int irq, void *arg);
/* This is the interface from the platform-specific driver code to obtain
 * interrupt handlers that have been registered. */
const struct qbman_uio_irq *qbman_get_irq_handler(int irq);
#endif
