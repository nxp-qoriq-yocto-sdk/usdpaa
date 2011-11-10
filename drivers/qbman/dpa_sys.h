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
#include <internal/of.h>

/* For 2-element tables related to cache-inhibited and cache-enabled mappings */
#define DPA_PORTAL_CE 0
#define DPA_PORTAL_CI 1

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

/* This takes a "phandle" and dereferences to the cpu device-tree node,
 * returning the cpu index. Returns negative error codes. */
static inline int check_cpu_phandle(phandle ph)
{
	const u32 *cpu_val;
	const struct device_node *tmp_node = of_find_node_by_phandle(ph);
	size_t lenp;

	if (!tmp_node)
		return -EINVAL;
	cpu_val = of_get_property(tmp_node, "reg", &lenp);
	if (!cpu_val || (lenp != sizeof(*cpu_val))) {
		pr_err("Can't get %s property 'reg'\n", tmp_node->full_name);
		return -ENODEV;
	}
	return *cpu_val;
}
