/* Copyright (c) 2011 Freescale Semiconductor, Inc.
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

#include "dpa_sys.h"

#ifdef CONFIG_FSL_DPA_HAVE_IRQ

static LIST_HEAD(irqs);

int qbman_request_irq(int irq, irqreturn_t (*isr)(int irq, void *arg),
			unsigned long flags, const char *name, void *arg)
{
	struct qbman_uio_irq *it, *newirq;
	list_for_each_entry(it, &irqs, node) {
		if (it->irq == irq) {
			pr_err("%s: irq %d, conflict '%s' and '%s'\n", __func__,
				irq, it->name, name);
			return -EINVAL;
		}
		if (it->irq > irq)
			break;
	}
	newirq = malloc(sizeof(*newirq));
	if (!newirq)
		return -ENOMEM;
	newirq->irq = irq;
	newirq->isr = isr;
	newirq->flags = flags;
	newirq->name = name;
	newirq->arg = arg;
	/* Append to the tail. NB this works if the for() loop found no
	 * insertion point, because in that case it->node==&irqs. */
	list_add_tail(&newirq->node, &it->node);
	pr_info("%s: registered irq %d:%s\n", __func__, irq, name);
	return 0;
}

static struct qbman_uio_irq *find_irq(int irq)
{
	struct qbman_uio_irq *it;
	list_for_each_entry(it, &irqs, node) {
		if (it->irq == irq)
			return it;
	}
	return NULL;
}

int qbman_free_irq(int irq, void *arg)
{
	struct qbman_uio_irq *it = find_irq(irq);
	if (!it) {
		pr_err("%s: no irq %d\n", __func__, irq);
		return -EINVAL;
	}
	if (it->arg != arg) {
		pr_err("%s: irq %d:%s arg mismatch\n", __func__, irq, it->name);
		return -EINVAL;
	}
	list_del(&it->node);
	pr_info("%s: deregistered irq %d:%s\n", __func__, it->irq, it->name);
	free(it);
	return 0;
}

const struct qbman_uio_irq *qbman_get_irq_handler(int irq)
{
	return find_irq(irq);
}

#endif

