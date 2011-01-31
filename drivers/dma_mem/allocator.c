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

#include "private.h"

#undef ALLOC_DEBUG
#ifdef DEBUG_DMA_ALLOC
#define ALLOC_DEBUG
#endif

/* Global state for the allocator */
static DEFINE_SPINLOCK(alloc_lock);
static LIST_HEAD(alloc_list);

/* The allocator is a (possibly-empty) list of these; */
struct alloc_node {
	struct list_head list;
	unsigned long base;
	unsigned long sz;
};

#ifdef ALLOC_DEBUG
#define DPRINT		pr_info
static void DUMP(void)
{
	int off = 0;
	char buf[256];
	struct alloc_node *p;
	if (list_empty(&alloc_list))
		off = snprintf(buf, 255, "<empty>");
	else list_for_each_entry(p, &alloc_list, list) {
		if (off < 255)
			off += snprintf(buf + off, 255-off, "{%lx,%lx}",
				p->base, p->sz);
	}
	buf[off] = '\0';
	pr_info("%s\n", buf);
}
#else
#define DPRINT(x...)	do { ; } while(0)
#define DUMP()		do { ; } while(0)
#endif

void *dma_mem_memalign(size_t align, size_t size)
{
	struct alloc_node *i = NULL;
	unsigned long base, num = 0;
	struct alloc_node *margin_left, *margin_right;
	void *result = NULL;

	DPRINT("dma_mem_memalign(align=%d,size=%d)\n", align, size);
	DUMP();
	/* If 'align' is 0, it should behave as though it was 1 */
	if (!align)
		align = 1;
	margin_left = kmalloc(sizeof(*margin_left), GFP_KERNEL);
	if (!margin_left)
		goto err;
	margin_right = kmalloc(sizeof(*margin_right), GFP_KERNEL);
	if (!margin_right) {
		kfree(margin_left);
		goto err;
	}
	spin_lock_irq(&alloc_lock);
	list_for_each_entry(i, &alloc_list, list) {
		base = (i->base + align - 1) / align;
		base *= align;
		if ((base - i->base) >= i->sz)
			/* alignment is impossible, regardless of size */
			continue;
		num = i->sz - (base - i->base);
		if (num >= size) {
			/* this one will do nicely */
			num = size;
			goto done;
		}
	}
	i = NULL;
done:
	if (i) {
		if (base != i->base) {
			margin_left->base = i->base;
			margin_left->sz = base - i->base;
			list_add_tail(&margin_left->list, &i->list);
		} else
			kfree(margin_left);
		if ((base + num) < (i->base + i->sz)) {
			margin_right->base = base + num;
			margin_right->sz = (i->base + i->sz) -
						(base + num);
			list_add(&margin_right->list, &i->list);
		} else
			kfree(margin_right);
		list_del(&i->list);
		kfree(i);
		result = (void *)base;
	}
	spin_unlock_irq(&alloc_lock);
err:
	DPRINT("returning %p\n", result);
	DUMP();
	return result;
}
EXPORT_SYMBOL(dma_mem_memalign);

static int _dma_mem_free(void *ptr, size_t size)
{
	struct alloc_node *i, *node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	DPRINT("dma_mem_free(ptr=%p,sz=%d)\n", ptr, size);
	DUMP();

	spin_lock_irq(&alloc_lock);
	node->base = (unsigned long)ptr;
	node->sz = size;
	list_for_each_entry(i, &alloc_list, list) {
		DPRINT("  comparing with (ptr=%lx,sz=%ld)\n",
			i->base, i->sz);
		if (i->base >= node->base) {
			DPRINT("  yes, we'll prepend to that\n");
			list_add_tail(&node->list, &i->list);
			goto done;
		} else
			DPRINT("  no, keep looking\n");
	}
	DPRINT("  we're to the right of everything\n");
	list_add_tail(&node->list, &alloc_list);
done:
	DUMP();
	/* Merge to the left if they match */
	i = list_entry(node->list.prev, struct alloc_node, list);
	if (node->list.prev != &alloc_list) {
		BUG_ON((i->base + i->sz) > node->base);
		if ((i->base + i->sz) == node->base) {
			DPRINT("  merging to the left with (ptr=%lx,sz=%ld)\n",
				i->base, i->sz);
			node->base = i->base;
			node->sz += i->sz;
			list_del(&i->list);
			kfree(i);
		}
	}
	/* Merge to the right */
	i = list_entry(node->list.next, struct alloc_node, list);
	if (node->list.next != &alloc_list) {
		BUG_ON((node->base + node->sz) > i->base);
		if ((node->base + node->sz) == i->base) {
			DPRINT("  merging to the right with (ptr=%lx,sz=%ld)\n",
				i->base, i->sz);
			node->sz += i->sz;
			list_del(&i->list);
			kfree(i);
		}
	}
	DPRINT("  done\n");
	spin_unlock_irq(&alloc_lock);
	DUMP();
	return 0;
}
void dma_mem_free(void *ptr, size_t size)
{
	__maybe_unused int ret = _dma_mem_free(ptr, size);
	BUG_ON(ret);
}
EXPORT_SYMBOL(dma_mem_free);

int dma_mem_alloc_init(void *bar, size_t sz)
{
	return _dma_mem_free(bar, sz);
}
