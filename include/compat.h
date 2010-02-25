/* Copyright (c) 2008-2010 Freescale Semiconductor, Inc.
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
 */

#ifndef HEADER_COMPAT_H
#define HEADER_COMPAT_H

#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

/* Strange though it may seem, all qman/bman-dependent apps include this header,
 * so this is a good place to force the inclusion of conf.h. There are
 * unfortunate side-effects to requiring that apps include it directly - eg. if
 * an app does not include it, it may compile ok but assume all configuration
 * choices are deselected (which may mean the driver and the app may be
 * behaviourally incompatible). */
#include <conf.h>

/* NB: these compatibility shims are in this exported header because they're
 * required by interfaces shared with linux drivers (ie. for "single-source"
 * purposes).
 */

/* Tracing - #define WANT_MARKPOINTS before including this file */
#ifdef WANT_MARKPOINTS
static inline void markpoint(const uint32_t markid) {
	asm volatile ("and %0,%0,%0\n" : : "i"(markid) : "memory");
}
#else
#define markpoint(id)	do { ; } while (0)
#endif

/* Compiler/type stuff */
typedef unsigned char   u8;
typedef unsigned char   __u8;
typedef unsigned short  u16;
typedef unsigned short  __u16;
typedef unsigned int    u32;
typedef unsigned int    __u32;
typedef uint64_t	u64;
typedef uint64_t	__u64;
typedef unsigned int	gfp_t;
typedef int		phandle;
#define __UNUSED	__attribute__((unused))
#define noinline	__attribute__((noinline))
#define __packed	__attribute__((__packed__))
#define ____cacheline_aligned __attribute__((aligned(64)))
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#define __iomem
#define __stringify_1(x) #x
#define __stringify(x)	__stringify_1(x)
/* GALAK: I doubt my impl of in/out_be32 are any good. There's probably an
 * __iomem missing (and presumably the above definition of __iomem is
 * insufficient too) and perhaps a volatile. Maybe some asm too? */
static inline u32 in_be32(volatile void *__p)
{
	volatile u32 *p = __p;
	return *p;
}
static inline void out_be32(volatile void *__p, u32 val)
{
	volatile u32 *p = __p;
	*p = val;
}
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
#define barrier() \
	do { \
		__asm__ __volatile__ ("" : : : "memory"); \
	} while(0)
#define dcbi(p) dcbf(p)
#define cpu_relax()	do { ; } while(0)
#define EINTR		4
#define ENODEV		19
#define MODULE_AUTHOR(s)
#define MODULE_LICENSE(s)
#define MODULE_DESCRIPTION(s)
#define EXPORT_SYMBOL(x)
#define module_init(fn) int m_##fn(void) { return fn(); }
#define module_exit(fn) void m_##fn(void) { fn(); }
#define GFP_KERNEL	0
#define __KERNEL__
#define __init
#define lower_32_bits(x) ((u32)(x))
#define upper_32_bits(x) ((u32)(((x) >> 16) >> 16))
#define panic(x) \
do { \
	printf("panic: %s", x); \
	abort(); \
} while(0)
#define container_of(p, t, f) (t *)((void *)p - offsetof(t, f))

/* SMP stuff */
#define DEFINE_PER_CPU(t,x)	__thread t per_cpu__##x
#define per_cpu(x,c)		per_cpu__##x
#define get_cpu_var(x)		per_cpu__##x
#define put_cpu_var(x)		do { ; } while(0)

/* Interrupt stuff */
typedef uint32_t	irqreturn_t; /* as per hwi.h */
#define IRQ_HANDLED	0
#define local_irq_disable()	do { ; } while(0)
#define local_irq_enable()	do { ; } while(0)
#define request_irq(irq, isr, args, devname, portal) 0
#define free_irq(irq, portal)	0
#define irq_can_set_affinity(x)	0
#define irq_set_affinity(x,y)	0

/* GALAK: this stuff is also presuming that we have no interrupts(/signals) and
 * that we're not multi-threading. */
/* Spinlock stuff */
#define spinlock_t		uint32_t
#define SPIN_LOCK_UNLOCKED	0
#define DEFINE_SPINLOCK(x)	__UNUSED spinlock_t x = SPIN_LOCK_UNLOCKED
#define spin_lock_init(x)	do { *(x) = 0; } while(0)
#define spin_lock(x)		do { ; } while(0)
#define spin_unlock(x)		do { ; } while(0)
#define spin_lock_irq(x)	do { ; } while(0)
#define spin_unlock_irq(x)	do { ; } while(0)

/* Atomic stuff */
typedef unsigned long	atomic_t;

/* Waitqueue stuff */
typedef struct { }		wait_queue_head_t;
#define DECLARE_WAIT_QUEUE_HEAD(x) DEFINE_SPINLOCK(x)
#define might_sleep()		do { ; } while(0)
#define init_waitqueue_head(x)	do { ; } while(0)
#define wake_up(x)		do { ; } while(0)
#define wait_event(x, c) \
do { \
	while (!(c)) { \
		bman_poll(); \
		qman_poll(); \
	} \
} while(0)
#define wait_event_interruptible(x, c) \
({ \
	wait_event(x, c); \
	0; \
})

/* Completion stuff */
#define DECLARE_COMPLETION(n) int n = 0;
#define complete(n) \
do { \
	*n = 1; \
} while(0)
#define wait_for_completion(n) \
do { \
	while (!*n) { \
		bman_poll(); \
		qman_poll(); \
	} \
	*n = 0; \
} while(0)

/* Platform device stuff */
struct platform_device { void *dev; };
static inline struct
platform_device *platform_device_alloc(const char *name __UNUSED,
					int id__UNUSED)
{
	struct platform_device *ret = malloc(sizeof(*ret));
	if (ret)
		ret->dev = NULL;
	return ret;
}
#define platform_device_add(pdev)	0
#define platform_device_del(pdev)	do { ; } while(0)
static inline void platform_device_put(struct platform_device *pdev)
{
	free(pdev);
}

/* DMA stuff */
typedef u32 dma_addr_t;
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};
static inline dma_addr_t dma_map_single(void *dev __UNUSED,
				void *cpu_addr,
				size_t size __UNUSED,
				enum dma_data_direction direction __UNUSED)
{
	/* GALAK: need this to convert cpu_addr to real-physical. The current
	 * implementation is a cast, which is clearly bogus. */
	return (dma_addr_t)cpu_addr;
}
static inline int dma_mapping_error(void *dev __UNUSED,
				dma_addr_t dma_addr __UNUSED)
{	
	return 0;
}

/* Allocator stuff */
#define kmalloc(sz, t)	malloc(sz)
#define kfree(p)	free(p)
static inline void *kzalloc(size_t sz, gfp_t foo __UNUSED)
{
	void *ptr = malloc(sz);
	if (ptr)
		memset(ptr, 0, sz);
	return ptr;
}
static inline unsigned long get_zeroed_page(gfp_t foo)
{
	void *p = memalign(4096, 4096);
	if (p)
		memset(p, 0, 4096);
	return (unsigned long)p;
}
struct kmem_cache {
	size_t sz;
	size_t align;
};
#define SLAB_HWCACHE_ALIGN	0
static inline struct kmem_cache *kmem_cache_create(const char *n __UNUSED,
		 size_t sz, size_t align, unsigned long flags __UNUSED,
			void (*c)(void *) __UNUSED)
{
	struct kmem_cache *ret = malloc(sizeof(*ret));
	if (ret) {
		ret->sz = sz;
		ret->align = align;
	}
	return ret;
}
static inline void kmem_cache_destroy(struct kmem_cache *c)
{
	free(c);
}
static inline void *kmem_cache_alloc(struct kmem_cache *c, gfp_t f __UNUSED)
{
	return memalign(c->align, c->sz);
}
static inline void kmem_cache_free(struct kmem_cache *c __UNUSED, void *p)
{
	free(p);
}
static inline void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t f)
{
	void *ret = kmem_cache_alloc(c, f);
	if (ret)
		memset(ret, 0, c->sz);
	return ret;
}

/* Bitfield stuff */
#define BITS_MASK(idx)	((unsigned long)1 << ((idx) & 31))
#define BITS_IDX(idx)	((idx) >> 5)
static inline unsigned long test_bits(unsigned long mask,
				volatile unsigned long *p)
{
	return *p & mask;
}
static inline int test_bit(int idx, volatile unsigned long *bits)
{
	return test_bits(BITS_MASK(idx), bits + BITS_IDX(idx));
}
static inline void set_bits(unsigned long mask, volatile unsigned long *p)
{
	*p |= mask;
}
static inline void set_bit(int idx, volatile unsigned long *bits)
{
	set_bits(BITS_MASK(idx), bits + BITS_IDX(idx));
}
static inline void clear_bits(unsigned long mask, volatile unsigned long *p)
{
	*p &= ~mask;
}
static inline void clear_bit(int idx, volatile unsigned long *bits)
{
	clear_bits(BITS_MASK(idx), bits + BITS_IDX(idx));
}
static inline unsigned long test_and_set_bits(unsigned long mask,
					volatile unsigned long *p)
{
	unsigned long ret = test_bits(mask, p);
	set_bits(mask, p);
	return ret;
}
static inline int test_and_set_bit(int idx, volatile unsigned long *bits)
{
	int ret = test_bit(idx, bits);
	set_bit(idx, bits);
	return ret;
}
static inline int test_and_clear_bit(int idx, volatile unsigned long *bits)
{
	int ret = test_bit(idx, bits);
	clear_bit(idx, bits);
	return ret;
}
static inline int find_next_zero_bit(unsigned long *bits, int limit, int idx)
{
	while ((++idx < limit) && test_bit(idx, bits))
		;
	return idx;
}
static inline int find_first_zero_bit(unsigned long *bits, int limit)
{
	int idx = 0;
	while (test_bit(idx, bits) && (++idx < limit))
		;
	return idx;
}

/* printk() stuff */
#define printk(fmt, args...)	do_not_use_printk
#define nada(fmt, args...)	do { ; } while(0)

#define pr_crit(fmt, args...)	printf(fmt, ##args)
#define pr_err(fmt, args...)	printf(fmt, ##args)
#define pr_warning(fmt, args...) printf(fmt, ##args)
#define pr_info(fmt, args...)	printf(fmt, ##args)

/* Debug stuff */
#define BUG()	abort()
#ifdef CONFIG_BUGON
#define BUG_ON(c) \
do { \
	if (c) { \
		pr_crit("BUG: %s:%d\n", __FILE__, __LINE__); \
		abort(); \
	} \
} while(0)
#define might_sleep_if(c)	BUG_ON(c)
#define msleep(x) \
do { \
	pr_crit("BUG: illegal call %s:%d\n", __FILE__, __LINE__); \
	exit(1); \
} while(0)
#else
#define BUG_ON(c)		do { ; } while(0)
#define might_sleep_if(c)	do { ; } while(0)
#define msleep(x)		do { ; } while(0)
#endif
#ifdef CONFIG_FSL_BMAN_CHECKING
#define BM_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			exit(1); \
		} \
	} while(0)
#else
#define BM_ASSERT(x)		do { ; } while(0)
#endif
#ifdef CONFIG_FSL_QMAN_CHECKING
#define QM_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			exit(1); \
		} \
	} while(0)
#else
#define QM_ASSERT(x)		do { ; } while(0)
#endif
static inline void __hexdump(unsigned long start, unsigned long end,
			unsigned long p, size_t sz, const unsigned char *c)
{
	while (start < end) {
		unsigned int pos = 0;
		char buf[64];
		int nl = 0;
		pos += sprintf(buf + pos, "%08lx: ", start);
		do {
			if ((start < p) || (start >= (p + sz)))
				pos += sprintf(buf + pos, "..");
			else
				pos += sprintf(buf + pos, "%02x", *(c++));
			if (!(++start & 15)) {
				buf[pos++] = '\n';
				nl = 1;
			} else {
				nl = 0;
				if(!(start & 1))
					buf[pos++] = ' ';
				if(!(start & 3))
					buf[pos++] = ' ';
			}
		} while (start & 15);
		if (!nl)
			buf[pos++] = '\n';
		buf[pos] = '\0';
		pr_info("%s", buf);
	}
}
static inline void hexdump(const void *ptr, size_t sz)
{
	unsigned long p = (unsigned long)ptr;
	unsigned long start = p & ~(unsigned long)15;
	unsigned long end = (p + sz + 15) & ~(unsigned long)15;
	const unsigned char *c = ptr;
	__hexdump(start, end, p, sz, c);
}

/****************/
/* Linked-lists */
/****************/

/* Allow linux linked-list-dependent code to build on LWE */
struct list_head {
	struct list_head *prev;
	struct list_head *next;
};
#define INIT_LIST_HEAD(p) \
do { \
	struct list_head *__p298 = (p); \
	__p298->prev = __p298->next =__p298; \
} while(0)
#define list_add_tail(p,l) \
do { \
	struct list_head *__p298 = (p); \
	struct list_head *__l298 = (l); \
	__p298->prev = __l298->prev; \
	__p298->next = __l298; \
	__l298->prev->next = __p298; \
	__l298->prev = __p298; \
} while(0)
#define list_for_each_entry(i, l, name) \
	for (i = (typeof(i))((void *)(l)->next - offsetof(typeof(*i), name)); \
		&i->name != (l); \
		i = (typeof(i))((void *)i->name.next - offsetof(typeof(*i), name)))
#define list_del(i) \
do { \
	(i)->next->prev = (i)->prev; \
	(i)->prev->next = (i)->next; \
} while(0)

/************/
/* RB-trees */
/************/

/* Linux has a good RB-tree implementation, that we can't use (GPL). It also has
 * a flat/hooked-in interface that virtually requires license-contamination in
 * order to write a caller-compatible implementation. Instead, I've created an
 * RB-tree encapsulation on top of linux's primitives (it does some of the work
 * the client logic would normally do), and this gives us something we can
 * reimplement on LWE. Unfortunately there's no good+free RB-tree
 * implementations out there that are license-compatible and "flat" (ie. no
 * dynamic allocation). I did find a malloc-based one that I could convert, but
 * that will be a task for later on. For now, LWE's RB-tree is implemented using
 * an ordered linked-list.
 *
 * Note, the only linux-esque type is "struct rb_node", because it's used
 * statically in the exported header, so it can't be opaque. Our version doesn't
 * include a "rb_parent_color" field because we're doing linked-list instead of
 * a true rb-tree.
 */

struct rb_node {
	struct rb_node *prev, *next;
};

struct qman_rbtree {
	struct rb_node *head, *tail;
};

#define QMAN_RBTREE { NULL, NULL }
static inline void qman_rbtree_init(struct qman_rbtree *tree)
{
	tree->head = tree->tail = NULL;
}

#define QMAN_NODE2OBJ(ptr, type, node_field) \
	(type *)((char *)ptr - offsetof(type, node_field))

#define IMPLEMENT_QMAN_RBTREE(name, type, node_field, val_field) \
static inline int name##_push(struct qman_rbtree *tree, type *obj) \
{ \
	struct rb_node *node = tree->head; \
	if (!node) { \
		tree->head = tree->tail = &obj->node_field; \
		obj->node_field.prev = obj->node_field.next = NULL; \
		return 0; \
	} \
	while (node) { \
		type *item = QMAN_NODE2OBJ(node, type, node_field); \
		if (obj->val_field == item->val_field) \
			return -EBUSY; \
		if (obj->val_field < item->val_field) { \
			if (tree->head == node) \
				tree->head = &obj->node_field; \
			obj->node_field.prev = node->prev; \
			obj->node_field.next = node; \
			node->prev = &obj->node_field; \
			return 0; \
		} \
		node = node->next; \
	} \
	obj->node_field.prev = tree->tail; \
	obj->node_field.next = NULL; \
	tree->tail->next = tree->tail = &obj->node_field; \
	return 0; \
} \
static inline void name##_del(struct qman_rbtree *tree, type *obj) \
{ \
	if (tree->head == &obj->node_field) { \
		if (tree->tail == &obj->node_field) \
			/* Only item in the list */ \
			tree->head = tree->tail = NULL; \
		else { \
			/* Is the head, next != NULL */ \
			tree->head = tree->head->next; \
			tree->head->prev = NULL; \
		} \
	} else { \
		if (tree->tail == &obj->node_field) { \
			/* Is the tail, prev != NULL */ \
			tree->tail = tree->tail->prev; \
			tree->tail->next = NULL; \
		} else { \
			/* Is neither the head nor the tail */ \
			obj->node_field.prev->next = obj->node_field.next; \
			obj->node_field.next->prev = obj->node_field.prev; \
		} \
	} \
} \
static inline type *name##_find(struct qman_rbtree *tree, u32 val) \
{ \
	struct rb_node *node = tree->head; \
	while (node) { \
		type *item = QMAN_NODE2OBJ(node, type, node_field); \
		if (val == item->val_field) \
			return item; \
		if (val < item->val_field) \
			return NULL; \
		node = node->next; \
	} \
	return NULL; \
}

/* Ensure the code that includes us gets both Bman and Qman headers, because of
 * wait_event() polling. */
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>

#endif /* HEADER_COMPAT_H */
