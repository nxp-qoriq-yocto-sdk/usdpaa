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

/* this stuff is system-specific but isn't Qman/Bman-specific, so share a single
 * implementation in Bman's directory (and Qman-ify the stuff that is named
 * after Bman). */
#if defined(CONFIG_FSL_QMAN_CHECKING) && !defined(CONFIG_FSL_BMAN_CHECKING)
#define CONFIG_FSL_BMAN_CHECKING
#elif !defined(CONFIG_FSL_QMAN_CHECKING) && defined(CONFIG_FSL_BMAN_CHECKING)
#undef CONFIG_FSL_BMAN_CHECKING
#endif
#define QM_ASSERT(x) BM_ASSERT(x)
#include "../hwalloc/bman_sys.h"

/* do slow-path processing via IRQ */
#define CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_SLOW

/* do not do fast-path processing via IRQ */
#define CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_FAST

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

/************/
/* RB-trees */
/************/

/* We encapsulate RB-trees so that its easier to use non-linux forms in
 * non-linux systems. This also encapsulates the extra plumbing that linux code
 * usually provides when using RB-trees. This encapsulation assumes that the
 * data type held by the tree is u32. */

struct qman_rbtree {
	struct rb_root root;
};
#define QMAN_RBTREE { .root = RB_ROOT }

static inline void qman_rbtree_init(struct qman_rbtree *tree)
{
	tree->root = RB_ROOT;
}

#define IMPLEMENT_QMAN_RBTREE(name, type, node_field, val_field) \
static inline int name##_push(struct qman_rbtree *tree, type *obj) \
{ \
	struct rb_node *parent = NULL, **p = &tree->root.rb_node; \
	while (*p) { \
		u32 item; \
		parent = *p; \
		item = rb_entry(parent, type, node_field)->val_field; \
		if (obj->val_field < item) \
			p = &parent->rb_left; \
		else if (obj->val_field > item) \
			p = &parent->rb_right; \
		else \
			return -EBUSY; \
	} \
	rb_link_node(&obj->node_field, parent, p); \
	rb_insert_color(&obj->node_field, &tree->root); \
	return 0; \
} \
static inline void name##_del(struct qman_rbtree *tree, type *obj) \
{ \
	rb_erase(&obj->node_field, &tree->root); \
} \
static inline type *name##_find(struct qman_rbtree *tree, u32 val) \
{ \
	type *ret; \
	struct rb_node *p = tree->root.rb_node; \
	while (p) { \
		ret = rb_entry(p, type, node_field); \
		if (val < ret->val_field) \
			p = p->rb_left; \
		else if (val > ret->val_field) \
			p = p->rb_right; \
		else \
			return ret; \
	} \
	return NULL; \
}

