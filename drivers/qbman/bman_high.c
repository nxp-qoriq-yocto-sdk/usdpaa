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

#include "bman_low.h"

/* Compilation constants */
#define RCR_THRESH	2	/* reread h/w CI when running out of space */
#define IRQNAME		"BMan portal %d"
#define MAX_IRQNAME	16	/* big enough for "BMan portal %d" */

struct bman_portal {
	struct bm_portal p;
	/* 2-element array. pools[0] is mask, pools[1] is snapshot. */
	struct bman_depletion *pools;
	int thresh_set;
	unsigned long irq_sources;
	u32 slowpoll;	/* only used when interrupts are off */
	wait_queue_head_t queue;
#ifdef CONFIG_FSL_DPA_CAN_WAIT_SYNC
	struct bman_pool *rcri_owned; /* only 1 release WAIT_SYNC at a time */
#endif
#ifdef CONFIG_FSL_BMAN_PORTAL_TASKLET
	struct tasklet_struct tasklet;
#endif
	/* When the cpu-affine portal is activated, this is non-NULL */
	const struct bm_portal_config *config;
	/* 64-entry hash-table of pool objects that are tracking depletion
	 * entry/exit (ie. BMAN_POOL_FLAG_DEPLETION). This isn't fast-path, so
	 * we're not fussy about cache-misses and so forth - whereas the above
	 * members should all fit in one cacheline.
	 * BTW, with 64 entries in the hash table and 64 buffer pools to track,
	 * you'll never guess the hash-function ... */
	struct bman_pool *cb[64];
	char irqname[MAX_IRQNAME];
};

static cpumask_t affine_mask;
static DEFINE_SPINLOCK(affine_mask_lock);
static DEFINE_PER_CPU(struct bman_portal, bman_affine_portal);
static inline struct bman_portal *get_affine_portal(void)
{
	return &get_cpu_var(bman_affine_portal);
}
static inline void put_affine_portal(void)
{
	put_cpu_var(bman_affine_portal);
}

/* GOTCHA: this object type refers to a pool, it isn't *the* pool. There may be
 * more than one such object per Bman buffer pool, eg. if different users of the
 * pool are operating via different portals. */
struct bman_pool {
	struct bman_pool_params params;
	/* Used for hash-table admin when using depletion notifications. */
	struct bman_portal *portal;
	struct bman_pool *next;
	/* stockpile state - NULL unless BMAN_POOL_FLAG_STOCKPILE is set */
	struct bm_buffer *sp;
	unsigned int sp_fill;
};

/* (De)Registration of depletion notification callbacks */
static void depletion_link(struct bman_portal *portal, struct bman_pool *pool)
{
	__maybe_unused unsigned long irqflags;
	pool->portal = portal;
	local_irq_save(irqflags);
	pool->next = portal->cb[pool->params.bpid];
	portal->cb[pool->params.bpid] = pool;
	if (!pool->next)
		/* First object for that bpid on this portal, enable the BSCN
		 * mask bit. */
		bm_isr_bscn_mask(&portal->p, pool->params.bpid, 1);
	local_irq_restore(irqflags);
}
static void depletion_unlink(struct bman_pool *pool)
{
	struct bman_pool *it, *last = NULL;
	struct bman_pool **base = &pool->portal->cb[pool->params.bpid];
	__maybe_unused unsigned long irqflags;
	local_irq_save(irqflags);
	it = *base;	/* <-- gotcha, don't do this prior to the irq_save */
	while (it != pool) {
		last = it;
		it = it->next;
	}
	if (!last)
		*base = pool->next;
	else
		last->next = pool->next;
	if (!last && !pool->next) {
		/* Last object for that bpid on this portal, disable the BSCN
		 * mask bit. */
		bm_isr_bscn_mask(&pool->portal->p, pool->params.bpid, 0);
		/* And "forget" that we last saw this pool as depleted */
		bman_depletion_unset(&pool->portal->pools[1], pool->params.bpid);
	}
	local_irq_restore(irqflags);
}

/* In the case that the application's core loop calls qman_poll() and
 * bman_poll(), we ought to balance how often we incur the overheads of the
 * slow-path poll. We'll use two decrementer sources. The idle decrementer
 * constant is used when the last slow-poll detected no work to do, and the busy
 * decrementer constant when the last slow-poll had work to do. */
#define SLOW_POLL_IDLE   1000
#define SLOW_POLL_BUSY   10
static u32 __poll_portal_slow(struct bman_portal *p, u32 is);

#ifdef CONFIG_FSL_DPA_HAVE_IRQ
/* This is called from the ISR or from a deferred tasklet */
static inline void do_isr_work(struct bman_portal *p)
{
	u32 clear = p->irq_sources;
	u32 is = bm_isr_status_read(&p->p) & p->irq_sources;
	clear |= __poll_portal_slow(p, is);
	bm_isr_status_clear(&p->p, clear);
}
#ifdef CONFIG_FSL_BMAN_PORTAL_TASKLET
static void portal_tasklet(unsigned long __p)
{
	struct bman_portal *p = (struct bman_portal *)__p;
	do_isr_work(p);
	bm_isr_uninhibit(&p->p);
}
#endif
/* Portal interrupt handler */
static irqreturn_t portal_isr(__always_unused int irq, void *ptr)
{
	struct bman_portal *p = ptr;
#ifdef CONFIG_FSL_BMAN_PORTAL_TASKLET
	bm_isr_inhibit(&p->p);
	tasklet_schedule(&p->tasklet);
#else
	do_isr_work(p);
#endif
	return IRQ_HANDLED;
}
#endif

int bman_have_affine_portal(void)
{
	struct bman_portal *bm = get_affine_portal();
	int ret = (bm->config ? 1 : 0);
	put_affine_portal();
	return ret;
}

int bman_create_affine_portal(const struct bm_portal_config *config,
				u32 irq_sources,
				int recovery_mode __maybe_unused)
{
	struct bman_portal *portal = get_affine_portal();
	struct bm_portal *__p = &portal->p;
	const struct bman_depletion *pools = &config->public_cfg.mask;
	int ret;

	/* prep the low-level portal struct with the mapped addresses from the
	 * config, everything that follows depends on it and "config" is more
	 * for (de)reference... */
	__p->addr = config->addr;
	if (bm_rcr_init(__p, bm_rcr_pvb, bm_rcr_cce)) {
		pr_err("Bman RCR initialisation failed\n");
		goto fail_rcr;
	}
	if (bm_mc_init(__p)) {
		pr_err("Bman MC initialisation failed\n");
		goto fail_mc;
	}
	if (bm_isr_init(__p)) {
		pr_err("Bman ISR initialisation failed\n");
		goto fail_isr;
	}
	if (!pools)
		portal->pools = NULL;
	else {
		u8 bpid = 0;
		portal->pools = kmalloc(2 * sizeof(*pools), GFP_KERNEL);
		if (!portal->pools)
			goto fail_pools;
		portal->pools[0] = *pools;
		bman_depletion_init(portal->pools + 1);
		while (bpid < 64) {
			/* Default to all BPIDs disabled, we enable as required
			 * at run-time. */
			bm_isr_bscn_mask(__p, bpid, 0);
			bpid++;
		}
	}
	portal->slowpoll = 0;
	init_waitqueue_head(&portal->queue);
#ifdef CONFIG_FSL_DPA_CAN_WAIT_SYNC
	portal->rcri_owned = NULL;
#endif
#ifdef CONFIG_FSL_BMAN_PORTAL_TASKLET
	tasklet_init(&portal->tasklet, portal_tasklet, (unsigned long)portal);
#endif
	memset(&portal->cb, 0, sizeof(portal->cb));
	/* Write-to-clear any stale interrupt status bits */
	bm_isr_disable_write(__p, 0xffffffff);
	portal->irq_sources = irq_sources;
	bm_isr_enable_write(__p, portal->irq_sources);
	bm_isr_status_clear(__p, 0xffffffff);
#ifdef CONFIG_FSL_DPA_HAVE_IRQ
	snprintf(portal->irqname, MAX_IRQNAME, IRQNAME, config->public_cfg.cpu);
	if (request_irq(config->public_cfg.irq, portal_isr, 0, portal->irqname,
				portal)) {
		pr_err("request_irq() failed\n");
		goto fail_irq;
	}
	if ((config->public_cfg.cpu != -1) &&
			irq_can_set_affinity(config->public_cfg.irq) &&
			irq_set_affinity(config->public_cfg.irq,
			     cpumask_of(config->public_cfg.cpu))) {
		pr_err("irq_set_affinity() failed\n");
		goto fail_affinity;
	}
	/* Enable the bits that make sense */
	if (!recovery_mode)
		bm_isr_uninhibit(__p);
#else
	if (irq_sources)
		panic("No Bman portal IRQ support, mustn't specify IRQ flags!");
#endif
	/* Need RCR to be empty before continuing */
	bm_isr_disable_write(__p, ~BM_PIRQ_RCRI);
	ret = bm_rcr_get_fill(__p);
	if (ret) {
		pr_err("Bman RCR unclean, need recovery\n");
		goto fail_rcr_empty;
	}
	/* Success */
	portal->config = config;
	spin_lock(&affine_mask_lock);
	cpumask_set_cpu(config->public_cfg.cpu, &affine_mask);
	spin_unlock(&affine_mask_lock);
	bm_isr_disable_write(__p, 0);
	put_affine_portal();
	return 0;
fail_rcr_empty:
#ifdef CONFIG_FSL_DPA_HAVE_IRQ
fail_affinity:
	free_irq(config->public_cfg.irq, portal);
fail_irq:
#endif
	if (portal->pools)
		kfree(portal->pools);
fail_pools:
	bm_isr_finish(__p);
fail_isr:
	bm_mc_finish(__p);
fail_mc:
	bm_rcr_finish(__p);
fail_rcr:
	put_affine_portal();
	return -EINVAL;
}

void bman_destroy_affine_portal(void)
{
	struct bman_portal *bm = get_affine_portal();
	bm_rcr_cce_update(&bm->p);
#ifdef CONFIG_FSL_DPA_HAVE_IRQ
	free_irq(bm->config->public_cfg.irq, bm);
#endif
	kfree(bm->pools);
	bm_isr_finish(&bm->p);
	bm_mc_finish(&bm->p);
	bm_rcr_finish(&bm->p);
	spin_lock(&affine_mask_lock);
	cpumask_clear_cpu(bm->config->public_cfg.cpu, &affine_mask);
	spin_unlock(&affine_mask_lock);
	bm->config = NULL;
	put_affine_portal();
}

/* When release logic waits on available RCR space, we need a global waitqueue
 * in the case of "affine" use (as the waits wake on different cpus which means
 * different portals - so we can't wait on any per-portal waitqueue). */
static DECLARE_WAIT_QUEUE_HEAD(affine_queue);

static u32 __poll_portal_slow(struct bman_portal *p, u32 is)
{
	struct bman_depletion tmp;
	u32 ret = is;

	/* There is a gotcha to be aware of. If we do the query before clearing
	 * the status register, we may miss state changes that occur between the
	 * two. If we write to clear the status register before the query, the
	 * cache-enabled query command may overtake the status register write
	 * unless we use a heavyweight sync (which we don't want). Instead, we
	 * write-to-clear the status register then *read it back* before doing
	 * the query, hence the odd while loop with the 'is' accumulation. */
	if (is & BM_PIRQ_BSCN) {
		struct bm_mc_result *mcr;
		__maybe_unused unsigned long irqflags;
		unsigned int i, j;
		u32 __is;
		bm_isr_status_clear(&p->p, BM_PIRQ_BSCN);
		while ((__is = bm_isr_status_read(&p->p)) & BM_PIRQ_BSCN) {
			is |= __is;
			bm_isr_status_clear(&p->p, BM_PIRQ_BSCN);
		}
		is &= ~BM_PIRQ_BSCN;
		local_irq_save(irqflags);
		bm_mc_start(&p->p);
		bm_mc_commit(&p->p, BM_MCC_VERB_CMD_QUERY);
		while (!(mcr = bm_mc_result(&p->p)))
			cpu_relax();
		tmp = mcr->query.ds.state;
		local_irq_restore(irqflags);
		for (i = 0; i < 2; i++) {
			int idx = i * 32;
			/* tmp is a mask of currently-depleted pools.
			 * pools[0] is mask of those we care about.
			 * pools[1] is our previous view (we only want to
			 * be told about changes). */
			tmp.__state[i] &= p->pools[0].__state[i];
			if (tmp.__state[i] == p->pools[1].__state[i])
				/* fast-path, nothing to see, move along */
				continue;
			for (j = 0; j <= 31; j++, idx++) {
				struct bman_pool *pool = p->cb[idx];
				int b4 = bman_depletion_get(&p->pools[1], idx);
				int af = bman_depletion_get(&tmp, idx);
				if (b4 == af)
					continue;
				while (pool) {
					pool->params.cb(p, pool,
						pool->params.cb_ctx, af);
					pool = pool->next;
				}
			}
		}
		p->pools[1] = tmp;
	}

	if (is & BM_PIRQ_RCRI) {
		__maybe_unused unsigned long irqflags;
		local_irq_save(irqflags);
		bm_rcr_cce_update(&p->p);
#ifdef CONFIG_FSL_DPA_CAN_WAIT_SYNC
		/* If waiting for sync, we only cancel the interrupt threshold
		 * when the ring utilisation hits zero. */
		if (p->rcri_owned) {
			if (!bm_rcr_get_fill(&p->p)) {
				p->rcri_owned = NULL;
				bm_rcr_set_ithresh(&p->p, 0);
			}
		} else
#endif
		bm_rcr_set_ithresh(&p->p, 0);
		local_irq_restore(irqflags);
		wake_up(&p->queue);
		bm_isr_status_clear(&p->p, BM_PIRQ_RCRI);
		is &= ~BM_PIRQ_RCRI;
	}

	/* There should be no status register bits left undefined */
	DPA_ASSERT(!is);
	return ret;
}

const struct bman_portal_config *bman_get_portal_config(void)
{
	struct bman_portal *p = get_affine_portal();
	const struct bman_portal_config *ret = &p->config->public_cfg;
	put_affine_portal();
	return ret;
}
EXPORT_SYMBOL(bman_get_portal_config);

u32 bman_irqsource_get(void)
{
	struct bman_portal *p = get_affine_portal();
	u32 ret = p->irq_sources & BM_PIRQ_VISIBLE;
	put_affine_portal();
	return ret;
}
EXPORT_SYMBOL(bman_irqsource_get);

void bman_irqsource_add(__maybe_unused u32 bits)
{
#ifdef CONFIG_FSL_DPA_HAVE_IRQ
	struct bman_portal *p = get_affine_portal();
	set_bits(bits & BM_PIRQ_VISIBLE, &p->irq_sources);
	bm_isr_enable_write(&p->p, p->irq_sources);
	put_affine_portal();
#else
	panic("No Bman portal IRQ support, mustn't spcify IRQ flags!");
#endif
}
EXPORT_SYMBOL(bman_irqsource_add);

void bman_irqsource_remove(u32 bits)
{
	struct bman_portal *p = get_affine_portal();
	/* Subtle but important: we need to update the interrupt enable register
	 * prior to clearing p->irq_sources. If we don't, an interrupt-spin
	 * might happen between us clearing p->irq_sources and preventing the
	 * same sources from triggering an interrupt. This means we have to read
	 * the register back with a data-dependency, to ensure the write reaches
	 * Bman before we update p->irq_sources. Hence the appearance of
	 * obfuscation... */
	u32 newval = p->irq_sources & ~(bits & BM_PIRQ_VISIBLE);
	bm_isr_enable_write(&p->p, newval);
	newval = bm_isr_enable_read(&p->p);
	clear_bits(~newval, &p->irq_sources);
	put_affine_portal();
}
EXPORT_SYMBOL(bman_irqsource_remove);

const cpumask_t *bman_affine_cpus(void)
{
	return &affine_mask;
}
EXPORT_SYMBOL(bman_affine_cpus);

void bman_poll_slow(void)
{
	struct bman_portal *p = get_affine_portal();
	u32 is = bm_isr_status_read(&p->p) & ~p->irq_sources;
	u32 active = __poll_portal_slow(p, is);
	bm_isr_status_clear(&p->p, active);
	put_affine_portal();
}
EXPORT_SYMBOL(bman_poll_slow);

/* Legacy wrapper */
void bman_poll(void)
{
	struct bman_portal *p = get_affine_portal();
	if (!(p->slowpoll--)) {
		u32 is = bm_isr_status_read(&p->p) & ~p->irq_sources;
		u32 active = __poll_portal_slow(p, is);
		if (active)
			p->slowpoll = SLOW_POLL_BUSY;
		else
			p->slowpoll = SLOW_POLL_IDLE;
	}
	put_affine_portal();
}
EXPORT_SYMBOL(bman_poll);

int bman_recovery_cleanup_bpid(u32 bpid)
{
	struct bman_pool pool = {
		.params = {
			.bpid = bpid
		}
	};
	struct bm_buffer bufs[8];
	int ret = 0;
	unsigned int num_bufs = 0;
	do {
		/* Acquire is all-or-nothing, so we drain in 8s, then in
		 * 1s for the remainder. */
		if (ret != 1)
			ret = bman_acquire(&pool, bufs, 8, 0);
		if (ret < 8)
			ret = bman_acquire(&pool, bufs, 1, 0);
		if (ret > 0)
			num_bufs += ret;
	} while (ret > 0);
	if (num_bufs)
		pr_info("Bman: BPID %d recovered (%d bufs)\n", bpid, num_bufs);
	return 0;
}
EXPORT_SYMBOL(bman_recovery_cleanup_bpid);

/* called from bman_driver.c::bman_recovery_exit() only */
void bman_recovery_exit_local(void)
{
	struct bman_portal *p = get_affine_portal();
	bm_isr_status_clear(&p->p, 0xffffffff);
	bm_isr_uninhibit(&p->p);
	put_affine_portal();
}

static const u32 zero_thresholds[4] = {0, 0, 0, 0};

struct bman_pool *bman_new_pool(const struct bman_pool_params *params)
{
	struct bman_pool *pool = NULL;
	u32 bpid;

	if (params->flags & BMAN_POOL_FLAG_DYNAMIC_BPID) {
		int ret = bm_pool_new(&bpid);
		if (ret)
			return NULL;
	} else
		bpid = params->bpid;
#ifdef CONFIG_FSL_BMAN_CONFIG
	if (params->flags & BMAN_POOL_FLAG_THRESH) {
		int ret = bm_pool_set(bpid, params->thresholds);
		if (ret)
			goto err;
	}
#else
	if (params->flags & BMAN_POOL_FLAG_THRESH)
		goto err;
#endif
	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		goto err;
	pool->sp = NULL;
	pool->sp_fill = 0;
	pool->params = *params;
	if (params->flags & BMAN_POOL_FLAG_DYNAMIC_BPID)
		pool->params.bpid = bpid;
	if (params->flags & BMAN_POOL_FLAG_STOCKPILE) {
		pool->sp = kmalloc(sizeof(struct bm_buffer) * BMAN_STOCKPILE_SZ,
					GFP_KERNEL);
		if (!pool->sp)
			goto err;
	}
	if (pool->params.flags & BMAN_POOL_FLAG_DEPLETION) {
		struct bman_portal *p = get_affine_portal();
		if (!p->pools || !bman_depletion_get(&p->pools[0], bpid)) {
			pr_err("Depletion events disabled for bpid %d\n", bpid);
			goto err;
		}
		depletion_link(p, pool);
		put_affine_portal();
	}
	return pool;
err:
#ifdef CONFIG_FSL_BMAN_CONFIG
	if (params->flags & BMAN_POOL_FLAG_THRESH)
		bm_pool_set(bpid, zero_thresholds);
#endif
	if (params->flags & BMAN_POOL_FLAG_DYNAMIC_BPID)
		bm_pool_free(bpid);
	if (pool) {
		if (pool->sp)
			kfree(pool->sp);
		kfree(pool);
	}
	return NULL;
}
EXPORT_SYMBOL(bman_new_pool);

void bman_free_pool(struct bman_pool *pool)
{
#ifdef CONFIG_FSL_BMAN_CONFIG
	if (pool->params.flags & BMAN_POOL_FLAG_THRESH)
		bm_pool_set(pool->params.bpid, zero_thresholds);
#endif
	if (pool->params.flags & BMAN_POOL_FLAG_DEPLETION)
		depletion_unlink(pool);
	if (pool->params.flags & BMAN_POOL_FLAG_DYNAMIC_BPID) {
		/* When releasing a BPID to the dynamic allocator, that pool
		 * must be *empty*. This code makes it so by dropping everything
		 * into the bit-bucket. This ignores whether or not it was a
		 * mistake (or a leak) on the caller's part not to drain the
		 * pool beforehand. */
		struct bm_buffer bufs[8];
		int ret = 0;
		do {
			/* Acquire is all-or-nothing, so we drain in 8s, then in
			 * 1s for the remainder. */
			if (ret != 1)
				ret = bman_acquire(pool, bufs, 8, 0);
			if (ret < 8)
				ret = bman_acquire(pool, bufs, 1, 0);
		} while (ret > 0);
		bm_pool_free(pool->params.bpid);
	}
	kfree(pool);
}
EXPORT_SYMBOL(bman_free_pool);

const struct bman_pool_params *bman_get_params(const struct bman_pool *pool)
{
	return &pool->params;
}
EXPORT_SYMBOL(bman_get_params);

static noinline void update_rcr_ci(struct bman_portal *p, u8 avail)
{
	if (avail)
		bm_rcr_cce_prefetch(&p->p);
	else
		bm_rcr_cce_update(&p->p);
}

int bman_rcr_is_empty(void)
{
	__maybe_unused unsigned long irqflags;
	struct bman_portal *p = get_affine_portal();
	u8 avail;

	local_irq_save(irqflags);
	update_rcr_ci(p, 0);
	avail = bm_rcr_get_fill(&p->p);
	local_irq_restore(irqflags);
	put_affine_portal();
	return (avail == 0);
}
EXPORT_SYMBOL(bman_rcr_is_empty);

static inline struct bm_rcr_entry *try_rel_start(struct bman_portal **p,
#ifdef CONFIG_FSL_DPA_CAN_WAIT
					__maybe_unused struct bman_pool *pool,
#endif
					__maybe_unused unsigned long *irqflags,
					__maybe_unused u32 flags)
{
	struct bm_rcr_entry *r;
	u8 avail;

	*p = get_affine_portal();
	local_irq_save((*irqflags));
#ifdef CONFIG_FSL_DPA_CAN_WAIT_SYNC
	if (unlikely((flags & BMAN_RELEASE_FLAG_WAIT) &&
			(flags & BMAN_RELEASE_FLAG_WAIT_SYNC))) {
		if ((*p)->rcri_owned) {
			local_irq_restore((*irqflags));
			put_affine_portal();
			return NULL;
		}
		(*p)->rcri_owned = pool;
	}
#endif
	avail = bm_rcr_get_avail(&(*p)->p);
	if (avail < 2)
		update_rcr_ci(*p, avail);
	r = bm_rcr_start(&(*p)->p);
	if (unlikely(!r)) {
#ifdef CONFIG_FSL_DPA_CAN_WAIT_SYNC
		if (unlikely((flags & BMAN_RELEASE_FLAG_WAIT) &&
				(flags & BMAN_RELEASE_FLAG_WAIT_SYNC)))
			(*p)->rcri_owned = NULL;
#endif
		local_irq_restore((*irqflags));
		put_affine_portal();
	}
	return r;
}

#ifdef CONFIG_FSL_DPA_CAN_WAIT
static noinline struct bm_rcr_entry *__wait_rel_start(struct bman_portal **p,
					struct bman_pool *pool,
					__maybe_unused unsigned long *irqflags,
					u32 flags)
{
	struct bm_rcr_entry *rcr = try_rel_start(p, pool, irqflags, flags);
	if (!rcr)
		bm_rcr_set_ithresh(&(*p)->p, 1);
	return rcr;
}

static noinline struct bm_rcr_entry *wait_rel_start(struct bman_portal **p,
					struct bman_pool *pool,
					__maybe_unused unsigned long *irqflags,
					u32 flags)
{
	struct bm_rcr_entry *rcr;
#ifndef CONFIG_FSL_DPA_CAN_WAIT_SYNC
	pool = NULL;
#endif
	if (flags & BMAN_RELEASE_FLAG_WAIT_INT)
		wait_event_interruptible(affine_queue,
			(rcr = __wait_rel_start(p, pool, irqflags, flags)));
	else
		wait_event(affine_queue,
			(rcr = __wait_rel_start(p, pool, irqflags, flags)));
	return rcr;
}
#endif

/* to facilitate better copying of bufs into the ring without either (a) copying
 * noise into the first byte (prematurely triggering the command), nor (b) being
 * very inefficient by copying small fields using read-modify-write */
struct overlay_bm_buffer {
	u32 first;
	u32 second;
};

static inline int __bman_release(struct bman_pool *pool,
			const struct bm_buffer *bufs, u8 num, u32 flags)
{
	struct bman_portal *p;
	struct bm_rcr_entry *r;
	struct overlay_bm_buffer *o_dest;
	struct overlay_bm_buffer *o_src = (struct overlay_bm_buffer *)&bufs[0];
	__maybe_unused unsigned long irqflags;
	u32 i = num - 1;

#ifdef CONFIG_FSL_DPA_CAN_WAIT
	if (flags & BMAN_RELEASE_FLAG_WAIT)
		r = wait_rel_start(&p, pool, &irqflags, flags);
	else
		r = try_rel_start(&p, pool, &irqflags, flags);
#else
	r = try_rel_start(&p, &irqflags, flags);
#endif
	if (!r)
		return -EBUSY;
	/* We can copy all but the first entry, as this can trigger badness
	 * with the valid-bit. Use the overlay to mask the verb byte. */
	o_dest = (struct overlay_bm_buffer *)&r->bufs[0];
	o_dest->first = (o_src->first & 0x0000ffff) |
		(((u32)pool->params.bpid << 16) & 0x00ff0000);
	o_dest->second = o_src->second;
	if (i)
		copy_words(&r->bufs[1], &bufs[1], i * sizeof(bufs[0]));
	bm_rcr_pvb_commit(&p->p, BM_RCR_VERB_CMD_BPID_SINGLE |
			(num & BM_RCR_VERB_BUFCOUNT_MASK));
#ifdef CONFIG_FSL_DPA_CAN_WAIT_SYNC
	/* if we wish to sync we need to set the threshold after h/w sees the
	 * new ring entry. As we're mixing cache-enabled and cache-inhibited
	 * accesses, this requires a heavy-weight sync. */
	if (unlikely((flags & BMAN_RELEASE_FLAG_WAIT) &&
			(flags & BMAN_RELEASE_FLAG_WAIT_SYNC))) {
		hwsync();
		bm_rcr_set_ithresh(&p->p, 1);
	}
#endif
	local_irq_restore(irqflags);
	put_affine_portal();
#ifdef CONFIG_FSL_DPA_CAN_WAIT_SYNC
	if (unlikely((flags & BMAN_RELEASE_FLAG_WAIT) &&
			(flags & BMAN_RELEASE_FLAG_WAIT_SYNC))) {
		if (flags & BMAN_RELEASE_FLAG_WAIT_INT)
			wait_event_interruptible(affine_queue,
					(p->rcri_owned != pool));
		else
			wait_event(affine_queue, (p->rcri_owned != pool));
	}
#endif
	return 0;
}

int bman_release(struct bman_pool *pool, const struct bm_buffer *bufs, u8 num,
			u32 flags)
{
#ifdef CONFIG_FSL_DPA_CHECKING
	if (!num || (num > 8))
		return -EINVAL;
	if (pool->params.flags & BMAN_POOL_FLAG_NO_RELEASE)
		return -EINVAL;
#endif
	/* Without stockpile, this API is a pass-through to the h/w operation */
	if (!(pool->params.flags & BMAN_POOL_FLAG_STOCKPILE))
		return __bman_release(pool, bufs, num, flags);
	/* This needs some explanation. Adding the given buffers may take the
	 * stockpile over the threshold, but in fact the stockpile may already
	 * *be* over the threshold if a previous release-to-hw attempt had
	 * failed. So we have 3 cases to cover;
	 *   1. we add to the stockpile and don't hit the threshold,
	 *   2. we add to the stockpile, hit the threshold and release-to-hw,
	 *   3. we have to release-to-hw before adding to the stockpile
	 *      (not enough room in the stockpile for case 2).
	 * Our constraints on thresholds guarantee that in case 3, there must be
	 * at least 8 bufs already in the stockpile, so all release-to-hw ops
	 * are for 8 bufs. Despite all this, the API must indicate whether the
	 * given buffers were taken off the caller's hands, irrespective of
	 * whether a release-to-hw was attempted. */
	while (num) {
		/* Add buffers to stockpile if they fit */
		if ((pool->sp_fill + num) < BMAN_STOCKPILE_SZ) {
			copy_words(pool->sp + pool->sp_fill, bufs,
				sizeof(struct bm_buffer) * num);
			pool->sp_fill += num;
			num = 0; /* --> will return success no matter what */
		}
		/* Do hw op if hitting the high-water threshold */
		if ((pool->sp_fill + num) >= BMAN_STOCKPILE_HIGH) {
			u8 ret = __bman_release(pool,
				pool->sp + (pool->sp_fill - 8), 8, flags);
			if (ret)
				return (num ? ret : 0);
			pool->sp_fill -= 8;
		}
	}
	return 0;
}
EXPORT_SYMBOL(bman_release);

static inline int __bman_acquire(struct bman_pool *pool, struct bm_buffer *bufs,
					u8 num)
{
	struct bman_portal *p = get_affine_portal();
	struct bm_mc_command *mcc;
	struct bm_mc_result *mcr;
	__maybe_unused unsigned long irqflags;
	int ret;

	local_irq_save(irqflags);
	mcc = bm_mc_start(&p->p);
	mcc->acquire.bpid = pool->params.bpid;
	bm_mc_commit(&p->p, BM_MCC_VERB_CMD_ACQUIRE |
			(num & BM_MCC_VERB_ACQUIRE_BUFCOUNT));
	while (!(mcr = bm_mc_result(&p->p)))
		cpu_relax();
	ret = mcr->verb & BM_MCR_VERB_ACQUIRE_BUFCOUNT;
	if (bufs)
		copy_words(&bufs[0], &mcr->acquire.bufs[0],
				num * sizeof(bufs[0]));
	local_irq_restore(irqflags);
	put_affine_portal();
	if (ret != num)
		ret = -ENOMEM;
	return ret;
}

int bman_acquire(struct bman_pool *pool, struct bm_buffer *bufs, u8 num,
			u32 flags)
{
#ifdef CONFIG_FSL_DPA_CHECKING
	if (!num || (num > 8))
		return -EINVAL;
	if (pool->params.flags & BMAN_POOL_FLAG_ONLY_RELEASE)
		return -EINVAL;
#endif
	/* Without stockpile, this API is a pass-through to the h/w operation */
	if (!(pool->params.flags & BMAN_POOL_FLAG_STOCKPILE))
		return __bman_acquire(pool, bufs, num);
#ifdef CONFIG_SMP
	panic("Bman stockpiles are not SMP-safe!");
#endif
	/* Only need a h/w op if we'll hit the low-water thresh */
	if (!(flags & BMAN_ACQUIRE_FLAG_STOCKPILE) &&
			(pool->sp_fill <= (BMAN_STOCKPILE_LOW + num))) {
		int ret = __bman_acquire(pool, pool->sp + pool->sp_fill, 8);
		if (ret < 0)
			goto hw_starved;
		DPA_ASSERT(ret == 8);
		pool->sp_fill += 8;
	} else {
hw_starved:
		if (pool->sp_fill < num)
			return -ENOMEM;
	}
	copy_words(bufs, pool->sp + (pool->sp_fill - num),
		sizeof(struct bm_buffer) * num);
	pool->sp_fill -= num;
	return num;
}
EXPORT_SYMBOL(bman_acquire);

int bman_query_pools(struct bm_pool_state *state)
{
	struct bman_portal *p = get_affine_portal();
	struct bm_mc_command *mcc;
	struct bm_mc_result *mcr;
	__maybe_unused unsigned long irqflags;

	local_irq_save(irqflags);
	mcc = bm_mc_start(&p->p);
	bm_mc_commit(&p->p, BM_MCC_VERB_CMD_QUERY);
	while (!(mcr = bm_mc_result(&p->p)))
		cpu_relax();
	DPA_ASSERT((mcr->verb & BM_MCR_VERB_CMD_MASK) == BM_MCR_VERB_CMD_QUERY);
	*state = mcr->query;
	local_irq_restore(irqflags);
	put_affine_portal();
	return 0;
}
EXPORT_SYMBOL(bman_query_pools);
