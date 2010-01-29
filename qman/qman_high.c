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

/* TODO:
 *
 * - make RECOVER also handle incomplete mgmt-commands
 */

#include "qman_private.h"

/* Compilation constants */
#define DQRR_MAXFILL	15
#define DQRR_STASH_RING	0	/* if enabled, we ought to check SDEST */
#define DQRR_STASH_DATA	0	/* ditto */
#define EQCR_THRESH	1	/* reread h/w CI when running out of space */
#define EQCR_ITHRESH	4	/* if EQCR congests, interrupt threshold */
#define RECOVER_MSLEEP	100	/* DQRR and MR need to be empty for 0.1s */
#define IRQNAME		"QMan portal %d"
#define MAX_IRQNAME	16	/* big enough for "QMan portal %d" */

/* Lock/unlock frame queues, subject to the "LOCKED" flag. This is about
 * inter-processor locking only. Note, FQLOCK() is always called either under a
 * local_irq_disable() or from interrupt context - hence there's no need for
 * spin_lock_irq() (and indeed, the nesting breaks as the "irq" bit isn't
 * recursive...). */
#define FQLOCK(fq) \
	do { \
		struct qman_fq *__fq478 = (fq); \
		if (fq_isset(__fq478, QMAN_FQ_FLAG_LOCKED)) \
			spin_lock(&__fq478->fqlock); \
	} while(0)
#define FQUNLOCK(fq) \
	do { \
		struct qman_fq *__fq478 = (fq); \
		if (fq_isset(__fq478, QMAN_FQ_FLAG_LOCKED)) \
			spin_unlock(&__fq478->fqlock); \
	} while(0)

static inline void fq_set(struct qman_fq *fq, u32 mask)
{
	set_bits(mask, &fq->flags);
}
static inline void fq_clear(struct qman_fq *fq, u32 mask)
{
	clear_bits(mask, &fq->flags);
}
static inline int fq_isset(struct qman_fq *fq, u32 mask)
{
	return fq->flags & mask;
}
static inline int fq_isclear(struct qman_fq *fq, u32 mask)
{
	return !(fq->flags & mask);
}

/**************/
/* Portal API */
/**************/

#define PORTAL_BITS_RECOVER	0x00010000	/* use default callbacks */
#define PORTAL_BITS_VDQCR	0x00008000	/* VDQCR active */
#define PORTAL_BITS_MASK_V	0x00007fff
#define PORTAL_BITS_NON_V	~(PORTAL_BITS_VDQCR | PORTAL_BITS_MASK_V)
#define PORTAL_BITS_GET_V(p)	((p)->bits & PORTAL_BITS_MASK_V)
#define PORTAL_BITS_INC_V(p) \
	do { \
		struct qman_portal *__p793 = (p); \
		u32 __r793 = __p793->bits & PORTAL_BITS_NON_V; \
		__r793 |= ((__p793->bits + 1) & PORTAL_BITS_MASK_V); \
		__p793->bits = __r793; \
	} while (0)

struct qman_portal {
	struct qm_portal *p;
	/* 2-element array. cgrs[0] is mask, cgrs[1] is snapshot. */
	struct qman_cgrs *cgrs;
	/* To avoid overloading the term "flags", we use these 2; */
	u32 options;	/* QMAN_PORTAL_FLAG_*** - static, caller-provided */
	u32 bits;	/* PORTAL_BITS_*** - dynamic, strictly internal */
	u32 slowpoll;	/* only used when interrupts are off */
	/* The wrap-around eq_[prod|cons] counters are used to support
	 * QMAN_ENQUEUE_FLAG_WAIT_SYNC. */
	u32 eq_prod, eq_cons;
	u32 sdqcr;
	volatile int disable_count;
	/* If we receive a DQRR or MR ring entry for a "null" FQ, ie. for which
	 * FQD::contextB is NULL rather than pointing to a FQ object, we use
	 * these handlers. (This is not considered a fast-path mechanism.) */
	struct qman_fq_cb null_cb;
	/* This is needed for providing a non-NULL device to dma_map_***() */
	struct platform_device *pdev;
	struct qman_rbtree retire_table;
	char irqname[MAX_IRQNAME];
};

/* This gives a FQID->FQ lookup to cover the fact that we can't directly demux
 * retirement notifications (the fact they are sometimes h/w-consumed means that
 * contextB isn't always a s/w demux - and as we can't know which case it is
 * when looking at the notification, we have to use the slow lookup for all of
 * them). NB, it's possible to have multiple FQ objects refer to the same FQID
 * (though at most one of them should be the consumer), so this table isn't for
 * all FQs - FQs are added when retirement commands are issued, and removed when
 * they complete, which also massively reduces the size of this table. */
IMPLEMENT_QMAN_RBTREE(fqtree, struct qman_fq, node, fqid);

/* This is what everything can wait on, even if it migrates to a different cpu
 * to the one whose affine portal it is waiting on. */
static DECLARE_WAIT_QUEUE_HEAD(affine_queue);

static inline int table_push_fq(struct qman_portal *p, struct qman_fq *fq)
{
	int ret = fqtree_push(&p->retire_table, fq);
	if (ret)
		pr_err("ERROR: double FQ-retirement %d\n", fq->fqid);
	return ret;
}

static inline void table_del_fq(struct qman_portal *p, struct qman_fq *fq)
{
	fqtree_del(&p->retire_table, fq);
}

static inline struct qman_fq *table_find_fq(struct qman_portal *p, u32 fqid)
{
	return fqtree_find(&p->retire_table, fqid);
}

/* In the case that slow- and fast-path handling are both done by qman_poll()
 * (ie. because there is no interrupt handling), we ought to balance how often
 * we do the fast-path poll versus the slow-path poll. We'll use two decrementer
 * sources, so we call the fast poll 'n' times before calling the slow poll
 * once. The idle decrementer constant is used when the last slow-poll detected
 * no work to do, and the busy decrementer constant when the last slow-poll had
 * work to do. */
#define SLOW_POLL_IDLE   1000
#define SLOW_POLL_BUSY   10
static u32 __poll_portal_slow(struct qman_portal *p, struct qm_portal *lowp,
				u32 is);
static inline void __poll_portal_fast(struct qman_portal *p,
					struct qm_portal *lowp);

#ifdef CONFIG_FSL_QMAN_HAVE_IRQ
/* Portal interrupt handler */
static irqreturn_t portal_isr(int irq, void *ptr)
{
	struct qman_portal *p = ptr;
	struct qm_portal *lowp = p->p;
	u32 clear = 0, is = qm_isr_status_read(lowp);
	/* Only do fast-path handling if it's required */
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_FAST
	clear |= QM_PIRQ_DQRI;
	__poll_portal_fast(p, lowp);
#endif
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_SLOW
	clear |= __poll_portal_slow(p, lowp, is);
#endif
	qm_isr_status_clear(lowp, clear);
	return IRQ_HANDLED;
}
#endif

/* This inner version is used privately by qman_create_portal(), as well as by
 * the exported qman_disable_portal(). */
static inline void qman_disable_portal_ex(struct qman_portal *p)
{
	local_irq_disable();
	if (!(p->disable_count++))
		qm_dqrr_set_maxfill(p->p, 0);
	local_irq_enable();
}

static int int_dqrr_mr_empty(struct qman_portal *p, int can_wait)
{
	int ret;
	might_sleep_if(can_wait);
	ret = (qm_dqrr_current(p->p) == NULL) &&
		(qm_mr_current(p->p) == NULL);
	if (ret && can_wait) {
		/* Stall and recheck to be sure it has quiesced. */
		msleep(RECOVER_MSLEEP);
		ret = (qm_dqrr_current(p->p) == NULL) &&
			(qm_mr_current(p->p) == NULL);
	}
	return ret;
}

struct qman_portal *qman_create_portal(struct qm_portal *__p, u32 flags,
			const struct qman_cgrs *cgrs,
			const struct qman_fq_cb *null_cb)
{
	struct qman_portal *portal;
	const struct qm_portal_config *config = qm_portal_config(__p);
	char buf[16];
	int ret;
	u32 isdr;

	portal = kmalloc(sizeof(*portal), GFP_KERNEL);
	if (!portal)
		return NULL;
	if (qm_eqcr_init(__p, qm_eqcr_pvb, qm_eqcr_cce)) {
		pr_err("Qman EQCR initialisation failed\n");
		goto fail_eqcr;
	}
	if (qm_dqrr_init(__p, qm_dqrr_dpush, qm_dqrr_pvb,
#ifdef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO_DCA
			qm_dqrr_cci
#else
			qm_dqrr_cdc
#endif
			, DQRR_MAXFILL,
			(flags & QMAN_PORTAL_FLAG_RSTASH) ? 1 : 0,
			(flags & QMAN_PORTAL_FLAG_DSTASH) ? 1 : 0)) {
		pr_err("Qman DQRR initialisation failed\n");
		goto fail_dqrr;
	}
	if (qm_mr_init(__p, qm_mr_pvb, qm_mr_cci)) {
		pr_err("Qman MR initialisation failed\n");
		goto fail_mr;
	}
	if (qm_mc_init(__p)) {
		pr_err("Qman MC initialisation failed\n");
		goto fail_mc;
	}
	if (qm_isr_init(__p)) {
		pr_err("Qman ISR initialisation failed\n");
		goto fail_isr;
	}
	/* static interrupt-gating controls */
	qm_dqrr_set_ithresh(__p, 12);
	qm_mr_set_ithresh(__p, 4);
	qm_isr_set_iperiod(__p, 100);
	portal->p = __p;
	if (!cgrs)
		portal->cgrs = NULL;
	else {
		portal->cgrs = kmalloc(2 * sizeof(*cgrs), GFP_KERNEL);
		if (!portal->cgrs)
			goto fail_cgrs;
		portal->cgrs[0] = *cgrs;
		memset(&portal->cgrs[1], 0, sizeof(*cgrs));
	}
	portal->options = flags;
	portal->bits = 0;
	portal->slowpoll = 0;
	portal->eq_prod = portal->eq_cons = 0;
	portal->sdqcr = QM_SDQCR_SOURCE_CHANNELS | QM_SDQCR_COUNT_UPTO3 |
			QM_SDQCR_DEDICATED_PRECEDENCE | QM_SDQCR_TYPE_PRIO_QOS |
			QM_SDQCR_TOKEN_SET(0xab) | QM_SDQCR_CHANNELS_DEDICATED;
	portal->disable_count = 0;
	if (null_cb)
		portal->null_cb = *null_cb;
	else
		memset(&portal->null_cb, 0, sizeof(*null_cb));
	sprintf(buf, "qportal-%d", config->channel);
	portal->pdev = platform_device_alloc(buf, -1);
	if (!portal->pdev) {
		ret = -ENOMEM;
		goto fail_devalloc;
	}
	ret = platform_device_add(portal->pdev);
	if (ret)
		goto fail_devadd;
	qman_rbtree_init(&portal->retire_table);
	isdr = 0xffffffff;
	qm_isr_disable_write(portal->p, isdr);
	qm_isr_enable_write(portal->p, QM_PIRQ_EQCI | QM_PIRQ_EQRI |
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_FAST
		QM_PIRQ_DQRI |
#endif
		QM_PIRQ_MRI | (cgrs ? QM_PIRQ_CSCI : 0));
	qm_isr_status_clear(portal->p, 0xffffffff);
#ifdef CONFIG_FSL_QMAN_HAVE_IRQ
	snprintf(portal->irqname, MAX_IRQNAME, IRQNAME, config->cpu);
	if (request_irq(config->irq, portal_isr, 0, portal->irqname, portal)) {
		pr_err("request_irq() failed\n");
		goto fail_irq;
	}
	if ((config->cpu != -1) && irq_can_set_affinity(config->irq) &&
				irq_set_affinity(config->irq,
					cpumask_of(config->cpu))) {
		pr_err("irq_set_affinity() failed\n");
		goto fail_affinity;
	}
	qm_isr_uninhibit(portal->p);
#endif
	/* Need EQCR to be empty before continuing */
	isdr ^= QM_PIRQ_EQCI;
	qm_isr_disable_write(portal->p, isdr);
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_RECOVER
	wait_event(affine_queue, !qm_eqcr_get_fill(portal->p));
	ret = 0;
#else
	ret = qm_eqcr_get_fill(portal->p);
#endif
	if (ret) {
		pr_err("Qman EQCR unclean, need recovery\n");
		goto fail_eqcr_empty;
	}
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_RECOVER
	/* Check DQRR and MR are empty too, subject to RECOVERY logic */
	if (flags & QMAN_PORTAL_FLAG_RECOVER)
		portal->bits |= PORTAL_BITS_RECOVER;
#endif
	isdr ^= (QM_PIRQ_DQRI | QM_PIRQ_MRI);
	qm_isr_disable_write(portal->p, isdr);
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_RECOVER
	wait_event(affine_queue, int_dqrr_mr_empty(portal, 1));
	ret = 0;
	qman_disable_portal_ex(portal);
	portal->bits ^= PORTAL_BITS_RECOVER;
#else
	ret = !int_dqrr_mr_empty(portal, 0);
#endif
	if (ret) {
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_RECOVER
		pr_err("Qman DQRR/MR unclean, recovery failed\n");
#else
		pr_err("Qman DQRR/MR unclean, need recovery\n");
#endif
		goto fail_dqrr_mr_empty;
	}
	qm_isr_disable_write(portal->p, 0);
	/* Write a sane SDQCR */
	qm_dqrr_sdqcr_set(portal->p, portal->sdqcr);
	return portal;
fail_dqrr_mr_empty:
fail_eqcr_empty:
fail_affinity:
#ifdef CONFIG_FSL_QMAN_HAVE_IRQ
	free_irq(config->irq, portal);
#endif
fail_irq:
	platform_device_del(portal->pdev);
fail_devadd:
	platform_device_put(portal->pdev);
fail_devalloc:
	if (portal->cgrs)
		kfree(portal->cgrs);
fail_cgrs:
	qm_isr_finish(__p);
fail_isr:
	qm_mc_finish(__p);
fail_mc:
	qm_mr_finish(__p);
fail_mr:
	qm_dqrr_finish(__p);
fail_dqrr:
	qm_eqcr_finish(__p);
fail_eqcr:
	kfree(portal);
	return NULL;
}

void qman_destroy_portal(struct qman_portal *qm)
{
	/* NB we do this to "quiesce" EQCR. If we add enqueue-completions or
	 * something related to QM_PIRQ_EQCI, this may need fixing. */
	qm_eqcr_cce_update(qm->p);
#ifdef CONFIG_FSL_QMAN_HAVE_IRQ
	free_irq(qm_portal_config(qm->p)->irq, qm);
#endif
	if (qm->cgrs)
		kfree(qm->cgrs);
	qm_isr_finish(qm->p);
	qm_mc_finish(qm->p);
	qm_mr_finish(qm->p);
	qm_dqrr_finish(qm->p);
	qm_eqcr_finish(qm->p);
	kfree(qm);
}

void qman_get_null_cb(struct qman_fq_cb *null_cb)
{
	struct qman_portal *p = get_affine_portal();
	*null_cb = p->null_cb;
	put_affine_portal();
}
EXPORT_SYMBOL(qman_get_null_cb);

void qman_set_null_cb(const struct qman_fq_cb *null_cb)
{
	struct qman_portal *p = get_affine_portal();
	p->null_cb = *null_cb;
	put_affine_portal();
}
EXPORT_SYMBOL(qman_set_null_cb);

/* Inline helper to reduce nesting in __poll_portal_slow() */
static inline void fq_state_change(struct qman_portal *p, struct qman_fq *fq,
				struct qm_mr_entry *msg, u8 verb)
{
	FQLOCK(fq);
	switch(verb) {
	case QM_MR_VERB_FQRL:
		QM_ASSERT(fq_isset(fq, QMAN_FQ_STATE_ORL));
		fq_clear(fq, QMAN_FQ_STATE_ORL);
		table_del_fq(p, fq);
		break;
	case QM_MR_VERB_FQRN:
		QM_ASSERT((fq->state == qman_fq_state_parked) ||
			(fq->state == qman_fq_state_sched));
		QM_ASSERT(fq_isset(fq, QMAN_FQ_STATE_CHANGING));
		fq_clear(fq, QMAN_FQ_STATE_CHANGING);
		if (msg->fq.fqs & QM_MR_FQS_NOTEMPTY)
			fq_set(fq, QMAN_FQ_STATE_NE);
		if (msg->fq.fqs & QM_MR_FQS_ORLPRESENT)
			fq_set(fq, QMAN_FQ_STATE_ORL);
		else
			table_del_fq(p, fq);
		fq->state = qman_fq_state_retired;
		break;
	case QM_MR_VERB_FQPN:
		QM_ASSERT(fq->state == qman_fq_state_sched);
		QM_ASSERT(fq_isclear(fq, QMAN_FQ_STATE_CHANGING));
		fq->state = qman_fq_state_parked;
	}
	FQUNLOCK(fq);
}

static noinline void eqcr_set_thresh(struct qman_portal *p, int check)
{
	if (!check || !qm_eqcr_get_ithresh(p->p))
		qm_eqcr_set_ithresh(p->p, EQCR_ITHRESH);
}

static u32 __poll_portal_slow(struct qman_portal *p, struct qm_portal *lowp,
				u32 is)
{
	struct qm_mr_entry *msg;

	qm_mr_pvb_prefetch(lowp);

	if (is & QM_PIRQ_CSCI) {
		struct qm_mc_result *mcr;
		unsigned int i;
		local_irq_disable();
		qm_mc_start(lowp);
		qm_mc_commit(lowp, QM_MCC_VERB_QUERYCONGESTION);
		while (!(mcr = qm_mc_result(lowp)))
			cpu_relax();
		p->cgrs[1].q = mcr->querycongestion.state;
		local_irq_enable();
		for (i = 0; i < 8; i++)
			p->cgrs[1].q.__state[i] &= p->cgrs[0].q.__state[i];
	}

#if 0
	/* PIRQ_EQCI serves no meaningful purpose for a high-level interface,
	 * so you can enable it to force interrupt-processing if you want (ie.
	 * as a consequence of h/w consuming your EQCR entry, despite this
	 * being unrelated to the work interrupt-processing needs to do).
	 * Callbacks for enqueue-completion don't make sense (because they can
	 * get rejected some time after EQCR-consumption, so you'd have to be
	 * call it enqueue-incompletion...), and even if they did, you'd have
	 * to call them irrespective of the EQCI interrupt source because it
	 * can get coalesced. */
	if (is & QM_PIRQ_EQCI) { ... }

#endif
	if (is & QM_PIRQ_EQRI) {
		local_irq_disable();
		p->eq_cons += qm_eqcr_cce_update(lowp);
		qm_eqcr_set_ithresh(lowp, 0);
		wake_up(&affine_queue);
		local_irq_enable();
	}

	if (is & QM_PIRQ_MRI) {
		u8 num = 0;
mr_loop:
		if (qm_mr_pvb_update(lowp))
			qm_mr_pvb_prefetch(lowp);
		msg = qm_mr_current(lowp);
		if (msg) {
			struct qman_fq *fq = (void *)msg->ern.tag;
			u8 verb = msg->verb & QM_MR_VERB_TYPE_MASK;
			if (unlikely(p->bits & PORTAL_BITS_RECOVER)) {
				/* use portal default handlers for recovery */
				if (likely(!(verb & QM_MR_VERB_DC_ERN)))
					p->null_cb.ern(p, NULL, msg);
				else if (verb == QM_MR_VERB_DC_ERN)
					p->null_cb.dc_ern(p, NULL, msg);
				else if (p->null_cb.fqs)
					p->null_cb.fqs(p, NULL, msg);
			}
			if (verb == QM_MR_VERB_FQRNI) {
				; /* nada, we drop FQRNIs on the floor */
			} else if ((verb == QM_MR_VERB_FQRN) ||
					(verb == QM_MR_VERB_FQRL)) {
				/* It's retirement related - need a lookup */
				fq = table_find_fq(p, msg->fq.fqid);
				if (!fq)
					panic("unexpected FQ retirement");
				fq_state_change(p, fq, msg, verb);
				if (fq->cb.fqs)
					fq->cb.fqs(p, fq, msg);
			} else if (likely(fq)) {
				/* As per the header note, this is the way to
				 * determine if it's a s/w ERN or not. */
				if (likely(!(verb & QM_MR_VERB_DC_ERN)))
					fq->cb.ern(p, fq, msg);
				else
					fq->cb.dc_ern(p, fq, msg);
			} else {
				/* use portal default handlers for 'null's */
				if (likely(!(verb & QM_MR_VERB_DC_ERN)))
					p->null_cb.ern(p, NULL, msg);
				else if (verb == QM_MR_VERB_DC_ERN)
					p->null_cb.dc_ern(p, NULL, msg);
				else if (p->null_cb.fqs)
					p->null_cb.fqs(p, NULL, msg);
			}
			num++;
			qm_mr_next(lowp);
			goto mr_loop;
		}
		qm_mr_cci_consume(lowp, num);
	}

	return is & (QM_PIRQ_CSCI | QM_PIRQ_EQCI | QM_PIRQ_EQRI | QM_PIRQ_MRI);
}

/* Look: no locks, no irq_disable()s, no preempt_disable()s! :-) The only states
 * that would conflict with other things if they ran at the same time on the
 * same cpu are;
 *
 *   (i) clearing/incrementing PORTAL_BITS_*** stuff related to VDQCR, and
 *  (ii) clearing the NE (Not Empty) flag.
 *
 * Both are safe. Because;
 *
 *   (i) this clearing/incrementing can only occur after qman_volatile_dequeue()
 *       has set the PORTAL_BITS_*** stuff (which it does before setting VDQCR),
 *       and qman_volatile_dequeue() blocks interrupts and preemption while this
 *       is done so that we can't interfere.
 *  (ii) the NE flag is only cleared after qman_retire_fq() has set it, and as
 *       with (i) that API prevents us from interfering until it's safe.
 *
 * The good thing is that qman_volatile_dequeue() and qman_retire_fq() run far
 * less frequently (ie. per-FQ) than __poll_portal_fast() does, so the nett
 * advantage comes from this function not having to "lock" anything at all.
 *
 * Note also that the callbacks are invoked at points which are safe against the
 * above potential conflicts, but that this function itself is not re-entrant
 * (this is because the function tracks one end of each FIFO in the portal and
 * we do *not* want to lock that). So the consequence is that it is safe for
 * user callbacks to call into any Qman API *except* qman_poll() (as that's the
 * sole API that could be invoking the callback through this function).
 */
static inline void __poll_portal_fast(struct qman_portal *p,
				struct qm_portal *lowp)
{
	struct qm_dqrr_entry *dq;
	struct qman_fq *fq;
	enum qman_cb_dqrr_result res;
	int prefetch = !(p->options & QMAN_PORTAL_FLAG_RSTASH);
	int limit = 0;

loop:
	if (qm_dqrr_pvb_update(lowp) && prefetch)
		qm_dqrr_pvb_prefetch(lowp);
	dq = qm_dqrr_current(lowp);
	if (!dq)
		goto done;
	fq = (void *)dq->contextB;
	/* Interpret 'dq' from the owner's perspective. */
	if (unlikely(
#ifdef CONFIG_FSL_QMAN_PORTAL_FLAG_RECOVER
			(p->bits & PORTAL_BITS_RECOVER) ||
#endif
			!fq)) {
		/* use portal default handlers */
		res = p->null_cb.dqrr(p, NULL, dq);
		QM_ASSERT(res == qman_cb_dqrr_consume);
		res = qman_cb_dqrr_consume;
	} else {
		if (dq->stat & QM_DQRR_STAT_FQ_EMPTY)
			fq_clear(fq, QMAN_FQ_STATE_NE);
		/* Now let the callback do its stuff */
		res = fq->cb.dqrr(p, fq, dq);
	}
	/* Interpret 'dq' from a driver perspective. */
#define VDQCR_DONE (QM_DQRR_STAT_UNSCHEDULED | QM_DQRR_STAT_DQCR_EXPIRED)
	if (unlikely((dq->stat & VDQCR_DONE) == VDQCR_DONE)) {
		PORTAL_BITS_INC_V(p);
		wake_up(&affine_queue);
	}
	/* Parking isn't possible unless HELDACTIVE was set. NB,
	 * FORCEELIGIBLE implies HELDACTIVE, so we only need to
	 * check for HELDACTIVE to cover both. */
	QM_ASSERT((dq->stat & QM_DQRR_STAT_FQ_HELDACTIVE) ||
		(res != qman_cb_dqrr_park));
#ifdef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO_DCA
	if (res == qman_cb_dqrr_park)
		/* The only thing to do for non-DCA is the park-request */
		qm_dqrr_park_ci(lowp);
	/* Move forward */
	qm_dqrr_next(lowp);
	qm_dqrr_cci_consume(lowp, 1);
#else
	/* Defer just means "skip it, I'll consume it myself later on" */
	if (res != qman_cb_dqrr_defer)
		qm_dqrr_cdc_consume_1ptr(lowp, dq, (res == qman_cb_dqrr_park));
	/* Move forward */
	qm_dqrr_next(lowp);
#endif
	if (++limit < CONFIG_FSL_QMAN_POLL_LIMIT)
		goto loop;
done:
	if (prefetch)
		qm_dqrr_pvb_prefetch(lowp);
}

#ifdef CONFIG_FSL_QMAN_HAVE_POLL
void qman_poll(void)
{
	struct qman_portal *p = get_affine_portal();
	struct qm_portal *lowp = p->p;
#ifndef CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_SLOW
	if (!(p->slowpoll--)) {
		u32 is = qm_isr_status_read(lowp);
		u32 active = __poll_portal_slow(p, lowp, is);
		if (active) {
			qm_isr_status_clear(lowp, active);
			p->slowpoll = SLOW_POLL_BUSY;
		} else
			p->slowpoll = SLOW_POLL_IDLE;
	}
#endif
#ifndef CONFIG_FSL_QMAN_PORTAL_FLAG_IRQ_FAST
	__poll_portal_fast(p, lowp);
#endif
	put_affine_portal();
}
EXPORT_SYMBOL(qman_poll);
#endif

void qman_disable_portal(void)
{
	struct qman_portal *p = get_affine_portal();
	qman_disable_portal_ex(p);
	put_affine_portal();
}
EXPORT_SYMBOL(qman_disable_portal);

void qman_enable_portal(void)
{
	struct qman_portal *p = get_affine_portal();
	local_irq_disable();
	QM_ASSERT(p->disable_count > 0);
	if (!(--p->disable_count))
		qm_dqrr_set_maxfill(p->p, DQRR_MAXFILL);
	local_irq_enable();
	put_affine_portal();
}
EXPORT_SYMBOL(qman_enable_portal);

/* This isn't a fast-path API, and qman_driver.c setup code needs to be able to
 * set initial SDQCR values to all portals, not just the affine one for the
 * current cpu, so we suction out the "_ex" version as a private hook. */
void qman_static_dequeue_add_ex(struct qman_portal *p, u32 pools)
{
	local_irq_disable();
	pools &= p->p->config.pools;
	p->sdqcr |= pools;
	qm_dqrr_sdqcr_set(p->p, p->sdqcr);
	local_irq_enable();
}

void qman_static_dequeue_add(u32 pools)
{
	struct qman_portal *p = get_affine_portal();
	qman_static_dequeue_add_ex(p, pools);
	put_affine_portal();
}
EXPORT_SYMBOL(qman_static_dequeue_add);

void qman_static_dequeue_del(u32 pools)
{
	struct qman_portal *p = get_affine_portal();
	local_irq_disable();
	pools &= p->p->config.pools;
	p->sdqcr &= ~pools;
	qm_dqrr_sdqcr_set(p->p, p->sdqcr);
	local_irq_enable();
	put_affine_portal();
}
EXPORT_SYMBOL(qman_static_dequeue_del);

u32 qman_static_dequeue_get(void)
{
	struct qman_portal *p = get_affine_portal();
	u32 ret = p->sdqcr;
	put_affine_portal();
	return ret;
}
EXPORT_SYMBOL(qman_static_dequeue_get);

void qman_dca(struct qm_dqrr_entry *dq, int park_request)
{
	struct qman_portal *p = get_affine_portal();
	qm_dqrr_cdc_consume_1ptr(p->p, dq, park_request);
	put_affine_portal();
}
EXPORT_SYMBOL(qman_dca);

/*******************/
/* Frame queue API */
/*******************/

static const char *mcr_result_str(u8 result)
{
	switch (result) {
	case QM_MCR_RESULT_NULL:
		return "QM_MCR_RESULT_NULL";
	case QM_MCR_RESULT_OK:
		return "QM_MCR_RESULT_OK";
	case QM_MCR_RESULT_ERR_FQID:
		return "QM_MCR_RESULT_ERR_FQID";
	case QM_MCR_RESULT_ERR_FQSTATE:
		return "QM_MCR_RESULT_ERR_FQSTATE";
	case QM_MCR_RESULT_ERR_NOTEMPTY:
		return "QM_MCR_RESULT_ERR_NOTEMPTY";
	case QM_MCR_RESULT_PENDING:
		return "QM_MCR_RESULT_PENDING";
	}
	return "<unknown MCR result>";
}

int qman_create_fq(u32 fqid, u32 flags, struct qman_fq *fq)
{
	struct qm_fqd fqd;
	struct qm_mcr_queryfq_np np;
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;

	if (flags & QMAN_FQ_FLAG_DYNAMIC_FQID) {
		fqid = qm_fq_new();
		if (!fqid)
			return -ENOMEM;
	}
	spin_lock_init(&fq->fqlock);
	fq->fqid = fqid;
	fq->flags = flags;
	fq->state = qman_fq_state_oos;
	fq->cgr_groupid = 0;
	if (!(flags & QMAN_FQ_FLAG_RECOVER) ||
			(flags & QMAN_FQ_FLAG_NO_MODIFY))
		return 0;
	/* Everything else is RECOVER support */
	p = get_affine_portal();
	local_irq_disable();
	mcc = qm_mc_start(p->p);
	mcc->queryfq.fqid = fqid;
	qm_mc_commit(p->p, QM_MCC_VERB_QUERYFQ);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCC_VERB_QUERYFQ);
	if (mcr->result != QM_MCR_RESULT_OK) {
		pr_err("QUERYFQ failed: %s\n", mcr_result_str(mcr->result));
		goto err;
	}
	fqd = mcr->queryfq.fqd;
	mcc = qm_mc_start(p->p);
	mcc->queryfq_np.fqid = fqid;
	qm_mc_commit(p->p, QM_MCC_VERB_QUERYFQ_NP);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCC_VERB_QUERYFQ_NP);
	if (mcr->result != QM_MCR_RESULT_OK) {
		pr_err("QUERYFQ_NP failed: %s\n", mcr_result_str(mcr->result));
		goto err;
	}
	np = mcr->queryfq_np;
	/* Phew, have queryfq and queryfq_np results, stitch together
	 * the FQ object from those. */
	fq->cgr_groupid = fqd.cgid;
	switch (np.state & QM_MCR_NP_STATE_MASK) {
	case QM_MCR_NP_STATE_OOS:
		break;
	case QM_MCR_NP_STATE_RETIRED:
		fq->state = qman_fq_state_retired;
		if (np.frm_cnt)
			fq_set(fq, QMAN_FQ_STATE_NE);
		break;
	case QM_MCR_NP_STATE_TEN_SCHED:
	case QM_MCR_NP_STATE_TRU_SCHED:
	case QM_MCR_NP_STATE_ACTIVE:
		fq->state = qman_fq_state_sched;
		if (np.state & QM_MCR_NP_STATE_R)
			fq_set(fq, QMAN_FQ_STATE_CHANGING);
		break;
	case QM_MCR_NP_STATE_PARKED:
		fq->state = qman_fq_state_parked;
		break;
	default:
		QM_ASSERT(NULL == "invalid FQ state");
	}
	if (fqd.fq_ctrl & QM_FQCTRL_CGE)
		fq->state |= QMAN_FQ_STATE_CGR_EN;
	local_irq_enable();
	put_affine_portal();
	return 0;
err:
	local_irq_enable();
	put_affine_portal();
	if (flags & QMAN_FQ_FLAG_DYNAMIC_FQID)
		qm_fq_free(fqid);
	return -EIO;
}
EXPORT_SYMBOL(qman_create_fq);

void qman_destroy_fq(struct qman_fq *fq, u32 flags)
{
	/* We don't need to lock the FQ as it is a pre-condition that the FQ be
	 * quiesced. Instead, run some checks. */
	switch (fq->state) {
	case qman_fq_state_parked:
		QM_ASSERT(flags & QMAN_FQ_DESTROY_PARKED);
	case qman_fq_state_oos:
		if (fq_isset(fq, QMAN_FQ_FLAG_DYNAMIC_FQID))
			qm_fq_free(fq->fqid);
		return;
	default:
		break;
	}
	QM_ASSERT(NULL == "qman_free_fq() on unquiesced FQ!");
}
EXPORT_SYMBOL(qman_destroy_fq);

u32 qman_fq_fqid(struct qman_fq *fq)
{
	return fq->fqid;
}
EXPORT_SYMBOL(qman_fq_fqid);

void qman_fq_state(struct qman_fq *fq, enum qman_fq_state *state, u32 *flags)
{
	*state = fq->state;
	if (flags)
		*flags = fq->flags;
}
EXPORT_SYMBOL(qman_fq_state);

int qman_init_fq(struct qman_fq *fq, u32 flags, struct qm_mcc_initfq *opts)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	u8 res, myverb = (flags & QMAN_INITFQ_FLAG_SCHED) ?
		QM_MCC_VERB_INITFQ_SCHED : QM_MCC_VERB_INITFQ_PARKED;

	QM_ASSERT((fq->state == qman_fq_state_oos) ||
		(fq->state == qman_fq_state_parked));
#ifdef CONFIG_FSL_QMAN_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_MODIFY)))
		return -EINVAL;
#endif
	/* Issue an INITFQ_[PARKED|SCHED] management command */
	p = get_affine_portal();
	local_irq_disable();
	FQLOCK(fq);
	if (unlikely((fq_isset(fq, QMAN_FQ_STATE_CHANGING)) ||
			((fq->state != qman_fq_state_oos) &&
				(fq->state != qman_fq_state_parked)))) {
		FQUNLOCK(fq);
		local_irq_enable();
		put_affine_portal();
		return -EBUSY;
	}
	mcc = qm_mc_start(p->p);
	if (opts)
		mcc->initfq = *opts;
	mcc->initfq.fqid = fq->fqid;
	mcc->initfq.count = 0;
	/* If INITFQ_FLAG_NULL is passed, contextB is set to zero. Otherwise,
	 * if the FQ does *not* have the TO_DCPORTAL flag, contextB is set as a
	 * demux pointer. Otherwise, TO_DCPORTAL is set, so the caller-provided
	 * value is allowed to stand, don't overwrite it. */
	if ((flags & QMAN_INITFQ_FLAG_NULL) ||
			fq_isclear(fq, QMAN_FQ_FLAG_TO_DCPORTAL)) {
		dma_addr_t phys_fq;
		BUG_ON(sizeof(phys_fq) > sizeof(u32));
		mcc->initfq.we_mask |= QM_INITFQ_WE_CONTEXTB;
		mcc->initfq.fqd.context_b = (flags & QMAN_INITFQ_FLAG_NULL) ?
						0 : (u32)fq;
		/* and the physical address - NB, if the user wasn't trying to
		 * set CONTEXTA, clear the stashing settings. */
		if (!(mcc->initfq.we_mask & QM_INITFQ_WE_CONTEXTA)) {
			mcc->initfq.we_mask |= QM_INITFQ_WE_CONTEXTA;
			memset(&mcc->initfq.fqd.context_a, 0,
				sizeof(&mcc->initfq.fqd.context_a));
		}
		phys_fq = dma_map_single(&p->pdev->dev, fq, sizeof(*fq),
					DMA_TO_DEVICE);
		mcc->initfq.fqd.context_a.context_hi = 0;
		mcc->initfq.fqd.context_a.context_lo = (u32)phys_fq;
	}
	if (flags & QMAN_INITFQ_FLAG_LOCAL) {
		mcc->initfq.fqd.dest.channel = p->p->config.channel;
		if (!(mcc->initfq.we_mask & QM_INITFQ_WE_DESTWQ)) {
			mcc->initfq.we_mask |= QM_INITFQ_WE_DESTWQ;
			mcc->initfq.fqd.dest.wq = 4;
		}
	}
	qm_mc_commit(p->p, myverb);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == myverb);
	res = mcr->result;
	if (res != QM_MCR_RESULT_OK) {
		pr_err("INITFQ failed: %s\n", mcr_result_str(res));
		FQUNLOCK(fq);
		local_irq_enable();
		put_affine_portal();
		return -EIO;
	}
	if (opts) {
		if (opts->we_mask & QM_INITFQ_WE_FQCTRL) {
			if (opts->fqd.fq_ctrl & QM_FQCTRL_CGE)
				fq_set(fq, QMAN_FQ_STATE_CGR_EN);
			else
				fq_clear(fq, QMAN_FQ_STATE_CGR_EN);
		}
		if (opts->we_mask & QM_INITFQ_WE_CGID)
			fq->cgr_groupid = opts->fqd.cgid;
	}
	fq->state = (flags & QMAN_INITFQ_FLAG_SCHED) ?
			qman_fq_state_sched : qman_fq_state_parked;
	FQUNLOCK(fq);
	local_irq_enable();
	put_affine_portal();
	return 0;
}
EXPORT_SYMBOL(qman_init_fq);

int qman_schedule_fq(struct qman_fq *fq)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	int ret = 0;
	u8 res;

	QM_ASSERT(fq->state == qman_fq_state_parked);
#ifdef CONFIG_FSL_QMAN_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_MODIFY)))
		return -EINVAL;
#endif
	/* Issue a ALTERFQ_SCHED management command */
	p = get_affine_portal();
	local_irq_disable();
	FQLOCK(fq);
	if (unlikely((fq_isset(fq, QMAN_FQ_STATE_CHANGING)) ||
			(fq->state != qman_fq_state_parked))) {
		ret = -EBUSY;
		goto out;
	}
	mcc = qm_mc_start(p->p);
	mcc->alterfq.fqid = fq->fqid;
	qm_mc_commit(p->p, QM_MCC_VERB_ALTER_SCHED);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCR_VERB_ALTER_SCHED);
	res = mcr->result;
	if (res != QM_MCR_RESULT_OK) {
		pr_err("ALTER_SCHED failed: %s\n", mcr_result_str(res));
		ret = -EIO;
		goto out;
	}
	fq->state = qman_fq_state_sched;
out:
	FQUNLOCK(fq);
	local_irq_enable();
	put_affine_portal();
	return ret;
}
EXPORT_SYMBOL(qman_schedule_fq);

int qman_retire_fq(struct qman_fq *fq, u32 *flags)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	int rval;
	u8 res;

	QM_ASSERT((fq->state == qman_fq_state_parked) ||
		(fq->state == qman_fq_state_sched));
#ifdef CONFIG_FSL_QMAN_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_MODIFY)))
		return -EINVAL;
#endif
	p = get_affine_portal();
	local_irq_disable();
	FQLOCK(fq);
	if (unlikely((fq_isset(fq, QMAN_FQ_STATE_CHANGING)) ||
			(fq->state == qman_fq_state_retired) ||
				(fq->state == qman_fq_state_oos))) {
		rval = -EBUSY;
		goto out;
	}
	rval = table_push_fq(p, fq);
	if (rval)
		goto out;
	mcc = qm_mc_start(p->p);
	mcc->alterfq.fqid = fq->fqid;
	qm_mc_commit(p->p, QM_MCC_VERB_ALTER_RETIRE);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCR_VERB_ALTER_RETIRE);
	res = mcr->result;
	/* "Elegant" would be to treat OK/PENDING the same way; set CHANGING,
	 * and defer the flags until FQRNI or FQRN (respectively) show up. But
	 * "Friendly" is to process OK immediately, and not set CHANGING. We do
	 * friendly, otherwise the caller doesn't necessarily have a fully
	 * "retired" FQ on return even if the retirement was immediate. However
	 * this does mean some code duplication between here and
	 * fq_state_change(). */
	if (likely(res == QM_MCR_RESULT_OK)) {
		rval = 0;
		/* Process 'fq' right away, we'll ignore FQRNI */
		if (mcr->alterfq.fqs & QM_MCR_FQS_NOTEMPTY)
			fq_set(fq, QMAN_FQ_STATE_NE);
		if (mcr->alterfq.fqs & QM_MCR_FQS_ORLPRESENT)
			fq_set(fq, QMAN_FQ_STATE_ORL);
		else
			table_del_fq(p, fq);
		if (flags)
			*flags = fq->flags;
		fq->state = qman_fq_state_retired;
		if (fq->cb.fqs) {
			/* Another issue with supporting "immediate" retirement
			 * is that we're forced to drop FQRNIs, because by the
			 * time they're seen it may already be "too late" (the
			 * fq may have been OOS'd and free()'d already). But if
			 * the upper layer wants a callback whether it's
			 * immediate or not, we have to fake a "MR" entry to
			 * look like an FQRNI... */
			struct qm_mr_entry msg;
			msg.verb = QM_MR_VERB_FQRNI;
			msg.fq.fqs = mcr->alterfq.fqs;
			msg.fq.fqid = fq->fqid;
			msg.fq.contextB = (u32)fq;
			fq->cb.fqs(p, fq, &msg);
		}
	} else if (res == QM_MCR_RESULT_PENDING) {
		rval = 1;
		fq_set(fq, QMAN_FQ_STATE_CHANGING);
	} else {
		rval = -EIO;
		table_del_fq(p, fq);
		pr_err("ALTER_RETIRE failed: %s\n", mcr_result_str(res));
	}
out:
	FQUNLOCK(fq);
	local_irq_enable();
	put_affine_portal();
	return rval;
}
EXPORT_SYMBOL(qman_retire_fq);

int qman_oos_fq(struct qman_fq *fq)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p;
	int ret = 0;
	u8 res;

	QM_ASSERT(fq->state == qman_fq_state_retired);
#ifdef CONFIG_FSL_QMAN_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_MODIFY)))
		return -EINVAL;
#endif
	p = get_affine_portal();
	local_irq_disable();
	FQLOCK(fq);
	if (unlikely((fq_isset(fq, QMAN_FQ_STATE_BLOCKOOS)) ||
			(fq->state != qman_fq_state_retired))) {
		ret = -EBUSY;
		goto out;
	}
	mcc = qm_mc_start(p->p);
	mcc->alterfq.fqid = fq->fqid;
	qm_mc_commit(p->p, QM_MCC_VERB_ALTER_OOS);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCR_VERB_ALTER_OOS);
	res = mcr->result;
	if (res != QM_MCR_RESULT_OK) {
		pr_err("ALTER_OOS failed: %s\n", mcr_result_str(res));
		ret = -EIO;
		goto out;
	}
	fq->state = qman_fq_state_oos;
out:
	FQUNLOCK(fq);
	local_irq_enable();
	put_affine_portal();
	return ret;
}
EXPORT_SYMBOL(qman_oos_fq);

int qman_query_fq(struct qman_fq *fq, struct qm_fqd *fqd)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p = get_affine_portal();
	u8 res;

	local_irq_disable();
	mcc = qm_mc_start(p->p);
	mcc->queryfq.fqid = fq->fqid;
	qm_mc_commit(p->p, QM_MCC_VERB_QUERYFQ);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCR_VERB_QUERYFQ);
	res = mcr->result;
	if (res == QM_MCR_RESULT_OK)
		*fqd = mcr->queryfq.fqd;
	local_irq_enable();
	put_affine_portal();
	if (res != QM_MCR_RESULT_OK) {
		pr_err("QUERYFQ failed: %s\n", mcr_result_str(res));
		return -EIO;
	}
	return 0;
}
EXPORT_SYMBOL(qman_query_fq);

int qman_query_fq_np(struct qman_fq *fq, struct qm_mcr_queryfq_np *np)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p = get_affine_portal();
	u8 res;

	local_irq_disable();
	mcc = qm_mc_start(p->p);
	mcc->queryfq.fqid = fq->fqid;
	qm_mc_commit(p->p, QM_MCC_VERB_QUERYFQ_NP);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCR_VERB_QUERYFQ_NP);
	res = mcr->result;
	if (res == QM_MCR_RESULT_OK)
		*np = mcr->queryfq_np;
	local_irq_enable();
	put_affine_portal();
	if (res != QM_MCR_RESULT_OK) {
		pr_err("QUERYFQ_NP failed: %s\n", mcr_result_str(res));
		return -EIO;
	}
	return 0;
}
EXPORT_SYMBOL(qman_query_fq_np);

/* internal function used as a wait_event() expression */
static int set_vdqcr(struct qman_portal **p, u32 vdqcr, u16 *v)
{
	int ret = -EBUSY;
	*p = get_affine_portal();
	local_irq_disable();
	if (!((*p)->bits & PORTAL_BITS_VDQCR)) {
		(*p)->bits |= PORTAL_BITS_VDQCR;
		ret = 0;
	}
	local_irq_enable();
	if (!ret) {
		if (v)
			*v = PORTAL_BITS_GET_V(*p);
		qm_dqrr_vdqcr_set((*p)->p, vdqcr);
	}
	put_affine_portal();
	return ret;
}

static int wait_vdqcr_start(struct qman_portal **p, u32 vdqcr, u16 *v,
					u32 flags)
{
	int ret = 0;
	if (flags & QMAN_VOLATILE_FLAG_WAIT_INT)
		ret = wait_event_interruptible(affine_queue,
					!(ret = set_vdqcr(p, vdqcr, v)));
	else
		wait_event(affine_queue, !(ret = set_vdqcr(p, vdqcr, v)));
	return ret;
}

int qman_volatile_dequeue(struct qman_fq *fq, u32 flags, u32 vdqcr)
{
	struct qman_portal *p;
	int ret;
	u16 v = 0; /* init not needed, but gcc is dumb */

	QM_ASSERT(!fq || (fq->state == qman_fq_state_parked) ||
			(fq->state == qman_fq_state_retired));
	QM_ASSERT(!fq || !(vdqcr & QM_VDQCR_FQID_MASK));
	if (fq)
		vdqcr = (vdqcr & ~QM_VDQCR_FQID_MASK) | fq->fqid;
	if (flags & QMAN_VOLATILE_FLAG_WAIT)
		ret = wait_vdqcr_start(&p, vdqcr, &v, flags);
	else
		ret = set_vdqcr(&p, vdqcr, &v);
	if (ret)
		return ret;
	/* VDQCR is set */
	if (flags & QMAN_VOLATILE_FLAG_FINISH) {
		if (flags & QMAN_VOLATILE_FLAG_WAIT_INT)
			/* NB: don't propagate any error - the caller wouldn't
			 * know whether the VDQCR was issued or not. A signal
			 * could arrive after returning anyway, so the caller
			 * can check signal_pending() if that's an issue. */
			wait_event_interruptible(affine_queue,
				PORTAL_BITS_GET_V(p) != v);
		else
			wait_event(affine_queue, PORTAL_BITS_GET_V(p) != v);
	}
	return 0;
}
EXPORT_SYMBOL(qman_volatile_dequeue);

static struct qm_eqcr_entry *try_eq_start(struct qman_portal **p)
{
	struct qm_eqcr_entry *eq;
	struct qm_portal *lowp;
	u8 avail;
	*p = get_affine_portal();
	lowp = (*p)->p;
	local_irq_disable();
	avail = qm_eqcr_get_avail(lowp);
	if (avail == EQCR_THRESH)
		/* We don't need EQCR:CI yet, but we will next time */
		qm_eqcr_cce_prefetch(lowp);
	else if (avail < EQCR_THRESH)
		/* The EQCR::CI cacheline is prefetched post-enqueue, so this
		 * would ideally be in cache from the previous commit. */
		(*p)->eq_cons += qm_eqcr_cce_update(lowp);
	eq = qm_eqcr_start(lowp);
	if (unlikely(!eq)) {
		local_irq_enable();
		put_affine_portal();
	}
	return eq;
}

static inline struct qm_eqcr_entry *__try_eq(struct qman_portal **p)
{
	struct qm_eqcr_entry *eq = try_eq_start(p);
	if (unlikely(!eq))
		/* TODO: this used to be in try_eq_start() prior to
		 * local_irq_enable() - verify that the reorder hasn't created a
		 * race... */
		eqcr_set_thresh(*p, 1);
	return eq;
}

static noinline struct qm_eqcr_entry *wait_eq_start(struct qman_portal **p,
							u32 flags)
{
	struct qm_eqcr_entry *eq;
	int ret = 0;
	if (flags & QMAN_ENQUEUE_FLAG_WAIT_INT)
		ret = wait_event_interruptible(affine_queue,
					(eq = __try_eq(p)));
	else
		wait_event(affine_queue, (eq = __try_eq(p)));
	return eq;
}

/* Used as a wait_event() condition to determine if eq_cons has caught up to
 * eq_poll. The complication is that they're wrap-arounds, so we use a cyclic
 * comparison. This would a lot simpler if it weren't to work around a
 * theoretical possibility - that the u32 prod/cons counters wrap so fast before
 * this task is woken that it appears the enqueue never completed. We can't wait
 * for it to wrap "another time" because activity might have stopped and the
 * interrupt threshold is no longer set to wake us up (about as improbable as
 * the scenario we're fixing). What we do then is wait until the cons counter
 * reaches a safely-completed distance from 'eq_poll' *or* EQCR becomes empty,
 * and continually reset the interrupt threshold until this happens (and for
 * qman_poll() to do wakeups *after* unsetting the interrupt threshold). */
static int eqcr_completed(struct qman_portal *p, u32 eq_poll)
{
	u32 tr_cons = p->eq_cons;
	if (eq_poll & 0xc0000000) {
		eq_poll &= 0x7fffffff;
		tr_cons ^= 0x80000000;
	}
	if (tr_cons >= eq_poll)
		return 1;
	if ((eq_poll - tr_cons) > QM_EQCR_SIZE)
		return 1;
	if (!qm_eqcr_get_fill(p->p))
		/* If EQCR is empty, we must have completed */
		return 1;
	eqcr_set_thresh(p, 0);
	return 0;
}

static noinline void wait_eqcr_commit(struct qman_portal *p, u32 flags,
					u32 eq_poll)
{
	eqcr_set_thresh(p, 1);
	/* So we're supposed to wait until the commit is consumed */
	if (flags & QMAN_ENQUEUE_FLAG_WAIT_INT)
		/* See __enqueue() (where this inline is called) as to why we're
		 * ignoring return codes from wait_***(). */
		wait_event_interruptible(affine_queue,
					eqcr_completed(p, eq_poll));
	else
		wait_event(affine_queue, eqcr_completed(p, eq_poll));
}

static inline void eqcr_commit(struct qman_portal *p, u32 flags, int orp)
{
	u32 eq_poll;
	qm_eqcr_pvb_commit(p->p,
		(flags & (QM_EQCR_VERB_COLOUR_MASK | QM_EQCR_VERB_INTERRUPT |
				QM_EQCR_VERB_CMD_ENQUEUE)) |
		(orp ? QM_EQCR_VERB_ORP : 0));
	/* increment the producer count and capture it for SYNC */
	eq_poll = ++p->eq_prod;
	local_irq_enable();
	put_affine_portal();
	if ((flags & QMAN_ENQUEUE_FLAG_WAIT_SYNC) ==
			QMAN_ENQUEUE_FLAG_WAIT_SYNC)
		wait_eqcr_commit(p, flags, eq_poll);
}

static inline void eqcr_abort(struct qman_portal *p)
{
	qm_eqcr_abort(p->p);
	local_irq_enable();
	put_affine_portal();
}

/* Internal version of enqueue, used by ORP and non-ORP variants. Inlining
 * should allow each instantiation to optimise appropriately (and this is why
 * the excess 'orp' parameters are not an issue). */
static inline int __enqueue(struct qman_fq *fq, const struct qm_fd *fd,
				u32 flags, struct qman_fq *orp_fq,
				u16 orp_seqnum, int orp)
{
	register struct qm_eqcr_entry *eq;
	struct qman_portal *p;

#ifdef CONFIG_FSL_QMAN_CHECKING
	if (unlikely(fq_isset(fq, QMAN_FQ_FLAG_NO_ENQUEUE)))
		return -EINVAL;
	if (unlikely(fq_isclear(fq, QMAN_FQ_FLAG_NO_MODIFY) &&
			((fq->state == qman_fq_state_retired) ||
			(fq->state == qman_fq_state_oos))))
		return -EBUSY;
#endif

	eq = try_eq_start(&p);
	if (unlikely(!eq)) {
		if (flags & QMAN_ENQUEUE_FLAG_WAIT) {
			eq = wait_eq_start(&p, flags);
			if (!eq)
				return -EBUSY;
		} else
			return -EBUSY;
	}
	/* If we're using ORP, it's very unwise to back-off because of
	 * WATCH_CGR - that would leave a hole in the ORP sequence which could
	 * block (if the caller doesn't retry). The idea is to enqueue via the
	 * ORP anyway, and let congestion take effect in h/w once
	 * order-restoration has occurred. */
#if 0
	if (unlikely(!orp && (flags & QMAN_ENQUEUE_FLAG_WATCH_CGR) && p->cgrs &&
			fq_isset(fq, QMAN_FQ_STATE_CGR_EN) &&
			qman_cgrs_get(&p->cgrs[1], fq->cgr_groupid))) {
		eqcr_abort(p);
		return -EAGAIN;
	}
#endif
	if (flags & QMAN_ENQUEUE_FLAG_DCA) {
		u8 dca = QM_EQCR_DCA_ENABLE;
		if (unlikely(flags & QMAN_ENQUEUE_FLAG_DCA_PARK))
			dca |= QM_EQCR_DCA_PARK;
		dca |= ((flags >> 8) & QM_EQCR_DCA_IDXMASK);
		eq->dca = dca;
	}
	if (orp) {
		if (flags & QMAN_ENQUEUE_FLAG_NLIS)
			orp_seqnum |= QM_EQCR_SEQNUM_NLIS;
		else {
			orp_seqnum &= ~QM_EQCR_SEQNUM_NLIS;
			if (flags & QMAN_ENQUEUE_FLAG_NESN)
				orp_seqnum |= QM_EQCR_SEQNUM_NESN;
			else
				/* No need to check 4 QMAN_ENQUEUE_FLAG_HOLE */
				orp_seqnum &= ~QM_EQCR_SEQNUM_NESN;
		}
		eq->seqnum = orp_seqnum;
		eq->orp = orp_fq->fqid;
	}
	eq->fqid = fq->fqid;
	eq->tag = (u32)fq;
	/* gcc does a dreadful job of the following;
	 *	eq->fd = *fd;
	 * It causes the entire function to save/restore a wider range of
	 * registers, and comes up with instruction-waste galore. This will do
	 * until we can rework the function for better code-generation. */
	{
		int *eqfdptr = (int *)&eq->fd;
		int *fdptr = (int *)fd;
		int temp;
		asm volatile (
			"lwz %0,0(%2);"
			"stw %0,0(%1);"
			"lwz %0,4(%2);"
			"stw %0,4(%1);"
			"lwz %0,8(%2);"
			"stw %0,8(%1);"
			"lwz %0,12(%2);"
			"stw %0,12(%1);"
			: "=&r"(temp) : "b"(eqfdptr), "b"(fdptr)
		);
	}
	/* Issue the enqueue command, and wait for sync if requested.
	 * NB: design choice - the commit can't fail, only waiting can. Don't
	 * propogate any failure if a signal arrives. Otherwise the caller can't
	 * distinguish whether the enqueue was issued or not. Code for
	 * user-space can check signal_pending() after we return. */
	eqcr_commit(p, flags, orp);
	return 0;
}

int qman_enqueue(struct qman_fq *fq, const struct qm_fd *fd, u32 flags)
{
	flags |= QM_EQCR_VERB_CMD_ENQUEUE;
	return __enqueue(fq, fd, flags, NULL, 0, 0);
}
EXPORT_SYMBOL(qman_enqueue);

int qman_enqueue_orp(struct qman_fq *fq, const struct qm_fd *fd, u32 flags,
			struct qman_fq *orp, u16 orp_seqnum)
{
	if (flags & (QMAN_ENQUEUE_FLAG_HOLE | QMAN_ENQUEUE_FLAG_NESN))
		flags &= ~QM_EQCR_VERB_CMD_ENQUEUE;
	else
		flags |= QM_EQCR_VERB_CMD_ENQUEUE;
	return __enqueue(fq, fd, flags, orp, orp_seqnum, 1);
}
EXPORT_SYMBOL(qman_enqueue_orp);

int qman_init_cgr(u32 cgid)
{
	struct qm_mc_command *mcc;
	struct qm_mc_result *mcr;
	struct qman_portal *p = get_affine_portal();
	u8 res;

	local_irq_disable();
	mcc = qm_mc_start(p->p);
	mcc->initcgr.cgid = cgid;
	qm_mc_commit(p->p, QM_MCC_VERB_INITCGR);
	while (!(mcr = qm_mc_result(p->p)))
		cpu_relax();
	QM_ASSERT((mcr->verb & QM_MCR_VERB_MASK) == QM_MCC_VERB_INITCGR);
	res = mcr->result;
	if (res != QM_MCR_RESULT_OK) {
		pr_err("INITCGR failed: %s\n", mcr_result_str(res));
	}
	local_irq_enable();
	put_affine_portal();
	return (res == QM_MCR_RESULT_OK) ? 0 : -EIO;
}
EXPORT_SYMBOL(qman_init_cgr);

