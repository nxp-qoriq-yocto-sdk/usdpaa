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

#include "bman_private.h"

/***************************/
/* Portal register assists */
/***************************/

/* Cache-inhibited register offsets */
#define REG_RCR_PI_CINH		(void *)0x0000
#define REG_RCR_CI_CINH		(void *)0x0004
#define REG_RCR_ITR		(void *)0x0008
#define REG_CFG			(void *)0x0100
#define REG_SCN(n)		((void *)(0x0200 + ((n) << 2)))
#define REG_ISR			(void *)0x0e00

/* Cache-enabled register offsets */
#define CL_CR			(void *)0x0000
#define CL_RR0			(void *)0x0100
#define CL_RR1			(void *)0x0140
#define CL_RCR			(void *)0x1000
#define CL_RCR_PI_CENA		(void *)0x3000
#define CL_RCR_CI_CENA		(void *)0x3100

/* The h/w design requires mappings to be size-aligned so that "add"s can be
 * reduced to "or"s. The primitives below do the same for s/w. */

/* Bitwise-OR two pointers */
static inline void *ptr_OR(void *a, void *b)
{
	return (void *)((unsigned long)a | (unsigned long)b);
}

/* Cache-inhibited register access */
static inline u32 __bm_in(struct bm_addr *bm, void *offset)
{
	return in_be32(ptr_OR(bm->addr_ci, offset));
}
static inline void __bm_out(struct bm_addr *bm, void *offset, u32 val)
{
	out_be32(ptr_OR(bm->addr_ci, offset), val);
}
#define bm_in(reg)		__bm_in(&portal->addr, REG_##reg)
#define bm_out(reg, val)	__bm_out(&portal->addr, REG_##reg, val)

/* Convert 'n' cachelines to a pointer value for bitwise OR */
#define bm_cl(n)		(void *)((n) << 6)

/* Cache-enabled (index) register access */
static inline void __bm_cl_touch_ro(struct bm_addr *bm, void *offset)
{
	dcbt_ro(ptr_OR(bm->addr_ce, offset));
}
static inline void __bm_cl_touch_rw(struct bm_addr *bm, void *offset)
{
	dcbt_rw(ptr_OR(bm->addr_ce, offset));
}
static inline u32 __bm_cl_in(struct bm_addr *bm, void *offset)
{
	return in_be32(ptr_OR(bm->addr_ce, offset));
}
static inline void __bm_cl_out(struct bm_addr *bm, void *offset, u32 val)
{
	out_be32(ptr_OR(bm->addr_ce, offset), val);
	dcbf(ptr_OR(bm->addr_ce, offset));
}
static inline void __bm_cl_invalidate(struct bm_addr *bm, void *offset)
{
	dcbi(ptr_OR(bm->addr_ce, offset));
}
#define bm_cl_touch_ro(reg)	__bm_cl_touch_ro(&portal->addr, CL_##reg##_CENA)
#define bm_cl_touch_rw(reg)	__bm_cl_touch_rw(&portal->addr, CL_##reg##_CENA)
#define bm_cl_in(reg)		__bm_cl_in(&portal->addr, CL_##reg##_CENA)
#define bm_cl_out(reg, val)	__bm_cl_out(&portal->addr, CL_##reg##_CENA, val)
#define bm_cl_invalidate(reg) __bm_cl_invalidate(&portal->addr, CL_##reg##_CENA)

/* Cyclic helper for rings. FIXME: once we are able to do fine-grain perf
 * analysis, look at using the "extra" bit in the ring index registers to avoid
 * cyclic issues. */
static inline u8 cyc_diff(u8 ringsize, u8 first, u8 last)
{
	/* 'first' is included, 'last' is excluded */
	if (first <= last)
		return last - first;
	return ringsize + last - first;
}

/* --------------- */
/* --- RCR API --- */

/* It's safer to code in terms of the 'rcr' object than the 'portal' object,
 * because the latter runs the risk of copy-n-paste errors from other code where
 * we could manipulate some other structure within 'portal'. */
#define RCR_API_START()		register struct bm_rcr *rcr = &portal->rcr

/* Bit-wise logic to wrap a ring pointer by clearing the "carry bit" */
#define RCR_CARRYCLEAR(p) \
	(void *)((unsigned long)(p) & (~(unsigned long)(BM_RCR_SIZE << 6)))

/* Bit-wise logic to convert a ring pointer to a ring index */
static inline u8 RCR_PTR2IDX(struct bm_rcr_entry *e)
{
	return ((u32)e >> 6) & (BM_RCR_SIZE - 1);
}

/* Increment the 'cursor' ring pointer, taking 'vbit' into account */
static inline void RCR_INC(struct bm_rcr *rcr)
{
	/* NB: this is odd-looking, but experiments show that it generates
	 * fast code with essentially no branching overheads. We increment to
	 * the next RCR pointer and handle overflow and 'vbit'. */
	struct bm_rcr_entry *partial = rcr->cursor + 1;
	rcr->cursor = RCR_CARRYCLEAR(partial);
	if (partial != rcr->cursor)
		rcr->vbit ^= BM_RCR_VERB_VBIT;
}

int bm_rcr_init(struct bm_portal *portal, enum bm_rcr_pmode pmode,
		enum bm_rcr_cmode cmode)
{
	RCR_API_START();
	u32 cfg;
	u8 pi;

	if (__bm_portal_bind(portal, BM_BIND_RCR))
		return -EBUSY;
	rcr->ring = ptr_OR(portal->addr.addr_ce, CL_RCR);
	rcr->ci = bm_in(RCR_CI_CINH) & (BM_RCR_SIZE - 1);
	pi = bm_in(RCR_PI_CINH) & (BM_RCR_SIZE - 1);
	rcr->cursor = rcr->ring + pi;
	rcr->vbit = (bm_in(RCR_PI_CINH) & BM_RCR_SIZE) ?  BM_RCR_VERB_VBIT : 0;
	rcr->available = BM_RCR_SIZE - 1 - cyc_diff(BM_RCR_SIZE, rcr->ci, pi);
	rcr->ithresh = bm_in(RCR_ITR);
#ifdef CONFIG_FSL_BMAN_CHECKING
	rcr->busy = 0;
	rcr->pmode = pmode;
	rcr->cmode = cmode;
#endif
	cfg = (bm_in(CFG) & 0xffffffe0) | (pmode & 0x3); /* BCSP_CFG::RPM */
	bm_out(CFG, cfg);
	return 0;
}
EXPORT_SYMBOL(bm_rcr_init);

void bm_rcr_finish(struct bm_portal *portal)
{
	RCR_API_START();
	u8 pi = bm_in(RCR_PI_CINH) & (BM_RCR_SIZE - 1);
	u8 ci = bm_in(RCR_CI_CINH) & (BM_RCR_SIZE - 1);
	BM_ASSERT(!rcr->busy);
	if (pi != RCR_PTR2IDX(rcr->cursor))
		pr_crit("losing uncommited RCR entries\n");
	if (ci != rcr->ci)
		pr_crit("missing existing RCR completions\n");
	if (rcr->ci != RCR_PTR2IDX(rcr->cursor))
		pr_crit("RCR destroyed unquiesced\n");
	__bm_portal_unbind(portal, BM_BIND_RCR);
}
EXPORT_SYMBOL(bm_rcr_finish);

struct bm_rcr_entry *bm_rcr_start(struct bm_portal *portal)
{
	RCR_API_START();
	BM_ASSERT(!rcr->busy);
	if (!rcr->available)
		return NULL;
#ifdef CONFIG_FSL_BMAN_CHECKING
	rcr->busy = 1;
#endif
	dcbzl(rcr->cursor);
	return rcr->cursor;
}
EXPORT_SYMBOL(bm_rcr_start);

void bm_rcr_abort(struct bm_portal *portal)
{
	RCR_API_START();
	BM_ASSERT(rcr->busy);
#ifdef CONFIG_FSL_BMAN_CHECKING
	rcr->busy = 0;
#endif
}
EXPORT_SYMBOL(bm_rcr_abort);

struct bm_rcr_entry *bm_rcr_pend_and_next(struct bm_portal *portal, u8 myverb)
{
	RCR_API_START();
	BM_ASSERT(rcr->busy);
	BM_ASSERT(rcr->pmode != bm_rcr_pvb);
	if (rcr->available == 1)
		return NULL;
	rcr->cursor->__dont_write_directly__verb = myverb | rcr->vbit;
	dcbf(rcr->cursor);
	RCR_INC(rcr);
	rcr->available--;
	dcbzl(rcr->cursor);
	return rcr->cursor;
}
EXPORT_SYMBOL(bm_rcr_pend_and_next);

void bm_rcr_pci_commit(struct bm_portal *portal, u8 myverb)
{
	RCR_API_START();
	BM_ASSERT(rcr->busy);
	BM_ASSERT(rcr->pmode == bm_rcr_pci);
	rcr->cursor->__dont_write_directly__verb = myverb | rcr->vbit;
	RCR_INC(rcr);
	rcr->available--;
	hwsync();
	bm_out(RCR_PI_CINH, RCR_PTR2IDX(rcr->cursor));
#ifdef CONFIG_FSL_BMAN_CHECKING
	rcr->busy = 0;
#endif
}
EXPORT_SYMBOL(bm_rcr_pci_commit);

void bm_rcr_pce_prefetch(struct bm_portal *portal)
{
	RCR_API_START();
	BM_ASSERT(rcr->pmode == bm_rcr_pce);
	bm_cl_invalidate(RCR_PI);
	bm_cl_touch_rw(RCR_PI);
}
EXPORT_SYMBOL(bm_rcr_pce_prefetch);

void bm_rcr_pce_commit(struct bm_portal *portal, u8 myverb)
{
	RCR_API_START();
	BM_ASSERT(rcr->busy);
	BM_ASSERT(rcr->pmode == bm_rcr_pce);
	rcr->cursor->__dont_write_directly__verb = myverb | rcr->vbit;
	RCR_INC(rcr);
	rcr->available--;
	lwsync();
	bm_cl_out(RCR_PI, RCR_PTR2IDX(rcr->cursor));
#ifdef CONFIG_FSL_BMAN_CHECKING
	rcr->busy = 0;
#endif
}
EXPORT_SYMBOL(bm_rcr_pce_commit);

void bm_rcr_pvb_commit(struct bm_portal *portal, u8 myverb)
{
	RCR_API_START();
	struct bm_rcr_entry *rcursor;
	BM_ASSERT(rcr->busy);
	BM_ASSERT(rcr->pmode == bm_rcr_pvb);
	lwsync();
	rcursor = rcr->cursor;
	rcursor->__dont_write_directly__verb = myverb | rcr->vbit;
	dcbf(rcursor);
	RCR_INC(rcr);
	rcr->available--;
#ifdef CONFIG_FSL_BMAN_CHECKING
	rcr->busy = 0;
#endif
}
EXPORT_SYMBOL(bm_rcr_pvb_commit);

u8 bm_rcr_cci_update(struct bm_portal *portal)
{
	RCR_API_START();
	u8 diff, old_ci = rcr->ci;
	BM_ASSERT(rcr->cmode == bm_rcr_cci);
	rcr->ci = bm_in(RCR_CI_CINH) & (BM_RCR_SIZE - 1);
	diff = cyc_diff(BM_RCR_SIZE, old_ci, rcr->ci);
	rcr->available += diff;
	return diff;
}
EXPORT_SYMBOL(bm_rcr_cci_update);

void bm_rcr_cce_prefetch(struct bm_portal *portal)
{
	RCR_API_START();
	BM_ASSERT(rcr->cmode == bm_rcr_cce);
	bm_cl_touch_ro(RCR_CI);
}
EXPORT_SYMBOL(bm_rcr_cce_prefetch);

u8 bm_rcr_cce_update(struct bm_portal *portal)
{
	RCR_API_START();
	u8 diff, old_ci = rcr->ci;
	BM_ASSERT(rcr->cmode == bm_rcr_cce);
	rcr->ci = bm_cl_in(RCR_CI) & (BM_RCR_SIZE - 1);
	bm_cl_invalidate(RCR_CI);
	diff = cyc_diff(BM_RCR_SIZE, old_ci, rcr->ci);
	rcr->available += diff;
	return diff;
}
EXPORT_SYMBOL(bm_rcr_cce_update);

u8 bm_rcr_get_ithresh(struct bm_portal *portal)
{
	RCR_API_START();
	return rcr->ithresh;
}
EXPORT_SYMBOL(bm_rcr_get_ithresh);

void bm_rcr_set_ithresh(struct bm_portal *portal, u8 ithresh)
{
	RCR_API_START();
	rcr->ithresh = ithresh;
	bm_out(RCR_ITR, ithresh);
}
EXPORT_SYMBOL(bm_rcr_set_ithresh);

u8 bm_rcr_get_avail(struct bm_portal *portal)
{
	RCR_API_START();
	return rcr->available;
}
EXPORT_SYMBOL(bm_rcr_get_avail);

u8 bm_rcr_get_fill(struct bm_portal *portal)
{
	RCR_API_START();
	return BM_RCR_SIZE - 1 - rcr->available;
}
EXPORT_SYMBOL(bm_rcr_get_fill);


/* ------------------------------ */
/* --- Management command API --- */

/* It's safer to code in terms of the 'mc' object than the 'portal' object,
 * because the latter runs the risk of copy-n-paste errors from other code where
 * we could manipulate some other structure within 'portal'. */
#define MC_API_START()		register struct bm_mc *mc = &portal->mc

int bm_mc_init(struct bm_portal *portal)
{
	MC_API_START();
	if (__bm_portal_bind(portal, BM_BIND_MC))
		return -EBUSY;
	mc->cr = ptr_OR(portal->addr.addr_ce, CL_CR);
	mc->rr = ptr_OR(portal->addr.addr_ce, CL_RR0);
	mc->rridx = (mc->cr->__dont_write_directly__verb & BM_MCC_VERB_VBIT) ?
			0 : 1;
	mc->vbit = mc->rridx ? BM_MCC_VERB_VBIT : 0;
#ifdef CONFIG_FSL_BMAN_CHECKING
	mc->state = mc_idle;
#endif
	return 0;
}
EXPORT_SYMBOL(bm_mc_init);

void bm_mc_finish(struct bm_portal *portal)
{
	MC_API_START();
	BM_ASSERT(mc->state == mc_idle);
#ifdef CONFIG_FSL_BMAN_CHECKING
	if (mc->state != mc_idle)
		pr_crit("Losing incomplete MC command\n");
#endif
	__bm_portal_unbind(portal, BM_BIND_MC);
}
EXPORT_SYMBOL(bm_mc_finish);

struct bm_mc_command *bm_mc_start(struct bm_portal *portal)
{
	MC_API_START();
	BM_ASSERT(mc->state == mc_idle);
#ifdef CONFIG_FSL_BMAN_CHECKING
	mc->state = mc_user;
#endif
	dcbzl(mc->cr);
	return mc->cr;
}
EXPORT_SYMBOL(bm_mc_start);

void bm_mc_abort(struct bm_portal *portal)
{
	MC_API_START();
	BM_ASSERT(mc->state == mc_user);
#ifdef CONFIG_FSL_BMAN_CHECKING
	mc->state = mc_idle;
#endif
}
EXPORT_SYMBOL(bm_mc_abort);

void bm_mc_commit(struct bm_portal *portal, u8 myverb)
{
	MC_API_START();
	BM_ASSERT(mc->state == mc_user);
	dcbi(mc->rr + mc->rridx);
	lwsync();
	mc->cr->__dont_write_directly__verb = myverb | mc->vbit;
	dcbf(mc->cr);
	dcbt_ro(mc->rr + mc->rridx);
#ifdef CONFIG_FSL_BMAN_CHECKING
	mc->state = mc_hw;
#endif
}
EXPORT_SYMBOL(bm_mc_commit);

struct bm_mc_result *bm_mc_result(struct bm_portal *portal)
{
	MC_API_START();
	struct bm_mc_result *rr = mc->rr + mc->rridx;
	BM_ASSERT(mc->state == mc_hw);
	/* The inactive response register's verb byte always returns zero until
	 * its command is submitted and completed. This includes the valid-bit,
	 * in case you were wondering... */
	if (!rr->verb) {
		dcbi(rr);
		dcbt_ro(rr);
		return NULL;
	}
	mc->rridx ^= 1;
	mc->vbit ^= BM_MCC_VERB_VBIT;
#ifdef CONFIG_FSL_BMAN_CHECKING
	mc->state = mc_idle;
#endif
	return rr;
}
EXPORT_SYMBOL(bm_mc_result);


/* ------------------------------------- */
/* --- Portal interrupt register API --- */

int bm_isr_init(struct bm_portal *portal)
{
	if (__bm_portal_bind(portal, BM_BIND_ISR))
		return -EBUSY;
	return 0;
}
EXPORT_SYMBOL(bm_isr_init);

void bm_isr_finish(struct bm_portal *portal)
{
	__bm_portal_unbind(portal, BM_BIND_ISR);
}
EXPORT_SYMBOL(bm_isr_finish);

#define SCN_REG(bpid) REG_SCN((bpid) / 32)
#define SCN_BIT(bpid) (0x80000000 >> (bpid & 31))
void bm_isr_bscn_mask(struct bm_portal *portal, u8 bpid, int enable)
{
	u32 val;
	BM_ASSERT(bpid < 64);
	/* REG_SCN for bpid=0..31, REG_SCN+4 for bpid=32..63 */
	val = __bm_in(&portal->addr, SCN_REG(bpid));
	if (enable)
		val |= SCN_BIT(bpid);
	else
		val &= ~SCN_BIT(bpid);
	__bm_out(&portal->addr, SCN_REG(bpid), val);
}
EXPORT_SYMBOL(bm_isr_bscn_mask);

u32 __bm_isr_read(struct bm_portal *portal, enum bm_isr_reg n)
{
	return __bm_in(&portal->addr, REG_ISR + (n << 2));
}
EXPORT_SYMBOL(__bm_isr_read);

void __bm_isr_write(struct bm_portal *portal, enum bm_isr_reg n, u32 val)
{
	__bm_out(&portal->addr, REG_ISR + (n << 2), val);
}
EXPORT_SYMBOL(__bm_isr_write);

