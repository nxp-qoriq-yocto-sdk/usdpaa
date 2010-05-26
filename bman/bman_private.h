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

#include "bman_sys.h"
#include <linux/fsl_bman.h>

/* Portal modes.
 *   Enum types;
 *     pmode == production mode
 *     cmode == consumption mode,
 *   Enum values use 3 letter codes. First letter matches the portal mode,
 *   remaining two letters indicate;
 *     ci == cache-inhibited portal register
 *     ce == cache-enabled portal register
 *     vb == in-band valid-bit (cache-enabled)
 */
enum bm_rcr_pmode {		/* matches BCSP_CFG::RPM */
	bm_rcr_pci = 0,		/* PI index, cache-inhibited */
	bm_rcr_pce = 1,		/* PI index, cache-enabled */
	bm_rcr_pvb = 2		/* valid-bit */
};
enum bm_rcr_cmode {		/* s/w-only */
	bm_rcr_cci,		/* CI index, cache-inhibited */
	bm_rcr_cce		/* CI index, cache-enabled */
};


struct bm_addr {
	void __iomem *addr_ce;	/* cache-enabled */
	void __iomem *addr_ci;	/* cache-inhibited */
};

/* RCR state */
struct bm_rcr {
	struct bm_rcr_entry *ring, *cursor;
	u8 ci, available, ithresh, vbit;
#ifdef CONFIG_FSL_BMAN_CHECKING
	u32 busy;
	enum bm_rcr_pmode pmode;
	enum bm_rcr_cmode cmode;
#endif
};

/* MC state */
struct bm_mc {
	struct bm_mc_command *cr;
	struct bm_mc_result *rr;
	u8 rridx, vbit;
#ifdef CONFIG_FSL_BMAN_CHECKING
	enum {
		/* Can only be _mc_start()ed */
		mc_idle,
		/* Can only be _mc_commit()ed or _mc_abort()ed */
		mc_user,
		/* Can only be _mc_retry()ed */
		mc_hw
	} state;
#endif
};

/* Portal constants */
#define BM_RCR_SIZE		8

/* Hardware constants */
enum bm_isr_reg {
	bm_isr_status = 0,
	bm_isr_enable = 1,
	bm_isr_disable = 2,
	bm_isr_inhibit = 3
};

/********************/
/* Portal structure */
/********************/

/* When iterating the available portals, this is the exposed config structure */
struct bm_portal_config {
	/* This is used for any "core-affine" portals, ie. default portals
	 * associated to the corresponding cpu. -1 implies that there is no core
	 * affinity configured. */
	int cpu;
	/* portal interrupt line */
	int irq;
	/* These are the buffer pool IDs that may be used via this portal. NB,
	 * this is only enforced in the high-level API. Also, BSCN depletion
	 * state changes will only be unmasked as/when pool objects are created
	 * with depletion callbacks - the mask is the superset. */
	struct bman_depletion mask;
	/* which portal sub-interfaces are already bound (ie. "in use") */
	u8 bound;
};
/* bm_portal_config::bound uses these bit masks */
#define BM_BIND_RCR	0x01
#define BM_BIND_MC	0x02
#define BM_BIND_ISR	0x04

struct bm_portal {
	struct bm_addr addr;
	struct bm_rcr rcr;
	struct bm_mc mc;
	struct bm_portal_config config;
} ____cacheline_aligned;

/* RCR/MC/ISR code uses this as a locked mechanism to bind/unbind to
 * bm_portal::config::bound. */
int __bm_portal_bind(struct bm_portal *portal, u8 iface);
void __bm_portal_unbind(struct bm_portal *portal, u8 iface);

/* Hooks between qman_driver.c and qman_high.c */
extern DEFINE_PER_CPU(struct bman_portal *, bman_affine_portal);
static inline struct bman_portal *get_affine_portal(void)
{
	return get_cpu_var(bman_affine_portal);
}
static inline void put_affine_portal(void)
{
	put_cpu_var(bman_affine_portal);
}
struct bman_portal *bman_create_portal(struct bm_portal *portal,
					const struct bman_depletion *pools);
void bman_destroy_portal(struct bman_portal *p);

/* Pool logic in the portal driver, during initialisation, needs to know if
 * there's access to CCSR or not (if not, it'll cripple the pool allocator). */
#ifdef CONFIG_FSL_BMAN_CONFIG
int bman_have_ccsr(void);
#else
#define bman_have_ccsr() 0
#endif

/* Stockpile build constants. The _LOW value: when bman_acquire() is called and
 * the stockpile fill-level is <= _LOW, an acquire is attempted from h/w but it
 * might fail (if the buffer pool is depleted). So this value provides some
 * "stagger" in that the bman_acquire() function will only fail if lots of bufs
 * are requested at once or if h/w has been tested a couple of times without
 * luck. The _HIGH value: when bman_release() is called and the stockpile
 * fill-level is >= _HIGH, a release is attempted to h/w but it might fail (if
 * the release ring is full). So this value provides some "stagger" so that
 * ring-access is retried a couple of times prior to the API returning a
 * failure. The following *must* be true;
 *   BMAN_STOCKPILE_HIGH-BMAN_STOCKPILE_LOW > 8
 *     (to avoid thrashing)
 *   BMAN_STOCKPILE_SZ >= 16
 *     (as the release logic expects to either send 8 buffers to hw prior to
 *     adding the given buffers to the stockpile or add the buffers to the
 *     stockpile before sending 8 to hw, as the API must be an all-or-nothing
 *     success/fail.)
 */
#define BMAN_STOCKPILE_SZ   16u /* number of bufs in per-pool cache */
#define BMAN_STOCKPILE_LOW  2u  /* when fill is <= this, acquire from hw */
#define BMAN_STOCKPILE_HIGH 14u /* when fill is >= this, release to hw */

/*************************************************/
/*   BMan s/w corenet portal, low-level i/face   */
/*************************************************/

/* Note: many of these functions are inlined, so are #if 0'd out */

/* ------------------------------ */
/* --- Portal enumeration API --- */

/* Obtain the number of portals available */
u8 bm_portal_num(void);

/* Obtain a portal handle */
struct bm_portal *bm_portal_get(u8 idx);
const struct bm_portal_config *bm_portal_config(const struct bm_portal *portal);

#if 0

/* --------------- */
/* --- RCR API --- */

/* Create/destroy */
int bm_rcr_init(struct bm_portal *portal, enum bm_rcr_pmode pmode,
		enum bm_rcr_cmode cmode);
void bm_rcr_finish(struct bm_portal *portal);

/* Start/abort RCR entry */
struct bm_rcr_entry *bm_rcr_start(struct bm_portal *portal);
void bm_rcr_abort(struct bm_portal *portal);

/* For PI modes only. This presumes a started but uncommited RCR entry. If
 * there's no more room in the RCR, this function returns NULL. Otherwise it
 * returns the next RCR entry and increments an internal PI counter without
 * flushing it to h/w. */
struct bm_rcr_entry *bm_rcr_pend_and_next(struct bm_portal *portal, u8 myverb);

/* Commit RCR entries, including pending ones (aka "write PI") */
void bm_rcr_pci_commit(struct bm_portal *portal, u8 myverb);
void bm_rcr_pce_prefetch(struct bm_portal *portal);
void bm_rcr_pce_commit(struct bm_portal *portal, u8 myverb);
void bm_rcr_pvb_commit(struct bm_portal *portal, u8 myverb);

/* Track h/w consumption. Returns non-zero if h/w had consumed previously
 * unconsumed RCR entries. */
u8 bm_rcr_cci_update(struct bm_portal *portal);
void bm_rcr_cce_prefetch(struct bm_portal *portal);
u8 bm_rcr_cce_update(struct bm_portal *portal);
/* Returns the number of available RCR entries */
u8 bm_rcr_get_avail(struct bm_portal *portal);
/* Returns the number of unconsumed RCR entries */
u8 bm_rcr_get_fill(struct bm_portal *portal);

/* Read/write the RCR interrupt threshold */
u8 bm_rcr_get_ithresh(struct bm_portal *portal);
void bm_rcr_set_ithresh(struct bm_portal *portal, u8 ithresh);

/* ------------------------------ */
/* --- Management command API --- */

/* Create/destroy */
int bm_mc_init(struct bm_portal *portal);
void bm_mc_finish(struct bm_portal *portal);

/* Start/abort mgmt command */
struct bm_mc_command *bm_mc_start(struct bm_portal *portal);
void bm_mc_abort(struct bm_portal *portal);

/* Writes 'verb' with appropriate 'vbit'. Invalidates and pre-fetches the
 * response. */
void bm_mc_commit(struct bm_portal *portal, u8 myverb);

/* Poll for result. If NULL, invalidates and prefetches for the next call. */
struct bm_mc_result *bm_mc_result(struct bm_portal *portal);

/* ------------------------------------- */
/* --- Portal interrupt register API --- */

/* For a quick explanation of the Bman interrupt model, see the comments in the
 * equivalent section of the qman_portal.h header.
 */

/* Create/destroy */
int bm_isr_init(struct bm_portal *portal);
void bm_isr_finish(struct bm_portal *portal);

/* BSCN masking is a per-portal configuration */
void bm_isr_bscn_mask(struct bm_portal *portal, u8 bpid, int enable);

#endif

/* Used by all portal interrupt registers except 'inhibit' */
#define BM_PIRQ_RCRI	0x00000002	/* RCR Ring (below threshold) */
#define BM_PIRQ_BSCN	0x00000001	/* Buffer depletion State Change */

/* These are bm_<reg>_<verb>(). So for example, bm_disable_write() means "write
 * the disable register" rather than "disable the ability to write". */
#define bm_isr_status_read(bm)		__bm_isr_read(bm, bm_isr_status)
#define bm_isr_status_clear(bm, m)	__bm_isr_write(bm, bm_isr_status, m)
#define bm_isr_enable_read(bm)		__bm_isr_read(bm, bm_isr_enable)
#define bm_isr_enable_write(bm, v)	__bm_isr_write(bm, bm_isr_enable, v)
#define bm_isr_disable_read(bm)		__bm_isr_read(bm, bm_isr_disable)
#define bm_isr_disable_write(bm, v)	__bm_isr_write(bm, bm_isr_disable, v)
#define bm_isr_inhibit(bm)		__bm_isr_write(bm, bm_isr_inhibit, 1)
#define bm_isr_uninhibit(bm)		__bm_isr_write(bm, bm_isr_inhibit, 0)

#if 0
/* Don't use these, use the wrappers above*/
u32 __bm_isr_read(struct bm_portal *portal, enum bm_isr_reg n);
void __bm_isr_write(struct bm_portal *portal, enum bm_isr_reg n, u32 val);
#endif

/* ------------------------------ */
/* --- Buffer pool allocation --- */

#ifdef CONFIG_FSL_BMAN_CONFIG

/* Allocate/release an unreserved buffer pool id */
int bm_pool_new(u32 *bpid);
void bm_pool_free(u32 bpid);

/* Set depletion thresholds associated with a buffer pool. Requires that the
 * operating system have access to Bman CCSR (ie. compiled in support and
 * run-time access courtesy of the device-tree). */
int bm_pool_set(u32 bpid, const u32 *thresholds);
#define BM_POOL_THRESH_SW_ENTER 0
#define BM_POOL_THRESH_SW_EXIT  1
#define BM_POOL_THRESH_HW_ENTER 2
#define BM_POOL_THRESH_HW_EXIT  3

#endif /* CONFIG_FSL_BMAN_CONFIG */

