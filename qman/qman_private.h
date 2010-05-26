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

#include "qman_sys.h"
#include <linux/fsl_qman.h>

/* Portal modes.
 *   Enum types;
 *     pmode == production mode
 *     cmode == consumption mode,
 *     dmode == h/w dequeue mode.
 *   Enum values use 3 letter codes. First letter matches the portal mode,
 *   remaining two letters indicate;
 *     ci == cache-inhibited portal register
 *     ce == cache-enabled portal register
 *     vb == in-band valid-bit (cache-enabled)
 *     dc == DCA (Discrete Consumption Acknowledgement), DQRR-only
 *   As for "enum qm_dqrr_dmode", it should be self-explanatory.
 */
enum qm_eqcr_pmode {		/* matches QCSP_CFG::EPM */
	qm_eqcr_pci = 0,	/* PI index, cache-inhibited */
	qm_eqcr_pce = 1,	/* PI index, cache-enabled */
	qm_eqcr_pvb = 2		/* valid-bit */
};
enum qm_eqcr_cmode {		/* s/w-only */
	qm_eqcr_cci,		/* CI index, cache-inhibited */
	qm_eqcr_cce		/* CI index, cache-enabled */
};
enum qm_dqrr_dmode {		/* matches QCSP_CFG::DP */
	qm_dqrr_dpush = 0,	/* SDQCR  + VDQCR */
	qm_dqrr_dpull = 1	/* PDQCR */
};
enum qm_dqrr_pmode {		/* s/w-only */
	qm_dqrr_pci,		/* reads DQRR_PI_CINH */
	qm_dqrr_pce,		/* reads DQRR_PI_CENA */
	qm_dqrr_pvb		/* reads valid-bit */
};
enum qm_dqrr_cmode {		/* matches QCSP_CFG::DCM */
	qm_dqrr_cci = 0,	/* CI index, cache-inhibited */
	qm_dqrr_cce = 1,	/* CI index, cache-enabled */
	qm_dqrr_cdc = 2		/* Discrete Consumption Acknowledgement */
};
enum qm_mr_pmode {		/* s/w-only */
	qm_mr_pci,		/* reads MR_PI_CINH */
	qm_mr_pce,		/* reads MR_PI_CENA */
	qm_mr_pvb		/* reads valid-bit */
};
enum qm_mr_cmode {		/* matches QCSP_CFG::MM */
	qm_mr_cci = 0,		/* CI index, cache-inhibited */
	qm_mr_cce = 1		/* CI index, cache-enabled */
};

struct qm_addr {
	void __iomem *addr_ce;	/* cache-enabled */
	void __iomem *addr_ci;	/* cache-inhibited */
};

/* EQCR state */
struct qm_eqcr {
	struct qm_eqcr_entry *ring, *cursor;
	u8 ci, available, ithresh, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	u32 busy;
	enum qm_eqcr_pmode pmode;
	enum qm_eqcr_cmode cmode;
#endif
};

/* DQRR state */
struct qm_dqrr {
	struct qm_dqrr_entry *ring, *cursor;
	u8 pi, ci, fill, ithresh, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	u8 flags;
	enum qm_dqrr_dmode dmode;
	enum qm_dqrr_pmode pmode;
	enum qm_dqrr_cmode cmode;
#endif
};
#define QM_DQRR_FLAG_RE 0x01 /* Stash ring entries */
#define QM_DQRR_FLAG_SE 0x02 /* Stash data */

/* MR state */
struct qm_mr {
	struct qm_mr_entry *ring, *cursor;
	u8 pi, ci, fill, ithresh, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	enum qm_mr_pmode pmode;
	enum qm_mr_cmode cmode;
#endif
};

/* MC state */
struct qm_mc {
	struct qm_mc_command *cr;
	struct qm_mc_result *rr;
	u8 rridx, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	enum {
		/* Can be _mc_start()ed */
		mc_idle,
		/* Can be _mc_commit()ed or _mc_abort()ed */
		mc_user,
		/* Can only be _mc_retry()ed */
		mc_hw
	} state;
#endif
};

/* Portal constants */
#define QM_EQCR_SIZE		8
#define QM_DQRR_SIZE		16
#define QM_MR_SIZE		8

enum qm_isr_reg {
	qm_isr_status = 0,
	qm_isr_enable = 1,
	qm_isr_disable = 2,
	qm_isr_inhibit = 3
};

/********************/
/* Portal structure */
/********************/

#ifdef CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1
/* For workarounds that require storage, this struct is overlayed on a
 * get_zeroed_page(), guaranteeing alignment and such. */
struct qm_portal_bugs {
	/* shadow MR ring, for QMAN9 workaround, 8-CL aligned */
	struct qm_mr_entry mr[QM_MR_SIZE];
	/* shadow MC result, for QMAN6 and QMAN7 workarounds, CL aligned */
	struct qm_mc_result result;
	/* boolean switch for QMAN7 workaround */
	int initfq_and_sched;
	/* histogram to track EQCR_CI updates */
#ifdef CONFIG_FSL_QMAN_ADAPTIVE_EQCR_THROTTLE
	u32 ci_histogram[8];
#endif
};
#endif

struct qm_portal_config {
	/* If the caller enables DQRR stashing (and thus wishes to operate the
	 * portal from only one cpu), this is the logical CPU that the portal
	 * will stash to. Whether stashing is enabled or not, this setting is
	 * also used for any "core-affine" portals, ie. default portals
	 * associated to the corresponding cpu. -1 implies that there is no core
	 * affinity configured. */
	int cpu;
	/* portal interrupt line */
	int irq;
	/* The portal's dedicated channel id, use this value for initialising
	 * frame queues to target this portal when scheduled. */
	enum qm_channel channel;
	/* A mask of which pool channels this portal has dequeue access to
	 * (using QM_SDQCR_CHANNELS_POOL(n) for the bitmask) */
	u32 pools;
	/* which portal sub-interfaces are already bound (ie. "in use") */
	u8 bound;
	/* does this portal have PAMU assistance from hypervisor? */
	int has_hv_dma;
};
/* qm_portal_config::bound uses these bit masks */
#define QM_BIND_EQCR	0x01
#define QM_BIND_DQRR	0x02
#define QM_BIND_MR	0x04
#define QM_BIND_MC	0x08
#define QM_BIND_ISR	0x10

struct qm_portal {
	/* In the non-CONFIG_FSL_QMAN_CHECKING case, everything up to and
	 * including 'mc' fits in a cacheline (yay!). The 'config' part is
	 * setup-only, so isn't a cause for a concern. In other words, don't
	 * rearrange this structure on a whim, there be dragons ... */
	struct qm_addr addr;
	struct qm_eqcr eqcr;
	struct qm_dqrr dqrr;
	struct qm_mr mr;
	struct qm_mc mc;
	struct qm_portal_config config;
	/* Logical index (not cell-index) */
	int index;
#ifdef CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1
	struct qm_portal_bugs *bugs;
#endif
} ____cacheline_aligned;

/* EQCR/DQRR/[...] code uses this as a locked mechanism to bind/unbind to
 * qm_portal::bound. */
int __qm_portal_bind(struct qm_portal *portal, u8 iface);
void __qm_portal_unbind(struct qm_portal *portal, u8 iface);

/* This struct represents a pool channel */
struct qm_pool_channel {
	/* The QM_SDQCR_CHANNELS_POOL(n) bit that corresponds to this channel */
	u32 pool;
	/* The channel id, used for initialising frame queues to target this
	 * channel. */
	enum qm_channel channel;
	/* Bitmask of portal (logical-, not cell-)indices that have dequeue
	 * access to this channel;
	 * 0x001 -> qm_portal_get(0)
	 * 0x002 -> qm_portal_get(1)
	 * 0x004 -> qm_portal_get(2)
	 * ...
	 * 0x200 -> qm_portal_get(9)
	 */
	u32 portals;
};

/* Hooks for driver initialisation */
#ifdef CONFIG_FSL_QMAN_FQALLOCATOR
__init int __fqalloc_init(void);
#endif

/* Revision info (for errata and feature handling) */
#define QMAN_REV1 0x0100
#define QMAN_REV2 0x0101
extern u16 qman_ip_rev; /* 0 if uninitialised, otherwise QMAN_REVx */

/* Hooks from qman_high.c in to qman_driver.c */
extern DEFINE_PER_CPU(struct qman_portal *, qman_affine_portal);
static inline struct qman_portal *get_affine_portal(void)
{
	return get_cpu_var(qman_affine_portal);
}
static inline void put_affine_portal(void)
{
	put_cpu_var(qman_affine_portal);
}

/* Hooks from qman_driver.c in to qman_high.c */
#define QMAN_PORTAL_FLAG_RSTASH      0x00000001 /* enable DQRR entry stashing */
#define QMAN_PORTAL_FLAG_DSTASH      0x00000002 /* enable data stashing */
struct qman_portal *qman_create_portal(struct qm_portal *portal, u32 flags,
			const struct qman_cgrs *cgrs,
			const struct qman_fq_cb *null_cb);
void qman_destroy_portal(struct qman_portal *p);
void qman_static_dequeue_add_ex(struct qman_portal *p, u32 pools);

/* There are no CGR-related APIs exported so far, but due to the
 * uninitialised-data ECC issue in rev1.0 Qman, the driver needs to issue "Init
 * CGR" commands on boot-up. So we're declaring some internal-only APIs to
 * facilitate this for now. */
int qman_init_cgr(u32 cgid);

/*************************************************/
/*   QMan s/w corenet portal, low-level i/face   */
/*************************************************/

/* Note: many of these functions are inlined, so are #if 0'd out */

/* ------------------------------ */
/* --- Portal enumeration API --- */

/* Obtain the number of portals available */
u8 qm_portal_num(void);

/* Obtain a portal handle and configuration information about it */
struct qm_portal *qm_portal_get(u8 idx);
const struct qm_portal_config *qm_portal_config(const struct qm_portal *portal);

/* ------------------------------------ */
/* --- Pool channel enumeration API --- */

/* Obtain a mask of the available pool channels, expressed using
 * QM_SDQCR_CHANNELS_POOL(n). */
u32 qm_pools(void);

/* Retrieve a pool channel configuration, given a QM_SDQCR_CHANNEL_POOL(n)
 * bit-mask (the least significant bit of 'mask' is used if more than one bit is
 * set). */
const struct qm_pool_channel *qm_pool_channel(u32 mask);

#if 0

/* ---------------- */
/* --- EQCR API --- */

/* Create/destroy */
int qm_eqcr_init(struct qm_portal *portal, enum qm_eqcr_pmode pmode,
		enum qm_eqcr_cmode cmode);
void qm_eqcr_finish(struct qm_portal *portal);

/* Start/abort EQCR entry */
struct qm_eqcr_entry *qm_eqcr_start(struct qm_portal *portal);
void qm_eqcr_abort(struct qm_portal *portal);

/* For PI modes only. This presumes a started but uncommited EQCR entry. If
 * there's no more room in the EQCR, this function returns NULL. Otherwise it
 * returns the next EQCR entry and increments an internal PI counter without
 * flushing it to h/w. */
struct qm_eqcr_entry *qm_eqcr_pend_and_next(struct qm_portal *portal, u8 myverb);

/* Commit EQCR entries, including pending ones (aka "write PI") */
void qm_eqcr_pci_commit(struct qm_portal *portal, u8 myverb);
void qm_eqcr_pce_prefetch(struct qm_portal *portal);
void qm_eqcr_pce_commit(struct qm_portal *portal, u8 myverb);
void qm_eqcr_pvb_commit(struct qm_portal *portal, u8 myverb);

/* Track h/w consumption. Returns non-zero if h/w had consumed previously
 * unconsumed EQCR entries (it returns the number of them in fact). */
u8 qm_eqcr_cci_update(struct qm_portal *portal);
void qm_eqcr_cce_prefetch(struct qm_portal *portal);
u8 qm_eqcr_cce_update(struct qm_portal *portal);
#ifdef CONFIG_FSL_QMAN_ADAPTIVE_EQCR_THROTTLE
static inline u32 qm_eqcr_cce_avg_x10(struct qm_portal *portal)
#endif
u8 qm_eqcr_get_ithresh(struct qm_portal *portal);
void qm_eqcr_set_ithresh(struct qm_portal *portal, u8 ithresh);
/* Returns the number of available EQCR entries */
u8 qm_eqcr_get_avail(struct qm_portal *portal);
/* Returns the number of unconsumed EQCR entries */
u8 qm_eqcr_get_fill(struct qm_portal *portal);

/* ---------------- */
/* --- DQRR API --- */

/* Create/destroy */
int qm_dqrr_init(struct qm_portal *portal, enum qm_dqrr_dmode dmode,
		enum qm_dqrr_pmode pmode, enum qm_dqrr_cmode cmode,
		/* QCSP_CFG fields; MF, RE, SE (respectively) */
		u8 max_fill, int stash_ring, int stash_data);
void qm_dqrr_finish(struct qm_portal *portal);

/* Read 'current' DQRR entry (ie. at the cursor). NB, prefetch generally not
 * required in pvb mode, as pvb_prefetch() will touch the same cacheline. */
void qm_dqrr_current_prefetch(struct qm_portal *portal);
struct qm_dqrr_entry *qm_dqrr_current(struct qm_portal *portal);
u8 qm_dqrr_cursor(struct qm_portal *portal);

/* Increment 'current' cursor, must not already be at "EOF". Returns number of
 * remaining DQRR entries, zero if the 'cursor' is now at "EOF". */
u8 qm_dqrr_next(struct qm_portal *portal);

/* Track h/w production. Returns non-zero if there are new DQRR entries. */
u8 qm_dqrr_pci_update(struct qm_portal *portal);
void qm_dqrr_pce_prefetch(struct qm_portal *portal);
u8 qm_dqrr_pce_update(struct qm_portal *portal);
void qm_dqrr_pvb_prefetch(struct qm_portal *portal);
u8 qm_dqrr_pvb_update(struct qm_portal *portal);
u8 qm_dqrr_get_ithresh(struct qm_portal *portal);
void qm_dqrr_set_ithresh(struct qm_portal *portal, u8 ithresh);
u8 qm_dqrr_get_maxfill(struct qm_portal *portal);
void qm_dqrr_set_maxfill(struct qm_portal *portal, u8 mf);

/* Consume DQRR entries. NB for 'bitmask', 0x8000 represents idx==0, 0x4000 is
 * idx==1, etc through to 0x0001 being idx==15. */
void qm_dqrr_cci_consume(struct qm_portal *portal, u8 num);
void qm_dqrr_cci_consume_to_current(struct qm_portal *portal);
void qm_dqrr_cce_prefetch(struct qm_portal *portal);
void qm_dqrr_cce_consume(struct qm_portal *portal, u8 num);
void qm_dqrr_cce_consume_to_current(struct qm_portal *portal);
void qm_dqrr_cdc_consume_1(struct qm_portal *portal, u8 idx, int park);
void qm_dqrr_cdc_consume_1ptr(struct qm_portal *portal, struct qm_dqrr_entry *dq,
				int park);
void qm_dqrr_cdc_consume_n(struct qm_portal *portal, u16 bitmask);

/* For CDC; use these to read the effective CI */
u8 qm_dqrr_cdc_cci(struct qm_portal *portal);
void qm_dqrr_cdc_cce_prefetch(struct qm_portal *portal);
u8 qm_dqrr_cdc_cce(struct qm_portal *portal);

/* For CCI/CCE; this returns the s/w-cached CI value */
u8 qm_dqrr_get_ci(struct qm_portal *portal);
/*            ; this issues a park-request */
void qm_dqrr_park(struct qm_portal *portal, u8 idx);
/*            ; or for the next-to-be-consumed DQRR entry */
void qm_dqrr_park_ci(struct qm_portal *portal);

#endif

/* For qm_dqrr_sdqcr_set(); Choose one SOURCE. Choose one COUNT. Choose one
 * dequeue TYPE. Choose TOKEN (8-bit).
 * If SOURCE == CHANNELS,
 *   Choose CHANNELS_DEDICATED and/or CHANNELS_POOL(n).
 *   You can choose DEDICATED_PRECEDENCE if the portal channel should have
 *   priority.
 * If SOURCE == SPECIFICWQ,
 *     Either select the work-queue ID with SPECIFICWQ_WQ(), or select the
 *     channel (SPECIFICWQ_DEDICATED or SPECIFICWQ_POOL()) and specify the
 *     work-queue priority (0-7) with SPECIFICWQ_WQ() - either way, you get the
 *     same value.
 */
#define QM_SDQCR_SOURCE_CHANNELS	0x0
#define QM_SDQCR_SOURCE_SPECIFICWQ	0x40000000
#define QM_SDQCR_COUNT_EXACT1		0x0
#define QM_SDQCR_COUNT_UPTO3		0x20000000
#define QM_SDQCR_DEDICATED_PRECEDENCE	0x10000000
#define QM_SDQCR_TYPE_MASK		0x03000000
#define QM_SDQCR_TYPE_NULL		0x0
#define QM_SDQCR_TYPE_PRIO_QOS		0x01000000
#define QM_SDQCR_TYPE_ACTIVE_QOS	0x02000000
#define QM_SDQCR_TYPE_ACTIVE		0x03000000
#define QM_SDQCR_TOKEN_MASK		0x00ff0000
#define QM_SDQCR_TOKEN_SET(v)		(((v) & 0xff) << 16)
#define QM_SDQCR_TOKEN_GET(v)		(((v) >> 16) & 0xff)
#define QM_SDQCR_CHANNELS_DEDICATED	0x00008000
#if 0 /* These are defined in the external API */
#define QM_SDQCR_CHANNELS_POOL_MASK	0x00007fff
#define QM_SDQCR_CHANNELS_POOL(n)	(0x00008000 >> (n))
#endif
#define QM_SDQCR_SPECIFICWQ_MASK	0x000000f7
#define QM_SDQCR_SPECIFICWQ_DEDICATED	0x00000000
#define QM_SDQCR_SPECIFICWQ_POOL(n)	((n) << 4)
#define QM_SDQCR_SPECIFICWQ_WQ(n)	(n)
#if 0
void qm_dqrr_sdqcr_set(struct qm_portal *portal, u32 sdqcr);
u32 qm_dqrr_sdqcr_get(struct qm_portal *portal);
#endif

/* For qm_dqrr_vdqcr_set(); Choose one PRECEDENCE. EXACT is optional. Use
 * NUMFRAMES(n) (6-bit) or NUMFRAMES_TILLEMPTY to fill in the frame-count. Use
 * FQID(n) to fill in the frame queue ID. */
#if 0 /* These are defined in the external API */
#define QM_VDQCR_PRECEDENCE_VDQCR	0x0
#define QM_VDQCR_PRECEDENCE_SDQCR	0x80000000
#define QM_VDQCR_EXACT			0x40000000
#define QM_VDQCR_NUMFRAMES_MASK		0x3f000000
#define QM_VDQCR_NUMFRAMES_SET(n)	(((n) & 0x3f) << 24)
#define QM_VDQCR_NUMFRAMES_GET(n)	(((n) >> 24) & 0x3f)
#define QM_VDQCR_NUMFRAMES_TILLEMPTY	QM_VDQCR_NUMFRAMES_SET(0)
#endif
#define QM_VDQCR_FQID_MASK		0x00ffffff
#define QM_VDQCR_FQID(n)		((n) & QM_VDQCR_FQID_MASK)

/* For qm_dqrr_pdqcr_set(); Choose one MODE. Choose one COUNT.
 * If MODE==SCHEDULED
 *   Choose SCHEDULED_CHANNELS or SCHEDULED_SPECIFICWQ. Choose one dequeue TYPE.
 *   If CHANNELS,
 *     Choose CHANNELS_DEDICATED and/or CHANNELS_POOL() channels.
 *     You can choose DEDICATED_PRECEDENCE if the portal channel should have
 *     priority.
 *   If SPECIFICWQ,
 *     Either select the work-queue ID with SPECIFICWQ_WQ(), or select the
 *     channel (SPECIFICWQ_DEDICATED or SPECIFICWQ_POOL()) and specify the
 *     work-queue priority (0-7) with SPECIFICWQ_WQ() - either way, you get the
 *     same value.
 * If MODE==UNSCHEDULED
 *     Choose FQID().
 */
#define QM_PDQCR_MODE_SCHEDULED		0x0
#define QM_PDQCR_MODE_UNSCHEDULED	0x80000000
#define QM_PDQCR_SCHEDULED_CHANNELS	0x0
#define QM_PDQCR_SCHEDULED_SPECIFICWQ	0x40000000
#define QM_PDQCR_COUNT_EXACT1		0x0
#define QM_PDQCR_COUNT_UPTO3		0x20000000
#define QM_PDQCR_DEDICATED_PRECEDENCE	0x10000000
#define QM_PDQCR_TYPE_MASK		0x03000000
#define QM_PDQCR_TYPE_NULL		0x0
#define QM_PDQCR_TYPE_PRIO_QOS		0x01000000
#define QM_PDQCR_TYPE_ACTIVE_QOS	0x02000000
#define QM_PDQCR_TYPE_ACTIVE		0x03000000
#define QM_PDQCR_CHANNELS_DEDICATED	0x00008000
#define QM_PDQCR_CHANNELS_POOL(n)	(0x00008000 >> (n))
#define QM_PDQCR_SPECIFICWQ_MASK	0x000000f7
#define QM_PDQCR_SPECIFICWQ_DEDICATED	0x00000000
#define QM_PDQCR_SPECIFICWQ_POOL(n)	((n) << 4)
#define QM_PDQCR_SPECIFICWQ_WQ(n)	(n)
#define QM_PDQCR_FQID(n)		((n) & 0xffffff)
#if 0
void qm_dqrr_pdqcr_set(struct qm_portal *portal, u32 pdqcr);
u32 qm_dqrr_pdqcr_get(struct qm_portal *portal);

/* -------------- */
/* --- MR API --- */

/* Create/destroy */
int qm_mr_init(struct qm_portal *portal, enum qm_mr_pmode pmode,
		enum qm_mr_cmode cmode);
void qm_mr_finish(struct qm_portal *portal);

/* Read 'current' MR entry (ie. at the cursor) */
void qm_mr_current_prefetch(struct qm_portal *portal);
struct qm_mr_entry *qm_mr_current(struct qm_portal *portal);
u8 qm_mr_cursor(struct qm_portal *portal);

/* Increment 'current' cursor, must not alreday be at "EOF". Returns number of
 * remaining MR entries, zero if the 'cursor' is now at "EOF". */
u8 qm_mr_next(struct qm_portal *portal);

/* Track h/w production. Returns non-zero if there are new DQRR entries. */
u8 qm_mr_pci_update(struct qm_portal *portal);
void qm_mr_pce_prefetch(struct qm_portal *portal);
u8 qm_mr_pce_update(struct qm_portal *portal);
void qm_mr_pvb_prefetch(struct qm_portal *portal);
u8 qm_mr_pvb_update(struct qm_portal *portal);
u8 qm_mr_get_ithresh(struct qm_portal *portal);
void qm_mr_set_ithresh(struct qm_portal *portal, u8 ithresh);

/* Consume MR entries */
void qm_mr_cci_consume(struct qm_portal *portal, u8 num);
void qm_mr_cci_consume_to_current(struct qm_portal *portal);
void qm_mr_cce_prefetch(struct qm_portal *portal);
void qm_mr_cce_consume(struct qm_portal *portal, u8 num);
void qm_mr_cce_consume_to_current(struct qm_portal *portal);

/* Return the s/w-cached CI value */
u8 qm_mr_get_ci(struct qm_portal *portal);

/* ------------------------------ */
/* --- Management command API --- */

/* Create/destroy */
int qm_mc_init(struct qm_portal *portal);
void qm_mc_finish(struct qm_portal *portal);

/* Start/abort mgmt command */
struct qm_mc_command *qm_mc_start(struct qm_portal *portal);
void qm_mc_abort(struct qm_portal *portal);

/* Writes 'verb' with appropriate 'vbit'. Invalidates and pre-fetches the
 * response. */
void qm_mc_commit(struct qm_portal *portal, u8 myverb);

/* Poll for result. If NULL, invalidates and prefetches for the next call. */
struct qm_mc_result *qm_mc_result(struct qm_portal *portal);

/* ------------------------------------- */
/* --- Portal interrupt register API --- */

/* Quick explanation of the Qman interrupt model. Each bit has a source
 * condition, that source is asserted iff the condition is true. Eg. Each
 * DQAVAIL source bit tracks whether the corresponding channel's work queues
 * contain any truly scheduled frame queues. That source exists "asserted" if
 * and while there are truly-scheduled FQs available, it is deasserted as/when
 * there are no longer any truly-scheduled FQs available. The same is true for
 * the various other interrupt source conditions (QM_PIRQ_***). The following
 * steps indicate what those source bits affect;
 *    1. if the corresponding bit is set in the disable register, the source
 *       bit is masked off, we never see any effect from it.
 *    2. otherwise, the corresponding bit is set in the status register. Once
 *       asserted in the status register, it must be write-1-to-clear'd - the
 *       status register bit will stay set even if the source condition
 *       deasserts.
 *    3. if a bit is set in the status register but *not* set in the enable
 *       register, it will not cause the interrupt to assert. Other bits may
 *       still cause the interrupt to assert of course, and a read of the
 *       status register can still reveal un-enabled bits - this is why the
 *       enable and disable registers aren't strictly speaking "opposites".
 *       "Un-enabled" means it won't, on its own, trigger an interrupt.
 *       "Disabled" means it won't even show up in the status register.
 *    4. if a bit is set in the status register *and* the enable register, the
 *       interrupt line will assert if and only if the inhibit register is
 *       zero. The inhibit register is the only interrupt-related register that
 *       does not share the bit definitions - it is a boolean on/off register.
 */

/* Create/destroy */
int qm_isr_init(struct qm_portal *portal);
void qm_isr_finish(struct qm_portal *portal);
void qm_isr_set_iperiod(struct qm_portal *portal, u16 iperiod);
#endif

/* Used by all portal interrupt registers except 'inhibit' */
#define QM_PIRQ_CSCI	0x00100000	/* Congestion State Change */
#define QM_PIRQ_EQCI	0x00080000	/* Enqueue Command Committed */
#define QM_PIRQ_EQRI	0x00040000	/* EQCR Ring (below threshold) */
#define QM_PIRQ_DQRI	0x00020000	/* DQRR Ring (non-empty) */
#define QM_PIRQ_MRI	0x00010000	/* MR Ring (non-empty) */
#define QM_PIRQ_DQAVAIL	0x0000ffff	/* Channels with frame availability */
/* The DQAVAIL interrupt fields break down into these bits; */
#define QM_DQAVAIL_PORTAL	0x8000		/* Portal channel */
#define QM_DQAVAIL_POOL(n)	(0x8000 >> (n))	/* Pool channel, n==[1..15] */

/* These are qm_<reg>_<verb>(). So for example, qm_disable_write() means "write
 * the disable register" rather than "disable the ability to write". */
#define qm_isr_status_read(qm)		__qm_isr_read(qm, qm_isr_status)
#define qm_isr_status_clear(qm, m)	__qm_isr_write(qm, qm_isr_status, m)
#define qm_isr_enable_read(qm)		__qm_isr_read(qm, qm_isr_enable)
#define qm_isr_enable_write(qm, v)	__qm_isr_write(qm, qm_isr_enable, v)
#define qm_isr_disable_read(qm)		__qm_isr_read(qm, qm_isr_disable)
#define qm_isr_disable_write(qm, v)	__qm_isr_write(qm, qm_isr_disable, v)
/* TODO: unfortunate name-clash here, reword? */
#define qm_isr_inhibit(qm)		__qm_isr_write(qm, qm_isr_inhibit, 1)
#define qm_isr_uninhibit(qm)		__qm_isr_write(qm, qm_isr_inhibit, 0)

#if 0
/* Don't use these, use the wrappers above*/
u32 __qm_isr_read(struct qm_portal *portal, enum qm_isr_reg n);
void __qm_isr_write(struct qm_portal *portal, enum qm_isr_reg n, u32 val);
#endif

