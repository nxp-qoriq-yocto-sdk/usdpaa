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

#ifndef FSL_QMAN_H
#define FSL_QMAN_H

/* User-space-specific initialisation: */
int qman_thread_init(int cpu);
/* Hooks for driver initialisation */
#ifdef CONFIG_FSL_QMAN_FQALLOCATOR
__init int __fqalloc_init(void);
#endif

/* Last updated for v00.800 of the BG */

/*************************************************/
/*   QMan s/w corenet portal, low-level i/face   */
/*************************************************/

/* Portal constants */
#define QM_EQCR_SIZE		8
#define QM_DQRR_SIZE		16
#define QM_MR_SIZE		8
/* Hardware constants */
enum qm_channel {
	qm_channel_swportal0 = 0, qm_channel_swportal1, qm_channel_swportal2,
	qm_channel_swportal3, qm_channel_swportal4, qm_channel_swportal5,
	qm_channel_swportal6, qm_channel_swportal7, qm_channel_swportal8,
	qm_channel_swportal9,
	qm_channel_pool1 = 0x21, qm_channel_pool2, qm_channel_pool3,
	qm_channel_pool4, qm_channel_pool5, qm_channel_pool6,
	qm_channel_pool7, qm_channel_pool8, qm_channel_pool9,
	qm_channel_pool10, qm_channel_pool11, qm_channel_pool12,
	qm_channel_pool13, qm_channel_pool14, qm_channel_pool15,
	qm_channel_fman0_sp0 = 0x40, qm_channel_fman0_sp1, qm_channel_fman0_sp2,
	qm_channel_fman0_sp3, qm_channel_fman0_sp4, qm_channel_fman0_sp5,
	qm_channel_fman0_sp6, qm_channel_fman0_sp7, qm_channel_fman0_sp8,
	qm_channel_fman0_sp9, qm_channel_fman0_sp10, qm_channel_fman0_sp11,
	qm_channel_fman1_sp0 = 0x60, qm_channel_fman1_sp1, qm_channel_fman1_sp2,
	qm_channel_fman1_sp3, qm_channel_fman1_sp4, qm_channel_fman1_sp5,
	qm_channel_fman1_sp6, qm_channel_fman1_sp7, qm_channel_fman1_sp8,
	qm_channel_fman1_sp9, qm_channel_fman1_sp10, qm_channel_fman1_sp11,
	qm_channel_caam = 0x80,
	qm_channel_pme = 0xa0,
};
enum qm_isr_reg {
	qm_isr_status = 0,
	qm_isr_enable = 1,
	qm_isr_disable = 2,
	qm_isr_inhibit = 3
};
enum qm_dc_portal {
	qm_dc_portal_fman0 = 0,
	qm_dc_portal_fman1 = 1,
	qm_dc_portal_caam = 2,
	qm_dc_portal_pme = 3
};

/* Represents s/w corenet portal mapped data structures */
struct qm_eqcr_entry;	/* EQCR (EnQueue Command Ring) entries */
struct qm_dqrr_entry;	/* DQRR (DeQueue Response Ring) entries */
struct qm_mr_entry;	/* MR (Message Ring) entries */
struct qm_mc_command;	/* MC (Management Command) command */
struct qm_mc_result;	/* MC result */

/* This type represents a s/w corenet portal space, and is used for creating the
 * portal objects within it (EQCR, DQRR, etc) */
struct qm_portal;

/* When iterating the available portals, this is the exposed config structure */
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


/* ------------------------ */
/* --- FQ allocator API --- */

/* Flags to qm_fq_free_flags() */
#define QM_FQ_FREE_WAIT       0x00000001 /* wait if RCR is full */
#define QM_FQ_FREE_WAIT_INT   0x00000002 /* if wait, interruptible? */
#define QM_FQ_FREE_WAIT_SYNC  0x00000004 /* if wait, until consumed? */

#ifdef CONFIG_FSL_QMAN_FQALLOCATOR

/* Allocate an unused FQID from the FQ allocator, returns zero for failure */
u32 qm_fq_new(void);
/* Release a FQID back to the FQ allocator */
int qm_fq_free_flags(u32 fqid, u32 flags);
static inline void qm_fq_free(u32 fqid)
{
	if (qm_fq_free_flags(fqid, QM_FQ_FREE_WAIT))
		BUG();
}

#else /* !CONFIG_FSL_QMAN_FQALLOCATOR */

#define qm_fq_new()                   0
#define qm_fq_free_flags(fqid,flags)  BUG()
#define qm_fq_free(fqid)              BUG()

#endif /* !CONFIG_FSL_QMAN_FQALLOCATOR */


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
#define QM_SDQCR_CHANNELS_POOL_MASK	0x00007fff
#define QM_SDQCR_CHANNELS_POOL(n)	(0x00008000 >> (n))
#define QM_SDQCR_SPECIFICWQ_MASK	0x000000f7
#define QM_SDQCR_SPECIFICWQ_DEDICATED	0x00000000
#define QM_SDQCR_SPECIFICWQ_POOL(n)	((n) << 4)
#define QM_SDQCR_SPECIFICWQ_WQ(n)	(n)
void qm_dqrr_sdqcr_set(struct qm_portal *portal, u32 sdqcr);
u32 qm_dqrr_sdqcr_get(struct qm_portal *portal);

/* For qm_dqrr_vdqcr_set(); Choose one PRECEDENCE. EXACT is optional. Use
 * NUMFRAMES(n) (6-bit) or NUMFRAMES_TILLEMPTY to fill in the frame-count. Use
 * FQID(n) to fill in the frame queue ID. */
#define QM_VDQCR_PRECEDENCE_VDQCR	0x0
#define QM_VDQCR_PRECEDENCE_SDQCR	0x80000000
#define QM_VDQCR_EXACT			0x40000000
#define QM_VDQCR_NUMFRAMES_MASK		0x3f000000
#define QM_VDQCR_NUMFRAMES_SET(n)	(((n) & 0x3f) << 24)
#define QM_VDQCR_NUMFRAMES_GET(n)	(((n) >> 24) & 0x3f)
#define QM_VDQCR_NUMFRAMES_TILLEMPTY	QM_VDQCR_NUMFRAMES_SET(0)
#define QM_VDQCR_FQID_MASK		0x00ffffff
#define QM_VDQCR_FQID(n)		((n) & QM_VDQCR_FQID_MASK)
void qm_dqrr_vdqcr_set(struct qm_portal *portal, u32 vdqcr);
u32 qm_dqrr_vdqcr_get(struct qm_portal *portal);

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

/* Don't use these, use the wrappers above*/
u32 __qm_isr_read(struct qm_portal *portal, enum qm_isr_reg n);
void __qm_isr_write(struct qm_portal *portal, enum qm_isr_reg n, u32 val);


/* ------------------------------------------------------- */
/* --- Qman data structures (and associated constants) --- */

/* See David Lapp's "Frame formats" document, "dpateam", Jan 07, 2008 */
#define QM_FD_FORMAT_SG		0x4
#define QM_FD_FORMAT_LONG	0x2
#define QM_FD_FORMAT_COMPOUND	0x1
enum qm_fd_format {
	/* 'contig' implies a contiguous buffer, whereas 'sg' implies a
	 * scatter-gather table. 'big' implies a 29-bit length with no offset
	 * field, otherwise length is 20-bit and offset is 9-bit. 'compound'
	 * implies a s/g-like table, where each entry itself represents a frame
	 * (contiguous or scatter-gather) and the 29-bit "length" is
	 * interpreted purely for congestion calculations, ie. a "congestion
	 * weight". */
	qm_fd_contig = 0,
	qm_fd_contig_big = QM_FD_FORMAT_LONG,
	qm_fd_sg = QM_FD_FORMAT_SG,
	qm_fd_sg_big = QM_FD_FORMAT_SG | QM_FD_FORMAT_LONG,
	qm_fd_compound = QM_FD_FORMAT_COMPOUND
};

/* See 1.5.1.1: "Frame Descriptor (FD)" */
struct qm_fd {
	u8 dd:2;	/* dynamic debug */
	u8 liodn_offset:6; /* aka. "Partition ID" in rev1.0 */
	u8 bpid;	/* Buffer Pool ID */
	u8 eliodn_offset:4;
	u8 __reserved:4;
	u8 addr_hi;	/* high 8-bits of 40-bit address */
	u32 addr_lo;	/* low 32-bits of 40-bit address */
	/* The 'format' field indicates the interpretation of the remaining 29
	 * bits of the 32-bit word. For packing reasons, it is duplicated in the
	 * other union elements. */
	union {
		/* If 'format' is _contig or _sg, 20b length and 9b offset */
		struct {
			enum qm_fd_format format:3;
			u16 offset:9;
			u32 length20:20;
		} __packed;
		/* If 'format' is _contig_big or _sg_big, 29b length */
		struct {
			enum qm_fd_format _format1:3;
			u32 length29:29;
		} __packed;
		/* If 'format' is _compound, 29b "congestion weight" */
		struct {
			enum qm_fd_format _format2:3;
			u32 cong_weight:29;
		} __packed;
		/* For easier/faster copying of this part of the fd (eg. from a
		 * DQRR entry to an EQCR entry) copy 'opaque' */
		u32 opaque;
	} __packed;
	union {
		u32 cmd;
		u32 status;
	};
} __packed;
#define QM_FD_DD_NULL		0x00
#define QM_FD_PID_MASK		0x3f

/* See 2.2.1.3 Multi-Core Datapath Acceleration Architecture */
struct qm_sg_entry {
	u8 __reserved1[3];
	u8 addr_hi;		/* high 8-bits of 40-bit address */
	u32 addr_lo;		/* low 32-bits of 40-bit address */
	u32 extension:1; 	/* Extension bit */
	u32 final:1; 		/* Final bit */
	u32 length:30;
	u8 __reserved2;
	u8 bpid;
	u16 __reserved3:3;
	u16 offset:13;
} __packed;

/* See 1.5.8.1: "Enqueue Command" */
struct qm_eqcr_entry {
	u8 __dont_write_directly__verb;
	u8 dca;
	u16 seqnum;
	u32 orp;	/* 24-bit */
	u32 fqid;	/* 24-bit */
	u32 tag;
	struct qm_fd fd;
	u8 __reserved3[32];
} __packed;
#define QM_EQCR_VERB_VBIT		0x80
#define QM_EQCR_VERB_CMD_MASK		0x61	/* but only one value; */
#define QM_EQCR_VERB_CMD_ENQUEUE	0x01
#define QM_EQCR_VERB_COLOUR_MASK	0x18	/* 4 possible values; */
#define QM_EQCR_VERB_COLOUR_GREEN	0x00
#define QM_EQCR_VERB_COLOUR_YELLOW	0x08
#define QM_EQCR_VERB_COLOUR_RED		0x10
#define QM_EQCR_VERB_COLOUR_OVERRIDE	0x18
#define QM_EQCR_VERB_INTERRUPT		0x04	/* on command consumption */
#define QM_EQCR_VERB_ORP		0x02	/* enable order restoration */
#define QM_EQCR_DCA_ENABLE		0x80
#define QM_EQCR_DCA_PARK		0x40
#define QM_EQCR_DCA_IDXMASK		0x0f	/* "DQRR::idx" goes here */
#define QM_EQCR_SEQNUM_NESN		0x8000	/* Advance NESN */
#define QM_EQCR_SEQNUM_NLIS		0x4000	/* More fragments to come */
#define QM_EQCR_SEQNUM_SEQMASK		0x3fff	/* sequence number goes here */
#define QM_EQCR_FQID_NULL		0	/* eg. for an ORP seqnum hole */

/* See 1.5.8.2: "Frame Dequeue Response" */
struct qm_dqrr_entry {
	u8 verb;
	u8 stat;
	u16 seqnum;	/* 15-bit */
	u8 tok;
	u8 __reserved2[3];
	u32 fqid;	/* 24-bit */
	u32 contextB;
	struct qm_fd fd;
	u8 __reserved4[32];
} __packed;
#define QM_DQRR_VERB_VBIT		0x80
#define QM_DQRR_VERB_MASK		0x7f	/* where the verb contains; */
#define QM_DQRR_VERB_FRAME_DEQUEUE	0x60	/* "this format" */
#define QM_DQRR_STAT_FQ_EMPTY		0x80	/* FQ empty */
#define QM_DQRR_STAT_FQ_HELDACTIVE	0x40	/* FQ held active */
#define QM_DQRR_STAT_FQ_FORCEELIGIBLE	0x20	/* FQ was force-eligible'd */
#define QM_DQRR_STAT_FD_VALID		0x10	/* has a non-NULL FD */
#define QM_DQRR_STAT_UNSCHEDULED	0x02	/* Unscheduled dequeue */
#define QM_DQRR_STAT_DQCR_EXPIRED	0x01	/* VDQCR or PDQCR expired*/

/* See 1.5.8.3: "ERN Message Response" */
/* See 1.5.8.4: "FQ State Change Notification" */
struct qm_mr_entry {
	u8 verb;
	union {
		struct {
			u8 dca;
			u16 seqnum;
			u8 rc;		/* Rejection Code */
			u32 orp:24;
			u32 fqid;	/* 24-bit */
			u32 tag;
			struct qm_fd fd;
		} __packed ern;
		struct {
			u8 colour:2;	/* See QM_MR_DCERN_COLOUR_* */
			u8 __reserved1:4;
			enum qm_dc_portal portal:2;
			u16 __reserved2;
			u8 rc;		/* Rejection Code */
			u32 __reserved3:24;
			u32 fqid;	/* 24-bit */
			u32 tag;
			struct qm_fd fd;
		} __packed dcern;
		struct {
			u8 fqs;		/* Frame Queue Status */
			u8 __reserved1[6];
			u32 fqid;	/* 24-bit */
			u32 contextB;
			u8 __reserved2[16];
		} __packed fq;		/* FQRN/FQRNI/FQRL/FQPN */
	};
	u8 __reserved2[32];
} __packed;
#define QM_MR_VERB_VBIT			0x80
/* The "ern" VERB bits match QM_EQCR_VERB_*** so aren't reproduced here. ERNs
 * originating from direct-connect portals ("dcern") use 0x20 as a verb which
 * would be invalid as a s/w enqueue verb. A s/w ERN can be distinguished from
 * the other MR types by noting if the 0x20 bit is unset. */
#define QM_MR_VERB_TYPE_MASK		0x27
#define QM_MR_VERB_DC_ERN		0x20
#define QM_MR_VERB_FQRN			0x21
#define QM_MR_VERB_FQRNI		0x22
#define QM_MR_VERB_FQRL			0x23
#define QM_MR_VERB_FQPN			0x24
#define QM_MR_RC_MASK			0xf0	/* contains one of; */
#define QM_MR_RC_CGR_TAILDROP		0x00
#define QM_MR_RC_WRED			0x10
#define QM_MR_RC_ERROR			0x20
#define QM_MR_RC_ORPWINDOW_EARLY	0x30
#define QM_MR_RC_ORPWINDOW_LATE		0x40
#define QM_MR_RC_FQ_TAILDROP		0x50
#define QM_MR_RC_ORPWINDOW_RETIRED	0x60
#define QM_MR_FQS_ORLPRESENT		0x02	/* ORL fragments to come */
#define QM_MR_FQS_NOTEMPTY		0x01	/* FQ has enqueued frames */
#define QM_MR_DCERN_COLOUR_GREEN	0x00
#define QM_MR_DCERN_COLOUR_YELLOW	0x01
#define QM_MR_DCERN_COLOUR_RED		0x02
#define QM_MR_DCERN_COLOUR_OVERRIDE	0x03

/* This identical structure of FQD fields is present in the "Init FQ" command
 * and the "Query FQ" result. It's suctioned out here into its own struct. It's
 * also used as the qman_query_fq() result structure in the high-level API. */
struct qm_fqd {
	union {
		u8 orpc;
		struct {
			u8 __reserved1:2;
			u8 orprws:3;
			u8 oa:1;
			u8 olws:2;
		} __packed;
	};
	u8 cgid;
	u16 fq_ctrl;	/* See QM_FQCTRL_<...> */
	union {
		u16 dest_wq;
		struct {
			u16 channel:13; /* enum qm_channel */
			u16 wq:3;
		} __packed dest;
	};
	u16 __reserved2:1;
	u16 ics_cred:15;
	union {
		u16 td_thresh;
		struct {
			u16 __reserved1:3;
			u16 exp:5;
			u16 mant:8;
		} __packed td;
	};
	u32 context_b;
	union {
		/* Treat it as 64-bit opaque */
		struct {
			u32 hi;
			u32 lo;
		};
		/* Treat it as s/w portal stashing config */
		/* See 1.5.6.7.1: "FQD Context_A field used for [...] */
		struct {
			struct qm_fqd_stashing {
				/* See QM_STASHING_EXCL_<...> */
				u8 exclusive;
				u8 __reserved1:2;
				/* Numbers of cachelines */
				u8 annotation_cl:2;
				u8 data_cl:2;
				u8 context_cl:2;
			} __packed stashing;
			/* 48-bit address of FQ context to
			 * stash, must be cacheline-aligned */
			u16 context_hi;
			u32 context_lo;
		} __packed;
	} context_a;
} __packed;

/* See 1.5.2.2: "Frame Queue Descriptor (FQD)" */
/* Frame Queue Descriptor (FQD) field 'fq_ctrl' uses these constants */
#define QM_FQCTRL_MASK		0x07ff	/* 'fq_ctrl' flags; */
#define QM_FQCTRL_CGE		0x0400	/* Congestion Group Enable */
#define QM_FQCTRL_TDE		0x0200	/* Tail-Drop Enable */
#define QM_FQCTRL_ORP		0x0100	/* ORP Enable */
#define QM_FQCTRL_CTXASTASHING	0x0080	/* Context-A stashing */
#define QM_FQCTRL_CPCSTASH	0x0040	/* CPC Stash Enable */
#define QM_FQCTRL_FORCESFDR	0x0008	/* High-priority SFDRs */
#define QM_FQCTRL_AVOIDBLOCK	0x0004	/* Don't block active */
#define QM_FQCTRL_HOLDACTIVE	0x0002	/* Hold active in portal */
#define QM_FQCTRL_PREFERINCACHE	0x0001	/* Aggressively cache FQD */
#define QM_FQCTRL_LOCKINCACHE	QM_FQCTRL_PREFERINCACHE /* older naming */

/* See 1.5.6.7.1: "FQD Context_A field used for [...] */
/* Frame Queue Descriptor (FQD) field 'CONTEXT_A' uses these constants */
#define QM_STASHING_EXCL_ANNOTATION	0x04
#define QM_STASHING_EXCL_DATA		0x02
#define QM_STASHING_EXCL_CTX		0x01

/* See 1.5.8.4: "FQ State Change Notification" */
/* This struct represents the 32-bit "WR_PARM_[GYR]" parameters in CGR fields
 * and associated commands/responses. The WRED parameters are calculated from
 * these fields as follows;
 *   MaxTH = MA * (2 ^ Mn)
 *   Slope = SA / (2 ^ Sn)
 *    MaxP = 4 * (Pn + 1)
 */
struct qm_cgr_wr_parm {
	union {
		u32 word;
		struct {
			u32 MA:8;
			u32 Mn:5;
			u32 SA:7; /* must be between 64-127 */
			u32 Sn:6;
			u32 Pn:6;
		} __packed;
	};
} __packed;
/* This struct represents the 13-bit "CS_THRES" CGR field. In the corresponding
 * management commands, this is padded to a 16-bit structure field, so that's
 * how we represent it here. The congestion state threshold is calculated from
 * these fields as follows;
 *   CS threshold = TA * (2 ^ Tn)
 */
struct qm_cgr_cs_thres {
	u16 __reserved:3;
	u16 TA:8;
	u16 Tn:5;
} __packed;

/* This identical structure of CGR fields is present in the "Init/Modify CGR"
 * commands and the "Query CGR" result. It's suctioned out here into its own
 * struct. */
struct __qm_mc_cgr {
	struct qm_cgr_wr_parm wr_parm_g;
	struct qm_cgr_wr_parm wr_parm_y;
	struct qm_cgr_wr_parm wr_parm_r;
	u8 wr_en_g;	/* boolean, use QM_CGR_EN */
	u8 wr_en_y;	/* boolean, use QM_CGR_EN */
	u8 wr_en_r;	/* boolean, use QM_CGR_EN */
	u8 cscn_en;	/* boolean, use QM_CGR_EN */
	u32 cscn_targ;	/* use QM_CGR_TARG_* */
	u8 cstd_en;	/* boolean, use QM_CGR_EN */
	u8 cs;		/* boolean, only used in query response */
	struct qm_cgr_cs_thres cs_thres;
} __packed;
#define QM_CGR_EN		0x01 /* For wr_en_*, cscn_en, cstd_en */
#define QM_CGR_TARG_PORTAL(n)	(0x80000000 >> (n)) /* s/w portal, 0-9 */
#define QM_CGR_TARG_FMAN0	0x00200000 /* direct-connect portal: fman0 */
#define QM_CGR_TARG_FMAN1	0x00100000 /*                      : fman1 */

/* See 1.5.8.5.1: "Initialize FQ" */
/* See 1.5.8.5.2: "Query FQ" */
/* See 1.5.8.5.3: "Query FQ Non-Programmable Fields" */
/* See 1.5.8.5.4: "Alter FQ State Commands " */
/* See 1.5.8.6.1: "Initialize/Modify CGR" */
/* See 1.5.8.6.2: "Query CGR" */
/* See 1.5.8.6.3: "Query Congestion Group State" */
struct qm_mc_command {
	u8 __dont_write_directly__verb;
	union {
		struct qm_mcc_initfq {
			u8 __reserved1;
			u16 we_mask;	/* Write Enable Mask */
			u32 fqid;	/* 24-bit */
			u16 count;	/* Initialises 'count+1' FQDs */
			struct qm_fqd fqd; /* the FQD fields go here */
			u8 __reserved3[32];
		} __packed initfq;
		struct qm_mcc_queryfq {
			u8 __reserved1[3];
			u32 fqid;	/* 24-bit */
			u8 __reserved2[56];
		} __packed queryfq;
		struct qm_mcc_queryfq_np {
			u8 __reserved1[3];
			u32 fqid;	/* 24-bit */
			u8 __reserved2[56];
		} __packed queryfq_np;
		struct qm_mcc_alterfq {
			u8 __reserved1[3];
			u32 fqid;	/* 24-bit */
			u8 __reserved2[56];
		} __packed alterfq;
		struct qm_mcc_initcgr {
			u8 __reserved1;
			u16 we_mask;	/* Write Enable Mask */
			struct __qm_mc_cgr cgr;	/* CGR fields */
			u8 __reserved2[3];
			u8 cgid;
			u8 __reserved4[32];
		} __packed initcgr;
		struct qm_mcc_querycgr {
			u8 __reserved1[30];
			u8 cgid;
			u8 __reserved2[32];
		} __packed querycgr;
		struct qm_mcc_querycongestion {
			u8 __reserved[63];
		} __packed querycongestion;
		struct qm_mcc_querywq {
			u8 __reserved;
			/* select channel if verb != QUERYWQ_DEDICATED */
			union {
				u16 channel_wq; /* ignores wq (3 lsbits) */
				struct {
					u16 id:13; /* enum qm_channel */
					u16 __reserved1:3;
				} __packed channel;
			};
			u8 __reserved2[60];
		} __packed querywq;
	};
} __packed;
#define QM_MCC_VERB_VBIT		0x80
#define QM_MCC_VERB_MASK		0x7f	/* where the verb contains; */
#define QM_MCC_VERB_INITFQ_PARKED	0x40
#define QM_MCC_VERB_INITFQ_SCHED	0x41
#define QM_MCC_VERB_QUERYFQ		0x44
#define QM_MCC_VERB_QUERYFQ_NP		0x45	/* "non-programmable" fields */
#define QM_MCC_VERB_QUERYWQ		0x46
#define QM_MCC_VERB_QUERYWQ_DEDICATED	0x47
#define QM_MCC_VERB_ALTER_SCHED		0x48	/* Schedule FQ */
#define QM_MCC_VERB_ALTER_FE		0x49	/* Force Eligible FQ */
#define QM_MCC_VERB_ALTER_RETIRE	0x4a	/* Retire FQ */
#define QM_MCC_VERB_ALTER_OOS		0x4b	/* Take FQ out of service */
#define QM_MCC_VERB_INITCGR		0x50
#define QM_MCC_VERB_MODIFYCGR		0x51
#define QM_MCC_VERB_QUERYCGR		0x58
#define QM_MCC_VERB_QUERYCONGESTION	0x59
/* INITFQ-specific flags */
#define QM_INITFQ_WE_MASK		0x00ff	/* 'Write Enable' flags; */
#define QM_INITFQ_WE_ORPC		0x0080
#define QM_INITFQ_WE_CGID		0x0040
#define QM_INITFQ_WE_FQCTRL		0x0020
#define QM_INITFQ_WE_DESTWQ		0x0010
#define QM_INITFQ_WE_ICSCRED		0x0008
#define QM_INITFQ_WE_TDTHRESH		0x0004
#define QM_INITFQ_WE_CONTEXTB		0x0002
#define QM_INITFQ_WE_CONTEXTA		0x0001
/* INITCGR/MODIFYCGR-specific flags */
#define QM_CGR_WE_MASK			0x07ff	/* 'Write Enable Mask'; */
#define QM_CGR_WE_WR_PARM_G		0x0400
#define QM_CGR_WE_WR_PARM_Y		0x0200
#define QM_CGR_WE_WR_PARM_R		0x0100
#define QM_CGR_WE_WR_EN_G		0x0080
#define QM_CGR_WE_WR_EN_Y		0x0040
#define QM_CGR_WE_WR_EN_R		0x0020
#define QM_CGR_WE_CSCN_EN		0x0010
#define QM_CGR_WE_CSCN_TARG		0x0008
#define QM_CGR_WE_CSTD_EN		0x0004
#define QM_CGR_WE_CS_THRES		0x0002

/* See 1.5.8.5.1: "Initialize FQ" */
/* See 1.5.8.5.2: "Query FQ" */
/* See 1.5.8.5.3: "Query FQ Non-Programmable Fields" */
/* See 1.5.8.5.4: "Alter FQ State Commands " */
/* See 1.5.8.6.1: "Initialize/Modify CGR" */
/* See 1.5.8.6.2: "Query CGR" */
/* See 1.5.8.6.3: "Query Congestion Group State" */
struct qm_mc_result {
	u8 verb;
	u8 result;
	union {
		struct qm_mcr_initfq {
			u8 __reserved1[62];
		} __packed initfq;
		struct qm_mcr_queryfq {
			u8 __reserved1[8];
			struct qm_fqd fqd;	/* the FQD fields are here */
			u8 __reserved2[32];
		} __packed queryfq;
		struct qm_mcr_queryfq_np {
			u8 __reserved1;
			u8 state;	/* QM_MCR_NP_STATE_*** */
			u8 __reserved2;
			u32 fqd_link:24;
			u16 odp_seq;
			u16 orp_nesn;
			u16 orp_ea_hseq;
			u16 orp_ea_tseq;
			u8 __reserved3;
			u32 orp_ea_hptr:24;
			u8 __reserved4;
			u32 orp_ea_tptr:24;
			u8 __reserved5;
			u32 pfdr_hptr:24;
			u8 __reserved6;
			u32 pfdr_tptr:24;
			u8 __reserved7[5];
			u8 __reserved8:7;
			u8 is:1;
			u16 ics_surp;
			u32 byte_cnt;
			u8 __reserved9;
			u32 frm_cnt:24;
			u32 __reserved10;
			u16 ra1_sfdr;	/* QM_MCR_NP_RA1_*** */
			u16 ra2_sfdr;	/* QM_MCR_NP_RA2_*** */
			u16 __reserved11;
			u16 od1_sfdr;	/* QM_MCR_NP_OD1_*** */
			u16 od2_sfdr;	/* QM_MCR_NP_OD2_*** */
			u16 od3_sfdr;	/* QM_MCR_NP_OD3_*** */
		} __packed queryfq_np;
		struct qm_mcr_alterfq {
			u8 fqs;		/* Frame Queue Status */
			u8 __reserved1[61];
		} __packed alterfq;
		struct qm_mcr_initcgr {
			u8 __reserved1[62];
		} __packed initcgr;
		struct qm_mcr_querycgr {
			u16 __reserved1;
			struct __qm_mc_cgr cgr; /* CGR fields */
			u32 __reserved2;
			u32 __reserved3:24;
			u32 i_bcnt_hi:8;/* high 8-bits of 40-bit "Instant" */
			u32 i_bcnt_lo;	/* low 32-bits of 40-bit */
			u32 __reserved4:24;
			u32 a_bcnt_hi:8;/* high 8-bits of 40-bit "Average" */
			u32 a_bcnt_lo;	/* low 32-bits of 40-bit */
			u32 lgt;	/* Last Group Tick */
			u8 __reserved5[12];
		} __packed querycgr;
		struct qm_mcr_querycongestion {
			u8 __reserved[30];
			/* Access this struct using QM_MCR_QUERYCONGESTION() */
			struct __qm_mcr_querycongestion {
				u32 __state[8];
			} state;
		} __packed querycongestion;
		struct qm_mcr_querywq {
			union {
				u16 channel_wq; /* ignores wq (3 lsbits) */
				struct {
					u16 id:13; /* enum qm_channel */
					u16 __reserved:3;
				} __packed channel;
			};
			u8 __reserved[28];
			u32 wq_len[8];
		} __packed querywq;
	};
} __packed;
#define QM_MCR_VERB_RRID		0x80
#define QM_MCR_VERB_MASK		QM_MCC_VERB_MASK
#define QM_MCR_VERB_INITFQ_PARKED	QM_MCC_VERB_INITFQ_PARKED
#define QM_MCR_VERB_INITFQ_SCHED	QM_MCC_VERB_INITFQ_SCHED
#define QM_MCR_VERB_QUERYFQ		QM_MCC_VERB_QUERYFQ
#define QM_MCR_VERB_QUERYFQ_NP		QM_MCC_VERB_QUERYFQ_NP
#define QM_MCR_VERB_QUERYWQ		QM_MCC_VERB_QUERYWQ
#define QM_MCR_VERB_QUERYWQ_DEDICATED	QM_MCC_VERB_QUERYWQ_DEDICATED
#define QM_MCR_VERB_ALTER_SCHED		QM_MCC_VERB_ALTER_SCHED
#define QM_MCR_VERB_ALTER_FE		QM_MCC_VERB_ALTER_FE
#define QM_MCR_VERB_ALTER_RETIRE	QM_MCC_VERB_ALTER_RETIRE
#define QM_MCR_VERB_ALTER_OOS		QM_MCC_VERB_ALTER_OOS
#define QM_MCR_RESULT_NULL		0x00
#define QM_MCR_RESULT_OK		0xf0
#define QM_MCR_RESULT_ERR_FQID		0xf1
#define QM_MCR_RESULT_ERR_FQSTATE	0xf2
#define QM_MCR_RESULT_ERR_NOTEMPTY	0xf3	/* OOS fails if FQ is !empty */
#define QM_MCR_RESULT_ERR_BADCHANNEL	0xf4
#define QM_MCR_RESULT_PENDING		0xf8
#define QM_MCR_RESULT_ERR_BADCOMMAND	0xff
#define QM_MCR_NP_STATE_FE		0x10
#define QM_MCR_NP_STATE_R		0x08
#define QM_MCR_NP_STATE_MASK		0x07	/* Reads FQD::STATE; */
#define QM_MCR_NP_STATE_OOS		0x00
#define QM_MCR_NP_STATE_RETIRED		0x01
#define QM_MCR_NP_STATE_TEN_SCHED	0x02
#define QM_MCR_NP_STATE_TRU_SCHED	0x03
#define QM_MCR_NP_STATE_PARKED		0x04
#define QM_MCR_NP_STATE_ACTIVE		0x05
#define QM_MCR_NP_PTR_MASK		0x07ff	/* for RA[12] & OD[123] */
#define QM_MCR_NP_RA1_NRA(v)		(((v) >> 14) & 0x3)	/* FQD::NRA */
#define QM_MCR_NP_RA2_IT(v)		(((v) >> 14) & 0x1)	/* FQD::IT */
#define QM_MCR_NP_OD1_NOD(v)		(((v) >> 14) & 0x3)	/* FQD::NOD */
#define QM_MCR_NP_OD3_NPC(v)		(((v) >> 14) & 0x3)	/* FQD::NPC */
#define QM_MCR_FQS_ORLPRESENT		0x02	/* ORL fragments to come */
#define QM_MCR_FQS_NOTEMPTY		0x01	/* FQ has enqueued frames */
/* This extracts the state for congestion group 'n' from a query response.
 * Eg.
 *   u8 cgr = [...];
 *   struct qm_mc_result *res = [...];
 *   printf("congestion group %d congestion state: %d\n", cgr,
 *       QM_MCR_QUERYCONGESTION(&res->querycongestion.state, cgr));
 */
#define __CGR_WORD(num)		(num >> 5)
#define __CGR_SHIFT(num)	(num & 0x1f)
static inline int QM_MCR_QUERYCONGESTION(struct __qm_mcr_querycongestion *p,
					u8 cgr)
{
	return p->__state[__CGR_WORD(cgr)] & (0x80000000 >> __CGR_SHIFT(cgr));
}


/*********************/
/* Utility interface */
/*********************/

/* Represents an allocator over a range of FQIDs. NB, accesses are not locked,
 * spinlock them yourself if needed. */
struct qman_fqid_pool;

/* Create/destroy a FQID pool, num must be a multiple of 32. NB, _destroy()
 * always succeeds, but returns non-zero if there were "leaked" FQID
 * allocations. */
struct qman_fqid_pool *qman_fqid_pool_create(u32 fqid_start, u32 num);
int qman_fqid_pool_destroy(struct qman_fqid_pool *pool);
/* Alloc/free a FQID from the range. _alloc() returns zero for success. */
int qman_fqid_pool_alloc(struct qman_fqid_pool *pool, u32 *fqid);
void qman_fqid_pool_free(struct qman_fqid_pool *pool, u32 fqid);
u32 qman_fqid_pool_used(struct qman_fqid_pool *pool);

/*******************************************************************/
/* Managed (aka "shared" or "mux/demux") portal, high-level i/face */
/*******************************************************************/

	/* Congestion Groups */
	/* ----------------- */
/* This wrapper represents a bit-array for the state of the 256 Qman congestion
 * groups. Is also used as a *mask* for congestion groups, eg. so we ignore
 * those that don't concern us. We harness the structure and accessor details
 * already used in the management command to query congestion groups. */
struct qman_cgrs {
	struct __qm_mcr_querycongestion q;
};
static inline void qman_cgrs_init(struct qman_cgrs *c)
{
	memset(c, 0, sizeof(*c));
}
static inline int qman_cgrs_get(struct qman_cgrs *c, int num)
{
	return QM_MCR_QUERYCONGESTION(&c->q, num);
}
static inline void qman_cgrs_set(struct qman_cgrs *c, int num)
{
	c->q.__state[__CGR_WORD(num)] |= (0x80000000 >> __CGR_SHIFT(num));
}
static inline void qman_cgrs_unset(struct qman_cgrs *c, int num)
{
	c->q.__state[__CGR_WORD(num)] &= ~(0x80000000 >> __CGR_SHIFT(num));
}

	/* Portal and Frame Queues */
	/* ----------------------- */
/* Represents a managed portal */
struct qman_portal;

/* This object type represents Qman frame queue descriptors (FQD), it is
 * cacheline-aligned, and initialised by qman_create_fq(). The structure is
 * defined further down. */
struct qman_fq;

/* This enum, and the callback type that returns it, are used when handling
 * dequeued frames via DQRR. Note that for "null" callbacks registered with the
 * portal object (for handling dequeues that do not demux because contextB is
 * NULL), the return value *MUST* be qman_cb_dqrr_consume. */
enum qman_cb_dqrr_result {
	/* DQRR entry can be consumed */
	qman_cb_dqrr_consume,
	/* Like _consume, but requests parking - FQ must be held-active */
	qman_cb_dqrr_park,
	/* Does not consume, for DCA mode only. This allows out-of-order
	 * consumes by explicit calls to qman_dca() and/or the use of implicit
	 * DCA via EQCR entries. */
	qman_cb_dqrr_defer
};
typedef enum qman_cb_dqrr_result (*qman_cb_dqrr)(struct qman_portal *qm,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr);

/* This callback type is used when handling ERNs, FQRNs and FQRLs via MR. They
 * are always consumed after the callback returns. */
typedef void (*qman_cb_mr)(struct qman_portal *qm, struct qman_fq *fq,
				const struct qm_mr_entry *msg);

/* s/w-visible states. Ie. tentatively scheduled + truly scheduled + active +
 * held-active + held-suspended are just "sched". Things like "retired" will not
 * be assumed until it is complete (ie. QMAN_FQ_STATE_CHANGING is set until
 * then, to indicate it's completing and to gate attempts to retry the retire
 * command). Note, park commands do not set QMAN_FQ_STATE_CHANGING because it's
 * technically impossible in the case of enqueue DCAs (which refer to DQRR ring
 * index rather than the FQ that ring entry corresponds to), so repeated park
 * commands are allowed (if you're silly enough to try) but won't change FQ
 * state, and the resulting park notifications move FQs from "sched" to
 * "parked". */
enum qman_fq_state {
	qman_fq_state_oos,
	qman_fq_state_parked,
	qman_fq_state_sched,
	qman_fq_state_retired
};

/* Frame queue objects (struct qman_fq) are stored within memory passed to
 * qman_create_fq(), as this allows stashing of caller-provided demux callback
 * pointers at no extra cost to stashing of (driver-internal) FQ state. If the
 * caller wishes to add per-FQ state and have it benefit from dequeue-stashing,
 * they should;
 *
 * (a) extend the qman_fq structure with their state; eg.
 *
 *     // myfq is allocated and driver_fq callbacks filled in;
 *     struct my_fq {
 *         struct qman_fq base;
 *         int an_extra_field;
 *         [ ... add other fields to be associated with each FQ ...]
 *     } *myfq = some_my_fq_allocator();
 *     struct qman_fq *fq = qman_create_fq(fqid, flags, &myfq->base);
 *
 *     // in a dequeue callback, access extra fields from 'fq' via a cast;
 *     struct my_fq *myfq = (struct my_fq *)fq;
 *     do_something_with(myfq->an_extra_field);
 *     [...]
 *
 * (b) when and if configuring the FQ for context stashing, specify how ever
 *     many cachelines are required to stash 'struct my_fq', to accelerate not
 *     only the Qman driver but the callback as well.
 */
struct qman_fq {
	/* Caller of qman_create_fq() provides these demux callbacks */
	struct qman_fq_cb {
		qman_cb_dqrr dqrr;	/* for dequeued frames */
		qman_cb_mr ern;		/* for s/w ERNs */
		qman_cb_mr dc_ern;	/* for diverted h/w ERNs */
		qman_cb_mr fqs;		/* frame-queue state changes*/
	} cb;
	/* These are internal to the driver, don't touch. In particular, they
	 * may change, be removed, or extended (so you shouldn't rely on
	 * sizeof(qman_fq) being a constant). */
	spinlock_t fqlock;
	u32 fqid;
	volatile unsigned long flags;
	enum qman_fq_state state;
	int cgr_groupid;
	struct rb_node node;
};

/* Flags to qman_create_fq() */
#define QMAN_FQ_FLAG_NO_ENQUEUE      0x00000001 /* can't enqueue */
#define QMAN_FQ_FLAG_NO_MODIFY       0x00000002 /* can only enqueue */
#define QMAN_FQ_FLAG_TO_DCPORTAL     0x00000004 /* consumed by CAAM/PME/Fman */
#define QMAN_FQ_FLAG_LOCKED          0x00000008 /* multi-core locking */
#define QMAN_FQ_FLAG_RECOVER         0x00000010 /* recovery mode */
#define QMAN_FQ_FLAG_DYNAMIC_FQID    0x00000020 /* (de)allocate fqid */

/* Flags to qman_destroy_fq() */
#define QMAN_FQ_DESTROY_PARKED       0x00000001 /* FQ can be parked or OOS */

/* Flags from qman_fq_state() */
#define QMAN_FQ_STATE_CHANGING       0x80000000 /* 'state' is changing */
#define QMAN_FQ_STATE_NE             0x40000000 /* retired FQ isn't empty */
#define QMAN_FQ_STATE_ORL            0x20000000 /* retired FQ has ORL */
#define QMAN_FQ_STATE_BLOCKOOS       0xe0000000 /* if any are set, no OOS */
#define QMAN_FQ_STATE_CGR_EN         0x10000000 /* CGR enabled */

/* Flags to qman_init_fq() */
#define QMAN_INITFQ_FLAG_SCHED       0x00000001 /* schedule rather than park */
#define QMAN_INITFQ_FLAG_NULL        0x00000002 /* zero 'contextB', no demux */
#define QMAN_INITFQ_FLAG_LOCAL       0x00000004 /* set dest portal */

/* Flags to qman_volatile_dequeue() */
#define QMAN_VOLATILE_FLAG_WAIT      0x00000001 /* wait if VDQCR is in use */
#define QMAN_VOLATILE_FLAG_WAIT_INT  0x00000002 /* if wait, interruptible? */
#define QMAN_VOLATILE_FLAG_FINISH    0x00000004 /* wait till VDQCR completes */

/* Flags to qman_enqueue(). NB, the strange numbering is to align with hardware,
 * bit-wise. (NB: the PME API is sensitive to these precise numberings too, so
 * any change here should be audited in PME.) */
#define QMAN_ENQUEUE_FLAG_WAIT       0x00010000 /* wait if EQCR is full */
#define QMAN_ENQUEUE_FLAG_WAIT_INT   0x00020000 /* if wait, interruptible? */
#define QMAN_ENQUEUE_FLAG_WAIT_SYNC  0x00040000 /* if wait, until consumed? */
#define QMAN_ENQUEUE_FLAG_WATCH_CGR  0x00080000 /* watch congestion state */
#define QMAN_ENQUEUE_FLAG_INTERRUPT  0x00000004 /* on command consumption */
#define QMAN_ENQUEUE_FLAG_DCA        0x00008000 /* perform enqueue-DCA */
#define QMAN_ENQUEUE_FLAG_DCA_PARK   0x00004000 /* If DCA, requests park */
#define QMAN_ENQUEUE_FLAG_DCA_PTR(p)		/* If DCA, p is DQRR entry */ \
		(((u32)(p) << 2) & 0x00000f00)
#define QMAN_ENQUEUE_FLAG_C_GREEN    0x00000000 /* choose one C_*** flag */
#define QMAN_ENQUEUE_FLAG_C_YELLOW   0x00000008
#define QMAN_ENQUEUE_FLAG_C_RED      0x00000010
#define QMAN_ENQUEUE_FLAG_C_OVERRIDE 0x00000018
/* For the ORP-specific qman_enqueue_orp() variant;
 * - this flag indicates "Not Last In Sequence", ie. all but the final fragment
 *   of a frame. */
#define QMAN_ENQUEUE_FLAG_NLIS       0x01000000
/* - this flag performs no enqueue but fills in an ORP sequence number that
 *   would otherwise block it (eg. if a frame has been dropped). */
#define QMAN_ENQUEUE_FLAG_HOLE       0x02000000
/* - this flag performs no enqueue but advances NESN to the given sequence
 *   number. */
#define QMAN_ENQUEUE_FLAG_NESN       0x04000000

	/* Portal Management */
	/* ----------------- */
/**
 * qman_get_null_cb - get callbacks currently used for "null" frame queues
 *
 * Copies the callbacks used for the affine portal of the current cpu.
 */
void qman_get_null_cb(struct qman_fq_cb *null_cb);

/**
 * qman_set_null_cb - set callbacks to use for "null" frame queues
 *
 * Sets the callbacks to use for the affine portal of the current cpu, whenever
 * a DQRR or MR entry refers to a "null" FQ object. (Eg. zero-conf messaging.)
 */
void qman_set_null_cb(const struct qman_fq_cb *null_cb);

/**
 * qman_poll - Runs portal updates not triggered by interrupts
 *
 * Dispatcher logic on a cpu can use this to trigger any maintenance of the
 * affine portal. There are two classes of portal processing in question;
 * fast-path (which involves demuxing dequeue ring (DQRR) entries and tracking
 * enqueue ring (EQCR) consumption), and slow-path (which involves EQCR
 * thresholds, congestion state changes, etc). The driver is configured to use
 * interrupts for either (a) all processing, (b) only slow-path processing, or
 * (c) no processing. This function does whatever processing is not triggered by
 * interrupts.
 */
#ifdef CONFIG_FSL_QMAN_HAVE_POLL
void qman_poll(void);
#else
#define qman_poll()	do { ; } while (0)
#endif

/**
 * qman_disable_portal - Cease processing DQRR and MR for a s/w portal
 *
 * Disables DQRR and MR processing of the portal. Portal disabling is
 * reference-counted, so qman_enable_portal() must be called as many times as
 * qman_disable_portal() to truly re-enable the portal.
 */
void qman_disable_portal(void);

/**
 * qman_enable_portal - Commence processing DQRR and MR for a s/w portal
 *
 * Enables DQRR and MR processing of the portal. Portal disabling is
 * reference-counted, so qman_enable_portal() must be called as many times as
 * qman_disable_portal() to truly re-enable the portal.
 */
void qman_enable_portal(void);

/**
 * qman_static_dequeue_add - Add pool channels to the portal SDQCR
 * @pools: bit-mask of pool channels, using QM_SDQCR_CHANNELS_POOL(n)
 *
 * Adds a set of pool channels to the portal's static dequeue command register
 * (SDQCR). The requested pools are limited to those the portal has dequeue
 * access to.
 */
void qman_static_dequeue_add(u32 pools);

/**
 * qman_static_dequeue_del - Remove pool channels from the portal SDQCR
 * @pools: bit-mask of pool channels, using QM_SDQCR_CHANNELS_POOL(n)
 *
 * Removes a set of pool channels from the portal's static dequeue command
 * register (SDQCR). The requested pools are limited to those the portal has
 * dequeue access to.
 */
void qman_static_dequeue_del(u32 pools);

/**
 * qman_static_dequeue_get - return the portal's current SDQCR
 *
 * Returns the portal's current static dequeue command register (SDQCR). The
 * entire register is returned, so if only the currently-enabled pool channels
 * are desired, mask the return value with QM_SDQCR_CHANNELS_POOL_MASK.
 */
u32 qman_static_dequeue_get(void);

/**
 * qman_dca - Perform a Discrete Consumption Acknowledgement
 * @p: the managed portal whose DQRR is targeted (and is in DCA mode)
 * @dq: the DQRR entry to be consumed
 * @park_request: indicates whether the held-active @fq should be parked
 *
 * Only allowed in DCA-mode portals, for DQRR entries whose handler callback had
 * previously returned 'qman_cb_dqrr_defer'. NB, as with the other APIs, this
 * does not take a 'portal' argument but implies the core affine portal from the
 * cpu that is currently executing the function. For reasons of locking, this
 * function must be called from the same CPU as that which processed the DQRR
 * entry in the first place.
 */
void qman_dca(struct qm_dqrr_entry *dq, int park_request);

	/* FQ management */
	/* ------------- */
/**
 * qman_create_fq - Allocates a FQ
 * @fqid: the index of the FQD to encapsulate, must be "Out of Service"
 * @flags: bit-mask of QMAN_FQ_FLAG_*** options
 * @fq: memory for storing the 'fq', with callbacks filled in
 *
 * Creates a frame queue object for the given @fqid, unless the
 * QMAN_FQ_FLAG_DYNAMIC_FQID flag is set in @flags, in which case a FQID is
 * dynamically allocated (or the function fails if none are available). Once
 * created, the caller should not touch the memory at 'fq' except as extended to
 * adjacent memory for user-defined fields (see the definition of "struct
 * qman_fq" for more info). NO_MODIFY is only intended for enqueuing to
 * pre-existing frame-queues that aren't to be otherwise interfered with, it
 * prevents all other modifications to the frame queue. The TO_DCPORTAL flag
 * causes the driver to honour any contextB modifications requested in the
 * qm_init_fq() API, as this indicates the frame queue will be consumed by a
 * direct-connect portal (PME, CAAM, or Fman). When frame queues are consumed by
 * software portals, the contextB field is controlled by the driver and can't be
 * modified by the caller. If the RECOVERY flag is specified, management
 * commands will be used on portal @p to query state for frame queue @fqid and
 * construct a frame queue object based on that, rather than assuming/requiring
 * that it be Out of Service.
 */
int qman_create_fq(u32 fqid, u32 flags, struct qman_fq *fq);

/**
 * qman_destroy_fq - Deallocates a FQ
 * @fq: the frame queue object to release
 * @flags: bit-mask of QMAN_FQ_FREE_*** options
 *
 * The memory for this frame queue object ('fq' provided in qman_create_fq()) is
 * not deallocated but the caller regains ownership, to do with as desired. The
 * FQ must be in the 'out-of-service' state unless the QMAN_FQ_FREE_PARKED flag
 * is specified, in which case it may also be in the 'parked' state.
 */
void qman_destroy_fq(struct qman_fq *fq, u32 flags);

/**
 * qman_fq_fqid - Queries the frame queue ID of a FQ object
 * @fq: the frame queue object to query
 */
u32 qman_fq_fqid(struct qman_fq *fq);

/**
 * qman_fq_state - Queries the state of a FQ object
 * @fq: the frame queue object to query
 * @state: pointer to state enum to return the FQ scheduling state
 * @flags: pointer to state flags to receive QMAN_FQ_STATE_*** bitmask
 *
 * Queries the state of the FQ object, without performing any h/w commands.
 * This captures the state, as seen by the driver, at the time the function
 * executes.
 */
void qman_fq_state(struct qman_fq *fq, enum qman_fq_state *state, u32 *flags);

/**
 * qman_init_fq - Initialises FQ fields, leaves the FQ "parked" or "scheduled"
 * @fq: the frame queue object to modify, must be 'parked' or new.
 * @flags: bit-mask of QMAN_INITFQ_FLAG_*** options
 * @opts: the FQ-modification settings, as defined in the low-level API
 *
 * The @opts parameter comes from the low-level portal API. Select
 * QMAN_INITFQ_FLAG_SCHED in @flags to cause the frame queue to be scheduled
 * rather than parked. Select QMAN_INITFQ_FLAG_NULL in @flags to configure a
 * frame queue that will not demux to a 'struct qman_fq' object when dequeued
 * frames or messages arrive at a software portal, but which will instead
 * trigger the portal's 'null_cb' callbacks (see qman_create_portal()). NB,
 * @opts can be NULL.
 *
 * Note that some fields and options within @opts may be ignored or overwritten
 * by the driver;
 * 1. the 'count' and 'fqid' fields are always ignored (this operation only
 * affects one frame queue: @fq).
 * 2. the QM_INITFQ_WE_CONTEXTB option of the 'we_mask' field and the associated
 * 'fqd' structure's 'context_b' field are sometimes overwritten;
 *   - if @flags contains QMAN_INITFQ_FLAG_NULL, then context_b is initialised
 *     to zero by the driver,
 *   - if @fq was not created with QMAN_FQ_FLAG_TO_DCPORTAL, then context_b is
 *     initialised to a value used by the driver for demux.
 *   - if context_b is initialised for demux, so is context_a in case stashing
 *     is requested (see item 4).
 * (So caller control of context_b is only possible for TO_DCPORTAL frame queue
 * objects.)
 * 3. if @flags contains QMAN_INITFQ_FLAG_LOCAL, the 'fqd' structure's
 * 'dest::channel' field will be overwritten to match the portal used to issue
 * the command. If the WE_DESTWQ write-enable bit had already been set by the
 * caller, the channel workqueue will be left as-is, otherwise the write-enable
 * bit is set and the workqueue is set to a default of 4. If the "LOCAL" flag
 * isn't set, the destination channel/workqueue fields and the write-enable bit
 * are left as-is.
 * 4. if the driver overwrites context_a/b for demux, then if
 * QM_INITFQ_WE_CONTEXTA is set, the driver will only overwrite
 * context_a.address fields and will leave the stashing fields provided by the
 * user alone, otherwise it will zero out the context_a.stashing fields.
 */
int qman_init_fq(struct qman_fq *fq, u32 flags, struct qm_mcc_initfq *opts);

/**
 * qman_schedule_fq - Schedules a FQ
 * @fq: the frame queue object to schedule, must be 'parked'
 *
 * Schedules the frame queue, which must be Parked, which takes it to
 * Tentatively-Scheduled or Truly-Scheduled depending on its fill-level.
 */
int qman_schedule_fq(struct qman_fq *fq);

/**
 * qman_retire_fq - Retires a FQ
 * @fq: the frame queue object to retire
 * @flags: FQ flags (as per qman_fq_state) if retirement completes immediately
 *
 * Retires the frame queue. This returns zero if it succeeds immediately, +1 if
 * the retirement was started asynchronously, otherwise it returns negative for
 * failure. When this function returns zero, @flags is set to indicate whether
 * the retired FQ is empty and/or whether it has any ORL fragments (to show up
 * as ERNs). Otherwise the corresponding flags will be known when a subsequent
 * FQRN message shows up on the portal's message ring.
 *
 * NB, if the retirement is asynchronous (the FQ was in the Truly Scheduled or
 * Active state), the completion will be via the message ring as a FQRN - but
 * the corresponding callback may occur before this function returns!! Ie. the
 * caller should be prepared to accept the callback as the function is called,
 * not only once it has returned.
 */
int qman_retire_fq(struct qman_fq *fq, u32 *flags);

/**
 * qman_oos_fq - Puts a FQ "out of service"
 * @fq: the frame queue object to be put out-of-service, must be 'retired'
 *
 * The frame queue must be retired and empty, and if any order restoration list
 * was released as ERNs at the time of retirement, they must all be consumed.
 */
int qman_oos_fq(struct qman_fq *fq);

/**
 * qman_query_fq - Queries FQD fields (via h/w query command)
 * @fq: the frame queue object to be queried
 * @fqd: storage for the queried FQD fields
 */
int qman_query_fq(struct qman_fq *fq, struct qm_fqd *fqd);

/**
 * qman_query_fq_np - Queries non-programmable FQD fields
 * @fq: the frame queue object to be queried
 * @np: storage for the queried FQD fields
 */
int qman_query_fq_np(struct qman_fq *fq, struct qm_mcr_queryfq_np *np);

/**
 * qman_volatile_dequeue - Issue a volatile dequeue command
 * @fq: the frame queue object to dequeue from (or NULL)
 * @flags: a bit-mask of QMAN_VOLATILE_FLAG_*** options
 * @vdqcr: bit mask of QM_VDQCR_*** options, as per qm_dqrr_vdqcr_set()
 *
 * Attempts to lock access to the portal's VDQCR volatile dequeue functionality.
 * The function will block and sleep if QMAN_VOLATILE_FLAG_WAIT is specified and
 * the VDQCR is already in use, otherwise returns non-zero for failure. If
 * QMAN_VOLATILE_FLAG_FINISH is specified, the function will only return once
 * the VDQCR command has finished executing (ie. once the callback for the last
 * DQRR entry resulting from the VDQCR command has been called). If @fq is
 * non-NULL, the corresponding FQID will be substituted in to the VDQCR command,
 * otherwise it is assumed that @vdqcr already contains the FQID to dequeue
 * from.
 */
int qman_volatile_dequeue(struct qman_fq *fq, u32 flags, u32 vdqcr);

/**
 * qman_enqueue - Enqueue a frame to a frame queue
 * @fq: the frame queue object to enqueue to
 * @fd: a descriptor of the frame to be enqueued
 * @flags: bit-mask of QMAN_ENQUEUE_FLAG_*** options
 *
 * Fills an entry in the EQCR of portal @qm to enqueue the frame described by
 * @fd. The descriptor details are copied from @fd to the EQCR entry, the 'pid'
 * field is ignored. The return value is non-zero on error, such as ring full
 * (and FLAG_WAIT not specified), congestion avoidance (FLAG_WATCH_CGR
 * specified), etc. If the ring is full and FLAG_WAIT is specified, this
 * function will block. If FLAG_INTERRUPT is set, the EQCI bit of the portal
 * interrupt will assert when Qman consumes the EQCR entry (subject to "status
 * disable", "enable", and "inhibit" registers). If FLAG_DCA is set, Qman will
 * perform an implied "discrete consumption acknowledgement" on the dequeue
 * ring's (DQRR) entry, at the ring index specified by the FLAG_DCA_IDX(x)
 * macro. (As an alternative to issuing explicit DCA actions on DQRR entries,
 * this implicit DCA can delay the release of a "held active" frame queue
 * corresponding to a DQRR entry until Qman consumes the EQCR entry - providing
 * order-preservation semantics in packet-forwarding scenarios.) If FLAG_DCA is
 * set, then FLAG_DCA_PARK can also be set to imply that the DQRR consumption
 * acknowledgement should "park request" the "held active" frame queue. Ie.
 * when the portal eventually releases that frame queue, it will be left in the
 * Parked state rather than Tentatively Scheduled or Truly Scheduled. If the
 * portal is watching congestion groups, the QMAN_ENQUEUE_FLAG_WATCH_CGR flag
 * is requested, and the FQ is a member of a congestion group, then this
 * function returns -EAGAIN if the congestion group is currently congested.
 * Note, this does not eliminate ERNs, as the async interface means we can be
 * sending enqueue commands to an un-congested FQ that becomes congested before
 * the enqueue commands are processed, but it does minimise needless thrashing
 * of an already busy hardware resource by throttling many of the to-be-dropped
 * enqueues "at the source".
 */
int qman_enqueue(struct qman_fq *fq, const struct qm_fd *fd, u32 flags);

/**
 * qman_enqueue_orp - Enqueue a frame to a frame queue using an ORP
 * @fq: the frame queue object to enqueue to
 * @fd: a descriptor of the frame to be enqueued
 * @flags: bit-mask of QMAN_ENQUEUE_FLAG_*** options
 * @orp: the frame queue object used as an order restoration point.
 * @orp_seqnum: the sequence number of this frame in the order restoration path
 *
 * Similar to qman_enqueue(), but with the addition of an Order Restoration
 * Point (@orp) and corresponding sequence number (@orp_seqnum) for this
 * enqueue operation to employ order restoration. Each frame queue object acts
 * as an Order Definition Point (ODP) by providing each frame dequeued from it
 * with an incrementing sequence number, this value is generally ignored unless
 * that sequence of dequeued frames will need order restoration later. Each
 * frame queue object also encapsulates an Order Restoration Point (ORP), which
 * is a re-assembly context for re-ordering frames relative to their sequence
 * numbers as they are enqueued. The ORP does not have to be within the frame
 * queue that receives the enqueued frame, in fact it is usually the frame
 * queue from which the frames were originally dequeued. For the purposes of
 * order restoration, multiple frames (or "fragments") can be enqueued for a
 * single sequence number by setting the QMAN_ENQUEUE_FLAG_NLIS flag for all
 * enqueues except the final fragment of a given sequence number. Ordering
 * between sequence numbers is guaranteed, even if fragments of different
 * sequence numbers are interlaced with one another. Fragments of the same
 * sequence number will retain the order in which they are enqueued. If no
 * enqueue is to performed, QMAN_ENQUEUE_FLAG_HOLE indicates that the given
 * sequence number is to be "skipped" by the ORP logic (eg. if a frame has been
 * dropped from a sequence), or QMAN_ENQUEUE_FLAG_NESN indicates that the given
 * sequence number should become the ORP's "Next Expected Sequence Number".
 *
 * Side note: a frame queue object can be used purely as an ORP, without
 * carrying any frames at all. Care should be taken not to deallocate a frame
 * queue object that is being actively used as an ORP, as a future allocation
 * of the frame queue object may start using the internal ORP before the
 * previous use has finished.
 */
int qman_enqueue_orp(struct qman_fq *fq, const struct qm_fd *fd, u32 flags,
			struct qman_fq *orp, u16 orp_seqnum);

/**
 * qman_alloc_fqid_range - Allocate a contiguous range of FQIDs
 * @result: is set by the API to the base FQID of the allocated range
 * @count: the number of FQIDs required
 * @align: required alignment of the allocated range
 * @partial: non-zero if the API can return fewer than @count FQIDs

 * Returns the number of frame queues allocated, or a negative error code. If
 * @partial is non zero, the allocation request may return a smaller range of
 * FQs than requested (though alignment will be as requested). If @partial is
 * zero, the return value will either be 'count' or negative.
 */
int qman_alloc_fqid_range(u32 *result, u32 count, u32 align, int partial);
static inline int qman_alloc_fqid(u32 *result)
{
	return qman_alloc_fqid_range(result, 1, 0, 0);
}

/**
 * qman_release_fqid_range - Release the specified range of frame queue IDs
 * @fqid: the base FQID of the range to deallocate
 * @count: the number of FQIDs in the range
 *
 * This function can also be used to seed the allocator with ranges of FQIDs
 * that it can subsequently use. Returns zero for success.
 */
void qman_release_fqid_range(u32 fqid, unsigned int count);
static inline void qman_release_fqid(u32 fqid)
{
	qman_release_fqid_range(fqid, 1);
}

	/* Helpers */
	/* ------- */
/**
 * qman_poll_fq_for_init - Check if an FQ has been initialised from OOS
 * @fqid: the FQID that will be initialised by other s/w
 *
 * In many situations, a FQID is provided for communication between s/w
 * entities, and whilst the consumer is responsible for initialising and
 * scheduling the FQ, the producer(s) generally create a wrapper FQ object using
 * and only call qman_enqueue() (no FQ initialisation, scheduling, etc). Ie;
 *     qman_create_fq(..., QMAN_FQ_FLAG_NO_MODIFY, ...);
 * However, data can not be enqueued to the FQ until it is initialised out of
 * the OOS state - this function polls for that condition. It is particularly
 * useful for users of IPC functions - each endpoint's Rx FQ is the other
 * endpoint's Tx FQ, so each side can initialise and schedule their Rx FQ object
 * and then use this API on the (NO_MODIFY) Tx FQ object in order to
 * synchronise. The function returns zero for success, +1 if the FQ is still in
 * the OOS state, or negative if there was an error.
 */
static inline int qman_poll_fq_for_init(struct qman_fq *fq)
{
	struct qm_mcr_queryfq_np np;
	int err;
	err = qman_query_fq_np(fq, &np);
	if (err)
		return err;
	if ((np.state & QM_MCR_NP_STATE_MASK) == QM_MCR_NP_STATE_OOS)
		return 1;
	return 0;
}

#endif /* FSL_QMAN_H */

