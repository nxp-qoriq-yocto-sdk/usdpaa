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

#ifndef FSL_BMAN_H
#define FSL_BMAN_H

/* Last updated for v00.79 of the BG */

/*************************************************/
/*   BMan s/w corenet portal, low-level i/face   */
/*************************************************/

/* Portal constants */
#define BM_RCR_SIZE		8

/* Hardware constants */
enum bm_isr_reg {
	bm_isr_status = 0,
	bm_isr_enable = 1,
	bm_isr_disable = 2,
	bm_isr_inhibit = 3
};

/* Represents s/w corenet portal mapped data structures */
struct bm_rcr_entry;	/* RCR (Release Command Ring) entries */
struct bm_mc_command;	/* MC (Management Command) command */
struct bm_mc_result;	/* MC result */

/* This type represents a s/w corenet portal space, and is used for creating the
 * portal objects within it (RCR, etc) */
struct bm_portal;

/* This wrapper represents a bit-array for the depletion state of the 64 Bman
 * buffer pools. */
struct bman_depletion {
	u32 __state[2];
};
#define __bmdep_word(x) ((x) >> 5)
#define __bmdep_shift(x) ((x) & 0x1f)
#define __bmdep_bit(x) (0x80000000 >> __bmdep_shift(x))
static inline void bman_depletion_init(struct bman_depletion *c)
{
	c->__state[0] = c->__state[1] = 0;
}
static inline void bman_depletion_fill(struct bman_depletion *c)
{
	c->__state[0] = c->__state[1] = ~0;
}
static inline int bman_depletion_get(const struct bman_depletion *c, u8 bpid)
{
	return c->__state[__bmdep_word(bpid)] & __bmdep_bit(bpid);
}
static inline void bman_depletion_set(struct bman_depletion *c, u8 bpid)
{
	c->__state[__bmdep_word(bpid)] |= __bmdep_bit(bpid);
}
static inline void bman_depletion_unset(struct bman_depletion *c, u8 bpid)
{
	c->__state[__bmdep_word(bpid)] &= ~__bmdep_bit(bpid);
}

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


/* ------------------------------ */
/* --- Portal enumeration API --- */

/* Obtain the number of portals available */
u8 bm_portal_num(void);

/* Obtain a portal handle */
struct bm_portal *bm_portal_get(u8 idx);
const struct bm_portal_config *bm_portal_config(const struct bm_portal *portal);


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

/* Don't use these, use the wrappers above*/
u32 __bm_isr_read(struct bm_portal *portal, enum bm_isr_reg n);
void __bm_isr_write(struct bm_portal *portal, enum bm_isr_reg n, u32 val);


/* ------------------------------------------------------- */
/* --- Bman data structures (and associated constants) --- */

/* Code-reduction, define a wrapper for 48-bit buffers. In cases where a buffer
 * pool id specific to this buffer is needed (BM_RCR_VERB_CMD_BPID_MULTI,
 * BM_MCC_VERB_ACQUIRE), the 'bpid' field is used. */
struct bm_buffer {
	u8 __reserved1;
	u8 bpid;
	u16 hi;	/* High 16-bits of 48-bit address */
	u32 lo;	/* Low 32-bits of 48-bit address */
} __packed;

/* See 1.5.3.5.4: "Release Command" */
struct bm_rcr_entry {
	union {
		struct {
			u8 __dont_write_directly__verb;
			u8 bpid; /* used with BM_RCR_VERB_CMD_BPID_SINGLE */
			u8 __reserved1[62];
		};
		struct bm_buffer bufs[8];
	};
} __packed;
#define BM_RCR_VERB_VBIT		0x80
#define BM_RCR_VERB_CMD_MASK		0x70	/* one of two values; */
#define BM_RCR_VERB_CMD_BPID_SINGLE	0x20
#define BM_RCR_VERB_CMD_BPID_MULTI	0x30
#define BM_RCR_VERB_BUFCOUNT_MASK	0x0f	/* values 1..8 */

/* See 1.5.3.1: "Acquire Command" */
/* See 1.5.3.2: "Query Command" */
struct bm_mc_command {
	u8 __dont_write_directly__verb;
	union {
		struct bm_mcc_acquire {
			u8 bpid;
			u8 __reserved1[62];
		} __packed acquire;
		struct bm_mcc_query {
			u8 __reserved1[63];
		} __packed query;
	};
} __packed;
#define BM_MCC_VERB_VBIT		0x80
#define BM_MCC_VERB_CMD_MASK		0x70	/* where the verb contains; */
#define BM_MCC_VERB_CMD_ACQUIRE		0x10
#define BM_MCC_VERB_CMD_QUERY		0x40
#define BM_MCC_VERB_ACQUIRE_BUFCOUNT	0x0f	/* values 1..8 go here */

/* See 1.5.3.3: "Acquire Reponse" */
/* See 1.5.3.4: "Query Reponse" */
struct bm_mc_result {
	union {
		struct {
			u8 verb;
			u8 __reserved1[63];
		};
		union {
			struct {
				u8 __reserved1;
				u8 bpid;
				u8 __reserved2[62];
			};
			struct bm_buffer bufs[8];
		} acquire;
		struct {
			u8 __reserved1[32];
			/* "availability state" and "depletion state" */
			struct {
				u8 __reserved1[8];
				/* Access using bman_depletion_***() */
				struct bman_depletion state;
			} as, ds;
		} query;
	};
} __packed;
#define BM_MCR_VERB_VBIT		0x80
#define BM_MCR_VERB_CMD_MASK		BM_MCC_VERB_CMD_MASK
#define BM_MCR_VERB_CMD_ACQUIRE		BM_MCC_VERB_CMD_ACQUIRE
#define BM_MCR_VERB_CMD_QUERY		BM_MCC_VERB_CMD_QUERY
#define BM_MCR_VERB_CMD_ERR_INVALID	0x60
#define BM_MCR_VERB_CMD_ERR_ECC		0x70
#define BM_MCR_VERB_ACQUIRE_BUFCOUNT	BM_MCC_VERB_ACQUIRE_BUFCOUNT /* 0..8 */
/* Determine the "availability state" of pool 'p' from a query result 'r' */
#define BM_MCR_QUERY_AVAILABILITY(r,p) bman_depletion_get(&r->query.as.state,p)
/* Determine the "depletion state" of pool 'p' from a query result 'r' */
#define BM_MCR_QUERY_DEPLETION(r,p) bman_depletion_get(&r->query.ds.state,p)

/*******************************************************************/
/* Managed (aka "shared" or "mux/demux") portal, high-level i/face */
/*******************************************************************/

	/* Portal and Buffer Pools */
	/* ----------------------- */
/* Represents a managed portal */
struct bman_portal;

/* This object type represents Bman buffer pools. */
struct bman_pool;

/* This callback type is used when handling pool depletion entry/exit. The
 * 'cb_ctx' value is the opaque value associated with the pool object in
 * bman_new_pool(). 'depleted' is non-zero on depletion-entry, and zero on
 * depletion-exit. */
typedef void (*bman_cb_depletion)(struct bman_portal *bm,
			struct bman_pool *pool, void *cb_ctx, int depleted);

/* This struct specifies parameters for a bman_pool object. */
struct bman_pool_params {
	/* index of the buffer pool to encapsulate (0-63), overwritten if
	 * BMAN_POOL_FLAG_DYNAMIC_BPID is set. */
	u32 bpid;
	/* bit-mask of BMAN_POOL_FLAG_*** options */
	u32 flags;
	/* depletion-entry/exit callback, if BMAN_POOL_FLAG_DEPLETION is set */
	bman_cb_depletion cb;
	/* opaque user value passed as a parameter to 'cb' */
	void *cb_ctx;
	/* depletion-entry/exit thresholds, if BMAN_POOL_FLAG_THRESH is set. NB:
	 * this is only allowed if BMAN_POOL_FLAG_DYNAMIC_BPID is used *and*
	 * when run in the control plane (which controls Bman CCSR). This array
	 * matches the definition of bm_pool_set(). */
	u32 thresholds[4];
};

/* Flags to bman_new_pool() */
#define BMAN_POOL_FLAG_NO_RELEASE    0x00000001 /* can't release to pool */
#define BMAN_POOL_FLAG_ONLY_RELEASE  0x00000002 /* can only release to pool */
#define BMAN_POOL_FLAG_DEPLETION     0x00000004 /* track depletion entry/exit */
#define BMAN_POOL_FLAG_DYNAMIC_BPID  0x00000008 /* (de)allocate bpid */
#define BMAN_POOL_FLAG_THRESH        0x00000010 /* set depletion thresholds */
#define BMAN_POOL_FLAG_STOCKPILE     0x00000020 /* stockpile to reduce hw ops */

/* Flags to bman_release() */
#define BMAN_RELEASE_FLAG_WAIT       0x00000001 /* wait if RCR is full */
#define BMAN_RELEASE_FLAG_WAIT_INT   0x00000002 /* if we wait, interruptible? */
#define BMAN_RELEASE_FLAG_WAIT_SYNC  0x00000004 /* if wait, until consumed? */
#define BMAN_RELEASE_FLAG_NOW        0x00000008 /* issue immediate release */

/* Flags to bman_acquire() */
#define BMAN_ACQUIRE_FLAG_STOCKPILE  0x00000001 /* no hw op, stockpile only */

	/* Portal Management */
	/* ----------------- */
/**
 * bman_poll - Runs portal updates not triggered by interrupts
 *
 * Dispatcher logic on a cpu can use this to trigger any maintenance of the
 * affine portal. There are two classes of portal processing in question;
 * fast-path (which involves tracking release ring (RCR) consumption), and
 * slow-path (which involves RCR thresholds, pool depletion state changes, etc).
 * The driver is configured to use interrupts for either (a) all processing, (b)
 * only slow-path processing, or (c) no processing. This function does whatever
 * processing is not triggered by interrupts.
 */
#ifdef CONFIG_FSL_BMAN_HAVE_POLL
void bman_poll(void);
#else
#define bman_poll()	do { ; } while (0)
#endif


	/* Pool management */
	/* --------------- */
/**
 * bman_new_pool - Allocates a Buffer Pool object
 * @params: parameters specifying the buffer pool ID and behaviour
 *
 * Creates a pool object for the given @params. A portal and the depletion
 * callback field of @params are only used if the BMAN_POOL_FLAG_DEPLETION flag
 * is set. NB, the fields from @params are copied into the new pool object, so
 * the structure provided by the caller can be released or reused after the
 * function returns.
 */
struct bman_pool *bman_new_pool(const struct bman_pool_params *params);

/**
 * bman_free_pool - Deallocates a Buffer Pool object
 * @pool: the pool object to release
 *
 */
void bman_free_pool(struct bman_pool *pool);

/**
 * bman_get_params - Returns a pool object's parameters.
 * @pool: the pool object
 *
 * The returned pointer refers to state within the pool object so must not be
 * modified and can no longer be read once the pool object is destroyed.
 */
const struct bman_pool_params *bman_get_params(const struct bman_pool *pool);

/**
 * bman_release - Release buffer(s) to the buffer pool
 * @pool: the buffer pool object to release to
 * @bufs: an array of buffers to release
 * @num: the number of buffers in @bufs (1-8)
 * @flags: bit-mask of BMAN_RELEASE_FLAG_*** options
 *
 * Adds the given buffers to RCR entries. If the portal @p was created with the
 * "COMPACT" flag, then it will be using a compaction algorithm to improve
 * utilisation of RCR. As such, these buffers may join an existing ring entry
 * and/or it may not be issued right away so as to allow future releases to join
 * the same ring entry. Use the BMAN_RELEASE_FLAG_NOW flag to override this
 * behaviour by committing the RCR entry (or entries) right away. If the RCR
 * ring is full, the function will return -EBUSY unless BMAN_RELEASE_FLAG_WAIT
 * is selected, in which case it will sleep waiting for space to become
 * available in RCR. If the function receives a signal before such time (and
 * BMAN_RELEASE_FLAG_WAIT_INT is set), the function returns -EINTR. Otherwise,
 * it returns zero.
 */
int bman_release(struct bman_pool *pool, const struct bm_buffer *bufs, u8 num,
			u32 flags);

/**
 * bman_acquire - Acquire buffer(s) from a buffer pool
 * @pool: the buffer pool object to acquire from
 * @bufs: array for storing the acquired buffers
 * @num: the number of buffers desired (@bufs is at least this big)
 *
 * Issues an "Acquire" command via the portal's management command interface.
 * The return value will be the number of buffers obtained from the pool, or a
 * negative error code if a h/w error or pool starvation was encountered.
 */
int bman_acquire(struct bman_pool *pool, struct bm_buffer *bufs, u8 num,
			u32 flags);

#endif /* FSL_BMAN_H */
