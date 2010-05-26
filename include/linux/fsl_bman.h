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

#ifndef FSL_BMAN_H
#define FSL_BMAN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Last updated for v00.79 of the BG */

/* Represents s/w corenet portal mapped data structures */
struct bm_rcr_entry;	/* RCR (Release Command Ring) entries */
struct bm_mc_command;	/* MC (Management Command) command */
struct bm_mc_result;	/* MC result */

/* This wrapper represents a bit-array for the depletion state of the 64 Bman
 * buffer pools. */
struct bman_depletion {
	u32 __state[2];
};
#define BMAN_DEPLETION_EMPTY \
	(struct bman_depletion){ { 0x00000000, 0x00000000 } }
#define BMAN_DEPLETION_FULL \
	(struct bman_depletion){ { 0xffffffff, 0xffffffff } }
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
struct bm_mcc_acquire {
	u8 bpid;
	u8 __reserved1[62];
} __packed;
struct bm_mcc_query {
	u8 __reserved2[63];
} __packed;
struct bm_mc_command {
	u8 __dont_write_directly__verb;
	union {
		struct bm_mcc_acquire acquire;
		struct bm_mcc_query query;
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
	/* index of the buffer pool to encapsulate (0-63), ignored if
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

#ifdef __cplusplus
}
#endif

#endif /* FSL_BMAN_H */
