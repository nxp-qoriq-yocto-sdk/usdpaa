/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

#ifndef __PPAC_H
#define	__PPAC_H

/* Note about acronyms:
 *   PPAC == Packet Processing Application Core
 *   PPAM == Packet Processing Application Module
 */

#include <usdpaa/of.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/dma_mem.h>
#include <usdpaa/usdpaa_netcfg.h>

#include <argp.h>

/* If defined, be lippy about everything */
#undef PPAC_TRACE
#ifdef ENABLE_TRACE
#define PPAC_TRACE
#endif

/* Application configuration */
#define PPAC_TX_FQS_10G		2
#define PPAC_TX_FQS_1G		2
#define PPAC_PRIO_2DROP		3	/* Error/default/etc */
#define PPAC_PRIO_2FWD		4	/* rx-hash */
#define PPAC_PRIO_2TX		4	/* Consumed by Fman */
#define PPAC_STASH_ANNOTATION_CL 0	/* Overridable by PPAM */
#define PPAC_STASH_DATA_CL	1	/* Overridable by PPAM */
#define PPAC_STASH_CONTEXT_CL	0	/* Overridable by PPAM */
#define PPAC_CGR_RX_PERFQ_THRESH 32
#define PPAC_CGR_TX_PERFQ_THRESH 64
#define PPAC_BACKOFF_CYCLES	512
#define PPAC_ORP_WINDOW_SIZE	3	/* 0->32, 1->64, 2->128, ... 7->4096 */
#define PPAC_ORP_AUTO_ADVANCE	0	/* boolean */
#define PPAC_ORP_ACCEPT_LATE	0	/* 0->no, 3->yes (for 1 & 2->see RM) */

/* Application options */
#undef PPAC_2FWD_HOLDACTIVE		/* Process each FQ on one portal at a time */
#undef PPAC_2FWD_ORDER_PRESERVATION	/* HOLDACTIVE + enqueue-DCAs */
#undef PPAC_2FWD_ORDER_RESTORATION	/* Use ORP */
#define PPAC_2FWD_AVOIDBLOCK		/* No full-DQRR blocking of FQs */
#define PPAC_2FWD_RX_10G_PREFERINCACHE	/* Keep 10G rx FQDs in-cache even when empty */
#define PPAC_2FWD_RX_1G_PREFERINCACHE	/* Keep 1G rx FQDs in-cache even when empty */
#define PPAC_2FWD_TX_PREFERINCACHE	/* Keep tx FQDs in-cache even when empty */
#undef PPAC_2FWD_TX_FORCESFDR		/* Priority allocation of SFDRs to egress */
#define PPAC_DEPLETION			/* Trace depletion entry/exit */
#undef PPAC_CGR				/* Track rx and tx fill-levels via CGR */
#undef PPAC_CSTD 			/* CGR tail-drop */
#undef PPAC_CSCN 			/* Log CGR state-change notifications */
#define PPAC_IDLE_IRQ			/* Block in interrupt-mode when idle */

#if defined(PPAC_2FWD_HOLDACTIVE) && defined(PPAC_2FWD_AVOIDBLOCK)
#error "HOLDACTIVE and AVOIDBLOCK options are mutually exclusive"
#endif

#if defined(PPAC_2FWD_ORDER_PRESERVATION) && !defined(PPAC_2FWD_HOLDACTIVE)
#error "ORDER_PRESERVATION requires HOLDACTIVE"
#endif

/**********/
/* macros */
/**********/

#ifdef PPAC_TRACE
#define TRACE		printf
#else
#define TRACE(x...)	do { ; } while(0)
#endif

struct ppam_arguments;
struct ppac_arguments
{
	const char *fm_cfg;
	const char *fm_pcd;
	int first, last;
	int noninteractive;
	struct ppam_arguments *ppam_args;
};

extern const struct argp ppam_argp;
extern struct ppam_arguments ppam_args;
extern const char ppam_doc[];
extern struct ppac_arguments ppac_args;

typedef int (*cli_handle_t)(int argc, char *argv[]);
struct cli_table_entry
{
	const char *cmd;
	const cli_handle_t handle;
};
#define cli_cmd(cmd, handle)					\
	const struct cli_table_entry cli_table_entry_##cmd	\
	__attribute__((used, section(".data.cli_table")))	\
	= {__stringify(cmd), handle}

extern const struct cli_table_entry cli_table_start[], cli_table_end[];

#define foreach_cli_table_entry(cli_cmd)	\
	for (cli_cmd = cli_table_start; cli_cmd < cli_table_end; cli_cmd++)

/*********************************/
/* Net interface data structures */
/*********************************/

/* Each Fman i/face has one of these */
struct ppac_if;

/* PPAM global startup/teardown */
int ppam_init(void);
void ppam_finish(void);

/***************/
/* Global data */
/***************/

/* Configuration */
extern struct usdpaa_netcfg_info *netcfg;
/* Default paths to configuration files - these are determined from the build,
 * but can be overriden at run-time using "DEF_PCD_PATH" and "DEF_CFG_PATH"
 * environment variables. Also, PPAC defines weakly-linked versions of these
 * variables, so a PPAM can declare its own and they will take precedence. */
extern const char ppam_pcd_path[];
extern const char ppam_cfg_path[];

/* Default CLI prompt. PPAC defines a weakly-linked version of this, but a PPAM
 * can declare its own and it will take precedence. */
extern const char ppam_prompt[];

/* We want a trivial mapping from bpid->pool, so just have a 64-wide array of
 * pointers, most of which are NULL. */
extern struct bman_pool *pool[64];

/* The interfaces in this list are allocated from dma_mem (stashing==DMA) */
extern struct list_head ifs;

/* The forwarding logic uses a per-cpu FQ object for handling enqueues (and
 * ERNs), irrespective of the destination FQID. In this way, cache-locality is
 * more assured, and any ERNs that do occur will show up on the same CPUs they
 * were enqueued from. This works because ERN messages contain the FQID of the
 * original enqueue operation, so in principle any demux that's required by the
 * ERN callback can be based on that. Ie. the FQID set within "local_fq" is from
 * whatever the last executed enqueue was, the ERN handler can ignore it. */
extern __thread struct qman_fq local_fq;

/* These are backdoors from PPAC to itself in order to support order
 * preservation/restoration. Packet-handling goes from a PPAC handler to a PPAM
 * handler which in turn calls PPAC APIs to perform the required packet
 * operations. Call stack is PPAC->PPAM->PPAC, with the possibility for inlining
 * to collapse it all down. The backdoors allow the packet operations to know
 * what was known back up in the PPAC handler but not passed down through the
 * call stack, like what DQRR entry was being processed (to encode enqueue-DCAs,
 * determine ORP sequeuence numbers, etc), what ORPID should be used (if any)
 * when dropping or forwarding the current frame, etc. */
#if defined(PPAC_2FWD_ORDER_PRESERVATION) || \
	defined(PPAC_2FWD_ORDER_RESTORATION)
extern __thread const struct qm_dqrr_entry *local_dqrr;
#endif
#ifdef PPAC_2FWD_ORDER_RESTORATION
extern __thread u32 local_orp_id;
#endif

#ifdef PPAC_CGR
extern struct qman_cgr cgr_tx;
#endif

/********************/
/* Common functions */
/********************/

/* Rx handling either leads to a forward (qman enqueue) or a drop (bman
 * release). In either case, we can't "block" and we don't want to defer until
 * outside the callback, because we still have to pushback somehow and as we're
 * a run-to-completion app, we don't have anything else to do than simply retry.
 * So ... we retry non-blocking enqueues/releases until they succeed, which
 * implicitly pushes back on dequeue handling.
 *
 * As for how DQRR entries are consumed ... if ORDER_PRESERVATION is off, then
 * DQRR entries are consumed as soon as the PPAM handler returns (the dropping
 * or forwarding of the frame has already occurred within the handler). But if
 * it is enabled, then forwarding of the frame implies that the DQRR entry
 * should be consumed by h/w when processing the enqueue! So (a) the
 * send_frame() logic needs to encode this, and (b) PPAC needs capture this once
 * the handler returns. "local_dqrr" provides this backdoor between PPAC's DQRR
 * handling and its send_frame() implementation as called from PPAM.
 *
 * If ORDER_RESTORATION is on, then drops and enqueues functions have other
 * obligations too. The drop function needs to perform an enqueue "HOLE" to fill
 * in the sequence number of the packet being dropped, whereas a forwarding
 * action needs to perform an ORP-enabled enqueue with the sequence number. In
 * both cases, the sequence number is extracted from the same "local_dqrr"
 * backdoor as used for ORDER_PRESERVATION.
 *
 * Due to these considerations, the interface works in the following way. The
 * PPAM handler must call either ppac_drop_frame() or ppac_send_frame() exactly
 * once before returning. If it wishes to enqueue multiple frames from the same
 * handler (eg. multicasting) it should use ppac_send_secondary_frame() for all
 * additional frames. If order-preservation is enabled, then the DQRR entry of
 * the received frame will be considered consumed once the enqueue generated by
 * ppac_send_frame() is processed by hardware. Likewise if order-restoration is
 * enabled, then order will be restored for the enqueue generated by
 * ppac_send_frame().
 */

static inline void ppac_drop_frame(const struct qm_fd *fd)
{
	struct bm_buffer buf;
	int ret;
#ifdef PPAC_2FWD_ORDER_PRESERVATION
	local_fq.fqid = local_orp_id;
	/* The "ORP object" passed to qman_enqueue_orp() is only used to extract
	 * the ORPID, so declare a temporary object to provide that. */
	struct qman_fq tmp_orp = {
		.fqid = local_orp_id
	};
#endif

	BUG_ON(fd->format != qm_fd_contig);
	bm_buffer_set64(&buf, qm_fd_addr(fd));
retry:
	ret = bman_release(pool[fd->bpid], &buf, 1, 0);
	if (ret) {
		cpu_spin(PPAC_BACKOFF_CYCLES);
		goto retry;
	}
	TRACE("drop: bpid %d <-- 0x%llx\n", fd->bpid, qm_fd_addr(fd));
#ifdef PPAC_2FWD_ORDER_PRESERVATION
	/* Perform a "HOLE" enqueue so that the ORP doesn't wait for the
	 * sequence number that we're dropping. */
retry_orp:
	ret = qman_enqueue_orp(&local_fq, fd, QMAN_ENQUEUE_FLAG_HOLE, &tmp_orp,
				local_dqrr->seqnum);
		cpu_spin(PPAC_BACKOFF_CYCLES);
		goto retry_orp;
	}
	TRACE("drop: fqid %d <-- 0x%x (HOLE)\n",
		local_fq.fqid, local_dqrr->seqnum);
#endif
}

#ifdef PPAC_2FWD_ORDER_PRESERVATION
#define EQ_FLAGS() QMAN_ENQUEUE_FLAG_DCA | QMAN_ENQUEUE_FLAG_DCA_PTR(local_dqrr)
#else
#define EQ_FLAGS() 0
#endif
static inline void ppac_send_frame(u32 fqid, const struct qm_fd *fd)
{
	int ret;
	local_fq.fqid = fqid;
retry:
#ifdef PPAC_2FWD_ORDER_RESTORATION
	if (local_orp_id) {
		/* The "ORP object" passed to qman_enqueue_orp() is only used to
		 * extract the ORPID, so declare a temporary object to provide
		 * that. */
		struct qman_fq tmp_orp = {
			.fqid = local_orp_id
		};
		ret = qman_enqueue_orp(&local_fq, fd, EQ_FLAGS(), &tmp_orp,
					local_dqrr->seqnum);
		TRACE("send ORP: fqid %d, orpid %d, seqnum %d <-- 0x%llx (%d)\n",
			local_fq.fqid, tmp_orp.fqid, local_dqrr->seqnum,
			qm_fd_addr(fd), ret);
	} else
#endif
	{
	ret = qman_enqueue(&local_fq, fd, EQ_FLAGS());
	TRACE("send: fqid %d <-- 0x%llx (%d)\n",
		local_fq.fqid, qm_fd_addr(fd), ret);
	}
	if (ret) {
		cpu_spin(PPAC_BACKOFF_CYCLES);
		goto retry;
	}
#ifdef PPAC_2FWD_ORDER_PRESERVATION
	/* NULLing this ensures the driver won't consume the ring entry
	 * explicitly (ie. PPAC's callback will return qman_cb_dqrr_defer). */
	local_dqrr = NULL;
#endif
}

static inline void ppac_send_secondary_frame(u32 fqid, const struct qm_fd *fd)
{
	int ret;
	local_fq.fqid = fqid;
retry:
	ret = qman_enqueue(&local_fq, fd, 0);
	if (ret) {
		cpu_spin(PPAC_BACKOFF_CYCLES);
		goto retry;
	}
}

void teardown_fq(struct qman_fq *fq);

/*******************/
/* Packet handling */
/*******************/

void ppac_fq_nonpcd_init(struct qman_fq *fq, u32 fqid,
			 enum qm_channel channel,
			 const struct qm_fqd_stashing *stashing,
			 qman_cb_dqrr cb);

void ppac_fq_pcd_init(struct qman_fq *fq, u32 fqid,
		      enum qm_channel channel,
		      const struct qm_fqd_stashing *stashing,
		      int prefer_in_cache);

#ifdef PPAC_2FWD_ORDER_RESTORATION
void ppac_orp_init(u32 *orp_id);
#endif

void ppac_fq_tx_init(struct qman_fq *fq,
		     enum qm_channel channel);

enum qman_cb_dqrr_result
cb_dqrr_rx_hash(struct qman_portal *qm __always_unused,
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr);

enum qm_channel get_rxc(void);

int lazy_init_bpool(u8 bpid);

int ppac_if_init(unsigned idx);
void ppac_if_enable_rx(const struct ppac_if *i);
void ppac_if_disable_rx(const struct ppac_if *i);
void ppac_if_finish(struct ppac_if *i);

#endif	/*  __PPAC_H */
