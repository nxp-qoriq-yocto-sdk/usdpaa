/* Copyright (c) 2014 Freescale Semiconductor, Inc.
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

#ifndef __CAPWAP_CFG_H
#define	__CAPWAP_CFG_H

#include <usdpaa/of.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/dma_mem.h>
#include <usdpaa/usdpaa_netcfg.h>

#include <argp.h>
#include <error.h>
#include <stdbool.h>
#include <capwap_debug.h>

/* Application options */
/* For Network applications, Packet ordering is one of the important QoS parameter.
   TCP and IPSec like scenario are worst impacted if packet goes out of order.
   Hold_Active Enable portal level packet ordering per FQ */
#define CAPWAP_HOLDACTIVE
#undef CAPWAP_ORDER_PRESERVATION	/* HOLDACTIVE + enqueue-DCAs */
#undef CAPWAP_ORDER_RESTORATION		/* Use ORP */
/* For RAW network performance which don't require QoS like packet ordering,
 Enable following setting to avoid full-DQRR blocking of FQs. This setting if
 used along CAPWAP_HOLDACTIVE will be ignored by Qman, thus USDPAA raise error
 if both are enabled simultaneously. Never set AVOIDBLOCK if packet order is
 important*/
#undef CAPWAP_AVOIDBLOCK
/* Trace BP depletion entry/exit, Enable only during debugging to avoid flood
 of prints above ZLT */
#undef CAPWAP_DEPLETION
/* Track rx and tx fill-levels via CGR. Full buffer depletion must be avoid
   to avoid  imbalance between fman port performance due to buffer depletion
   by other FMAN port */
#undef CAPWAP_CGR
/* CGR tail-drop should be set with CGR though for debugging CAPWAP_CGR can be
   set only with CSCN to check congestion point in FMAN */
#undef CAPWAP_CSTD
/* Log CGR state-change notifications. Should only be defined during
 debugging */
#undef CAPWAP_CSCN
#define CAPWAP_IDLE_IRQ		/* Block in interrupt-mode when idle */
#undef CAPWAP_TX_CONFIRM		/* Use Tx confirmation for all transmits */

/* sanity check the application options for basic conflicts */
#if defined(CAPWAP_HOLDACTIVE) && defined(CAPWAP_AVOIDBLOCK)
#error "HOLDACTIVE and AVOIDBLOCK options are mutually exclusive"
#endif
#if defined(CAPWAP_ORDER_PRESERVATION) && !defined(CAPWAP_HOLDACTIVE)
#error "ORDER_PRESERVATION requires HOLDACTIVE"
#endif

/* Application configuration (any modification of these requires an
 * understanding of valid ranges, consequences, etc). */
#define CAPWAP_TX_FQS_10G		2	/* 10G Port Tx FQ count */
#define CAPWAP_TX_FQS_1G		2	/* 1G Port Tx FQ count */
#define CAPWAP_TX_FQS_OFFLINE	2	/* Offline Port Tx FQ count */
#define CAPWAP_PRIORITY_2DROP	3	/* Error/default/etc */
#define CAPWAP_PRIORITY_2FWD	4	/* rx-hash */
#define CAPWAP_PRIORITY_2TX	4	/* Consumed by Fman */
#define CAPWAP_STASH_ANNOTATION_CL 0
#define CAPWAP_STASH_DATA_CL	1
#define CAPWAP_STASH_CONTEXT_CL	0
#define CAPWAP_CGR_RX_PERFQ_THRESH 32
#define CAPWAP_CGR_TX_PERFQ_THRESH 64
#define CAPWAP_BACKOFF_CYCLES	512
#define CAPWAP_ORP_WINDOW_SIZE	7	/* 0->32, 1->64, 2->128, ... 7->4096 */
#define CAPWAP_ORP_AUTO_ADVANCE	1	/* boolean */
#define CAPWAP_ORP_ACCEPT_LATE	3	/* 0->no, 3->yes (for 1 & 2->see RM) */
#define CAPWAP_MAX_BPID		64	/* size of BPID->object lookup array */
#define CAPWAP_NUM_POOL_CHANNELS	3
#define CAPWAP_DMA_MAP_SIZE	0x4000000 /* 64MB */

#define ETH_HDR_SIZE                    14
#define IPv4_HDR_SIZE                   20
#define UDP_HDR_SIZE                    8
#define CAPWAP_DTLS_HDR_SIZE            4

#define CAPWAP_FRAG_BPID	8

/* The dynamically allocated pool-channels, and the iterator index that loops
 * around them binding Rx FQs to them in a round-robin fashion. */
uint32_t pchannels[CAPWAP_NUM_POOL_CHANNELS];

/***************/
/* CLI support */
/***************/

typedef int (*cli_handle_t)(int argc, char *argv[]);
struct cli_table_entry
{
	const char *cmd;
	const cli_handle_t handle;
};
#define cli_cmd(cmd, handle)					\
	const struct cli_table_entry cli_table_entry_##cmd	\
	__attribute__((used, section(".rodata.cli_table")))	\
	= {__stringify(cmd), handle}

/*********************************/
/* Net interface data structures */
/*********************************/

/* Each Fman interface has one of these */
struct capwap_interface;

const struct fm_eth_port_cfg *capwap_interface_pcfg(struct capwap_interface *i);

extern struct usdpaa_netcfg_info *netcfg;

extern struct bman_pool *pool[CAPWAP_MAX_BPID];
extern struct list_head ifs;
extern __thread struct qman_fq local_fq;
#if defined(CAPWAP_ORDER_PRESERVATION) || \
	defined(CAPWAP_ORDER_RESTORATION)
extern __thread const struct qm_dqrr_entry *local_dqrr;
#endif
#ifdef CAPWAP_ORDER_RESTORATION
extern __thread struct qman_fq *local_orp_fq;
extern __thread u32 local_seqnum;
#endif

static inline void
bm_free_buf(struct bman_pool *bp, const struct bm_buffer *buf, int count)
{
	while (bman_release(bp, buf, count, 0))
		cpu_spin(CAPWAP_BACKOFF_CYCLES);
}

static inline void capwap_drop_frame(const struct qm_fd *fd)
{
	struct bm_buffer buf;
#ifdef CAPWAP_ORDER_RESTORATION
	int ret;
#endif

	BUG_ON(fd->format != qm_fd_contig);
	BUG_ON(fd->bpid >= CAPWAP_MAX_BPID);
	bm_buffer_set64(&buf, qm_fd_addr(fd));
	bm_free_buf(pool[fd->bpid], &buf, 1);
	TRACE("drop: bpid %d <-- 0x%"PRIu64"\n", fd->bpid, qm_fd_addr(fd));
#ifdef CAPWAP_ORDER_RESTORATION
	/* Perform a "HOLE" enqueue so that the ORP doesn't wait for the
	 * sequence number that we're dropping. */
	if (!local_orp_fq)
		return;
retry_orp:
	ret = qman_enqueue_orp(local_orp_fq, fd, QMAN_ENQUEUE_FLAG_HOLE,
			       local_orp_fq, local_seqnum);
	if (ret) {
		cpu_spin(CAPWAP_BACKOFF_CYCLES);
		goto retry_orp;
	}
	TRACE("drop: fqid %d <-- 0x%x (HOLE)\n",
		local_orp_fq->fqid, local_seqnum);
#endif
}

#ifdef CAPWAP_ORDER_PRESERVATION
#define EQ_FLAGS() QMAN_ENQUEUE_FLAG_DCA | QMAN_ENQUEUE_FLAG_DCA_PTR(local_dqrr)
#else
#define EQ_FLAGS() 0
#endif
static inline void capwap_send_frame(u32 fqid, const struct qm_fd *fd)
{
	int ret;
	local_fq.fqid = fqid;
retry:
#ifdef CAPWAP_ORDER_RESTORATION
	if (local_orp_fq) {
		ret = qman_enqueue_orp(&local_fq, fd, EQ_FLAGS(), local_orp_fq,
					local_dqrr->seqnum);
		TRACE("send ORP: fqid %d, orpid %d, seqnum %d <-- 0x%llx (%d)\n",
			local_fq.fqid, tmp_orp.fqid, local_dqrr->seqnum,
			qm_fd_addr(fd), ret);
	} else
#endif
	{
	ret = qman_enqueue(&local_fq, fd, EQ_FLAGS());
/*	TRACE("send: fqid %d <-- 0x%llx (%d)\n",
		local_fq.fqid, qm_fd_addr(fd), ret);*/
	}
	if (ret) {
		cpu_spin(CAPWAP_BACKOFF_CYCLES);
		goto retry;
	}
#ifdef CAPWAP_ORDER_PRESERVATION
	/* NULLing this ensures the driver won't consume the ring entry
	 * explicitly (ie. CAPWAP's callback will return qman_cb_dqrr_defer). */
	local_dqrr = NULL;
#endif
}

static inline void capwap_send_secondary_frame(u32 fqid, const struct qm_fd *fd)
{
	int ret;
	local_fq.fqid = fqid;
retry:
	ret = qman_enqueue(&local_fq, fd, 0);
	if (ret) {
		cpu_spin(CAPWAP_BACKOFF_CYCLES);
		goto retry;
	}
}

void teardown_fq(struct qman_fq *fq);

void capwap_fq_nonpcd_init(struct qman_fq *fq, u32 fqid,
			 u16 channel,
			 const struct qm_fqd_stashing *stashing,
			 qman_cb_dqrr cb);

void capwap_fq_pcd_init(struct qman_fq *fq, u32 fqid,
		      u16 channel,
		      const struct qm_fqd_stashing *stashing,
		      int prefer_in_cache);
#ifdef CAPWAP_ORDER_RESTORATION
struct qman_fq *capwap_orp_init(void);
#endif
void capwap_fq_tx_init(struct qman_fq *fq,
		     u16 channel,
		     uint64_t context_a,
		     uint32_t context_b);
enum qman_cb_dqrr_result
cb_dqrr_rx_hash(struct qman_portal *qm __always_unused,
		struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr);
u16 get_rxc(void);
int lazy_init_bpool(u8 bpid, u8 depletion_notify);
void do_global_finish(void);
int capwap_init(void);
int interface_init(void);
int capwap_interface_init_rx(struct capwap_interface *i);
void capwap_interface_enable_rx(const struct capwap_interface *i);
void capwap_interface_disable_rx(const struct capwap_interface *i);
void capwap_interface_finish(struct capwap_interface *i);
void capwap_interface_finish_rx(struct capwap_interface *i);
void capwap_interface_enable_shared_rx(const struct capwap_interface *i);
void capwap_interface_disable_shared_rx(const struct capwap_interface *i);
void cb_ern(struct qman_portal *qm __always_unused,
	    struct qman_fq *fq, const struct qm_mr_entry *msg);

/**************************************/
/* FQ Ranges stored in this structure */
/**************************************/
struct fmc_netcfg_fqrange {
	struct list_head list;
	uint32_t start;
	uint32_t count;
};

#endif	/*  __CAPWAP_CFG_H */
