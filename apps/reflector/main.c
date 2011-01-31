/* Copyright (c) 2010,2011 Freescale Semiconductor, Inc.
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

#include <compat.h>
#include <dma_mem.h>
#include <fman.h>
#include <usdpa_netcfg.h>

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/ip.h>

/* if defined, be lippy about everything */
#undef RFL_TRACE
#ifdef ENABLE_TRACE
#define RFL_TRACE
#endif

/* application configuration */
#define RFL_TX_FQS_10G		16
#define RFL_TX_FQS_1G		16
#define RFL_PRIO_2DROP		3 /* error/default/etc */
#define RFL_PRIO_2FWD		4 /* rx-hash */
#define RFL_PRIO_2TX		4 /* consumed by Fman */
#define RFL_STASH_DATA_CL	1
#define RFL_CLI_BUFFER		(2*1024)
#define RFL_CGR_RX_PERFQ_THRESH	32
#define RFL_CGR_TX_PERFQ_THRESH 64
#define RFL_BACKOFF_CYCLES	512

/* application options */
#undef RFL_2FWD_HOLDACTIVE	/* process each FQ on one cpu at a time */
#define RFL_2FWD_RX_PREFERINCACHE /* keep rx FQDs in-cache even when empty */
#define RFL_2FWD_TX_PREFERINCACHE /* keep tx FQDs in-cache even when empty */
#undef RFL_2FWD_TX_FORCESFDR	/* priority allocation of SFDRs to egress */
#define RFL_DEPLETION		/* trace depletion entry/exit */
#undef RFL_CGR			/* track rx and tx fill-levels via CGR */

/**********/
/* macros */
/**********/

#ifdef RFL_TRACE
#define TRACE		printf
#else
#define TRACE(x...)	do { ; } while(0)
#endif

/*********************************/
/* Net interface data structures */
/*********************************/

/* Rx FQs that always drop (ie. "Rx error", "Rx default", "Tx error",
 * "Tx confirm"). */
struct rfl_fq_2drop {
	struct qman_fq fq;
};

/* Rx FQs that fwd (or drop selectively). */
struct rfl_fq_2fwd {
	struct qman_fq fq_rx;
	/* A more general network processing application (eg. routing) would
	 * take into account the contents of the recieved frame when computing
	 * the appropriate Tx FQID. These wrapper structures around each Rx FQ
	 * would typically contain state to assist/optimise that choice of Tx
	 * FQID, as that's one of the reasons for hashing Rx traffic to multiple
	 * FQIDs - each FQID carries proportionally fewer flows than the network
	 * interface itself, and a proportionally higher likelihood of bursts
	 * from the same flow. In "reflector" though, the choice of Tx FQID is
	 * constant for each Rx FQID, and so the only "optimisation" we can do
	 * is to store tx_fqid itself! */
	uint32_t tx_fqid;
} ____cacheline_aligned;

/* Each Fman i/face has one of these */
struct rfl_if {
	struct list_head node;
	size_t sz;
	const struct fm_eth_port_cfg *port_cfg;
	/* NB: the Tx FQs kept here are created to (a) initialise and schedule
	 * the FQIDs on startup, and (b) be able to clean them up on shutdown.
	 * The forwarding logic doesn't use them for its enqueues, as that's not
	 * in keeping with how a "generic network processing application" would
	 * work (see the comment for rfl_fq_2fwd::tx_fqid). Instead, we "choose"
	 * the Tx FQID for each recieved packet (let's ignore the fact it's a
	 * constant), and the frame is then enqueued via a "local_fq" object
	 * that acts on behalf of any Tx FQID. There's one such object for each
	 * cpu so it's cache-local and doesn't need locking. See "local_fq"
	 * below for more info. */
	unsigned int num_tx_fqs;
	struct qman_fq *tx_fqs;
	struct rfl_fq_2drop rx_error;
	struct rfl_fq_2drop rx_default;
	struct rfl_fq_2drop tx_error;
	struct rfl_fq_2drop tx_confirm;
	struct rfl_fq_2fwd rx_hash[0];
} ____cacheline_aligned;

/***************/
/* Global data */
/***************/

/* Configuration */
static struct usdpa_netcfg_info *cfg;
/* Default paths to configuration files - these are determined from the build,
 * but can be overriden at run-time using "DEF_PCD_PATH" and "DEF_CFG_PATH"
 * environment variables. */
static const char default_pcd_path[] = __stringify(DEF_PCD_PATH);
static const char default_cfg_path[] = __stringify(DEF_CFG_PATH);

/* The SDQCR mask to use (computed from cfg's pool-channels) */
static uint32_t sdqcr;

/* We want a trivial mapping from bpid->pool, so just have a 64-wide array of
 * pointers, most of which are NULL. */
static struct bman_pool *pool[64];

/* The interfaces in this list are allocated from dma_mem (stashing==DMA) */
static LIST_HEAD(ifs);

/* The forwarding logic uses a per-cpu FQ object for handling enqueues (and
 * ERNs), irrespective of the destination FQID. In this way, cache-locality is
 * more assured, and any ERNs that do occur will show up on the same CPUs they
 * were enqueued from. This works because ERN messages contain the FQID of the
 * original enqueue operation, so in principle any demux that's required by the
 * ERN callback can be based on that. Ie. the FQID set within "local_fq" is from
 * whatever the last executed enqueue was, the ERN handler can ignore it. */
static __PERCPU struct qman_fq local_fq;

#ifdef RFL_CGR
/* A congestion group to hold Rx FQs (uses cfg::cgrids[0]) */
static struct qman_cgr cgr_rx;
/* Tx FQs go into a separate CGR (uses cfg::cgrids[1]) */
static struct qman_cgr cgr_tx;
#endif

/********************/
/* common functions */
/********************/

/* Rx handling either leads to a forward (qman enqueue) or a drop (bman
 * release). In either case, we can't "block" and we don't want to defer until
 * outside the callback, because we still have to pushback somehow and as we're
 * a run-to-completion app, we don't have anything else to do than simply retry.
 * So ... we retry non-blocking enqueues/releases until they succeed, which
 * implicitly pushes back on dequeue handling. */

static inline void drop_frame(const struct qm_fd *fd)
{
	struct bm_buffer buf;
	int ret;
	BUG_ON(fd->format != qm_fd_contig);
	buf.hi = fd->addr_hi;
	buf.lo = fd->addr_lo;
retry:
	ret = bman_release(pool[fd->bpid], &buf, 1, 0);
	if (ret) {
		cpu_spin(RFL_BACKOFF_CYCLES);
		goto retry;
	}
}

static inline void send_frame(u32 fqid, const struct qm_fd *fd)
{
	int ret;
	local_fq.fqid = fqid;
retry:
	ret = qman_enqueue(&local_fq, fd, 0);
	if (ret) {
		cpu_spin(RFL_BACKOFF_CYCLES);
		goto retry;
	}
}

static void teardown_fq(struct qman_fq *fq)
{
	u32 flags;
	int s = qman_retire_fq(fq, &flags);
	if (s == 1) {
		/* Retire is non-blocking, poll for completion */
		enum qman_fq_state state;
		do {
			qman_poll();
			qman_fq_state(fq, &state, &flags);
		} while (state != qman_fq_state_retired);
		if (flags & QMAN_FQ_STATE_NE) {
			/* FQ isn't empty, drain it */
			s = qman_volatile_dequeue(fq, 0,
				QM_VDQCR_NUMFRAMES_TILLEMPTY);
			BUG_ON(s);
			/* Poll for completion */
			do {
				qman_poll();
				qman_fq_state(fq, &state, &flags);
			} while (flags & QMAN_FQ_STATE_VDQCR);
		}
	}
	s = qman_oos_fq(fq);
	BUG_ON(s);
	qman_destroy_fq(fq, 0);
}

/***********************/
/* struct rfl_fq_2drop */
/***********************/

static enum qman_cb_dqrr_result cb_dqrr_2drop(
					struct qman_portal *qm __always_unused,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	TRACE("Rx: 2drop fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static void rfl_fq_2drop_init(struct rfl_fq_2drop *p, u32 fqid,
				enum qm_channel channel)
{
	struct qm_mcc_initfq opts;
	int ret;

	p->fq.cb.dqrr = cb_dqrr_2drop;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &p->fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2drop" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = RFL_PRIO_2DROP;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = 0;
	ret = qman_init_fq(&p->fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

static void rfl_fq_2drop_finish(struct rfl_fq_2drop *p)
{
	teardown_fq(&p->fq);
}

/**********************/
/* struct rfl_fq_2fwd */
/**********************/

/* Swap 6-byte MAC headers "efficiently" (hopefully) */
static inline void ether_header_swap(struct ether_header *prot_eth)
{
	register u32 a, b, c;
	u32 *overlay = (u32 *)prot_eth;
	a = overlay[0];
	b = overlay[1];
	c = overlay[2];
	overlay[0] = (b << 16) | (c >> 16);
	overlay[1] = (c << 16) | (a >> 16);
	overlay[2] = (a << 16) | (b >> 16);
}

static enum qman_cb_dqrr_result cb_dqrr_2fwd(
					struct qman_portal *qm __always_unused,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	struct rfl_fq_2fwd *p = container_of(fq, struct rfl_fq_2fwd, fq_rx);
	const struct qm_fd *fd = &dqrr->fd;
	void *addr;
	struct ether_header *prot_eth;

	BUG_ON(fd->format != qm_fd_contig);
	addr = dma_mem_ptov(fd->addr_lo);
	TRACE("Rx: 2fwd	 fqid=%d\n", fq->fqid);
	TRACE("	     phys=0x%08x, virt=%p, offset=%d, len=%d, bpid=%d\n",
		fd->addr_lo, addr, fd->offset, fd->length20, fd->bpid);
	addr += fd->offset;
	prot_eth = addr;
	TRACE("	     dhost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_dhost[0], prot_eth->ether_dhost[1],
		prot_eth->ether_dhost[2], prot_eth->ether_dhost[3],
		prot_eth->ether_dhost[4], prot_eth->ether_dhost[5]);
	TRACE("	     shost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_shost[0], prot_eth->ether_shost[1],
		prot_eth->ether_shost[2], prot_eth->ether_shost[3],
		prot_eth->ether_shost[4], prot_eth->ether_shost[5]);
	TRACE("	     ether_type=%04x\n", prot_eth->ether_type);
	/* Eliminate ethernet broadcasts. */
	if (prot_eth->ether_dhost[0] & 0x01)
		TRACE("	     -> dropping broadcast packet\n");
	else
	switch (prot_eth->ether_type)
	{
	case ETH_P_IP:
		TRACE("	       -> it's ETH_P_IP!\n");
		{
		struct iphdr *iphdr = addr + 14;
		__be32 tmp;
#ifdef RFL_TRACE
		u8 *src = (void *)&iphdr->saddr;
		u8 *dst = (void *)&iphdr->daddr;
		TRACE("		  ver=%d,ihl=%d,tos=%d,len=%d,id=%d\n",
			iphdr->version, iphdr->ihl, iphdr->tos, iphdr->tot_len,
			iphdr->id);
		TRACE("		  frag_off=%d,ttl=%d,prot=%d,csum=0x%04x\n",
			iphdr->frag_off, iphdr->ttl, iphdr->protocol,
			iphdr->check);
		TRACE("		  src=%d.%d.%d.%d\n",
			src[0], src[1], src[2], src[3]);
		TRACE("		  dst=%d.%d.%d.%d\n",
			dst[0], dst[1], dst[2], dst[3]);
#endif
		/* switch ipv4 src/dst addresses */
		tmp = iphdr->daddr;
		iphdr->daddr = iphdr->saddr;
		iphdr->saddr = tmp;
		/* switch ethernet src/dest MAC addresses */
		ether_header_swap(prot_eth);
		TRACE("Tx: 2fwd	 fqid=%d\n", p->tx_fqid);
		TRACE("	     phys=0x%08x, offset=%d, len=%d, bpid=%d\n",
			fd->addr_lo, fd->offset, fd->length20, fd->bpid);
		send_frame(p->tx_fqid, fd);
		}
		return qman_cb_dqrr_consume;
	case ETH_P_ARP:
		TRACE("	       -> it's ETH_P_ARP!\n");
#ifdef RFL_TRACE
		{
		struct arphdr *arphdr = addr + 14;
		TRACE("		  hrd=%d, pro=%d, hln=%d, pln=%d, op=%d\n",
			arphdr->ar_hrd, arphdr->ar_pro, arphdr->ar_hln,
			arphdr->ar_pln, arphdr->ar_op);
		}
#endif
		TRACE("		  -> dropping ARP packet\n");
		break;
	default:
		TRACE("	       -> it's UNKNOWN (!!) type 0x%04x\n",
			prot_eth->ether_type);
		TRACE("		  -> dropping unknown packet\n");
	}
	drop_frame(fd);
	return qman_cb_dqrr_consume;
}

static void cb_ern_2fwd(struct qman_portal *qm __always_unused,
			struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	drop_frame(&msg->ern.fd);
}

static enum qman_cb_dqrr_result cb_tx_drain_2fwd(
					struct qman_portal *qm __always_unused,
					struct qman_fq *fq __always_unused,
					const struct qm_dqrr_entry *dqrr)
{
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static void rfl_fq_2fwd_init(struct rfl_fq_2fwd *p, u32 rx_fqid, u32 tx_fqid,
				enum qm_channel channel)
{
	struct qm_mcc_initfq opts;
	int ret;
	p->tx_fqid = tx_fqid;
	p->fq_rx.cb.dqrr = cb_dqrr_2fwd;
	ret = qman_create_fq(rx_fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &p->fq_rx);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2fwd" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = RFL_PRIO_2FWD;
	opts.fqd.fq_ctrl =
#ifdef RFL_2FWD_HOLDACTIVE
		QM_FQCTRL_HOLDACTIVE |
#endif
#ifdef RFL_2FWD_RX_PREFERINCACHE
		QM_FQCTRL_PREFERINCACHE |
#endif
		QM_FQCTRL_CTXASTASHING;
#ifdef RFL_CGR
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_rx.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = 0;
	ret = qman_init_fq(&p->fq_rx, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

static void rfl_fq_2fwd_finish(struct rfl_fq_2fwd *p)
{
	teardown_fq(&p->fq_rx);
}

/*************************/
/* buffer-pool depletion */
/*************************/

#ifdef RFL_DEPLETION
static void bp_depletion(struct bman_portal *bm __always_unused,
			struct bman_pool *p,
			void *cb_ctx __maybe_unused,
			int depleted)
{
	u8 bpid = bman_get_params(p)->bpid;
	BUG_ON(p != *(typeof(&p))cb_ctxt);

	pr_info("%s: BP%u -> %s\n", __func__, bpid,
		depleted ? "entry" : "exit");
}
#endif

/*********************************/
/* CGR state-change notification */
/*********************************/

#ifdef RFL_CGR
static void cgr_rx_cb(struct qman_portal *qm, struct qman_cgr *c, int congested)
{
	BUG_ON(c != &cgr_rx);

	pr_info("%s: rx CGR -> congestion %s\n", __func__,
		congested ? "entry" : "exit");
}
static void cgr_tx_cb(struct qman_portal *qm, struct qman_cgr *c, int congested)
{
	BUG_ON(c != &cgr_tx);

	pr_info("%s: tx CGR -> congestion %s\n", __func__,
		congested ? "entry" : "exit");
}
#endif

/*****************/
/* struct rfl_if */
/*****************/

static uint32_t pchannel_idx;

static enum qm_channel get_rxc(void)
{
	enum qm_channel ret = cfg->pool_channels[pchannel_idx];
	pchannel_idx = (pchannel_idx + 1) % cfg->num_pool_channels;
	return ret;
}

static int lazy_init_bpool(const struct fman_if_bpool *bpool)
{
	struct bman_pool_params params = {
		.bpid	= bpool->bpid,
#ifdef RFL_DEPLETION
		.flags	= BMAN_POOL_FLAG_ONLY_RELEASE |
			BMAN_POOL_FLAG_DEPLETION,
		.cb	= bp_depletion,
		.cb_ctx	= &pool[bpool->bpid]
#else
		.flags	= BMAN_POOL_FLAG_ONLY_RELEASE
#endif
	};
	if (pool[bpool->bpid])
		/* this BPID is already handled */
		return 0;
	pool[bpool->bpid] = bman_new_pool(&params);
	if (!pool[bpool->bpid]) {
		fprintf(stderr, "error: bman_new_pool(%d) failed\n",
			bpool->bpid);
		return -ENOMEM;
	}
	return 0;
}

static int rfl_if_init(unsigned int idx)
{
	struct rfl_if *i;
	const struct fman_if_bpool *bp;
	int loop;
	const struct fm_eth_port_cfg *port = &cfg->port_cfg[idx];
	const struct fman_if *fif = port->fman_if;
	size_t sz = sizeof(struct rfl_if) +
		(port->pcd.count * sizeof(struct rfl_fq_2fwd));

	/* Handle any pools used by this i/f that are not already handled */
	fman_if_for_each_bpool(bp, fif) {
		int err = lazy_init_bpool(bp);
		if (err)
			return err;
	}
	/* allocate stashable memory for the interface object */
	i = dma_mem_memalign(64, sz);
	if (!i)
		return -ENOMEM;
	memset(i, 0, sz);
	i->sz = sz;
	i->port_cfg = port;
	/* allocate and initialise Tx FQs for this interface */
	i->num_tx_fqs = (fif->mac_type == fman_mac_10g) ?
			RFL_TX_FQS_10G : RFL_TX_FQS_1G;
	i->tx_fqs = malloc(sizeof(*i->tx_fqs) * i->num_tx_fqs);
	if (!i->tx_fqs) {
		dma_mem_free(i, sz);
		return -ENOMEM;
	}
	memset(i->tx_fqs, 0, sizeof(*i->tx_fqs) * i->num_tx_fqs);
	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qm_mcc_initfq opts;
		struct qman_fq *fq = &i->tx_fqs[loop];
		int err;
		/* These FQ objects need to be able to handle DQRR callbacks,
		 * when cleaning up. */
		fq->cb.dqrr = cb_tx_drain_2fwd;
		err = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID |
					QMAN_FQ_FLAG_TO_DCPORTAL, fq);
		BUG_ON(err);
		opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
		opts.fqd.dest.channel = fif->tx_channel_id;
		opts.fqd.dest.wq = RFL_PRIO_2TX;
		opts.fqd.fq_ctrl =
#ifdef RFL_2FWD_TX_PREFERINCACHE
			QM_FQCTRL_PREFERINCACHE |
#endif
#ifdef RFL_2FWD_TX_FORCESFDR
			QM_FQCTRL_FORCESFDR |
#endif
			0;
#if defined(RFL_CGR)
		opts.we_mask |= QM_INITFQ_WE_CGID;
		opts.fqd.cgid = cgr_tx.cgrid;
		opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
		opts.fqd.context_b = 0;
		opts.fqd.context_a.hi = 0x80000000;
		opts.fqd.context_a.lo = 0;
		err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
		BUG_ON(err);
		TRACE("I/F %d, using Tx FQID %d\n", idx, fq->fqid);
	}
	rfl_fq_2drop_init(&i->rx_error, fif->fqid_rx_err, get_rxc());
	rfl_fq_2drop_init(&i->rx_default, port->rx_def, get_rxc());
	rfl_fq_2drop_init(&i->tx_error, fif->fqid_tx_err, get_rxc());
	rfl_fq_2drop_init(&i->tx_confirm, fif->fqid_tx_confirm,
		get_rxc());
	for (loop = 0; loop < port->pcd.count; loop++) {
		enum qm_channel c = get_rxc();
		rfl_fq_2fwd_init(&i->rx_hash[loop], port->pcd.start + loop,
			i->tx_fqs[loop % i->num_tx_fqs].fqid, c);
	}
	TRACE("Interface %d:%d, enabling RX\n", fif->fman_idx, fif->mac_idx);
	fman_if_enable_rx(fif);
	list_add_tail(&i->node, &ifs);
	return 0;
}

static void rfl_if_finish(struct rfl_if *i)
{
	const struct fman_if *fif = i->port_cfg->fman_if;
	int loop;
	list_del(&i->node);
	fman_if_disable_rx(fif);
	TRACE("Interface %d:%d, disabled RX\n", fif->fman_idx, fif->mac_idx);
	rfl_fq_2drop_finish(&i->rx_error);
	rfl_fq_2drop_finish(&i->rx_default);
	rfl_fq_2drop_finish(&i->tx_error);
	rfl_fq_2drop_finish(&i->tx_confirm);
	for (loop = 0; loop < i->port_cfg->pcd.count; loop++)
		rfl_fq_2fwd_finish(&i->rx_hash[loop]);
	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qman_fq *fq = &i->tx_fqs[loop];
		teardown_fq(fq);
		TRACE("I/F %d, destroying Tx FQID %d\n", fif->fman_idx,
				fq->fqid);
	}
	free(i->tx_fqs);
	dma_mem_free(i, i->sz);
}

/******************/
/* Worker threads */
/******************/

struct worker_msg {
	/* The CLI thread sets ::msg!=worker_msg_none then waits on the barrier.
	 * The worker thread checks for this in its polling loop, and if set it
	 * will perform the desired function, set ::msg=worker_msg_none, then go
	 * into the barrier (releasing itself and the CLI thread). */
	volatile enum worker_msg_type {
		worker_msg_none = 0,
		worker_msg_list,
		worker_msg_quit,
		worker_msg_do_global_init,
		worker_msg_do_global_finish,
#ifdef RFL_CGR
		worker_msg_query_cgr
#endif
	} msg;
	pthread_barrier_t barr;
#ifdef RFL_CGR
	union {
		struct {
			struct qm_mcr_querycgr res_rx;
			struct qm_mcr_querycgr res_tx;
		} query_cgr;
	};
#endif
} ____cacheline_aligned;

struct worker {
	struct worker_msg *msg;
	int cpu;
	pthread_t id;
	int result;
	struct list_head node;
} ____cacheline_aligned;

/* -------------------------------- */
/* msg-processing within the worker */

static void do_global_finish(void)
{
	struct rfl_if *i, *tmpi;
	int loop;

	/* Tear down interfaces */
	list_for_each_entry_safe(i, tmpi, &ifs, node)
		rfl_if_finish(i);
	/* Tear down buffer pools */
	for (loop = 0; loop < 64; loop++) {
		if (pool[loop]) {
			bman_free_pool(pool[loop]);
			pool[loop] = NULL;
		}
	}
}

static void do_global_init(void)
{
	unsigned int loop;
	int err;

#ifdef RFL_CGR
	struct qm_mcc_initcgr opts = {
		.we_mask = QM_CGR_WE_CSCN_EN | QM_CGR_WE_CS_THRES |
				QM_CGR_WE_MODE,
		.cgr = {
			.cscn_en = QM_CGR_EN,
			.mode = QMAN_CGR_MODE_FRAME
		}
	};
	if (cfg->num_cgrids < 2) {
		fprintf(stderr, "error: insufficient CGRIDs available\n");
		exit(-1);
	}

	/* Set up Rx CGR */
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, RFL_IF_NUM *
		(RFL_CGR_RX_PERFQ_THRESH * RFL_RX_HASH_SIZE), 0);
	cgr_rx.cgrid = cfg->cgrids[0];
	cgr_rx.cb = cgr_rx_cb;
	err = qman_create_cgr(&cgr_rx, QMAN_CGR_FLAG_USE_INIT, &opts);
	if (err)
		fprintf(stderr, "error: rx CGR init, continuing\n");

	/* Set up Tx CGR */
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, RFL_IF_NUM *
		(RFL_CGR_TX_PERFQ_THRESH * RFL_TX_NUM), 0);
	cgr_tx.cgrid = cfg->cgrids[1];
	cgr_tx.cb = cgr_tx_cb;
	err = qman_create_cgr(&cgr_tx, QMAN_CGR_FLAG_USE_INIT, &opts);
	if (err)
		fprintf(stderr, "error: tx CGR init, continuing\n");
#endif
	/* Initialise interface objects (internally, this takes care of
	 * initialising buffer pool objects for any BPIDs used by the Fman Rx
	 * ports). */
	for (loop = 0; loop < cfg->num_ethports; loop++) {
		TRACE("Initialising interface %d\n", loop);
		err = rfl_if_init(loop);
		if (err) {
			fprintf(stderr, "error: interface %d failed\n", loop);
			do_global_finish();
			return;
		}
	}
}

static noinline int process_msg(struct worker *worker, struct worker_msg *msg)
{
	int ret = 1;

	/* List */
	if (msg->msg == worker_msg_list)
		printf("Thread alive on cpu %d\n", worker->cpu);

	/* Quit */
	else if (msg->msg == worker_msg_quit)
		ret = 0;

	/* Do global init */
	else if (msg->msg == worker_msg_do_global_init)
		do_global_init();

	/* Do global finish */
	else if (msg->msg == worker_msg_do_global_finish)
		do_global_finish();

#ifdef RFL_CGR
	/* Query the CGR state */
	else if (msg->msg == worker_msg_query_cgr) {
		int err = qman_query_cgr(&cgr_rx, &msg->query_cgr.res_rx);
		if (err)
			fprintf(stderr, "error: query rx CGR, continuing\n");
		err = qman_query_cgr(&cgr_tx, &msg->query_cgr.res_tx);
		if (err)
			fprintf(stderr, "error: query tx CGR, continuing\n");
	}
#endif

	/* What did you want? */
	else
		panic("bad message type");

	/* Release ourselves and the CLI thread from this message */
	msg->msg = worker_msg_none;
	pthread_barrier_wait(&msg->barr);
	return ret;
}

/* the worker's polling loop calls this function to drive the message pump */
static inline int check_msg(struct worker *worker)
{
	struct worker_msg *msg = worker->msg;
	if (likely(msg->msg == worker_msg_none))
		return 1;
	return process_msg(worker, msg);
}

/* ---------------------- */
/* worker thread function */

static void *worker_fn(void *__worker)
{
	struct worker *worker = __worker;
	cpu_set_t cpuset;
	int s;
	int calm_down = 16;

	TRACE("This is the thread on cpu %d\n", worker->cpu);

	/* Set this cpu-affinity */
	CPU_ZERO(&cpuset);
	CPU_SET(worker->cpu, &cpuset);
	s = pthread_setaffinity_np(worker->id, sizeof(cpu_set_t), &cpuset);
	if (s != 0) {
		fprintf(stderr, "pthread_setaffinity_np(%d) failed, ret=%d\n",
			worker->cpu, s);
		goto end;
	}

	/* Initialise bman/qman portals */
	s = bman_thread_init(worker->cpu, 0);
	if (s) {
		fprintf(stderr, "bman_thread_init(%d) failed, ret=%d\n",
			worker->cpu, s);
		goto end;
	}
	s = qman_thread_init(worker->cpu, 0);
	if (s) {
		fprintf(stderr, "qman_thread_init(%d) failed, ret=%d\n",
			worker->cpu, s);
		goto end;
	}
	/* Initialise the enqueue-only FQ object for this cpu/thread. NB, the
	 * fqid argument ("1") is superfluous, the point is to mark the object
	 * as ready for enqueuing and handling ERNs, but unfit for any FQD
	 * modifications. The forwarding logic will substitute in the required
	 * FQID. */
	local_fq.cb.ern = cb_ern_2fwd;
	s = qman_create_fq(1, QMAN_FQ_FLAG_NO_MODIFY, &local_fq);
	BUG_ON(s);

	/* Set the qman portal's SDQCR mask */
	qman_static_dequeue_add(sdqcr);

	/* Run! */
	TRACE("Starting poll loop on cpu %d\n", worker->cpu);
	while (check_msg(worker)) {
		qman_poll();
		bman_poll();
	}

end:
	qman_static_dequeue_del(~(u32)0);
	while (calm_down--) {
		qman_poll_slow();
		qman_poll_dqrr(16);
	}
	qman_thread_finish();
	bman_thread_finish();
	TRACE("Leaving thread on cpu %d\n", worker->cpu);
	/* TODO: tear down the portal! */
	pthread_exit(NULL);
}

/* ------------------------------ */
/* msg-processing from main()/CLI */

static void msg_list(struct worker *worker)
{
	struct worker_msg *msg = worker->msg;
	msg->msg = worker_msg_list;
	pthread_barrier_wait(&msg->barr);
}

static void msg_quit(struct worker *worker)
{
	struct worker_msg *msg = worker->msg;
	msg->msg = worker_msg_quit;
	pthread_barrier_wait(&msg->barr);
}

static void msg_do_global_init(struct worker *worker)
{
	struct worker_msg *msg = worker->msg;
	msg->msg = worker_msg_do_global_init;
	pthread_barrier_wait(&msg->barr);
}

static void msg_do_global_finish(struct worker *worker)
{
	struct worker_msg *msg = worker->msg;
	msg->msg = worker_msg_do_global_finish;
	pthread_barrier_wait(&msg->barr);
}

#ifdef RFL_CGR
static void dump_cgr(const struct qm_mcr_querycgr *res)
{
	u64 val64;
	printf("      cscn_en: %d\n", res->cgr.cscn_en);
	printf("    cscn_targ: 0x%08x\n", res->cgr.cscn_targ);
	printf("      cstd_en: %d\n", res->cgr.cstd_en);
	printf("           cs: %d\n", res->cgr.cs);
	val64 = qm_cgr_cs_thres_get64(&res->cgr.cs_thres);
	printf("    cs_thresh: 0x%02x_%04x_%04x\n", (u32)(val64 >> 32),
		(u32)(val64 >> 16) & 0xffff, (u32)val64 & 0xffff);
	printf("         mode: %d\n", res->cgr.mode);
	val64 = qm_mcr_querycgr_i_get64(res);
	printf("       i_bcnt: 0x%02x_%04x_%04x\n", (u32)(val64 >> 32),
		(u32)(val64 >> 16) & 0xffff, (u32)val64 & 0xffff);
	val64 = qm_mcr_querycgr_a_get64(res);
	printf("       a_bcnt: 0x%02x_%04x_%04x\n", (u32)(val64 >> 32),
		(u32)(val64 >> 16) & 0xffff, (u32)val64 & 0xffff);
}
static void msg_query_cgr(struct worker *worker)
{
	struct worker_msg *msg = worker->msg;
	msg->msg = worker_msg_query_cgr;
	pthread_barrier_wait(&msg->barr);
	printf("Rx CGR ID: %d, selected fields;\n", cgr_rx.cgrid);
	dump_cgr(&worker->msg->query_cgr.res_rx);
	printf("Tx CGR ID: %d, selected fields;\n", cgr_tx.cgrid);
	dump_cgr(&worker->msg->query_cgr.res_tx);
}
#endif

/* ---------------------------- */
/* worker setup from main()/CLI */

static struct worker *worker_new(int cpu)
{
	struct worker *ret;
	int err = posix_memalign((void **)&ret, 64, sizeof(*ret));
	if (err)
		goto out;
	err = posix_memalign((void **)&ret->msg, 64, sizeof(*ret->msg));
	if (err) {
		free(ret);
		goto out;
	}
	ret->cpu = cpu;
	ret->msg->msg = worker_msg_none;
	pthread_barrier_init(&ret->msg->barr, NULL, 2);
	err = pthread_create(&ret->id, NULL, worker_fn, ret);
	if (err) {
		free(ret);
		goto out;
	}
	/* Block until the worker is in its polling loop (by sending a "list"
	 * command and waiting for it to get processed). This ensures any
	 * start-up logging is produced before the CLI prints another prompt. */
	msg_list(ret);
	return ret;
out:
	fprintf(stderr, "error: failed to create thread for %d\n", cpu);
	return NULL;
}

static void __worker_free(struct worker *worker)
{
	int err;
	msg_quit(worker);
	err = pthread_join(worker->id, NULL);
	if (err) {
		/* Leak, but warn */
		fprintf(stderr, "Failed to join thread %d\n", worker->cpu);
		return;
	}
	free(worker->msg);
	free(worker);
}

/********************/
/* main()/CLI logic */
/********************/

static LIST_HEAD(workers);
static unsigned long ncpus;

/* This worker is the first one created, must not be deleted, and must be the
 * last one to exit. (The buffer pools objects are initialised against its
 * portal.) */
static struct worker *primary;

static void worker_add(struct worker *worker)
{
	struct worker *i;
	/* Keep workers ordered by cpu */
	list_for_each_entry(i, &workers, node) {
		if (i->cpu >= worker->cpu) {
			list_add_tail(&worker->node, &i->node);
			return;
		}
	}
	list_add_tail(&worker->node, &workers);
}

static void worker_free(struct worker *worker)
{
	BUG_ON(worker == primary);
	list_del(&worker->node);
	__worker_free(worker);
}

static void worker_reap(struct worker *worker)
{
	if (!pthread_tryjoin_np(worker->id, NULL)) {
		if (worker == primary) {
			pr_crit("Primary thread died!\n");
			abort();
		}
		list_del(&worker->node);
		__worker_free(worker);
		pr_info("Caught dead thread, cpu %d\n", worker->cpu);
		free(worker->msg);
		free(worker);
	}
}

/* Parse a cpu id. On entry legit/len contain acceptable "next char" values, on
 * exit *legit points to the "next char" we found. Return -1 for bad * parse. */
static int parse_cpu(const char *str, const char **legit, int legitlen)
{
	char *endptr;
	int ret = -EINVAL;
	/* Extract a ulong */
	unsigned long tmp = strtoul(str, &endptr, 0);
	if ((tmp == ULONG_MAX) || (endptr == str))
		goto out;
	/* Check next char */
	while (legitlen--) {
		if (**legit == *endptr) {
			/* validate range */
			if (tmp >= ncpus) {
				ret = -ERANGE;
				goto out;
			}
			*legit = endptr;
			return (int)tmp;
		}
		(*legit)++;
	}
out:
	fprintf(stderr, "error: invalid cpu '%s'\n", str);
	return ret;
}

/* Parse a cpu range (eg. "3"=="3..3"). Return 0 for valid parse. */
static int parse_cpus(const char *str, int *start, int *end)
{
	/* NB: arrays of chars, not strings. Also sizeof(), not strlen()! */
	static const char PARSE_STR1[] = { ' ', '.', '\0' };
	static const char PARSE_STR2[] = { ' ', '\0' };
	const char *p = &PARSE_STR1[0];
	int ret;
	ret = parse_cpu(str, &p, sizeof(PARSE_STR1));
	if (ret < 0)
		return ret;
	*start = ret;
	if ((p[0] == '.') && (p[1] == '.')) {
		const char *p2 = &PARSE_STR2[0];
		ret = parse_cpu(p + 2, &p2, sizeof(PARSE_STR2));
		if (ret < 0)
			return ret;
	}
	*end = ret;
	return 0;
}

static struct worker *worker_find(int cpu, int want)
{
	struct worker *worker;
	list_for_each_entry(worker, &workers, node) {
		if (worker->cpu == cpu) {
			if (!want)
				fprintf(stderr, "skipping cpu %d, in use.\n",
					cpu);
			return worker;
		}
	}
	if (want)
		fprintf(stderr, "skipping cpu %d, not in use.\n", cpu);
	return NULL;
}

#define call_for_each_worker(str, fn) \
	do { \
		int fstart, fend, fret = parse_cpus(str, &fstart, &fend); \
		if (!fret) { \
			while (fstart <= fend) { \
				struct worker *fw = worker_find(fstart, 1); \
				if (fw) \
					fn(fw); \
				fstart++; \
			} \
		} \
	} while (0)

#ifdef RFL_CGR
/* This function is, so far, only used by CGR-specific code. */
static struct worker *worker_first(void)
{
	if (list_empty(&workers))
		return NULL;
	return list_entry(workers.next, struct worker, node);
}
#endif

static void usage(void)
{
	fprintf(stderr, "usage: reflector [cpu-range]\n");
	fprintf(stderr, "where [cpu-range] is 'n' or 'm..n'\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	struct worker *worker, *tmpworker;
	const char *pcd_path = default_pcd_path;
	const char *cfg_path = default_cfg_path;
	const char *envp;
	int first, last, loop;
	int rcode;

	ncpus = (unsigned long)sysconf(_SC_NPROCESSORS_ONLN);

	/* Parse the args */
	if (ncpus == 1)
		first = last = 0;
	else
		first = last = 1;
	if (argc == 2) {
		rcode = parse_cpus(argv[1], &first, &last);
		if (rcode)
			usage();
	} else if (argc != 1)
		usage();

	/* Do global init that doesn't require portal access; */
	/* - load the config (includes discovery and mapping of MAC devices) */
	TRACE("Loading configuration\n");
	envp = getenv("DEF_PCD_PATH");
	if (envp)
		pcd_path = envp;
	envp = getenv("DEF_CFG_PATH");
	if (envp)
		cfg_path = envp;
	cfg = usdpa_netcfg_acquire(pcd_path, cfg_path);
	if (!cfg) {
		fprintf(stderr, "error: failed to load configuration\n");
		return -1;
	}
	/* - validate the config */
	if (!cfg->num_ethports) {
		fprintf(stderr, "error: no network interfaces available\n");
		return -1;
	}
	if (!cfg->num_pool_channels) {
		fprintf(stderr, "error: no pool channels available\n");
		return -1;
	}
	printf("Configuring for %d network interface%s and %d pool channel%s\n",
		cfg->num_ethports, cfg->num_ethports > 1 ? "s" : "",
		cfg->num_pool_channels, cfg->num_pool_channels > 1 ? "s" : "");
	/* - compute SDQCR */
	for (loop = 0; loop < cfg->num_pool_channels; loop++) {
		sdqcr |= QM_SDQCR_CHANNELS_POOL_CONV(cfg->pool_channels[loop]);
		TRACE("Adding 0x%08x to SDQCR -> 0x%08x\n",
			QM_SDQCR_CHANNELS_POOL_CONV(cfg->pool_channels[loop]),
			sdqcr);
	}
	/* - map shmem */
	TRACE("Initialising shmem\n");
	rcode = dma_mem_setup();
	if (rcode)
		fprintf(stderr, "error: shmem init, continuing\n");

	/* Create the threads */
	TRACE("Starting %d threads for cpu-range '%s'\n",
		last - first + 1, argv[1]);
	for (loop = first; loop <= last; loop++) {
		worker = worker_new(loop);
		if (!worker) {
			rcode = -1;
			goto leave;
		}
		if (!primary) {
			/* Do datapath-dependent global init on "primary" */
			msg_do_global_init(worker);
			primary = worker;

		}
		worker_add(worker);
	}

	/* TODO: catch dead threads - for now, we rely on the dying thread to
	 * print an error, and for the CLI user to then "remove" it. */

	/* Run the CLI loop */
	while (1) {
		char cli[RFL_CLI_BUFFER];

		/* Reap any dead threads */
		list_for_each_entry_safe(worker, tmpworker, &workers, node)
			worker_reap(worker);

		/* Command prompt */
		printf("reflector> ");
		fflush(stdout);

		/* Get command */
		if (!fgets(cli, RFL_CLI_BUFFER, stdin))
			break;
		while ((cli[strlen(cli) - 1] == '\r') ||
				(cli[strlen(cli) - 1] == '\n'))
			cli[strlen(cli) - 1] = '\0';

		/* Quit */
		if (!strncmp(cli, "q", 1))
			break;

		/* List cpus/threads */
		else if (!strncmp(cli, "list", 4)) {
			/* cpu-range is an optional argument */
			if (strlen(cli) > 4)
				call_for_each_worker(cli + 4, msg_list);
			else
				list_for_each_entry(worker, &workers, node)
					msg_list(worker);
		}

		/* Add a cpu */
		else if (!strncmp(cli, "add", 3)) {
			if (!parse_cpus(cli + 4, &first, &last)) {
				for (loop = first; loop <= last; loop++) {
					worker = worker_find(loop, 0);
					if (worker)
						continue;
					worker = worker_new(loop);
					if (worker)
						worker_add(worker);
				}
			}
		}

		/* Remove a cpu */
		else if (!strncmp(cli, "rm", 2)) {
			if (!parse_cpus(cli + 2, &first, &last)) {
				for (loop = first; loop <= last; loop++) {
					worker = worker_find(loop, 1);
					if (!worker)
						continue;
					if (worker != primary) {
						worker_free(worker);
						continue;
					}
					fprintf(stderr, "skipping cpu %d, it "
						"has responsibilities\n", loop);
				}
			}
		}

		/* Disable MACs */
		else if (!strncmp(cli, "macs_off", 8)) {
			struct rfl_if *i;
			list_for_each_entry(i, &ifs, node) {
				fman_if_disable_rx(i->port_cfg->fman_if);
				TRACE("Interface %d:%d, disabled RX\n",
					i->port_cfg->fman_if->fman_idx,
					i->port_cfg->fman_if->mac_idx);
			}
		}

		/* Enable MACs */
		else if (!strncmp(cli, "macs_on", 7)) {
			struct rfl_if *i;
			list_for_each_entry(i, &ifs, node) {
				TRACE("Interface %d:%d, enabling RX\n",
					i->port_cfg->fman_if->fman_idx,
					i->port_cfg->fman_if->mac_idx);
				fman_if_enable_rx(i->port_cfg->fman_if);
			}
		}

		/* Dump the CGR state */
		else if (!strncmp(cli, "cgr", 3)) {
#ifdef RFL_CGR
			worker = worker_first();
			msg_query_cgr(worker);
#else
			fprintf(stderr, "error: no CGR support\n");
#endif
		}

		/* try again */
		else
			fprintf(stderr, "unknown cmd: %s\n", cli);
	}
	/* success */
	rcode = 0;
leave:
	/* Remove all workers except the primary */
	list_for_each_entry_safe(worker, tmpworker, &workers, node) {
		if (worker != primary)
			worker_free(worker);
	}
	/* Do datapath dependent cleanup before removing the primary worker */
	msg_do_global_finish(primary);
	worker = primary;
	primary = NULL;
	worker_free(worker);
	usdpa_netcfg_release(cfg);
	return rcode;
}
