/* Copyright (c) 2010 Freescale Semiconductor, Inc.
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
#include <bigatomic.h>

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/ip.h>

/* if defined, be lippy about everything */
#undef RFL_TRACE

/* application configuration */
#define RFL_RX_HASH_SIZE	0x20
#define RFL_TX_NUM		0x10
#define RFL_IF_NUM		ARRAY_SIZE(ifid)
#define RFL_POOLCHANNEL_NUM	4
#define RFL_POOLCHANNEL_FIRST	4
/* n==interface, x=[0..(RFL_RX_HASH_SIZE-1)] */
#define RFL_FQID_RX_ERROR(n)	(0x50 + 2*(n))
#define RFL_FQID_RX_DEFAULT(n)	(0x51 + 2*(n))
#define RFL_FQID_TX_ERROR(n)	(0x70 + 2*(n))
#define RFL_FQID_TX_CONFIRM(n)	(0x71 + 2*(n))
#define RFL_FQID_RX_HASH(n,x)	(0x400 + 0x100*(n) + (x))
#define RFL_FQID_TX(n,x)	(0x480 + 0x100*(n) + (x & (RFL_TX_NUM - 1)))
#define RFL_PRIO_2DROP		3 /* error/default/etc */
#define RFL_PRIO_2FWD		4 /* rx-hash */
#define RFL_PRIO_2TX		4 /* consumed by Fman */
#define RFL_CHANNEL_TX(n)	((qm_channel_fman0_sp0 + 0x20 * ((n) / 5)) + ((n) + 1) % 5)
#define RFL_STASH_DATA_CL	1
#define RFL_STASH_CTX_CL(p) \
({ \
	__always_unused const typeof(*(p)) *foo = (p); \
	int foolen = sizeof(*foo) / 64; \
	if (foolen > 3) \
		foolen = 3; \
	foolen; \
})
#define RFL_CLI_BUFFER		(2*1024)
#define RFL_BPIDS		{7, 8, 9}
#define RFL_IFIDS		{4, 7, 8, 9}
#define RFL_CGRID		12
#define RFL_CGRID_TXMON		13
#define RFL_CGR_RX_PERFQ_THRESH	32
#define RFL_CGR_TX_PERFQ_THRESH 64

static const uint8_t bpids[] = RFL_BPIDS;
static const uint8_t ifid[] = RFL_IFIDS;
static const struct bman_bpid_range bpid_range[] =
	{ {FSL_BPID_RANGE_START, FSL_BPID_RANGE_LENGTH} };
static const struct bman_bpid_ranges bpid_allocator = {
	.num_ranges = 1,
	.ranges = bpid_range
};
static const struct qman_fqid_range fqid_range[] =
	{ {FSL_FQID_RANGE_START, FSL_FQID_RANGE_LENGTH} };
static const struct qman_fqid_ranges fqid_allocator = {
	.num_ranges = 1,
	.ranges = fqid_range
};

/* application options */
#undef RFL_2FWD_HOLDACTIVE	/* process each FQ on one cpu at a time */
#define RFL_2FWD_RX_PREFERINCACHE /* keep rx FQDs in-cache even when empty */
#define RFL_2FWD_TX_PREFERINCACHE /* keep tx FQDs in-cache even when empty */
#undef RFL_2FWD_RX_TD		/* whether to enable taildrop */
#define RFL_2FWD_RX_TD_THRESH 	295 /* keep ingress SFDR-only (<= 5 frames) */
#undef RFL_2FWD_TX_FORCESFDR	/* priority allocation of SFDRs to egress */
#define RFL_BACKOFF		/* consume cycles when EQCR/RCR is full */
#define RFL_BACKOFF_CYCLES	512
#undef RFL_DATA_DCBF		/* cache flush modified data during Tx */
#define RFL_DEPLETION		/* trace depletion entry/exit */
#undef RFL_DEPLETION_SWFLOW 	/* flow-control MACs based on bpool depl */
#define RFL_CGR			/* add rx and tx FQDs to the CGR */
#undef RFL_CGR_SWFLOW		/* flow-control MACs based on CGR notifs */
#undef RFL_CGR_HWFLOW		/* h/w flow-control using CGR taildrop */

/* Run checks */
#if defined(RFL_DEPLETION_SWFLOW) && !defined(RFL_DEPLETION)
#error "RFL_DEPLETION_SWFLOW depends on RFL_DEPLETION"
#endif
#if defined(RFL_CGR_SWFLOW) && !defined(RFL_CGR)
#error "RFL_CGR_SWFLOW depends on RFL_CGR"
#endif
#if defined(RFL_CGR_HWFLOW) && !defined(RFL_CGR)
#error "RFL_CGR_HWFLOW depends on RFL_CGR"
#endif

#if (defined(RFL_DEPLETION_SWFLOW) && \
	(defined(RFL_CGR_SWFLOW) || defined(RFL_CGR_HWFLOW))) || \
	(defined(RFL_CGR_SWFLOW) && defined(RFL_CGR_HWFLOW))
#error "only one kind of flow-control may be used at once"
#endif

/**********/
/* macros */
/**********/

/* Construct the SDQCR mask */
#define RFL_CPU_SDQCR() \
({ \
	u32 __foo = 0, __foo2 = RFL_POOLCHANNEL_FIRST; \
	while (__foo2 < (RFL_POOLCHANNEL_FIRST + RFL_POOLCHANNEL_NUM)) \
		__foo |= QM_SDQCR_CHANNELS_POOL(__foo2++); \
	__foo; \
})

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
	struct qman_fq fq_tx;
};

/* Each Fman i/face has one of these */
struct rfl_if {
	struct rfl_fq_2fwd rx_hash[RFL_RX_HASH_SIZE];
	struct rfl_fq_2drop rx_error;
	struct rfl_fq_2drop rx_default;
	struct rfl_fq_2drop tx_error;
	struct rfl_fq_2drop tx_confirm;
} ____cacheline_aligned;

/***************/
/* Global data */
/***************/

/* We want a trivial mapping from bpid->pool, so just have a 64-wide array of
 * pointers, most of which are NULL. */
static struct bman_pool *pool[64];

/* This array is allocated from the dma_mem region so that it DMAs OK */
static struct rfl_if *ifs;

#ifdef RFL_CGR
/* A congestion group to hold FQs */
static struct qman_cgr cgr;
#if !defined(RFL_CGR_SWFLOW)
/* Tx FQs go into a separate CGR unless doing s/w flow-control, which should be
 * based on total Rx+Tx build-up. (For h/w flow-control, we don't want to
 * trigger ERNs to s/w egress, and for no flow-control, we want to be able to
 * query Rx and Tx build-up independently.) */
static struct qman_cgr cgr_txmon;
#endif
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
#ifdef RFL_BACKOFF
		cpu_spin(RFL_BACKOFF_CYCLES);
#else
		barrier();
#endif
		goto retry;
	}
}

static inline void send_frame(struct qman_fq *fq, const struct qm_fd *fd)
{
	int ret;
retry:
	ret = qman_enqueue(fq, fd, 0);
	if (ret) {
#ifdef RFL_BACKOFF
		cpu_spin(RFL_BACKOFF_CYCLES);
#else
		barrier();
#endif
		goto retry;
	}
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
	opts.fqd.context_a.stashing.context_cl = RFL_STASH_CTX_CL(p);
	ret = qman_init_fq(&p->fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
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

#ifdef RFL_DATA_DCBF
/* Flush cacheline(s) containing the data starting at addr, size len */
static inline void cache_flush(void *addr, unsigned long len)
{
	void *s = (void *)((unsigned long)addr & ~(unsigned long)63);
	addr += len;
	while (s < addr) {
		dcbf(s);
		s += 64;
	}
}
#endif

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
#ifdef RFL_DATA_DCBF
		cache_flush(addr, (unsigned long)iphdr + 12 -
				(unsigned long)addr);
#endif
		TRACE("Tx: 2fwd	 fqid=%d\n", p->fq_tx.fqid);
		TRACE("	     phys=0x%08x, offset=%d, len=%d, bpid=%d\n",
			fd->addr_lo, fd->offset, fd->length20, fd->bpid);
		send_frame(&p->fq_tx, fd);
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

static void rfl_fq_2fwd_init(struct rfl_fq_2fwd *p, u32 rx_fqid, u32 tx_fqid,
			enum qm_channel channel, enum qm_channel tx_channel)
{
	struct qm_mcc_initfq opts;
	int ret;
	/* Each Rx FQ object has its own Tx FQ object, but that doesn't mean
	 * that each Rx FQID has its own Tx FQ FQID. As such, the Tx FQ object
	 * we're initialising here may be for a FQID that is already fronted by
	 * another FQ object, and thus the FQD would already be initialised.
	 * Before an enqueue may be attempted against a FQ object, the Qman API
	 * requires that it complete a successful qman_init_fq() operation or
	 * that the FQ object be declared with the QMAN_FQ_FLAG_NO_MODIFY flag.
	 * An application that has a single well-defined configuration could
	 * just initialise all the FQ objects such that the first occurance of a
	 * FQID perform the init() and the others use NO_MODIFY. But to allow
	 * this application to support wildly different configurations, it's
	 * preferable here to "discover" on-the-fly whether or not we're the
	 * first object for a given Tx FQID. We do this by handling failure of
	 * qman_init_fq() to imply that we're not the first user of the FQID (so
	 * revert to NO_MODIFY). The weakness of this scheme is that a real
	 * failure to initialise the Tx FQD (eg. if it's out of bounds or
	 * conflicts with some other FQ), will not be detected, and subsequent
	 * forwarding actions will have undefined consequences. */
	p->fq_tx.cb.ern = cb_ern_2fwd;
	ret = qman_create_fq(tx_fqid, QMAN_FQ_FLAG_TO_DCPORTAL, &p->fq_tx);
	BUG_ON(ret);
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = tx_channel;
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
#if defined(RFL_CGR_SWFLOW)
	/* Only subscribe Tx to the same CGR as Rx if CGR s/w flow-control is
	 * enabled. Otherwise, for h/w flow-control, we want that CGR to have
	 * only Rx, and for no flow-control we want the same but simply because
	 * that lets us query the level of Rx and Tx build-up independently. */
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
	pr_info("Adding Tx FQ %d to CGR %d\n", tx_fqid, cgr.cgrid);
#else
	/* But if tail-drop *is* enabled, we can subscribe Tx to the *txmon* CGR
	 * if desired. */
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_txmon.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
#endif
	opts.fqd.context_b = 0;
	opts.fqd.context_a.hi = 0x80000000;
	opts.fqd.context_a.lo = 0;
	ret = qman_init_fq(&p->fq_tx, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (ret) {
		/* revert to NO_MODIFY */
		qman_destroy_fq(&p->fq_tx, 0);
		ret = qman_create_fq(tx_fqid, QMAN_FQ_FLAG_NO_MODIFY, &p->fq_tx);
		BUG_ON(ret);
	}
	p->fq_rx.cb.dqrr = cb_dqrr_2fwd;
	ret = qman_create_fq(rx_fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &p->fq_rx);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2fwd" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_TDTHRESH;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = RFL_PRIO_2FWD;
	opts.fqd.fq_ctrl =
#ifdef RFL_2FWD_HOLDACTIVE
		QM_FQCTRL_HOLDACTIVE |
#endif
#ifdef RFL_2FWD_RX_PREFERINCACHE
		QM_FQCTRL_PREFERINCACHE |
#endif
#ifdef RFL_2FWD_RX_TD
		QM_FQCTRL_TDE |
#endif
		QM_FQCTRL_CTXASTASHING;
#ifdef RFL_CGR
	/* If there is a CGR, Rx is always subscribed to it */
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = RFL_STASH_CTX_CL(p);
	ret = qm_fqd_taildrop_set(&opts.fqd.td, RFL_2FWD_RX_TD_THRESH, 0);
	BUG_ON(ret);
	ret = qman_init_fq(&p->fq_rx, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

/*****************/
/* struct rfl_if */
/*****************/

/* Pick which pool channel to schedule a(ny) Rx FQ to using a 32-bit LFSR and
 * 'modulo'. This should help us avoid any bad harmonies, eg. if we just
 * scrolled round the pool channels in order, we could have all Rx errors come
 * to the same channel, or end up with hot flows "just happening" to beat on the
 * same channel.
 *
 * Update: for fear of this not balancing the assignment of FQs to pool channels
 * in an even way, I'm making sure that each sequence of RFL_POOLCHANNEL_NUM FQs
 * is assigned 1-to-1 with the same number of pool channels, and just using the
 * LFSR to randomise the order at that level.
 */
static u32 my_lfsr = 0xabbaf00d;
static unsigned long my_rxc_mask;
static int my_rxc_mask_used;
static enum qm_channel get_rxc(void)
{
	unsigned int choice;
	/* Find an unset bit in my_rxc_mask */
	do {
		my_lfsr = (my_lfsr >> 1) ^ (-(my_lfsr & 1u) & 0xd0000001u);
		choice = my_lfsr % RFL_POOLCHANNEL_NUM;
	} while (test_bit(choice, &my_rxc_mask));
	if (++my_rxc_mask_used == RFL_POOLCHANNEL_NUM) {
		my_rxc_mask_used = 0;
		clear_bits(~(unsigned long)0, &my_rxc_mask);
	}
	return qm_channel_pool1 + RFL_POOLCHANNEL_FIRST + choice - 1;
}

static void rfl_if_init(struct rfl_if *i, int idx)
{
	int loop;
	rfl_fq_2drop_init(&i->rx_error, RFL_FQID_RX_ERROR(idx), get_rxc());
	rfl_fq_2drop_init(&i->rx_default, RFL_FQID_RX_DEFAULT(idx), get_rxc());
	rfl_fq_2drop_init(&i->tx_error, RFL_FQID_TX_ERROR(idx), get_rxc());
	rfl_fq_2drop_init(&i->tx_confirm, RFL_FQID_TX_CONFIRM(idx), get_rxc());
	for (loop = 0; loop < RFL_RX_HASH_SIZE; loop++)
		rfl_fq_2fwd_init(&i->rx_hash[loop], RFL_FQID_RX_HASH(idx, loop),
			RFL_FQID_TX(idx, loop), get_rxc(), RFL_CHANNEL_TX(idx));
}

/******************************************************/
/* S/w flow-control, whether bpool-based or CGR-based */
/******************************************************/

/* If doing flow-control, depletion/congestion entry/exit may thrash quickly. So
 * the "freq_xctl" CLI command can modify the throttling of logging. */
static unsigned int freq_xctl = 1;
#define XCTL_EVENT_ACTIVE(pref, is_entry) \
	do { \
		if (is_entry) { \
			__mac_disable_all(); \
			pref##_num_xctl++; \
		} else \
			__mac_enable_all(); \
		/* bypass pr_info()s when appropriate */ \
		if (pref##_num_xctl % freq_xctl) \
			return; \
		if (is_entry) \
			pr_info("%s: num_xctl = %u\n", __func__, \
				pref##_num_xctl); \
	} while (0)
#define XCTL_EVENT_PASSIVE(pref, is_entry) \
	do { \
		if (is_entry) \
			pref##_num_xctl++; \
		/* bypass pr_info()s when appropriate */ \
		if (pref##_num_xctl % freq_xctl) \
			return; \
		if (is_entry) \
			pr_info("%s: num_xctl = %u\n", __func__, \
				pref##_num_xctl); \
	} while (0)

/*************************/
/* buffer-pool depletion */
/*************************/

#ifdef RFL_DEPLETION
#ifdef RFL_DEPLETION_SWFLOW
static unsigned int bp_num_xctl;
#endif
static void bp_depletion(struct bman_portal *bm __always_unused,
			struct bman_pool *p,
			void *cb_ctx __maybe_unused,
			int depleted)
{
	u8 bpid = bman_get_params(p)->bpid;
	BUG_ON(p != *(typeof(&p))cb_ctxt);

#ifdef RFL_DEPLETION_SWFLOW
	if (bpid == bpids[0])
		XCTL_EVENT_ACTIVE(bp, depleted);
#endif
	pr_info("%s: BP%u -> %s\n", __func__, bpid,
		depleted ? "entry" : "exit");
}
#endif

/*********************************/
/* CGR state-change notification */
/*********************************/

#ifdef RFL_CGR
#if defined(RFL_CGR_SWFLOW) || defined(RFL_CGR_HWFLOW)
static unsigned int cgr_num_xctl;
#endif
static void cgr_cb(struct qman_portal *qm, struct qman_cgr *c, int congested)
{
	BUG_ON(c != &cgr);

#ifdef RFL_CGR_SWFLOW
	XCTL_EVENT_ACTIVE(cgr, congested);
#elif defined(RFL_CGR_HWFLOW)
	XCTL_EVENT_PASSIVE(cgr, congested);
#endif
	pr_info("%s: CGR -> congestion %s\n", __func__,
		congested ? "entry" : "exit");
}
#if !defined(RFL_CGR_SWFLOW)
static unsigned int cgr_txmon_num_xctl;
static void cgr_cb_txmon(struct qman_portal *qm, struct qman_cgr *c,
			int congested)
{
	BUG_ON(c != &cgr_txmon);

	XCTL_EVENT_PASSIVE(cgr_txmon, congested);
	pr_info("%s: txmon CGR -> congestion %s\n", __func__,
		congested ? "entry" : "exit");
}
#endif
#endif

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
#ifdef RFL_CGR
		worker_msg_query_cgr
#endif
	} msg;
	pthread_barrier_t barr;
#ifdef RFL_CGR
	union {
		struct {
			struct qm_mcr_querycgr res;
#if !defined(RFL_CGR_SWFLOW)
			struct qm_mcr_querycgr res_txmon;
#endif
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

static noinline int process_msg(struct worker *worker, struct worker_msg *msg)
{
	int ret = 1;

	/* List */
	if (msg->msg == worker_msg_list)
		printf("Thread alive on cpu %d\n", worker->cpu);

	/* Quit */
	else if (msg->msg == worker_msg_quit) {
		int calm_down = 16;
		qman_static_dequeue_del(~(u32)0);
		while (calm_down--) {
			qman_poll_slow();
			qman_poll_dqrr(16);
		}
		qman_thread_finish();
		bman_thread_finish();
		printf("Stopping thread on cpu %d\n", worker->cpu);
		ret = 0;
	}

	/* Do global init */
	else if (msg->msg == worker_msg_do_global_init) {
		unsigned int loop;
		int err;

		/* Set up the bpid allocator */
		err = bman_setup_allocator(0, &bpid_allocator);
		if (err)
			fprintf(stderr, "error: BPID init, continuing\n");
		/* Set up the fqid allocator */
		err = qman_setup_allocator(0, &fqid_allocator);
		if (err)
			fprintf(stderr, "error: FQID init, continuing\n");
#ifdef RFL_CGR
		/* Set up the CGR for Rx (and possibly Tx) monitoring. If
		 * CGR_HWFLOW is enabled, Tx is not included because we don't
		 * want ERNs in the s/w egress path. */
		{
		struct qm_mcc_initcgr opts = {
			.we_mask = QM_CGR_WE_CSCN_EN | QM_CGR_WE_CSTD_EN |
				QM_CGR_WE_CS_THRES | QM_CGR_WE_MODE,
			.cgr = {
				.cscn_en = QM_CGR_EN,
#ifdef RFL_CGR_HWFLOW
				/* Enable CGR tail-drop, in this mode only Rx
				 * FQs will be subscribed to the CGR. */
				.cstd_en = QM_CGR_EN,
#endif
				.mode = QMAN_CGR_MODE_FRAME
			}
		};
#ifdef RFL_CGR_HWFLOW
		qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, RFL_IF_NUM *
			(RFL_CGR_RX_PERFQ_THRESH * RFL_RX_HASH_SIZE), 0);
#else
		qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, RFL_IF_NUM *
			((RFL_CGR_RX_PERFQ_THRESH * RFL_RX_HASH_SIZE) +
				(RFL_CGR_TX_PERFQ_THRESH * RFL_TX_NUM)), 0);
#endif
		/* initialise congestion group */
		cgr.cgrid = RFL_CGRID;
		cgr.cb = cgr_cb;
		err = qman_create_cgr(&cgr, QMAN_CGR_FLAG_USE_INIT, &opts);
		if (err)
			fprintf(stderr, "error: CGR init, continuing\n");
		}
#endif
#if !defined(RFL_CGR_SWFLOW)
		/* Set up the CGR for Tx monitoring. */
		{
		struct qm_mcc_initcgr opts = {
			.we_mask = QM_CGR_WE_CSCN_EN | QM_CGR_WE_CS_THRES |
					QM_CGR_WE_MODE,
			.cgr = {
				.cscn_en = QM_CGR_EN,
				.mode = QMAN_CGR_MODE_FRAME
			}
		};
		qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, RFL_IF_NUM *
			(RFL_CGR_TX_PERFQ_THRESH * RFL_TX_NUM), 0);
		/* initialise congestion group */
		cgr_txmon.cgrid = RFL_CGRID_TXMON;
		cgr_txmon.cb = cgr_cb_txmon;
		err = qman_create_cgr(&cgr_txmon, QMAN_CGR_FLAG_USE_INIT, &opts);
		if (err)
			fprintf(stderr, "error: CGR (txmon) init, continuing\n");
		}
#endif
		/* allocate interface structs in dma_mem region */
		ifs = dma_mem_memalign(64, RFL_IF_NUM * sizeof(*ifs));
		BUG_ON(!ifs);
		memset(ifs, 0, RFL_IF_NUM * sizeof(*ifs));
		for (loop = 0; loop < RFL_IF_NUM; loop++) {
			TRACE("Initialising interface %d\n", ifid[loop]);
			rfl_if_init(&ifs[loop], ifid[loop]);
		}
		/* initialise buffer pools */
		for (loop = 0; loop < sizeof(bpids); loop++) {
			struct bman_pool_params params = {
				.bpid	= bpids[loop],
#ifdef RFL_DEPLETION
				.flags	= BMAN_POOL_FLAG_ONLY_RELEASE |
					BMAN_POOL_FLAG_DEPLETION,
				.cb	= bp_depletion,
				.cb_ctx	= pool + bpids[loop]
#else
				.flags	= BMAN_POOL_FLAG_ONLY_RELEASE
#endif
			};
			TRACE("Initialising pool for bpid %d\n", bpids[loop]);
			pool[bpids[loop]] = bman_new_pool(&params);
			BUG_ON(!pool[bpids[loop]]);
		}
	}

#ifdef RFL_CGR
	/* Query the CGR state */
	else if (msg->msg == worker_msg_query_cgr) {
		int err = qman_query_cgr(&cgr, &msg->query_cgr.res);
		if (err)
			fprintf(stderr, "error: query CGR, continuing\n");
#if !defined(RFL_CGR_SWFLOW)
		err = qman_query_cgr(&cgr_txmon, &msg->query_cgr.res_txmon);
		if (err)
			fprintf(stderr, "error: query txmon CGR, continuing\n");
#endif
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

	/* Set the qman portal's SDQCR mask */
	qman_static_dequeue_add(RFL_CPU_SDQCR());

	/* Run! */
	TRACE("Starting poll loop on cpu %d\n", worker->cpu);
	while (check_msg(worker)) {
		qman_poll();
		bman_poll();
	}

end:
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
	printf("CGR ID: %d, selected fields;\n", cgr.cgrid);
	dump_cgr(&worker->msg->query_cgr.res);
#if !defined(RFL_CGR_SWFLOW)
	printf("txmon CGR ID: %d, selected fields;\n", cgr_txmon.cgrid);
	dump_cgr(&worker->msg->query_cgr.res_txmon);
#endif
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

/* Keep "workers" ordered by cpu on insert */
static void worker_add(struct worker *worker)
{
	struct worker *i;
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
	list_del(&worker->node);
	__worker_free(worker);
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

static struct worker *worker_first(void)
{
	if (list_empty(&workers))
		return NULL;
	return list_entry(workers.next, struct worker, node);
}

static void usage(void)
{
	fprintf(stderr, "usage: reflector [cpu-range]\n");
	fprintf(stderr, "where [cpu-range] is 'n' or 'm..n'\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	struct worker *worker, *tmpworker;
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
	/* - map shmem */
	TRACE("Initialising shmem\n");
	rcode = dma_mem_setup();
	if (rcode)
		fprintf(stderr, "error: shmem init, continuing\n");
	/* - discover+map MAC devices */
	TRACE("Initialising MACs\n");
	rcode = __mac_init();
	if (rcode)
		fprintf(stderr, "error: MAC init, continuing\n");

	/* Create the threads */
	TRACE("Starting %d threads for cpu-range '%s'\n",
		last - first + 1, argv[1]);
	for (loop = first; loop <= last; loop++) {
		worker = worker_new(loop);
		if (!worker) {
			rcode = -1;
			goto leave;
		}
		/* Do datapath initialisation in the first thread (we can't do
		 * it here, because it requires access to portals) */
		if (loop == first)
			msg_do_global_init(worker);
		worker_add(worker);
	}
	TRACE("Enabling MACs\n");
	rcode = __mac_enable_all();
	if (rcode)
		fprintf(stderr, "error: MAC enable, continuing\n");

	/* TODO: catch dead threads - for now, we rely on the dying thread to
	 * print an error, and for the CLI user to then "remove" it. */

	/* Run the CLI loop */
	while (1) {
		char cli[RFL_CLI_BUFFER];

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
					worker_free(worker);
				}
			}
		}

		/* Disable MACs */
		else if (!strncmp(cli, "macs_off", 8)) {
#if defined(RFL_DEPLETION_SWFLOW) || defined(RFL_CGR_SWFLOW)
			fprintf(stderr, "error: s/w flow-control drives MACs\n");
#else
			rcode = __mac_disable_all();
			if (rcode)
				fprintf(stderr, "error: MAC disable, continuing\n");
#endif
		}

		/* Enable MACs */
		else if (!strncmp(cli, "macs_on", 7)) {
#if defined(RFL_DEPLETION_SWFLOW) || defined(RFL_CGR_SWFLOW)
			fprintf(stderr, "error: s/w flow-control drives MACs\n");
#else
			rcode = __mac_enable_all();
			if (rcode)
				fprintf(stderr, "error: MAC enable, continuing\n");
#endif
		}

		/* Modify 'freq_xctl' */
		else if (!strncmp(cli, "freq_xctl", 9)) {
			char *endptr;
			unsigned long tmp = strtoul(cli + 9, &endptr, 0);
			if ((tmp == ULONG_MAX) || (endptr == (cli + 9)) ||
						(*endptr != '\0'))
				fprintf(stderr, "error: bad freq_xctl '%s'\n",
					cli + 9);
			/* the cast handles sizeof(long)!=sizeof(freq_xctl) */
			else if (!(unsigned int)tmp)
				fprintf(stderr, "error: freq_xctl must be non-zero\n");
			else
				freq_xctl = tmp;
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
	list_for_each_entry_safe(worker, tmpworker, &workers, node)
		worker_free(worker);
	__mac_finish();
	return rcode;
}
