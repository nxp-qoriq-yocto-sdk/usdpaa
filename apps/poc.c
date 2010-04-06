/* Copyright (c) 2010 Freescale Semiconductor, Inc.
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

#include "common.h"

/* if defined, be lippy about everything */
#undef POC_TRACE

/* application configuration */
#define POC_RX_HASH_SIZE	0x20
#define POC_IF_NUM		4
#define POC_POOLCHANNEL_NUM	4
#define POC_POOLCHANNEL_FIRST	4
/* n==interface, x=[0..(POC_RX_HASH_SIZE-1)] */
#define POC_FQID_RX_ERROR(n)	(0x50 + 2*(n))
#define POC_FQID_RX_DEFAULT(n)	(0x51 + 2*(n))
#define POC_FQID_TX_ERROR(n)	(0x70 + 2*(n))
#define POC_FQID_TX_CONFIRM(n)	(0x71 + 2*(n))
#define POC_FQID_RX_HASH(n,x)	(0x400 + 0x100*(n) + (x))
#define POC_FQID_TX(n,x)	(0x480 + 0x100*(n) + (x & 15))
#define POC_PRIO_2DROP		3 /* error/default/etc */
#define POC_PRIO_2FWD		4 /* rx-hash */
#define POC_PRIO_2TX		4 /* consumed by Fman */
#define POC_CHANNEL_TX(n)	(qm_channel_fman0_sp1 + (n))
#define POC_STASH_DATA_CL	1
#define POC_STASH_CTX_CL(p) \
({ \
	__always_unused const typeof(*(p)) *foo = (p); \
	int foolen = sizeof(*foo) / 64; \
	if (foolen > 3) \
		foolen = 3; \
	foolen; \
})
#define POC_BPIDS		{7, 8, 9}

/* application options */
#undef POC_2FWD_HOLDACTIVE	/* process each FQ on one cpu at a time */
#define POC_2FWD_RX_PREFERINCACHE /* keep rx FQDs in-cache even when empty */
#define POC_2FWD_TX_PREFERINCACHE /* keep tx FQDs in-cache even when empty */
#undef POC_2FWD_RX_TD		/* whether to enable taildrop */
#define POC_2FWD_RX_TD_THRESH 64000
#undef POC_BACKOFF		/* consume cycles when EQCR/RCR is full */
#define POC_BACKOFF_CYCLES	200
#define POC_COUNTERS		/* enable counters */
#undef POC_COUNTERS_SUCCESS	/*   not just errors, count everything */

/**********/
/* macros */
/**********/

/* Construct the SDQCR mask */
#define POC_CPU_SDQCR(x) \
({ \
	u32 __foo = 0, __foo2 = POC_POOLCHANNEL_FIRST; \
	while (__foo2 < (POC_POOLCHANNEL_FIRST + POC_POOLCHANNEL_NUM)) \
		__foo |= QM_SDQCR_CHANNELS_POOL(__foo2++); \
	__foo; \
})

#ifdef POC_TRACE
#define TRACE		printf
#else
#define TRACE(x...)	do { ; } while(0)
#endif

#ifdef POC_COUNTERS
#define CNT(a)      struct bigatomic a
#define CNT_INC(a)  bigatomic_inc(a)
#else
#define CNT(a)      struct { }
#define CNT_INC(a)  do { ; } while (0)
#endif

/*******************/
/* Data structures */
/*******************/

/* Rx FQs that count packets and drop (ie. "Rx error", "Rx default", "Tx
 * error", "Tx confirm"). */
struct poc_fq_2drop {
	struct qman_fq fq;
	size_t percpu_offset;
};
struct poc_fq_2drop_percpu {
	CNT(cnt);
};
#define set_fq_2drop_percpu(p,pc) \
do { \
	struct poc_fq_2drop *__foo = (p); \
	struct poc_fq_2drop_percpu *__foo2 = (pc); \
	__foo->percpu_offset = (unsigned long)__foo2 - \
			(unsigned long)&ifs_percpu[0]; \
} while (0)
#define get_fq_2drop_percpu(p) \
(struct poc_fq_2drop_percpu *)({ \
	struct poc_fq_2drop *__foo = (p); \
	(void *)ifs_percpu + __foo->percpu_offset; \
})

/* Rx FQs that fwd, count packets and drop-decisions. */
struct poc_fq_2fwd {
	struct qman_fq fq_rx;
	struct qman_fq fq_tx;
	size_t percpu_offset;
};
struct poc_fq_2fwd_percpu {
#ifdef POC_COUNTERS_SUCCESS
	CNT(cnt);
#endif
#ifdef POC_COUNTERS_SUCCESS
	CNT(cnt_tx);
#endif
	CNT(cnt_tx_ern);
	CNT(cnt_drop_bcast);
	CNT(cnt_drop_arp);
	CNT(cnt_drop_other);
} ____cacheline_aligned;
#define set_fq_2fwd_percpu(p,pc) \
do { \
	struct poc_fq_2fwd *__foo = (p); \
	struct poc_fq_2fwd_percpu *__foo2 = (pc); \
	__foo->percpu_offset = (unsigned long)__foo2 - \
			(unsigned long)&ifs_percpu[0]; \
} while (0)
#define get_fq_2fwd_percpu(p) \
(struct poc_fq_2fwd_percpu *)({ \
	struct poc_fq_2fwd *__foo = (p); \
	(void *)ifs_percpu + __foo->percpu_offset; \
})

/* Each DTSEC i/face (fm1-dtsec[0123]) has one of these */
struct poc_if {
	struct poc_fq_2fwd rx_hash[POC_RX_HASH_SIZE];
	struct poc_fq_2drop rx_error;
	struct poc_fq_2drop rx_default;
	struct poc_fq_2drop tx_error;
	struct poc_fq_2drop tx_confirm;
	size_t percpu_offset;
} ____cacheline_aligned;
struct poc_if_percpu {
	struct poc_fq_2fwd_percpu rx_hash[POC_RX_HASH_SIZE];
	struct poc_fq_2drop_percpu rx_error;
	struct poc_fq_2drop_percpu rx_default;
	struct poc_fq_2drop_percpu tx_error;
	struct poc_fq_2drop_percpu tx_confirm;
};
#define set_if_percpu(p,pc) \
do { \
	struct poc_if *__foo = (p); \
	struct poc_if_percpu *__foo2 = (pc); \
	__foo->percpu_offset = (unsigned long)__foo2 - \
			(unsigned long)&ifs_percpu[0]; \
} while (0)
#define get_if_percpu(p) \
(struct poc_if_percpu *)({ \
	struct poc_if *__foo = (p); \
	(void *)ifs_percpu + __foo->percpu_offset; \
})

/***************/
/* Global data */
/***************/

/* We want a trivial mapping from bpid->pool, so just have a 64-wide array of
 * pointers, most of which are NULL. */
static struct bman_pool *pool[64];

/* This array is allocated from the shmem region so that it DMAs OK */
static struct poc_if *ifs;

/* A per-cpu shadown structure for keeping stats */
static __PERCPU struct poc_if_percpu ifs_percpu[POC_IF_NUM];

/********************/
/* common functions */
/********************/

/* Rx handling either leads to a forward (qman enqueue) or a drop (bman
 * release). In either case, we're in the callback so can't "block" (by using a
 * WAIT flag) and we don't want to defer until outside the callback, because we
 * still have to pushback somehow and as we're a run-to-completion app, we don't
 * have anything else to do than simply retry. So ... we simply retry
 * non-blocking enqueues/releases until they work, which implicitly pushes back
 * on dequeue handling. */
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
#ifdef POC_BACKOFF
		cpu_spin(POC_BACKOFF_CYCLES);
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
#ifdef POC_BACKOFF
		cpu_spin(POC_BACKOFF_CYCLES);
#else
		barrier();
#endif
		goto retry;
	}
}

/***********************/
/* struct poc_fq_2drop */
/***********************/

static enum qman_cb_dqrr_result cb_dqrr_2drop(struct qman_portal *qm,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	__maybe_unused struct poc_fq_2drop *p = container_of(fq,
					struct poc_fq_2drop, fq);
	__maybe_unused struct poc_fq_2drop_percpu *pc = get_fq_2drop_percpu(p);
	TRACE("Rx: 2drop fqid=%d\n", fq->fqid);
	CNT_INC(&pc->cnt);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static void poc_fq_2drop_init(struct poc_fq_2drop *p,
				struct poc_fq_2drop_percpu *pc, u32 fqid,
				enum qm_channel channel)
{
	struct qm_mcc_initfq opts;
	int ret;
	set_fq_2drop_percpu(p, pc);
	p->fq.cb.dqrr = cb_dqrr_2drop;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &p->fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2drop" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = POC_PRIO_2DROP;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = POC_STASH_CTX_CL(p);
	ret = qman_init_fq(&p->fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

/**********************/
/* struct poc_fq_2fwd */
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

static enum qman_cb_dqrr_result cb_dqrr_2fwd(struct qman_portal *qm,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	struct poc_fq_2fwd *p = container_of(fq, struct poc_fq_2fwd, fq_rx);
	__maybe_unused struct poc_fq_2fwd_percpu *pc = get_fq_2fwd_percpu(p);
	const struct qm_fd *fd = &dqrr->fd;
	void *addr;
	struct ether_header *prot_eth;

	BUG_ON(fd->format != qm_fd_contig);
	addr = fsl_shmem_ptov(fd->addr_lo);
	TRACE("Rx: 2fwd  fqid=%d\n", fq->fqid);
	TRACE("      phys=0x%08x, virt=%p, offset=%d, len=%d, bpid=%d\n",
		fd->addr_lo, addr, fd->offset, fd->length20, fd->bpid);
	addr += fd->offset;
	prot_eth = addr;
#ifdef POC_COUNTERS_SUCCESS
	CNT_INC(&pc->cnt);
#endif
	TRACE("      dhost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_dhost[0], prot_eth->ether_dhost[1],
		prot_eth->ether_dhost[2], prot_eth->ether_dhost[3],
		prot_eth->ether_dhost[4], prot_eth->ether_dhost[5]);
	TRACE("      shost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_shost[0], prot_eth->ether_shost[1],
		prot_eth->ether_shost[2], prot_eth->ether_shost[3],
		prot_eth->ether_shost[4], prot_eth->ether_shost[5]);
	TRACE("      ether_type=%04x\n", prot_eth->ether_type);
	/* Eliminate ethernet broadcasts. */
	if (prot_eth->ether_dhost[0] & 0x01) {
		TRACE("      -> dropping broadcast packet\n");
		CNT_INC(&pc->cnt_drop_bcast);
	} else
	switch (prot_eth->ether_type)
	{
	case ETH_P_IP:
		TRACE("        -> it's ETH_P_IP!\n");
		{
		struct iphdr *iphdr = addr + 14;
		__be32 tmp;
#ifdef POC_TRACE
		u8 *src = (void *)&iphdr->saddr;
		u8 *dst = (void *)&iphdr->daddr;
		TRACE("           ver=%d,ihl=%d,tos=%d,len=%d,id=%d\n",
			iphdr->version, iphdr->ihl, iphdr->tos, iphdr->tot_len,
			iphdr->id);
		TRACE("           frag_off=%d,ttl=%d,prot=%d,csum=0x%04x\n",
			iphdr->frag_off, iphdr->ttl, iphdr->protocol,
			iphdr->check);
		TRACE("           src=%d.%d.%d.%d\n",
			src[0], src[1], src[2], src[3]);
		TRACE("           dst=%d.%d.%d.%d\n",
			dst[0], dst[1], dst[2], dst[3]);
#endif
		/* switch ipv4 src/dst addresses */
		tmp = iphdr->daddr;
		iphdr->daddr = iphdr->saddr;
		iphdr->saddr = tmp;
		/* switch ethernet src/dest MAC addresses */
		ether_header_swap(prot_eth);
		TRACE("Tx: 2fwd  fqid=%d\n", p->tx.fqid);
		TRACE("      phys=0x%08x, offset=%d, len=%d, bpid=%d\n",
			fd->addr_lo, fd->offset, fd->length20, fd->bpid);
#ifdef POC_COUNTERS_SUCCESS
		CNT_INC(&pc->cnt_tx);
#endif
		send_frame(&p->fq_tx, fd);
		}
		return qman_cb_dqrr_consume;
	case ETH_P_ARP:
		TRACE("        -> it's ETH_P_ARP!\n");
#ifdef POC_TRACE
		{
		struct arphdr *arphdr = addr + 14;
		TRACE("           hrd=%d, pro=%d, hln=%d, pln=%d, op=%d\n",
			arphdr->ar_hrd, arphdr->ar_pro, arphdr->ar_hln,
			arphdr->ar_pln, arphdr->ar_op);
		}
#endif
		TRACE("           -> dropping ARP packet\n");
		CNT_INC(&pc->cnt_drop_arp);
		break;
	default:
		TRACE("        -> it's UNKNOWN (!!) type 0x%04x\n",
			prot_eth->ether_type);
		TRACE("           -> dropping unknown packet\n");
		CNT_INC(&pc->cnt_drop_other);
	}
	drop_frame(fd);
	return qman_cb_dqrr_consume;
}

static void cb_ern_2fwd(struct qman_portal *qm, struct qman_fq *fq,
				const struct qm_mr_entry *msg)
{
	__maybe_unused struct poc_fq_2fwd *p = container_of(fq,
					struct poc_fq_2fwd, fq_tx);
	__maybe_unused struct poc_fq_2fwd_percpu *pc = get_fq_2fwd_percpu(p);
	CNT_INC(&pc->cnt_tx_ern);
	drop_frame(&msg->ern.fd);
}

static void poc_fq_2fwd_init(struct poc_fq_2fwd *p,
			struct poc_fq_2fwd_percpu *pc, u32 rx_fqid, u32 tx_fqid,
			enum qm_channel channel, enum qm_channel tx_channel)
{
	struct qm_mcc_initfq opts;
	int ret;
	set_fq_2fwd_percpu(p, pc);
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
	opts.fqd.dest.wq = POC_PRIO_2TX;
	opts.fqd.fq_ctrl =
#ifdef POC_2FWD_TX_PREFERINCACHE
		QM_FQCTRL_PREFERINCACHE |
#endif
		0;
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
	opts.fqd.dest.wq = POC_PRIO_2FWD;
	opts.fqd.fq_ctrl =
#ifdef POC_2FWD_HOLDACTIVE
		QM_FQCTRL_HOLDACTIVE |
#endif
#ifdef POC_2FWD_RX_PREFERINCACHE
		QM_FQCTRL_PREFERINCACHE |
#endif
#ifdef POC_2FWD_RX_TD
		QM_FQCTRL_TDE |
#endif
		QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = POC_STASH_CTX_CL(p);
	ret = qm_fqd_taildrop_set(&opts.fqd.td, POC_2FWD_RX_TD_THRESH, 0);
	BUG_ON(ret);
	ret = qman_init_fq(&p->fq_rx, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

/*****************/
/* struct poc_if */
/*****************/

/* Pick which pool channel to schedule a(ny) Rx FQ to using a 32-bit LFSR and
 * 'modulo'. This should help us avoid any bad harmonies, eg. if we just
 * scrolled round the pool channels in order, we could have all Rx errors come
 * to the same channel, or end up with hot flows "just happening" to beat on the
 * same channel. */
static u32 my_lfsr = 0xabbaf00d;
static enum qm_channel get_rxc(void)
{
	u32 tmp;
	int n;
	my_lfsr = (my_lfsr >> 1) ^ (-(my_lfsr & 1u) & 0xd0000001u);
	tmp = (my_lfsr & 0x00ffff00) >> 8;
	n = POC_POOLCHANNEL_FIRST + (tmp % POC_POOLCHANNEL_NUM);
	return qm_channel_pool1 + (n - 1);
}

static void poc_if_init(struct poc_if *i, int idx)
{
	int loop;
	struct poc_if_percpu *pc = &ifs_percpu[idx];
	set_if_percpu(i, pc);
	poc_fq_2drop_init(&i->rx_error, &pc->rx_error,
			POC_FQID_RX_ERROR(idx), get_rxc());
	poc_fq_2drop_init(&i->rx_default, &pc->rx_default,
			POC_FQID_RX_DEFAULT(idx), get_rxc());
	poc_fq_2drop_init(&i->tx_error, &pc->tx_error,
			POC_FQID_TX_ERROR(idx), get_rxc());
	poc_fq_2drop_init(&i->tx_confirm, &pc->tx_confirm,
			POC_FQID_TX_CONFIRM(idx), get_rxc());
	for (loop = 0; loop < POC_RX_HASH_SIZE; loop++)
		poc_fq_2fwd_init(&i->rx_hash[loop], &pc->rx_hash[loop],
				POC_FQID_RX_HASH(idx, loop),
				POC_FQID_TX(idx, loop),
				get_rxc(), POC_CHANNEL_TX(idx));
}

/*******/
/* app */
/*******/

static void calm_down(void)
{
	int die_slowly = 1000;
	/* FIXME: there may be stale MR entries (eg. FQRNIs that the driver
	 * ignores and drops in the bin), but these will hamper any attempt to
	 * run another user-driver instance after we exit. Loop on the portal
	 * processing a bit to let it "go idle". */
	while (die_slowly--) {
		barrier();
		qman_poll();
		bman_poll();
	}
}

static int worker_fn(thread_data_t *tdata)
{
	int loop;
	TRACE("This is the thread on cpu %d\n", tdata->cpu);

	sync_if_master(tdata) {
		u8 bpids[] = POC_BPIDS;
		/* initialise interfaces */
		ifs = fsl_shmem_memalign(64, POC_IF_NUM * sizeof(*ifs));
		BUG_ON(!ifs);
		memset(ifs, 0, POC_IF_NUM * sizeof(*ifs));
		for (loop = 0; loop < POC_IF_NUM; loop++) {
			TRACE("Initialising interface %d\n", loop);
			poc_if_init(&ifs[loop], loop);
		}
		/* initialise buffer pools */
		for (loop = 0; loop < sizeof(bpids); loop++) {
			struct bman_pool_params params = {
				.bpid = bpids[loop],
				.flags = BMAN_POOL_FLAG_ONLY_RELEASE
			};
			TRACE("Initialising pool for bpid %d\n", bpids[loop]);
			pool[bpids[loop]] = bman_new_pool(&params);
			BUG_ON(!pool[bpids[loop]]);
		}
		/* ready to go, open the flood-gates */
		__mac_enable_all();
	}
	sync_end(tdata);

	qman_static_dequeue_add(POC_CPU_SDQCR(tdata->index));

	printf("Starting poll loop on cpu %d\n", tdata->cpu);
	while (1) {
		qman_poll();
		bman_poll();
	}

	calm_down();
	TRACE("Leaving thread on cpu %d\n", tdata->cpu);
	return 0;
}

int main(int argc, char *argv[])
{
	thread_data_t thread_data[MAX_THREADS];
	int ret, first, last;
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (ncpus == 1)
		first = last = 0;
	else {
		first = 1;
		last = ncpus - 1;
	}
	if (argc == 2) {
		char *endptr;
		first = my_toul(argv[1], &endptr, ncpus);
		if (*endptr == '\0') {
			last = first;
		} else if ((*(endptr++) == '.') && (*(endptr++) == '.') &&
				(*endptr != '\0')) {
			last = my_toul(endptr, &endptr, ncpus);
			if (last < first) {
				ret = first;
				first = last;
				last = ret;
			}
		} else {
			fprintf(stderr, "error: can't parse cpu-range '%s'\n",
				argv[1]);
			exit(-1);
		}
	} else if (argc != 1) {
		fprintf(stderr, "usage: poc [cpu-range]\n");
		fprintf(stderr, "where [cpu-range] is 'n' or 'm..n'\n");
		exit(-1);
	}

	/* Create the threads */
	TRACE("Starting %d threads for cpu-range '%s'\n",
		last - first + 1, argv[1]);
	ret = run_threads(thread_data, last - first + 1, first, worker_fn);
	if (ret != 0)
		handle_error_en(ret, "run_threads");

	TRACE("Done\n");
	exit(EXIT_SUCCESS);
}
