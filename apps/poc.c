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

/* application settings/configuration */
#define POC_RX_HASH_SIZE	0x20
#define POC_IF_NUM		4
#define POC_FQID_RX_ERROR(n)	(0x50 + 2*(n))
#define POC_FQID_RX_DEFAULT(n)	(0x51 + 2*(n))
#define POC_FQID_TX_ERROR(n)	(0x70 + 2*(n))
#define POC_FQID_TX_CONFIRM(n)	(0x71 + 2*(n))
#define POC_FQID_RX_HASH(n)	(0x400 + 0x100*(n))
#define POC_FQID_TX(n)		(0x480 + 0x100*(n))
#define POC_PRIO_2DROP		3 /* error/default/etc */
#define POC_PRIO_2FWD		4 /* rx-hash */
#define POC_PRIO_2TX		4 /* consumed by Fman */
#define POC_CHANNEL_TX(n)	(qm_channel_fman0_sp1 + (n))
#define POC_CHANNEL_RX(n)	qm_channel_pool4
#define POC_CPU_SDQCR(x)	QM_SDQCR_CHANNELS_POOL(4)
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

/* We want a trivial mapping from bpid->pool, so just have a 64-wide array of
 * pointers, most of which are NULL. */
static struct bman_pool *pool[64];

/********************/
/* common functions */
/********************/

#ifdef POC_TRACE
#define TRACE		printf
#else
#define TRACE(x...)	do { ; } while(0)
#endif

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
		/* anything better than this to avoid thrashing but without
		 * going idle for too long? */
		barrier();
		goto retry;
	}
}

static inline void send_frame(struct qman_fq *fq, const struct qm_fd *fd)
{
	int ret;
retry:
	ret = qman_enqueue(fq, fd, 0);
	if (ret) {
		barrier();
		goto retry;
	}
}

/***********************/
/* struct poc_fq_2drop */
/***********************/

/* Rx FQs that count packets and drop (ie. "Rx error", "Rx default", "Tx
 * error", "Tx confirm"). */
struct poc_fq_2drop {
	struct qman_fq fq;
	struct bigatomic cnt;
};

static enum qman_cb_dqrr_result cb_dqrr_2drop(struct qman_portal *qm,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	struct poc_fq_2drop *p = container_of(fq, struct poc_fq_2drop, fq);
	TRACE("Rx: 2drop fqid=%d\n", fq->fqid);
	bigatomic_inc(&p->cnt);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static void poc_fq_2drop_init(struct poc_fq_2drop *p, u32 fqid,
				enum qm_channel channel)
{
	struct qm_mcc_initfq opts;
	int ret;
	bigatomic_set(&p->cnt, 0);
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

/*********************/
/* struct poc_fq_2tx */
/*********************/

/* Tx FQs that count EQs and ERNs (later <= former, obviously). */
struct poc_fq_2tx {
	struct qman_fq fq;
	struct bigatomic cnt;
	struct bigatomic cnt_ern;
};

static void cb_ern_2tx(struct qman_portal *qm, struct qman_fq *fq,
				const struct qm_mr_entry *msg)
{
	struct poc_fq_2tx *p = container_of(fq, struct poc_fq_2tx, fq);
	bigatomic_inc(&p->cnt_ern);
	drop_frame(&msg->ern.fd);
}

static void poc_fq_2tx_init(struct poc_fq_2tx *p, u32 fqid,
				enum qm_channel channel)
{
	struct qm_mcc_initfq opts;
	int ret;
	bigatomic_set(&p->cnt, 0);
	bigatomic_set(&p->cnt_ern, 0);
	p->fq.cb.ern = cb_ern_2tx;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_TO_DCPORTAL, &p->fq);
	BUG_ON(ret);
	opts.we_mask = QM_INITFQ_WE_DESTWQ	|
		       QM_INITFQ_WE_CONTEXTB	| QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = POC_PRIO_2TX;
	opts.fqd.context_b = 0;
	opts.fqd.context_a.hi = 0x80000000;
	opts.fqd.context_a.lo = 0;
	ret = qman_init_fq(&p->fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

static void poc_fq_2tx_send(struct poc_fq_2tx *p, const struct qm_fd *fd)
{
	TRACE("Tx: 2tx   fqid=%d\n", p->fq.fqid);
	TRACE("      phys=0x%08x, offset=%d, len=%d, bpid=%d\n",
		fd->addr_lo, fd->offset, fd->length20, fd->bpid);
	bigatomic_inc(&p->cnt);
	send_frame(&p->fq, fd);
}

/**********************/
/* struct poc_fq_2fwd */
/**********************/

/* Rx FQs that fwd, count packets and drop-decisions. */
struct poc_fq_2fwd {
	struct qman_fq fq;
	struct bigatomic cnt;
	struct bigatomic cnt_drop_bcast;
	struct bigatomic cnt_drop_arp;
	struct bigatomic cnt_drop_other;
	struct poc_fq_2tx *tx;
} ____cacheline_aligned;

static enum qman_cb_dqrr_result cb_dqrr_2fwd(struct qman_portal *qm,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	struct poc_fq_2fwd *p = container_of(fq, struct poc_fq_2fwd, fq);
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
	bigatomic_inc(&p->cnt);
	TRACE("      dhost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_dhost[0], prot_eth->ether_dhost[1],
		prot_eth->ether_dhost[2], prot_eth->ether_dhost[3],
		prot_eth->ether_dhost[4], prot_eth->ether_dhost[5]);
	TRACE("      shost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_shost[0], prot_eth->ether_shost[1],
		prot_eth->ether_shost[2], prot_eth->ether_shost[3],
		prot_eth->ether_shost[4], prot_eth->ether_shost[5]);
	TRACE("      ether_type=%04x\n", prot_eth->ether_type);
	/* Eliminate ethernet broadcasts. memcpy() would be cleaner, but
	 * probably slower... */
	if (prot_eth->ether_dhost[0] & 0x01) {
		TRACE("      -> dropping broadcast packet\n");
		bigatomic_inc(&p->cnt_drop_bcast);
	} else
	switch (prot_eth->ether_type)
	{
	case ETH_P_IP:
		TRACE("        -> it's ETH_P_IP!\n");
		{
		struct iphdr *iphdr = addr + 14;
		__be32 tmp;
		struct ether_addr tmp2;
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
		/* switch ethernet src/dest MAC addresses (we're aligned so
		 * should try to do better than memcpy()...) */
		memcpy(&tmp2, prot_eth->ether_dhost, sizeof(tmp2));
		memcpy(prot_eth->ether_dhost, prot_eth->ether_shost,
			sizeof(tmp2));
		memcpy(prot_eth->ether_shost, &tmp2, sizeof(tmp2));
		}
		poc_fq_2tx_send(p->tx, fd);
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
		bigatomic_inc(&p->cnt_drop_arp);
		break;
	default:
		TRACE("        -> it's UNKNOWN (!!) type 0x%04x\n",
			prot_eth->ether_type);
		TRACE("           -> dropping unknown packet\n");
		bigatomic_inc(&p->cnt_drop_other);
	}
	drop_frame(fd);
	return qman_cb_dqrr_consume;
}

static void poc_fq_2fwd_init(struct poc_fq_2fwd *p, u32 fqid,
			enum qm_channel channel, struct poc_fq_2tx *tx)
{
	struct qm_mcc_initfq opts;
	int ret;
	bigatomic_set(&p->cnt, 0);
	bigatomic_set(&p->cnt_drop_bcast, 0);
	bigatomic_set(&p->cnt_drop_arp, 0);
	bigatomic_set(&p->cnt_drop_other, 0);
	p->tx = tx;
	p->fq.cb.dqrr = cb_dqrr_2fwd;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, &p->fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2fwd" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = POC_PRIO_2FWD;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = POC_STASH_CTX_CL(p);
	ret = qman_init_fq(&p->fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

/*****************/
/* struct poc_if */
/*****************/

/* Each DTSEC i/face (fm1-dtsec[0123]) has one of these */
struct poc_if {
	struct poc_fq_2fwd rx_hash[POC_RX_HASH_SIZE];
	struct poc_fq_2drop rx_error;
	struct poc_fq_2drop rx_default;
	struct poc_fq_2drop tx_error;
	struct poc_fq_2drop tx_confirm;
	struct poc_fq_2tx tx;
	enum qm_channel rx_channel_id;
	enum qm_channel tx_channel_id;
} ____cacheline_aligned;

static void poc_if_init(struct poc_if *i, int idx)
{
	int loop, rxh = POC_FQID_RX_HASH(idx);
	enum qm_channel rxc = i->rx_channel_id = POC_CHANNEL_RX(idx);
	enum qm_channel txc = i->tx_channel_id = POC_CHANNEL_TX(idx);
	poc_fq_2drop_init(&i->rx_error, POC_FQID_RX_ERROR(idx), rxc);
	poc_fq_2drop_init(&i->rx_default, POC_FQID_RX_DEFAULT(idx), rxc);
	poc_fq_2drop_init(&i->tx_error, POC_FQID_TX_ERROR(idx), rxc);
	poc_fq_2drop_init(&i->tx_confirm, POC_FQID_TX_CONFIRM(idx), rxc);
	poc_fq_2tx_init(&i->tx, POC_FQID_TX(idx), txc);
	for (loop = 0; loop < POC_RX_HASH_SIZE; loop++, rxh++)
		poc_fq_2fwd_init(&i->rx_hash[loop], rxh, rxc, &i->tx);
}

/*******/
/* app */
/*******/

/* This array is allocated from the shmem region so it DMAs OK */
static struct poc_if *ifs;

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
	TRACE("This is the thread on cpu %d\n", tdata->cpu);

	sync_start_if_master(tdata) {
		int loop;
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
