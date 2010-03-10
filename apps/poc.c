/*
 * Copyright (c) 2010 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor RESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "common.h"

/* if defined, be lippy about everything */
#define POC_TRACE

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
	__UNUSED const typeof(*(p)) *foo = (p); \
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
	opts.we_mask = QM_INITFQ_WE_DESTWQ;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = POC_PRIO_2TX;
	ret = qman_init_fq(&p->fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

/**********************/
/* struct poc_fq_2fwd */
/**********************/

/* Rx FQs that fwd, count packets and drop-decisions. */
struct poc_fq_2fwd {
	struct qman_fq fq;
	struct bigatomic cnt;
	struct bigatomic cnt_drop_notipv4;
	struct bigatomic cnt_drop_bcast;
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
	TRACE("      dhost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_dhost[0], prot_eth->ether_dhost[1],
		prot_eth->ether_dhost[2], prot_eth->ether_dhost[3],
		prot_eth->ether_dhost[4], prot_eth->ether_dhost[5]);
	TRACE("      shost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_shost[0], prot_eth->ether_shost[1],
		prot_eth->ether_shost[2], prot_eth->ether_shost[3],
		prot_eth->ether_shost[4], prot_eth->ether_shost[5]);
	TRACE("      ether_type=%04x\n", prot_eth->ether_type);
	if (prot_eth->ether_type == ETH_P_IP)
		TRACE("        -> it's ETH_P_IP!\n");
	else if (prot_eth->ether_type == ETH_P_ARP)
		TRACE("        -> it's ETH_P_ARP!\n");
	else
		TRACE("        -> it's type 0x%04x\n", prot_eth->ether_type);
	bigatomic_inc(&p->cnt);
	/* FIXME: duh */
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static void poc_fq_2fwd_init(struct poc_fq_2fwd *p, u32 fqid,
			enum qm_channel channel, struct poc_fq_2tx *tx)
{
	struct qm_mcc_initfq opts;
	int ret;
	bigatomic_set(&p->cnt, 0);
	bigatomic_set(&p->cnt_drop_notipv4, 0);
	bigatomic_set(&p->cnt_drop_bcast, 0);
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
#if 0
	struct poc_fq_2drop rx_default;
#else
	struct poc_fq_2fwd rx_default;
#endif
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
#if 0
	poc_fq_2drop_init(&i->rx_default, POC_FQID_RX_DEFAULT(idx), rxc);
#else
	poc_fq_2fwd_init(&i->rx_default, POC_FQID_RX_DEFAULT(idx), rxc, &i->tx);
#endif
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
		ifs = fsl_shmem_memalign(64, POC_IF_NUM * sizeof(*ifs));
		BUG_ON(!ifs);
		memset(ifs, 0, POC_IF_NUM * sizeof(*ifs));
		for (loop = 0; loop < POC_IF_NUM; loop++) {
			TRACE("Initialising interface %d\n", loop);
			poc_if_init(&ifs[loop], loop);
		}
		for (loop = 0; loop < sizeof(bpids); loop++) {
			struct bman_pool_params params = {
				.bpid = bpids[loop],
				.flags = BMAN_POOL_FLAG_ONLY_RELEASE
			};
			TRACE("Initialising pool for bpid %d\n", bpids[loop]);
			pool[bpids[loop]] = bman_new_pool(&params);
			BUG_ON(!pool[bpids[loop]]);
		}
	}
	sync_end(tdata);

	qman_static_dequeue_add(POC_CPU_SDQCR(tdata->index));

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
	printf("Starting %d threads for cpu-range '%s'\n",
		last - first + 1, argv[1]);
	ret = run_threads(thread_data, last - first + 1, first, worker_fn);
	if (ret != 0)
		handle_error_en(ret, "run_threads");

	printf("Done\n");
	exit(EXIT_SUCCESS);
}
