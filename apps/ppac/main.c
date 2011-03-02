/* Copyright (c) 2010 - 2011 Freescale Semiconductor, Inc.
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

#include <ppac.h>

#include <stdlib.h>
#include <unistd.h>
#include <readline.h>  /* libedit */

/***************/
/* Global data */
/***************/

/* Configuration */
struct usdpaa_netcfg_info *netcfg;
/* Default paths to configuration files - these are determined from the build,
 * but can be overriden at run-time using "DEF_PCD_PATH" and "DEF_CFG_PATH"
 * environment variables. */
const char ppam_pcd_path[] __attribute__((weak)) = __stringify(DEF_PCD_PATH);
const char ppam_cfg_path[] __attribute__((weak)) = __stringify(DEF_CFG_PATH);

/* The SDQCR mask to use (computed from netcfg's pool-channels) */
static uint32_t sdqcr;

/* We want a trivial mapping from bpid->pool, so just have a 64-wide array of
 * pointers, most of which are NULL. */
struct bman_pool *pool[64];

/* The interfaces in this list are allocated from dma_mem (stashing==DMA) */
LIST_HEAD(ifs);

/* The forwarding logic uses a per-cpu FQ object for handling enqueues (and
 * ERNs), irrespective of the destination FQID. In this way, cache-locality is
 * more assured, and any ERNs that do occur will show up on the same CPUs they
 * were enqueued from. This works because ERN messages contain the FQID of the
 * original enqueue operation, so in principle any demux that's required by the
 * ERN callback can be based on that. Ie. the FQID set within "local_fq" is from
 * whatever the last executed enqueue was, the ERN handler can ignore it. */
__PERCPU struct qman_fq local_fq;

#ifdef PPAC_CGR
/* A congestion group to hold Rx FQs (uses netcfg::cgrids[0]) */
static struct qman_cgr cgr_rx;
/* Tx FQs go into a separate CGR (uses netcfg::cgrids[1]) */
static struct qman_cgr cgr_tx;
#endif

void teardown_fq(struct qman_fq *fq)
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

/*******************/
/* packet handling */
/*******************/

void ppac_fq_nonpcd_init(struct qman_fq *fq, u32 fqid,
			 enum qm_channel channel,
			 qman_cb_dqrr cb)
{
	struct qm_mcc_initfq opts;
	int ret;

	fq->cb.dqrr = cb;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2drop" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = PPAC_PRIO_2DROP;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = 0;
	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

void ppac_fq_pcd_init(struct qman_fq *fq, u32 fqid,
		      enum qm_channel channel)
{
	struct qm_mcc_initfq opts;
	int ret;
	fq->cb.dqrr = cb_dqrr_rx_hash;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2fwd" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = PPAC_PRIO_2FWD;
	opts.fqd.fq_ctrl =
#ifdef PPAC_2FWD_HOLDACTIVE
		QM_FQCTRL_HOLDACTIVE |
#endif
#ifdef PPAC_2FWD_RX_PREFERINCACHE
		QM_FQCTRL_PREFERINCACHE |
#endif
		QM_FQCTRL_CTXASTASHING;
#ifdef PPAC_CGR
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_rx.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.context_cl = 0;
	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

static uint32_t pchannel_idx;

enum qm_channel get_rxc(void)
{
	enum qm_channel ret = netcfg->pool_channels[pchannel_idx];
	pchannel_idx = (pchannel_idx + 1) % netcfg->num_pool_channels;
	return ret;
}

int lazy_init_bpool(const struct fman_if_bpool *bpool)
{
	struct bman_pool_params params = {
		.bpid	= bpool->bpid,
#ifdef PPAC_DEPLETION
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
#ifdef PPAC_CGR
		worker_msg_query_cgr
#endif
	} msg;
	pthread_barrier_t barr;
#ifdef PPAC_CGR
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
	struct list_head *i, *tmpi;
	int loop;

	/* Tear down interfaces */
	list_for_each_safe(i, tmpi, &ifs)
		ppac_if_finish((struct ppac_if *)i);
	/* Tear down buffer pools */
	for (loop = 0; loop < ARRAY_SIZE(pool); loop++) {
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

#ifdef PPAC_CGR
	struct qm_mcc_initcgr opts = {
		.we_mask = QM_CGR_WE_CSCN_EN | QM_CGR_WE_CS_THRES |
				QM_CGR_WE_MODE,
		.cgr = {
			.cscn_en = QM_CGR_EN,
			.mode = QMAN_CGR_MODE_FRAME
		}
	};
	if (netcfg->num_cgrids < 2) {
		fprintf(stderr, "error: insufficient CGRIDs available\n");
		exit(EXIT_FAILURE);
	}

	/* Set up Rx CGR */
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, PPAC_IF_NUM *
		(PPAC_CGR_RX_PERFQ_THRESH * PPAC_RX_HASH_SIZE), 0);
	cgr_rx.cgrid = netcfg->cgrids[0];
	cgr_rx.cb = cgr_rx_cb;
	err = qman_create_cgr(&cgr_rx, QMAN_CGR_FLAG_USE_INIT, &opts);
	if (err)
		fprintf(stderr, "error: rx CGR init, continuing\n");

	/* Set up Tx CGR */
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, PPAC_IF_NUM *
		(PPAC_CGR_TX_PERFQ_THRESH * PPAC_TX_NUM), 0);
	cgr_tx.cgrid = netcfg->cgrids[1];
	cgr_tx.cb = cgr_tx_cb;
	err = qman_create_cgr(&cgr_tx, QMAN_CGR_FLAG_USE_INIT, &opts);
	if (err)
		fprintf(stderr, "error: tx CGR init, continuing\n");
#endif
	/* Initialise interface objects (internally, this takes care of
	 * initialising buffer pool objects for any BPIDs used by the Fman Rx
	 * ports). */
	for (loop = 0; loop < netcfg->num_ethports; loop++) {
		TRACE("Initialising interface %d\n", loop);
		err = ppac_if_init(loop);
		if (err) {
			fprintf(stderr, "error: interface %d failed\n", loop);
			do_global_finish();
			return;
		}
	}
}

static int process_msg(struct worker *worker, struct worker_msg *msg)
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

#ifdef PPAC_CGR
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

/* The main polling loop will adapt into interrupt mode when it has been idle
 * for a period of time. The interrupt mode corresponds to a select() with
 * timeout (so that we can still catch thread-messaging). We similarly handle
 * slow-path processing based on loop counters - rather than using the implicit
 * slow/fast-path adaptations in qman_poll() and bman_poll().
 */
#define WORKER_SELECT_TIMEOUT_us 1000000
#define WORKER_SLOWPOLL_BUSY 4
#define WORKER_SLOWPOLL_IDLE 400
#define WORKER_FASTPOLL_DQRR 16
#define WORKER_FASTPOLL_DOIRQ 2000
static void drain_4_bytes(int fd, fd_set *fdset)
{
	if (FD_ISSET(fd, fdset)) {
		uint32_t junk;
		ssize_t sjunk = read(fd, &junk, sizeof(junk));
		if (sjunk != sizeof(junk))
			perror("UIO irq read error");
	}
}
static void *worker_fn(void *__worker)
{
	struct worker *worker = __worker;
	cpu_set_t cpuset;
	int s, fd_qman, fd_bman, nfds;
	int calm_down = 16, irq_mode = 0, slowpoll = 0, fastpoll = 0;

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
	fd_qman = qman_thread_fd();
	fd_bman = bman_thread_fd();
	if (fd_qman > fd_bman)
		nfds = fd_qman + 1;
	else
		nfds = fd_bman + 1;
	/* Initialise the enqueue-only FQ object for this cpu/thread. NB, the
	 * fqid argument ("1") is superfluous, the point is to mark the object
	 * as ready for enqueuing and handling ERNs, but unfit for any FQD
	 * modifications. The forwarding logic will substitute in the required
	 * FQID. */
	local_fq.cb.ern = cb_ern;
	s = qman_create_fq(1, QMAN_FQ_FLAG_NO_MODIFY, &local_fq);
	BUG_ON(s);

	/* Set the qman portal's SDQCR mask */
	qman_static_dequeue_add(sdqcr);

	/* Run! */
	TRACE("Starting poll loop on cpu %d\n", worker->cpu);
	while (check_msg(worker)) {
		/* IRQ mode */
		if (irq_mode) {
			/* Go into (and back out of) IRQ mode for each select,
			 * it simplifies exit-path considerations and other
			 * potential nastiness. */
			fd_set readset;
			struct timeval tv = {
				.tv_sec = WORKER_SELECT_TIMEOUT_us / 1000000,
				.tv_usec = WORKER_SELECT_TIMEOUT_us % 1000000
			};
			FD_ZERO(&readset);
			FD_SET(fd_qman, &readset);
			FD_SET(fd_bman, &readset);
			bman_irqsource_add(BM_PIRQ_RCRI | BM_PIRQ_BSCN);
			qman_irqsource_add(QM_PIRQ_SLOW | QM_PIRQ_DQRI);
			s = select(nfds, &readset, NULL, NULL, &tv);
			/* Calling irqsource_remove() prior to thread_irq()
			 * means thread_irq() will not process whatever caused
			 * the interrupts, however it does ensure that, once
			 * thread_irq() re-enables interrupts, they won't fire
			 * again immediately. The calls to poll_slow() force
			 * handling of whatever triggered the interrupts. */
			bman_irqsource_remove(~0);
			qman_irqsource_remove(~0);
			bman_thread_irq();
			qman_thread_irq();
			bman_poll_slow();
			qman_poll_slow();
			if (s < 0) {
				perror("QBMAN select error");
				goto end;
			}
			if (!s)
				/* timeout, stay in IRQ mode */
				continue;
			drain_4_bytes(fd_bman, &readset);
			drain_4_bytes(fd_qman, &readset);
			/* Transition out of IRQ mode */
			irq_mode = 0;
			fastpoll = 0;
			slowpoll = 0;
		}
		/* non-IRQ mode */
		if (!(slowpoll--)) {
			if (qman_poll_slow() || bman_poll_slow()) {
				slowpoll = WORKER_SLOWPOLL_BUSY;
				fastpoll = 0;
			} else
				slowpoll = WORKER_SLOWPOLL_IDLE;
		}
		if (qman_poll_dqrr(WORKER_FASTPOLL_DQRR))
			fastpoll = 0;
		else
			/* No fast-path work, do we transition to IRQ mode? */
			if (++fastpoll > WORKER_FASTPOLL_DOIRQ)
				irq_mode = 1;
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

#ifdef PPAC_CGR
static void dump_cgr(const struct qm_mcr_querycgr *res)
{
	u64 val64;
	printf("      cscn_en: %d\n", res->cgr.cscn_en);
	printf("    cscn_targ: 0x%08x\n", res->cgr.cscn_targ);
	printf("      cstd_en: %d\n", res->cgr.cstd_en);
	printf("	   cs: %d\n", res->cgr.cs);
	val64 = qm_cgr_cs_thres_get64(&res->cgr.cs_thres);
	printf("    cs_thresh: 0x%02x_%04x_%04x\n", (u32)(val64 >> 32),
		(u32)(val64 >> 16) & 0xffff, (u32)val64 & 0xffff);
	printf("	 mode: %d\n", res->cgr.mode);
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
	int err = posix_memalign((void **)&ret, L1_CACHE_BYTES, sizeof(*ret));
	if (err)
		goto out;
	err = posix_memalign((void **)&ret->msg, L1_CACHE_BYTES, sizeof(*ret->msg));
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

#ifdef PPAC_CGR
/* This function is, so far, only used by CGR-specific code. */
static struct worker *worker_first(void)
{
	if (list_empty(&workers))
		return NULL;
	return list_entry(workers.next, struct worker, node);
}
#endif

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = "<usdpa-devel@gforge.freescale.net>";

static struct argp_child _ppam_argp[] = {
	{&ppam_argp, 0, ppam_doc},
	{}
};

static const char argp_doc[] = "\n\
USDPAA PPAC-based application\
";
static const char _ppac_args[] = "[cpu-range]";

static const struct argp_option argp_opts[] = {
	{"cpu-range", 0, 0, OPTION_DOC, "'index' or 'first'..'last'"},
	{}
};

static error_t ppac_parse(int key, char *arg, struct argp_state *state)
{
	int _errno;
	struct ppac_arguments *args;

	switch (key) {
	case ARGP_KEY_ARGS:
		if (state->argc - state->next != 1)
			argp_usage(state);
		args = (typeof(args))state->input;
		_errno = parse_cpus(state->argv[state->next], &args->first, &args->last);
		if (unlikely(_errno < 0))
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp ppac_argp = {argp_opts, ppac_parse, _ppac_args, argp_doc, _ppam_argp};

struct ppac_arguments ppac_args;

static int ppac_cli_help(int argc, char *argv[])
{
	const struct cli_table_entry *cli_cmd;

	puts("Available commands:");
	foreach_cli_table_entry (cli_cmd) {
		printf("%s ", cli_cmd->cmd);
	}
	puts("");

	return argc != 1 ? -EINVAL: 0;
}

static int ppac_cli_add(int argc, char *argv[])
{
	struct worker *worker;
	int first, last, loop;

	if (argc != 2)
		return -EINVAL;

	if (parse_cpus(argv[1], &first, &last) == 0)
		for (loop = first; loop <= last; loop++) {
			worker = worker_find(loop, 0);
			if (worker)
				continue;
			worker = worker_new(loop);
			if (worker)
				worker_add(worker);
		}

	return 0;
}

#ifdef PPAC_CGR
static int ppac_cli_cgr(int argc, char *argv[])
{
	struct worker *worker;

	if (argc != 1)
		return -EINVAL;

	worker = worker_first();
	msg_query_cgr(worker);

	return 0;
}
#endif

static int ppac_cli_list(int argc, char *argv[])
{
	struct worker *worker;

	if (argc > 2)
		return -EINVAL;
	/* cpu-range is an optional argument */
	if (argc > 1)
		call_for_each_worker(argv[1], msg_list);
	else
		list_for_each_entry(worker, &workers, node)
			msg_list(worker);
	return 0;
}

static int ppac_cli_macs(int argc, char *argv[])
{
	struct list_head *i;

	if (argc != 2)
		return -EINVAL;

	if (strcmp(argv[1], "off") == 0)
		list_for_each(i, &ifs)
			ppac_if_disable_rx((struct ppac_if *)i);
	else if (strcmp(argv[1], "on") == 0) {
		list_for_each(i, &ifs)
			ppac_if_enable_rx((struct ppac_if *)i);
	}
	else
		return -EINVAL;

	return 0;
}

static int ppac_cli_rm(int argc, char *argv[])
{
	struct worker *worker;
	int first, last, loop;

	if (argc != 2)
		return -EINVAL;

	if (parse_cpus(argv[1], &first, &last) == 0)
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

	return 0;
}

cli_cmd(help, ppac_cli_help);
cli_cmd(add, ppac_cli_add);
#ifdef PPAC_CGR
cli_cmd(cgr, ppac_cli_cgr);
#endif
cli_cmd(list, ppac_cli_list);
cli_cmd(macs, ppac_cli_macs);
cli_cmd(rm, ppac_cli_rm);

int main(int argc, char *argv[])
{
	struct worker *worker, *tmpworker;
	const char *pcd_path = ppam_pcd_path;
	const char *cfg_path = ppam_cfg_path;
	const char *envp;
	int loop;
	int rcode, cli_argc;
	char *cli, **cli_argv;
	const struct cli_table_entry *cli_cmd;

	ncpus = (unsigned long)sysconf(_SC_NPROCESSORS_ONLN);

	if (ncpus == 1) {
		ppac_args.first = 0;
		ppac_args.last = 0;
	} else {
		ppac_args.first = 1;
		ppac_args.last = 1;
	}

	rcode = argp_parse(&ppac_argp, argc, argv, 0, NULL, &ppac_args);
	if (unlikely(rcode != 0))
		return -rcode;

	/* Do global init that doesn't require portal access; */
	/* - load the config (includes discovery and mapping of MAC devices) */
	TRACE("Loading configuration\n");
	envp = getenv("DEF_PCD_PATH");
	if (envp)
		pcd_path = envp;
	envp = getenv("DEF_CFG_PATH");
	if (envp)
		cfg_path = envp;
	netcfg = usdpaa_netcfg_acquire(pcd_path, cfg_path);
	if (!netcfg) {
		fprintf(stderr, "error: failed to load configuration\n");
		return -1;
	}
	/* - validate the config */
	if (!netcfg->num_ethports) {
		fprintf(stderr, "error: no network interfaces available\n");
		return -1;
	}
	if (!netcfg->num_pool_channels) {
		fprintf(stderr, "error: no pool channels available\n");
		return -1;
	}
	/* - initialise DPAA */
	rcode = qman_global_init(0);
	if (rcode)
		fprintf(stderr, "error: qman global init, continuing\n");
	rcode = bman_global_init(0);
	if (rcode)
		fprintf(stderr, "error: bman global init, continuing\n");
	printf("Configuring for %d network interface%s and %d pool channel%s\n",
		netcfg->num_ethports, netcfg->num_ethports > 1 ? "s" : "",
		netcfg->num_pool_channels,
		netcfg->num_pool_channels > 1 ? "s" : "");
	/* - compute SDQCR */
	for (loop = 0; loop < netcfg->num_pool_channels; loop++) {
		sdqcr |= QM_SDQCR_CHANNELS_POOL_CONV(netcfg->pool_channels[loop]);
		TRACE("Adding 0x%08x to SDQCR -> 0x%08x\n",
			QM_SDQCR_CHANNELS_POOL_CONV(netcfg->pool_channels[loop]),
			sdqcr);
	}
	/* - map shmem */
	TRACE("Initialising shmem\n");
	rcode = dma_mem_setup();
	if (rcode)
		fprintf(stderr, "error: shmem init, continuing\n");

	/* Create the threads */
	TRACE("Starting %d threads for cpu-range '%d..%d'\n",
	      ppac_args.last - ppac_args.first + 1, ppac_args.first, ppac_args.last);
	for (loop = ppac_args.first; loop <= ppac_args.last; loop++) {
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
		/* Reap any dead threads */
		list_for_each_entry_safe(worker, tmpworker, &workers, node)
			worker_reap(worker);

		/* Get command */
		cli = readline("> ");
		if (unlikely((cli == NULL) || strncmp(cli, "q", 1) == 0))
			break;
		if (cli[0] == 0) {
			free(cli);
			continue;
		}

		cli_argv = history_tokenize(cli);
		if (unlikely(cli_argv == NULL)) {
			fprintf(stderr, "Out of memory while parsing: %s\n", cli);
			free(cli);
			continue;
		}
		for (cli_argc = 0; cli_argv[cli_argc] != NULL; cli_argc++);

		foreach_cli_table_entry (cli_cmd) {
			if (strcmp(cli_argv[0], cli_cmd->cmd) == 0) {
				rcode = cli_cmd->handle(cli_argc, cli_argv);
				if (unlikely(rcode < 0))
				    fprintf(stderr, "%s: %s\n",
					    cli_cmd->cmd, strerror(-rcode));
				add_history(cli);
				break;
			}
		}

		if (cli_cmd == cli_table_end)
			fprintf(stderr, "Unknown command: %s\n", cli);

		for (cli_argc = 0; cli_argv[cli_argc] != NULL; cli_argc++)
			free(cli_argv[cli_argc]);
		free(cli_argv);
		free(cli);
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
	usdpaa_netcfg_release(netcfg);
	return rcode;
}
