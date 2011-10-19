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

#include <ppac.h>
#include <readline.h>  /* libedit */

#include "fra_network_interface.h"
#include "fra.h"
#include "fra_cfg_parser.h"
#include "test_speed.h"

/*
 * PPAM global startup/teardown
 *
 * These hooks are not performance-sensitive and so are declared as real
 * functions, called from the PPAC library code (ie. not from the inline
 * packet-handling support).
 */
int __attribute__((weak)) ppam_init(void)
{
	return 0;
}
void __attribute__((weak)) ppam_finish(void)
{
	fprintf(stderr, "%s stopping\n",
		program_invocation_short_name);
}

/*
 * PPAM thread startup/teardown
 *
 * Same idea, but these are invoked as each thread is set up (after portals are
 * initialised but prior to the appication-loop starting) or torn down (prior to
 * portals being torn down).
 */
int __attribute__((weak)) ppam_thread_init(void)
{
	return 0;
}
void __attribute__((weak)) ppam_thread_finish(void)
{
}

/*
 * PPAM thread polling hook
 *
 * The idea here is that a PPAM can implement an override for this function if
 * it wishes to perform processing from within the core application-loop running
 * in each thread. In this case, the application-loop invokes ppam_thread_poll()
 * whenever the 'ppam_thread_poll_enabled' thread-local boolean variable is set
 * non-zero. This boolean is zero by default, so can be enabled/disabled as
 * required by PPAM itself (during initialisation, packet-processing, and/or
 * from within ppam_thread_poll() itself). For this reason, it is illegal for
 * the weakly-linked default to ever execute - it implies the PPAM has activated
 * the polling hook without implementing it. If the hook returns non-zero, the
 * thread will cleanup and terminate.
 */
__thread int ppam_thread_poll_enabled;
int __attribute__((weak)) ppam_thread_poll(void)
{
	error(EXIT_SUCCESS, 0,
	      "PPAM requested polling but didn't implement it!");
	abort();
	return 0;
}

#define DMA_MEM_BP4_BPID	10
#define DMA_MEM_BP4_SIZE	80
#define DMA_MEM_BP4_NUM		0x100 /* 0x100*80==20480 (20KB) */
#define DMA_MEM_BP5_BPID	11
#define DMA_MEM_BP5_SIZE	1600
#define DMA_MEM_BP5_NUM		0x2000 /* 0x2000*1600==13107200 (12.5M) */
#define DMA_MEM_BP6_BPID	12
#define DMA_MEM_BP6_SIZE	64
#define DMA_MEM_BP6_NUM		0x2000 /* 0x2000*64==524288 (0.5MB) */
#define DMA_MEM_BPOOL_SIZE						\
	(DMA_MEM_BP3_SIZE * DMA_MEM_BP3_NUM +				\
	 DMA_MEM_BP4_SIZE * DMA_MEM_BP4_NUM +				\
	 DMA_MEM_BP5_SIZE * DMA_MEM_BP5_NUM +				\
	 DMA_MEM_BP6_SIZE * DMA_MEM_BP6_NUM) /* 27787264 (26.5MB) */

/*
 * PPAM-overridable paths to FMan configuration files.
 */
const char ppam_pcd_path[] __attribute__((weak)) = __stringify(DEF_PCD_PATH);
const char ppam_cfg_path[] __attribute__((weak)) = __stringify(DEF_CFG_PATH);
const char default_fra_cfg_path[] __attribute__((weak)) =
	__stringify(DEF_FRA_CFG_PATH);

/***************/
/* Global data */
/***************/

/* Seed buffer pools according to the configuration symbols */
const struct bpool_config  bpool_config[] = {
	{ DMA_MEM_BP3_BPID, DMA_MEM_BP3_NUM, DMA_MEM_BP3_SIZE},
	{ DMA_MEM_BP4_BPID, DMA_MEM_BP4_NUM, DMA_MEM_BP4_SIZE},
	{ DMA_MEM_BP5_BPID, DMA_MEM_BP5_NUM, DMA_MEM_BP5_SIZE},
	{ DMA_MEM_BP6_BPID, DMA_MEM_BP6_NUM, DMA_MEM_BP6_SIZE}
};

/* The SDQCR mask to use (computed from netcfg's pool-channels) */
static uint32_t sdqcr;

/* The follow global variables are non-static because they're used from inlined
 * code in ppac.h too. */

/* Configuration */
struct usdpaa_netcfg_info *netcfg;

/* We want a trivial mapping from bpid->pool, so just have an array of pointers,
 * most of which are probably NULL. */
struct bman_pool *pool[PPAC_MAX_BPID];

/* The interfaces in this list are allocated from dma_mem (stashing==DMA) */
LIST_HEAD(ifs);

/* The forwarding logic uses a per-cpu FQ object for handling enqueues (and
 * ERNs), irrespective of the destination FQID. In this way, cache-locality is
 * more assured, and any ERNs that do occur will show up on the same CPUs they
 * were enqueued from. This works because ERN messages contain the FQID of the
 * original enqueue operation, so in principle any demux that's required by the
 * ERN callback can be based on that. Ie. the FQID set within "local_fq" is from
 * whatever the last executed enqueue was, the ERN handler can ignore it. */
__thread struct qman_fq local_fq;

/* These are backdoors from PPAC to itself in order to support order
 * preservation/restoration. Packet-handling goes from a PPAC handler to a PPAM
 * handler which in turn calls PPAC APIs to perform the required packet
 * operations. Call stack is PPAC->PPAM->PPAC, with the possibility for inlining
 * to collapse it all down. The backdoors allow the packet operations to know
 * what was known back up in the PPAC handler but not passed down through the
 * call stack, like what DQRR entry was being processed (to encode enqueue-DCAs,
 * determine ORP sequeuence numbers, etc), what ORPID should be used (if any)
 * when dropping or forwarding the current frame, etc. */
#if defined(PPAC_ORDER_PRESERVATION) ||		\
	defined(PPAC_ORDER_RESTORATION)
__thread const struct qm_dqrr_entry *local_dqrr;
#endif
#ifdef PPAC_ORDER_RESTORATION
__thread uint32_t local_orp_id;
__thread uint32_t local_seqnum;
#endif

#ifdef PPAC_CGR
/* A congestion group to hold Rx FQs (uses netcfg::cgrids[0]) */
struct qman_cgr cgr_rx;
/* Tx FQs go into a separate CGR (uses netcfg::cgrids[1]) */
struct qman_cgr cgr_tx;
#endif

static uint32_t pchannel_idx;

int lazy_init_bpool(uint8_t bpid, uint8_t depletion_notify)
{
	return 0;
}

enum qm_channel get_rxc(void)
{
	enum qm_channel ret = netcfg->pool_channels[pchannel_idx];
	pchannel_idx = (pchannel_idx + 1) % netcfg->num_pool_channels;
	return ret;
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
		worker_msg_do_test_speed,
#ifdef PPAC_CGR
		worker_msg_query_cgr
#endif
	} msg;
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
	uint32_t uid;
	pthread_t id;
	int result;
	struct list_head node;
} ____cacheline_aligned;

static uint32_t next_worker_uid;

/* -------------------------------- */
/* msg-processing within the worker */

static void do_global_finish(void)
{
	struct list_head *i, *tmpi;
	/* During init, we initialise all interfaces and their Tx FQs in a first
	 * phase, then we initialise their Rx FQs in a second phase. This means
	 * PPAM handlers know about all frame destinations before initialising
	 * their handling of frame sources. This cleanup logic uses a similar
	 * split, in the reverse order. */
	list_for_each(i, &ifs)
		/* NB: we cast rather than use list_for_each_entry_safe()
		 * because this code can not include ppac_interface.h to know
		 * about "struct ppac_interface" internals - doing so requires
		 * that the PPAM structs be known too, which is impossible in
		 * this PPAM-agnostic code. */
		ppac_interface_finish_rx((struct ppac_interface *)i);
	list_for_each_safe(i, tmpi, &ifs)
		/* This loop uses "_safe()" because the list entries delete
		 * themselves. */
		ppac_interface_finish((struct ppac_interface *)i);

	bpools_finish();
	ppam_finish();
	fra_finish();
}


static void do_global_init(void)
{
	struct list_head *i;
	uint32_t loop;
	int err;

#ifdef PPAC_CGR
	ppac_cgr_init(netcfg);
#endif
	dma_mem_bpool_set_range(DMA_MEM_BPOOL_SIZE);
	bpools_init(bpool_config, ARRAY_SIZE(bpool_config));
	for (loop = 0; loop < PPAC_MAX_BPID; loop++)
		pool[loop] = bpid_to_bpool(loop);
	/* Here, we give the PPAM it's opportunity to perform "global"
	 * initialisation, before individual interfaces come up (which each
	 * provide their own, more fine-grained, init hooks). We do it here
	 * because the portals are available, pools and CGRs have all been
	 * created, etc. Ie. PPAC global init has essentially finished, and the
	 * remaining step (interface setup) could very well be removed from
	 * global init anyway, and made a run-time consideration (like setup and
	 * teardown of non-primary threads). */
	err = ppam_init();
	if (unlikely(err < 0)) {
		error(EXIT_SUCCESS, -err,
		      "error: PPAM init failed (%d)", err);
		return;
	}
	/* Initialise interface objects (internally, this takes care of
	 * initialising buffer pool objects for any BPIDs used by the Fman Rx
	 * ports). We initialise the interface objects and their Tx FQs in one
	 * loop (so each interface generates hooks to PPAM for both phases
	 * before we move on to the next interface). We do a second loop for
	 * setting up Rx FQs, meaning that PPAM hooks have already seen all
	 * interfaces and Tx FQs before being forced to determine how to handle
	 * Rx FQs ... (ie. "know all the destinations before knowing how you'll
	 * handle any of the sources") */
	for (loop = 0; loop < netcfg->num_ethports; loop++) {
		FRA_DBG("Initialising interface %d", loop);
		err = ppac_interface_init(loop);
		if (err) {
			error(EXIT_SUCCESS, -err,
			      "error: interface %d failed", loop);
			do_global_finish();
			return;
		}
	}
	list_for_each(i, &ifs) {
		FRA_DBG("Initialising interface Tx %p", i);
		/* Same comment applies as the cast in do_global_finish() */
		err = ppac_interface_init_rx((struct ppac_interface *)i);
		if (err) {
			error(EXIT_SUCCESS, -err, "ppac_interface_init_rx()");
			do_global_finish();
			return;
		}
	}

	err = fra_init();
	if (unlikely(err < 0)) {
		error(EXIT_SUCCESS, -err, "fra_init()");
		do_global_finish();
		return;
	}
}

static int process_msg(struct worker *worker, struct worker_msg *msg)
{
	int ret = 1;

	/* List */
	if (msg->msg == worker_msg_list)
		fprintf(stderr, "Thread uid:%u alive (on cpu %d)\n",
			worker->uid, worker->cpu);

	/* Quit */
	else if (msg->msg == worker_msg_quit)
		ret = 0;

	/* Do global init */
	else if (msg->msg == worker_msg_do_global_init)
		do_global_init();

	/* Do global finish */
	else if (msg->msg == worker_msg_do_global_finish)
		do_global_finish();

	/* Do test speed */
	else if (msg->msg == worker_msg_do_test_speed)
		test_speed_send_msg();
#ifdef PPAC_CGR
	/* Query the CGR state */
	else if (msg->msg == worker_msg_query_cgr) {
		int err = qman_query_cgr(&cgr_rx, &msg->query_cgr.res_rx);
		if (err)
			error(EXIT_SUCCESS, 0,
			      "error: query rx CGR, continuing");
		err = qman_query_cgr(&cgr_tx, &msg->query_cgr.res_tx);
		if (err)
			error(EXIT_SUCCESS, 0,
			      "error: query tx CGR, continuing");
	}
#endif

	/* What did you want? */
	else
		panic("bad message type");

	msg->msg = worker_msg_none;
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
#define WORKER_SELECT_TIMEOUT_us 10000
#define WORKER_SLOWPOLL_BUSY 4
#define WORKER_SLOWPOLL_IDLE 400
#define WORKER_FASTPOLL_DQRR 16
#define WORKER_FASTPOLL_DOIRQ 2000
#ifdef PPAC_IDLE_IRQ
static void drain_4_bytes(int fd, fd_set *fdset)
{
	if (FD_ISSET(fd, fdset)) {
		uint32_t junk;
		ssize_t sjunk = read(fd, &junk, sizeof(junk));
		if (sjunk != sizeof(junk))
			error(EXIT_SUCCESS, errno, "UIO irq read error");
	}
}
#endif
static void *worker_fn(void *__worker)
{
	struct worker *worker = __worker;
	cpu_set_t cpuset;
	int s, fd_qman, fd_bman, nfds;
	int calm_down = 16, slowpoll = 0;
#ifdef PPAC_IDLE_IRQ
	int irq_mode = 0, fastpoll = 0;
#endif

	FRA_DBG("This is the thread on cpu %d", worker->cpu);

	/* Set this cpu-affinity */
	CPU_ZERO(&cpuset);
	CPU_SET(worker->cpu, &cpuset);
	s = pthread_setaffinity_np(worker->id, sizeof(cpu_set_t), &cpuset);
	if (s != 0) {
		error(EXIT_SUCCESS, -s, "pthread_setaffinity_np(%d)",
		      worker->cpu);
		goto err;
	}

	/* Initialise bman/qman portals */
	s = bman_thread_init(worker->cpu, 0);
	if (s) {
		error(EXIT_SUCCESS, -s,
		      "No available Bman portals for cpu %d",
		      worker->cpu);
		goto err;
	}
	s = qman_thread_init(worker->cpu, 0);
	if (s) {
		error(EXIT_SUCCESS, -s,
		      "No available Qman portals for cpu %d",
		      worker->cpu);
		bman_thread_finish();
		goto err;
	}
	fd_qman = qman_thread_fd();
	fd_bman = bman_thread_fd();
	if (fd_qman > fd_bman)
		nfds = fd_qman + 1;
	else
		nfds = fd_bman + 1;

	/* Initialise the enqueue-only FQ object for this cpu/thread. Note, the
	 * fqid argument ("1") is superfluous, the point is to mark the object
	 * as ready for enqueuing and handling ERNs, but unfit for any FQD
	 * modifications. The forwarding logic will substitute in the required
	 * FQID. */
	local_fq.cb.ern = cb_ern;
	s = qman_create_fq(1, QMAN_FQ_FLAG_NO_MODIFY, &local_fq);
	BUG_ON(s);

	/* Set the qman portal's SDQCR mask */
	qman_static_dequeue_add(sdqcr);

	/* Global init is triggered by having the message preset to
	 * "do_global_init" before the thread even runs. This means we can catch
	 * it here before entering the loop (which in turn means we can call
	 * ppam_thread_init() after global init but prior to the app loop). */
	if (worker->msg->msg == worker_msg_do_global_init) {
		s = process_msg(worker, worker->msg);
		if (s <= 0)
			goto global_init_fail;
	}

	/* Do any PPAM-specific thread initialisation */
	s = ppam_thread_init();
	BUG_ON(s);

	/* Run! */
	FRA_DBG("Starting poll loop on cpu %d", worker->cpu);
	while (check_msg(worker)) {
		if (ppam_thread_poll_enabled) {
			s = ppam_thread_poll();
			if (s)
				break;
		}
#ifdef PPAC_IDLE_IRQ
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
				error(EXIT_SUCCESS, 0, "QBMAN select error");
				break;
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
#endif
		/* non-IRQ mode */
		if (!(slowpoll--)) {
			if (qman_poll_slow() || bman_poll_slow()) {
				slowpoll = WORKER_SLOWPOLL_BUSY;
#ifdef PPAC_IDLE_IRQ
				fastpoll = 0;
#endif
			} else
				slowpoll = WORKER_SLOWPOLL_IDLE;
		}
#ifdef PPAC_IDLE_IRQ
		if (qman_poll_dqrr(WORKER_FASTPOLL_DQRR))
			fastpoll = 0;
		else
			/* No fast-path work, do we transition to IRQ mode? */
			if (++fastpoll > WORKER_FASTPOLL_DOIRQ)
				irq_mode = 1;
#else
		qman_poll_dqrr(WORKER_FASTPOLL_DQRR);
#endif
	}

	/* Do any PPAM-specific thread cleanup */
	ppam_thread_finish();

global_init_fail:
	qman_static_dequeue_del(~(uint32_t)0);
	while (calm_down--) {
		qman_poll_slow();
		qman_poll_dqrr(16);
	}
	qman_thread_finish();
	bman_thread_finish();
err:
	FRA_DBG("Leaving thread on cpu %d", worker->cpu);
	pthread_exit(NULL);
}

/* ------------------------------ */
/* msg-processing from main()/CLI */

/* This is implemented in the worker-management code lower down, but we need to
 * use it from msg_post() */
static int worker_reap(struct worker *worker);

static int msg_post(struct worker *worker, enum worker_msg_type m)
{
	worker->msg->msg = m;
	while (worker->msg->msg != worker_msg_none) {
		if (!worker_reap(worker))
			/* The worker is already gone */
			return -EIO;
		pthread_yield();
	}
	return 0;
}

static int msg_list(struct worker *worker)
{
	return msg_post(worker, worker_msg_list);
}

static int msg_quit(struct worker *worker)
{
	return msg_post(worker, worker_msg_quit);
}

static int msg_do_global_finish(struct worker *worker)
{
	return msg_post(worker, worker_msg_do_global_finish);
}

int msg_do_test_speed(struct worker *worker)
{
	return msg_post(worker, worker_msg_do_test_speed);
}

#ifdef PPAC_CGR
static void dump_cgr(const struct qm_mcr_querycgr *res)
{
	uint64_t val64;
	error(EXIT_SUCCESS, 0, "      cscn_en: %d", res->cgr.cscn_en);
	error(EXIT_SUCCESS, 0, "    cscn_targ: 0x%08x", res->cgr.cscn_targ);
	error(EXIT_SUCCESS, 0, "      cstd_en: %d", res->cgr.cstd_en);
	error(EXIT_SUCCESS, 0, "	   cs: %d", res->cgr.cs);
	val64 = qm_cgr_cs_thres_get64(&res->cgr.cs_thres);
	error(EXIT_SUCCESS, 0,
	      "	   cs_thresh: 0x%02x_%04x_%04x", (uint32_t)(val64 >> 32),
	      (uint32_t)(val64 >> 16) & 0xffff, (uint32_t)val64 & 0xffff);
	error(EXIT_SUCCESS, 0, "	 mode: %d", res->cgr.mode);
	val64 = qm_mcr_querycgr_i_get64(res);
	error(EXIT_SUCCESS, 0,
	      "	i_bcnt: 0x%02x_%04x_%04x", (uint32_t)(val64 >> 32),
	      (uint32_t)(val64 >> 16) & 0xffff, (uint32_t)val64 & 0xffff);
	val64 = qm_mcr_querycgr_a_get64(res);
	error(EXIT_SUCCESS, 0,
	      "	a_bcnt: 0x%02x_%04x_%04x", (uint32_t)(val64 >> 32),
	      (uint32_t)(val64 >> 16) & 0xffff, (uint32_t)val64 & 0xffff);
}
static int msg_query_cgr(struct worker *worker)
{
	int ret = msg_post(worker, worker_msg_query_cgr);
	if (ret)
		return ret;
	error(EXIT_SUCCESS, 0,
	      "Rx CGR ID: %d, selected fields;", cgr_rx.cgrid);
	dump_cgr(&worker->msg->query_cgr.res_rx);
	error(EXIT_SUCCESS, 0,
	      "Tx CGR ID: %d, selected fields;", cgr_tx.cgrid);
	dump_cgr(&worker->msg->query_cgr.res_tx);
	return 0;
}
#endif

/**********************/
/* worker thread mgmt */
/**********************/

static LIST_HEAD(workers);
static unsigned long ncpus;

/* This worker is the first one created, must not be deleted, and must be the
 * last one to exit. (The buffer pools objects are initialised against its
 * portal.) */
static struct worker *primary;

static struct worker *worker_new(int cpu, int is_primary)
{
	struct worker *ret;
	int err = posix_memalign((void **)&ret, L1_CACHE_BYTES, sizeof(*ret));
	if (err)
		goto out;
	err = posix_memalign((void **)&ret->msg, L1_CACHE_BYTES,
			     sizeof(*ret->msg));
	if (err) {
		free(ret);
		goto out;
	}
	ret->cpu = cpu;
	ret->uid = next_worker_uid++;
	ret->msg->msg = is_primary ? worker_msg_do_global_init :
		worker_msg_none;
	INIT_LIST_HEAD(&ret->node);
	err = pthread_create(&ret->id, NULL, worker_fn, ret);
	if (err) {
		free(ret->msg);
		free(ret);
		goto out;
	}
	/* If is_primary, global init is processed on thread startup, so we poll
	 * for the message queue to be idle before proceeding. Note, the reason
	 * for doing this is to ensure global-init happens before the regular
	 * message processing loop, which is turn to allow the
	 * ppam_thread_init() hook to be placed between the two. */
	while (ret->msg->msg != worker_msg_none) {
		if (!pthread_tryjoin_np(ret->id, NULL)) {
			/* The worker is already gone */
			free(ret->msg);
			free(ret);
			goto out;
		}
		pthread_yield();
	}
	/* Block until the worker is in its polling loop (by sending a "list"
	 * command and waiting for it to get processed). This ensures any
	 * start-up logging is produced before the CLI prints another prompt. */
	if (!msg_list(ret))
		return ret;
out:
	error(EXIT_SUCCESS, 0,
	      "error: failed to create worker for cpu %d", cpu);
	return NULL;
}

static void worker_add(struct worker *worker)
{
	struct worker *i;
	/* Keep workers ordered by cpu */
	list_for_each_entry(i, &workers, node) {
		if (i->cpu > worker->cpu) {
			list_add_tail(&worker->node, &i->node);
			return;
		}
	}
	list_add_tail(&worker->node, &workers);
}

static void worker_free(struct worker *worker)
{
	int err, cpu = worker->cpu;
	uint32_t uid = worker->uid;
	BUG_ON(worker == primary);
	msg_quit(worker);
	err = pthread_join(worker->id, NULL);
	if (err) {
		/* Leak, but warn */
		error(EXIT_SUCCESS, 0,
		      "Failed to join thread uid:%u (cpu %d)",
		      worker->uid, worker->cpu);
		return;
	}
	list_del(&worker->node);
	free(worker->msg);
	free(worker);
	fprintf(stderr, "Thread uid:%u killed (cpu %d)\n", uid, cpu);
}

static int worker_reap(struct worker *worker)
{
	if (pthread_tryjoin_np(worker->id, NULL))
		return -EBUSY;
	if (worker == primary) {
		error(EXIT_SUCCESS, 0, "Primary thread died!");
		abort();
	}
	if (!list_empty(&worker->node))
		list_del(&worker->node);
	free(worker->msg);
	free(worker);
	return 0;
}

static struct worker *worker_find(int cpu, int can_be_primary)
{
	struct worker *worker;
	list_for_each_entry(worker, &workers, node) {
		if ((worker->cpu == cpu) && (can_be_primary ||
					     (worker != primary)))
			return worker;
	}
	return NULL;
}

#ifdef PPAC_CGR
/* This function is, so far, only used by CGR-specific code. */
static struct worker *worker_first(void)
{
	if (list_empty(&workers))
		return NULL;
	return list_entry(workers.next, struct worker, node);
}
#endif

/**************************************/
/* CLI and command-line parsing utils */
/**************************************/

/* Parse a cpu id. On entry legit/len contain acceptable "next char" values, on
 * exit legit points to the "next char" we found. Return -1 for bad parse. */
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
	error(EXIT_SUCCESS, 0, "error: invalid cpu '%s'", str);
	return ret;
}

/* Parse a cpu range (eg. "3"=="3..3"). Return 0 for valid parse. */
static int parse_cpus(const char *str, int *start, int *end)
{
	/* Note: arrays of chars, not strings. Also sizeof(), not strlen()! */
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

/****************/
/* ARGP support */
/****************/

struct ppac_arguments {
	const char *fm_cfg;
	const char *fm_pcd;
	const char *fra_cfg;
	int first, last;
	int noninteractive;
};

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = "<usdpa-devel@gforge.freescale.net>";

static const char argp_doc[] = "\nUSDPAA PPAC-based application";
static const char _ppac_args[] = "[cpu-range]";

static const struct argp_option argp_opts[] = {
	{"fm-config", 'c', "FILE", 0, "FMC configuration XML file"},
	{"fm-pcd", 'p', "FILE", 0, "FMC PCD XML file"},
	{"fra-config", 'f', "FILE", 0, "FRA configuration XML file"},
	{"non-interactive", 'n', 0, 0, "Ignore stdin"},
	{"cpu-range", 0, 0, OPTION_DOC, "'index' or 'first'..'last'"},
	{}
};

static error_t ppac_parse(int key, char *arg, struct argp_state *state)
{
	int _errno;
	struct ppac_arguments *args;

	args = (typeof(args))state->input;
	switch (key) {
	case 'c':
		args->fm_cfg = arg;
		break;
	case 'p':
		args->fm_pcd = arg;
		break;
	case 'f':
		args->fra_cfg = arg;
		break;
	case 'n':
		args->noninteractive = 1;
		break;
	case ARGP_KEY_ARGS:
		if (state->argc - state->next != 1)
			argp_usage(state);
		_errno = parse_cpus(state->argv[state->next],
				    &args->first, &args->last);
		if (unlikely(_errno < 0))
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp ppac_argp = {argp_opts, ppac_parse, _ppac_args,
				      argp_doc, NULL};

static struct ppac_arguments ppac_args;

/***************/
/* CLI support */
/***************/

extern const struct cli_table_entry cli_table_start[], cli_table_end[];

#define foreach_cli_table_entry(cli_cmd)				\
	for (cli_cmd = cli_table_start; cli_cmd < cli_table_end; cli_cmd++)

static int ppac_cli_help(int argc, char *argv[])
{
	const struct cli_table_entry *cli_cmd;

	puts("Available commands:");
	foreach_cli_table_entry(cli_cmd) {
		error(EXIT_SUCCESS, 0, "%s ", cli_cmd->cmd);
	}
	puts("");

	return argc != 1 ? -EINVAL : 0;
}

static int ppac_cli_add(int argc, char *argv[])
{
	struct worker *worker;
	int first, last, loop;

	if (argc != 2)
		return -EINVAL;

	if (parse_cpus(argv[1], &first, &last) == 0)
		for (loop = first; loop <= last; loop++) {
			worker = worker_new(loop, 0);
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

	if (argc > 1)
		return -EINVAL;
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
			ppac_interface_disable_rx((struct ppac_interface *)i);
	else if (strcmp(argv[1], "on") == 0) {
		list_for_each(i, &ifs)
			ppac_interface_enable_rx((struct ppac_interface *)i);
	} else
		return -EINVAL;

	return 0;
}

static int ppac_cli_rm(int argc, char *argv[])
{
	struct worker *worker;
	int first, last, loop;

	if (argc != 2)
		return -EINVAL;

	/* Either lookup via uid, or by cpu (single or range) */
	if (!strncmp(argv[1], "uid:", 4)) {
		list_for_each_entry(worker, &workers, node) {
			char buf[16];
			sprintf(buf, "uid:%u", worker->uid);
			if (!strcmp(argv[1], buf)) {
				worker_free(worker);
				return 0;
			}
		}
	} else if (parse_cpus(argv[1], &first, &last) == 0) {
		for (loop = first; loop <= last; loop++) {
			worker = worker_find(loop, 0);
			if (worker)
				worker_free(worker);
		}
		return 0;
	}
	return -EINVAL;
}

void test_speed_to_send(void)
{
	struct worker *worker;
	int loop;

	for (loop = 0; loop < test_speed.total_loop; loop++) {
		memset(send_time, 0, sizeof(send_time));
		memset(receive_time, 0, sizeof(receive_time));
		list_for_each_entry(worker, &workers, node) {
			msg_do_test_speed(worker);
			break;
		}
		test_speed_wait_receive();
	}
	test_speed.end_flag = 1;
	list_for_each_entry(worker, &workers, node) {
		msg_do_test_speed(worker);
		break;
	}
	test_speed_info();
}

cli_cmd(help, ppac_cli_help);
cli_cmd(add, ppac_cli_add);
#ifdef PPAC_CGR
cli_cmd(cgr, ppac_cli_cgr);
#endif
cli_cmd(list, ppac_cli_list);
cli_cmd(macs, ppac_cli_macs);
cli_cmd(rm, ppac_cli_rm);

const char ppam_prompt[] = "fra> ";

int main(int argc, char *argv[])
{
	struct worker *worker, *tmpworker;
	const char *pcd_path = ppam_pcd_path;
	const char *cfg_path = ppam_cfg_path;
	const char *fra_cfg_path = default_fra_cfg_path;
	const char *envp;
	int loop;
	int rcode, cli_argc;
	char *cli, **cli_argv;
	const struct cli_table_entry *cli_cmd;

	rcode = of_init();
	if (rcode) {
		pr_err("of_init() failed");
		exit(EXIT_FAILURE);
	}

	ncpus = (unsigned long)sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus > 1) {
		ppac_args.first = 1;
		ppac_args.last = 1;
	}

	ppac_args.noninteractive = 0;

	rcode = argp_parse(&ppac_argp, argc, argv, 0, NULL, &ppac_args);
	if (unlikely(rcode != 0))
		return -rcode;

	/* Do global init that doesn't require portal access; */
	/* - load the config (includes discovery and mapping of MAC devices) */
	FRA_DBG("Loading configuration");
	if (ppac_args.fm_pcd != NULL)
		pcd_path = ppac_args.fm_pcd;
	else {
		envp = getenv("DEF_PCD_PATH");
		if (envp != NULL)
			pcd_path = envp;
	}
	if (ppac_args.fm_cfg != NULL)
		cfg_path = ppac_args.fm_cfg;
	else {
		envp = getenv("DEF_CFG_PATH");
		if (envp != NULL)
			cfg_path = envp;
	}
	if (ppac_args.fra_cfg != NULL)
		fra_cfg_path = ppac_args.fra_cfg;
	else {
		envp = getenv("DEF_FRA_CFG_PATH");
		if (envp != NULL)
			fra_cfg_path = envp;
	}
	/* Parse FMC policy and configuration files for the network
	 * configuration. This also "extracts" other settings into 'netcfg' that
	 * are not necessarily from the XML files, such as the pool channels
	 * that the application is allowed to use (these are currently
	 * hard-coded into the netcfg code). */
	netcfg = usdpaa_netcfg_acquire(pcd_path, cfg_path);
	if (!netcfg) {
		error(EXIT_SUCCESS, 0,
		      "error: failed to load configuration");
		return -EINVAL;
	}
	if (!netcfg->num_ethports) {
		error(EXIT_SUCCESS, 0,
		      "error: no network interfaces available");
		return -EINVAL;
	}
	if (!netcfg->num_pool_channels) {
		error(EXIT_SUCCESS, 0,
		      "error: no pool channels available");
		return -EINVAL;
	}

	if (fra_parse_cfgfile(fra_cfg_path)) {
		error(EXIT_SUCCESS, 0,
		      "error: failed to load fra configuration");
		return -EINVAL;
	}
	/* - initialise DPAA */
	rcode = qman_global_init(0);
	if (rcode)
		error(EXIT_SUCCESS, 0,
		      "error: qman global init, continuing");
	rcode = bman_global_init(0);
	if (rcode)
		error(EXIT_SUCCESS, 0,
		      "error: bman global init, continuing");
	fprintf(stderr, "Configuring for %d network interface%s"
		" and %d pool channel%s\n",
		netcfg->num_ethports, netcfg->num_ethports > 1 ? "s" : "",
		netcfg->num_pool_channels,
		netcfg->num_pool_channels > 1 ? "s" : "");
	/* - compute SDQCR */
	for (loop = 0; loop < netcfg->num_pool_channels; loop++) {
		sdqcr |=
			QM_SDQCR_CHANNELS_POOL_CONV(netcfg->pool_channels[loop]);
		FRA_DBG("Adding 0x%08x to SDQCR -> 0x%08x",
			QM_SDQCR_CHANNELS_POOL_CONV(netcfg->pool_channels[loop]),
			sdqcr);
	}
	/* - map shmem */
	FRA_DBG("Initialising shmem");
	rcode = dma_mem_setup();
	if (rcode)
		error(EXIT_SUCCESS, 0, "error: shmem init, continuing");

	/* Create the threads */
	FRA_DBG("Starting %d threads for cpu-range '%d..%d'",
		ppac_args.last - ppac_args.first + 1,
		ppac_args.first, ppac_args.last);
	for (loop = ppac_args.first; loop <= ppac_args.last; loop++) {
		worker = worker_new(loop, !primary);
		if (!worker) {
			rcode = -EINVAL;
			goto leave;
		}
		if (!primary)
			primary = worker;
		worker_add(worker);
	}

	/* Run the CLI loop */
	while (1) {
		/* Reap any dead threads */
		list_for_each_entry_safe(worker, tmpworker, &workers, node)
			if (!worker_reap(worker))
				error(EXIT_SUCCESS, 0,
				      "Caught dead thread uid:%u (cpu %d)",
				      worker->uid, worker->cpu);

		/* If non-interactive, have the CLI thread twiddle its thumbs
		 * between (infrequent) checks for dead threads. */
		if (ppac_args.noninteractive) {
			sleep(1);
			continue;
		}
		/* Get CLI input */
		cli = readline(ppam_prompt);
		if (unlikely((cli == NULL) || strncmp(cli, "q", 1) == 0))
			break;
		if (cli[0] == 0) {
			free(cli);
			continue;
		}

		cli_argv = history_tokenize(cli);
		if (unlikely(cli_argv == NULL)) {
			error(EXIT_SUCCESS, 0,
			      "Out of memory while parsing: %s", cli);
			free(cli);
			continue;
		}
		for (cli_argc = 0; cli_argv[cli_argc] != NULL; cli_argc++)
			;

		foreach_cli_table_entry(cli_cmd) {
			if (strcmp(cli_argv[0], cli_cmd->cmd) == 0) {
				rcode = cli_cmd->handle(cli_argc, cli_argv);
				if (unlikely(rcode < 0))
					error(EXIT_SUCCESS, 0, "%s: %s",
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
	of_finish();
	return rcode;
}
