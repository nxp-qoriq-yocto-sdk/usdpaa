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

#include <unistd.h>
#include <readline.h>  /* libedit */
#include <error.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <internal/compat.h>

#include <fsl_cpu_hotplug.h>
#include <app_config.h>
#include <capwap_cfg.h>

/*
 * CAPWAP paths to FMan configuration files.
 */
const char capwap_pcd_path[] __attribute__((weak)) = __stringify(DEF_PCD_PATH);
const char capwap_cfg_path[] __attribute__((weak)) = __stringify(DEF_CFG_PATH);
const char tunnel_cfg_path[] __attribute__((weak)) = __stringify(DEF_TUNNEL_PATH);

/***************/
/* Global data */
/***************/

/* The SDQCR mask to use (computed from pchannels) */
static uint32_t sdqcr;

struct app_conf app_conf;

/* Configuration */
struct usdpaa_netcfg_info *netcfg;

/* We want a trivial mapping from bpid->pool, so just have an array of pointers,
 * most of which are probably NULL. */
struct bman_pool *pool[CAPWAP_MAX_BPID];

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


#ifdef CAPWAP_CGR
/* A congestion group to hold Rx FQs (uses netcfg::cgrids[0]) */
static struct qman_cgr cgr_rx;
/* Tx FQs go into a separate CGR (uses netcfg::cgrids[1]) */
static struct qman_cgr cgr_tx;
#endif

uint32_t send_packets_count;

extern int tunnel_parse_cfgfile(const char *cfg_file);

static int init_pool_channels(void)
{
	int ret = qman_alloc_pool_range(&pchannels[0], CAPWAP_NUM_POOL_CHANNELS,
					1, 0);
	printf("alloced %d pool channel\n", ret);
	if (ret != CAPWAP_NUM_POOL_CHANNELS)
		return -ENOMEM;
	for (ret = 0; ret < CAPWAP_NUM_POOL_CHANNELS; ret++) {
		sdqcr |= QM_SDQCR_CHANNELS_POOL_CONV(pchannels[ret]);
		TRACE("Adding pool 0x%x to SDQCR, 0x%08x -> 0x%08x\n",
		      pchannels[ret],
		      QM_SDQCR_CHANNELS_POOL_CONV(pchannels[ret]),
		      sdqcr);
	}
	return 0;
}

static void finish_pool_channels(void)
{
	qman_release_pool_range(pchannels[0], CAPWAP_NUM_POOL_CHANNELS);
}

#ifdef CAPWAP_CGR
static void release_cgrids(void)
{
	qman_release_cgrid(cgr_rx.cgrid);
	qman_release_cgrid(cgr_tx.cgrid);
}
#endif

/*********************************/
/* CGR state-change notification */
/*********************************/

#ifdef CAPWAP_CGR
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
#ifdef CAPWAP_CGR
		worker_msg_query_cgr
#endif
	} msg;
#ifdef CAPWAP_CGR
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
	unsigned int uid;
	pthread_t id;
	int result;
	struct list_head node;
} ____cacheline_aligned;

static unsigned int next_worker_uid;

/* -------------------------------- */
/* msg-processing within the worker */

void do_global_finish(void)
{
	struct list_head *i, *tmpi;
	int loop;

	list_for_each(i, &ifs)
		capwap_interface_finish_rx((struct capwap_interface *)i);
	list_for_each_safe(i, tmpi, &ifs)
		capwap_interface_finish((struct capwap_interface *)i);
#ifdef CAPWAP_CGR
	qman_delete_cgr(&cgr_rx);
	qman_delete_cgr(&cgr_tx);
#endif
	/* Tear down buffer pools */
	for (loop = 0; loop < ARRAY_SIZE(pool); loop++) {
		if (pool[loop]) {
			bman_free_pool(pool[loop]);
			bman_release_bpid(loop);
			pool[loop] = NULL;
		}
	}
}

static void do_global_init(void)
{
#ifdef CAPWAP_CGR
	uint32_t cgrids[2];
#endif
	int err;

#ifdef CAPWAP_CGR
	unsigned int numrxfqs = 0, numtxfqs = 0;
	struct qm_mcc_initcgr opts = {
		.we_mask = QM_CGR_WE_CS_THRES |
#ifdef CAPWAP_CSCN
				QM_CGR_WE_CSCN_EN |
#endif
#ifdef CAPWAP_CSTD
				QM_CGR_WE_CSTD_EN |
#endif
				QM_CGR_WE_MODE,
		.cgr = {
#ifdef CAPWAP_CSCN
			.cscn_en = QM_CGR_EN,
#endif
#ifdef CAPWAP_CSTD
			.cstd_en = QM_CGR_EN,
#endif
			.mode = QMAN_CGR_MODE_FRAME
		}
	};
	err = qman_alloc_cgrid_range(&cgrids[0], 2, 1, 0);
	if (err != 2) {
		fprintf(stderr, "error: insufficient CGRIDs available\n");
		exit(EXIT_FAILURE);
	}

	/* Set up Rx CGR */
	for (loop = 0; loop < netcfg->num_ethports; loop++) {
		const struct fm_eth_port_cfg *p = &netcfg->port_cfg[loop];
		struct fmc_netcfg_fqrange *fqr;
		list_for_each_entry(fqr, p->list, list) {
			numrxfqs += fqr->count;
			numtxfqs += (p->fman_if->mac_type == fman_mac_10g) ?
				CAPWAP_TX_FQS_10G :
				(p->fman_if->mac_type == fman_offline) ?
				CAPWAP_TX_FQS_OFFLINE : CAPWAP_TX_FQS_1G;
		}
	}
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres,
		numrxfqs * CAPWAP_CGR_RX_PERFQ_THRESH, 0);
	cgr_rx.cgrid = cgrids[0];
	cgr_rx.cb = cgr_rx_cb;
	err = qman_create_cgr(&cgr_rx, QMAN_CGR_FLAG_USE_INIT, &opts);
	if (err)
		fprintf(stderr, "error: rx CGR init, continuing\n");

	/* Set up Tx CGR */
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres,
		numtxfqs * CAPWAP_CGR_TX_PERFQ_THRESH, 0);
	cgr_tx.cgrid = cgrids[1];
	cgr_tx.cb = cgr_tx_cb;
	err = qman_create_cgr(&cgr_tx, QMAN_CGR_FLAG_USE_INIT, &opts);
	if (err)
		fprintf(stderr, "error: tx CGR init, continuing\n");
#endif
	/* Init CAPWAP Interface, FQs and BMan pool */
	err = interface_init();
	if (unlikely(err < 0)) {
		fprintf(stderr, "error: capwap interface init failed (%d)\n", err);
		exit(EXIT_FAILURE);
	}
	/* Setup CAPWAP tunnels */
	err = capwap_usecase();
	if (err) {
		fprintf(stderr, "error: capwap use case init failed:0x%x", err);
		exit(EXIT_FAILURE);
	}
	if(app_conf.loop_back)
		fman_if_loopback_enable(app_conf.capwap_eth.interface);

	/* Enable promiscuous mode for CAPWAP Ethernet port */
	fman_if_promiscuous_enable(app_conf.capwap_eth.interface);
}

static int process_msg(struct worker *worker, struct worker_msg *msg)
{
	int ret = 1;

	/* List */
	if (msg->msg == worker_msg_list)
		printf("Thread uid:%u alive (on cpu %d)\n",
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

#ifdef CAPWAP_CGR
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
#ifdef CAPWAP_IDLE_IRQ
static void drain_4_bytes(int fd, fd_set *fdset)
{
	if (FD_ISSET(fd, fdset)) {
		uint32_t junk;
		ssize_t sjunk = read(fd, &junk, sizeof(junk));
		if (sjunk != sizeof(junk))
			perror("UIO irq read error");
	}
}
#endif
static void *worker_fn(void *__worker)
{
	struct worker *worker = __worker;
	cpu_set_t cpuset;
	int s, ret;
	int calm_down = 16, slowpoll = 0;
#ifdef CAPWAP_IDLE_IRQ
	int fd_qman, fd_bman, nfds;
	int irq_mode = 0, fastpoll = 0;
	fd_set readset;
#endif

	TRACE("This is the thread on cpu %d\n", worker->cpu);

	/* Set this cpu-affinity */
	CPU_ZERO(&cpuset);
	CPU_SET(worker->cpu, &cpuset);
	s = pthread_setaffinity_np(worker->id, sizeof(cpu_set_t), &cpuset);
	if (s != 0) {
		fprintf(stderr, "pthread_setaffinity_np(%d) failed, ret=%d\n",
			worker->cpu, s);
		goto err;
	}

	/* Initialise bman/qman portals */
	s = bman_thread_init();
	if (s) {
		fprintf(stderr, "No available Bman portals for cpu %d\n",
			worker->cpu);
		goto err;
	}
	s = qman_thread_init();
	if (s) {
		fprintf(stderr, "No available Qman portals for cpu %d\n",
			worker->cpu);
		bman_thread_finish();
		goto err;
	}

#ifdef CAPWAP_IDLE_IRQ
	fd_qman = qman_thread_fd();
	fd_bman = bman_thread_fd();
	if (fd_qman > fd_bman)
		nfds = fd_qman + 1;
	else
		nfds = fd_bman + 1;
#endif

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
	 * "do_global_init" before the thread even runs. */
	if (worker->msg->msg == worker_msg_do_global_init) {
		s = process_msg(worker, worker->msg);
		if (s <= 0)
			goto global_init_fail;
	}

	/* Run! */
	TRACE("Starting poll loop on cpu %d\n", worker->cpu);
	while (check_msg(worker)) {
#ifdef CAPWAP_IDLE_IRQ
		/* IRQ mode */
		if (irq_mode) {
			/* Go into (and back out of) IRQ mode for each select,
			 * it simplifies exit-path considerations and other
			 * potential nastiness. */
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
			ret = qman_poll_slow();
			ret |= bman_poll_slow();
			if (ret) {
				slowpoll = WORKER_SLOWPOLL_BUSY;
#ifdef CAPWAP_IDLE_IRQ
				fastpoll = 0;
#endif
			} else
				slowpoll = WORKER_SLOWPOLL_IDLE;
		}
#ifdef CAPWAP_IDLE_IRQ
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

global_init_fail:
	qman_static_dequeue_del(~(u32)0);
	while (calm_down--) {
		qman_poll_slow();
		qman_poll_dqrr(16);
	}
	qman_thread_finish();
	bman_thread_finish();
err:
	TRACE("Leaving thread on cpu %d\n", worker->cpu);
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

#ifdef CAPWAP_CGR
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
static int msg_query_cgr(struct worker *worker)
{
	int ret = msg_post(worker, worker_msg_query_cgr);
	if (ret)
		return ret;
	printf("Rx CGR ID: %d, selected fields;\n", cgr_rx.cgrid);
	dump_cgr(&worker->msg->query_cgr.res_rx);
	printf("Tx CGR ID: %d, selected fields;\n", cgr_tx.cgrid);
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
	err = posix_memalign((void **)&ret->msg, L1_CACHE_BYTES, sizeof(*ret->msg));
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
	 * message processing loop.*/
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
	fprintf(stderr, "error: failed to create worker for cpu %d\n", cpu);
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
	unsigned int uid = worker->uid;
	BUG_ON(worker == primary);
	msg_quit(worker);
	err = pthread_join(worker->id, NULL);
	if (err) {
		/* Leak, but warn */
		fprintf(stderr, "Failed to join thread uid:%u (cpu %d)\n",
			worker->uid, worker->cpu);
		return;
	}
	list_del(&worker->node);
	free(worker->msg);
	free(worker);
	printf("Thread uid:%u killed (cpu %d)\n", uid, cpu);
}

static int worker_reap(struct worker *worker)
{
	if (pthread_tryjoin_np(worker->id, NULL))
		return -EBUSY;
	if (worker == primary) {
		pr_crit("Primary thread died!\n");
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

#ifdef CAPWAP_CGR
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
	fprintf(stderr, "error: invalid cpu '%s'\n", str);
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

struct capwap_arguments
{
	const char *fm_cfg;
	const char *fm_pcd;
	const char *tunnel_cfg;
	int first, last;
	int noninteractive;
	size_t dma_sz;
	const char *fm;
	const char *capwap_eth;
	const char *ib_op;
	const char *ob_op;
	const char *mode;
	const char *non_capwap_eth1;
	const char *non_capwap_eth2;
	bool loopback;
};

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = "<usdpa-devel@gforge.freescale.net>";

static const char argp_doc[] = "\n\
USDPAA capwap application\
";
static const char _capwap_args[] = "[cpu-range]";

static const struct argp_option argp_opts[] = {
	{"fm-config", 'c', "FILE", 0, "FMC configuration XML file"},
	{"fm-pcd", 'p',	"FILE",	0, "FMC PCD XML file"},
	{"tunnel-config", 't', "FILE", 0, "CAPWAP tunnel configuration XML file"},
	{"non-interactive", 'n', 0, 0, "Ignore stdin"},
	{"dma-mem", 'd', "SIZE", 0, "Size of DMA region to allocate"},
	{"cpu-range", 0, 0, OPTION_DOC,	"'index' or 'first'..'last'"},
	{"loopback", 'l', 0, 0, "Loopback on CAPWAP Ethernet port"},
	{"fm", 'f', "INT", 0, "FMAN index"},
	{"capwap-eth", 'a', "MAC-Index,type", 0, "MAC Index and type(1:1G,2:10G) for CAPWAP Ethernet Port"},
	{"ib-op", 'g', "INT", 0, "Inbound Offline Port Index"},
	{"ob-op", 'o', "INT", 0, "Outbound Offline Port Index"},
	{"mode", 'm', "INT", 0, "Case Mode(1: default normal mode, 2: all-offload mode)"},
	{"n-capwap-eth1", 's', "MAC-Index,type", 0, "Mode 2:MAC Index and type(1:1G,2:10G) for Non-CAPWAP Ethernet Port I"},
	{"n-capwap-eth2", 'u', "MAC-Index,type", 0, "Mode 2:MAC Index and type(1:1G,2:10G) for Non-CAPWAP Ethernet Port II"},
	{}
};

static error_t capwap_parse(int key, char *arg, struct argp_state *state)
{
	int _errno;
	struct capwap_arguments *args;
	char *endptr;
	unsigned long val;

	args = (typeof(args))state->input;
	switch (key) {
	case 'c':
		args->fm_cfg = arg;
		break;
	case 'p':
		args->fm_pcd = arg;
		break;
	case 't':
		args->tunnel_cfg = arg;
		break;
	case 'n':
		args->noninteractive = 1;
		break;
	case 'd':
		val = strtoul(arg, &endptr, 0);
		if ((val == ULONG_MAX) || (*endptr != '\0') || !val)
			argp_usage(state);
		args->dma_sz = (size_t)val;
		break;
	case 'l':
		args->loopback = true;
		break;
	case 'f':
		args->fm = arg;
		break;
	case 'a':
		args->capwap_eth = arg;
		break;
	case 'g':
		args->ib_op = arg;
		break;
	case 'o':
		args->ob_op = arg;
		break;
	case 'm':
		args->mode = arg;
		break;
	case 's':
		args->non_capwap_eth1 = arg;
		break;
	case 'u':
		args->non_capwap_eth2 = arg;
		break;
	case ARGP_KEY_ARGS:
		if (state->argc - state->next != 1)
			argp_usage(state);
		_errno = parse_cpus(state->argv[state->next], &args->first, &args->last);
		if (unlikely(_errno < 0))
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp capwap_argp = {argp_opts, capwap_parse, _capwap_args, argp_doc, NULL};

static struct capwap_arguments capwap_args;

/***************/
/* CLI support */
/***************/

extern const struct cli_table_entry cli_table_start[], cli_table_end[];

#define foreach_cli_table_entry(cli_cmd)	\
	for (cli_cmd = cli_table_start; cli_cmd < cli_table_end; cli_cmd++)

static int capwap_cli_help(int argc, char *argv[])
{
	const struct cli_table_entry *cli_cmd;

	puts("Available commands:");
	foreach_cli_table_entry (cli_cmd) {
		printf("%s ", cli_cmd->cmd);
	}
	puts("");

	return argc != 1 ? -EINVAL: 0;
}

static int capwap_cli_add(int argc, char *argv[])
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

#ifdef CAPWAP_CGR
static int capwap_cli_cgr(int argc, char *argv[])
{
	struct worker *worker;

	if (argc != 1)
		return -EINVAL;

	worker = worker_first();
	msg_query_cgr(worker);

	return 0;
}
#endif

static int capwap_cli_list(int argc, char *argv[])
{
	struct worker *worker;

	if (argc > 1)
		return -EINVAL;
	list_for_each_entry(worker, &workers, node)
		msg_list(worker);
	return 0;
}

static int capwap_cli_loopback(int argc, char *argv[])
{
	if (argc != 2)
		return -EINVAL;

	if (strcmp(argv[1], "off") == 0)
		fman_if_loopback_disable(app_conf.capwap_eth.interface);
	else if (strcmp(argv[1], "on") == 0)
		fman_if_loopback_enable(app_conf.capwap_eth.interface);

	return 0;
}

static int capwap_cli_macs(int argc, char *argv[])
{
	struct list_head *i;
	const struct fman_if *fif;
	const struct fm_eth_port_cfg *pcfg;

	if (argc != 2)
		return -EINVAL;

	if (strcmp(argv[1], "off") == 0)
		list_for_each(i, &ifs) {
			pcfg = capwap_interface_pcfg((struct capwap_interface *)i);
			fif = pcfg->fman_if;
			if (fif->mac_type == fman_mac_less ||
				 fif->shared_mac_info.is_shared_mac == 1)
				capwap_interface_disable_shared_rx(
					(struct capwap_interface *)i);
			else
				capwap_interface_disable_rx(
					(struct capwap_interface *)i);
		}
	else if (strcmp(argv[1], "on") == 0) {
		list_for_each(i, &ifs) {
			pcfg = capwap_interface_pcfg((struct capwap_interface *)i);
			fif = pcfg->fman_if;
			if (fif->mac_type == fman_mac_less ||
				 fif->shared_mac_info.is_shared_mac == 1)
				capwap_interface_enable_shared_rx(
					(struct capwap_interface *)i);
			else
				capwap_interface_enable_rx(
					(struct capwap_interface *)i);
		}
	}
	else
		return -EINVAL;

	return 0;
}

static int capwap_cli_rm(int argc, char *argv[])
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

static int capwap_cli_promisc(int argc, char *argv[])
{
	struct list_head *i;
	const struct fman_if *fif;
	const struct fm_eth_port_cfg *pcfg;
	bool enable;
	uint8_t fman_idx, mac_idx;
	int ret = -ENODEV;

	if (argc != 4)
		return -EINVAL;

	/* Parse promiscuous mode type */
	if (!strncmp(argv[1], "enable", 6)) {
		enable = true;
	} else if (!strncmp(argv[1], "disable", 7)) {
		enable = false;
	} else
		return -EINVAL;

	/* Parse FMan number */
	if (!strncmp(argv[2], "f:", 2)) {
		fman_idx = argv[2][2] - '0';
	} else
		return -EINVAL;

	/* Parse port number */
	if (!strncmp(argv[3], "p:", 2)) {
		mac_idx = argv[3][2] - '0';
	} else
		return -EINVAL;

	list_for_each(i, &ifs) {
		pcfg = capwap_interface_pcfg((struct capwap_interface *)i);
		fif = pcfg->fman_if;
		if ((fif->fman_idx == fman_idx) && (fif->mac_idx == mac_idx)) {
			if (enable)
				fman_if_promiscuous_enable(fif);
			else
				fman_if_promiscuous_disable(fif);
			ret = 0;
			break;
		}
	}

	if (ret)
		fprintf(stderr, "error: no such network interface (fman:%d, "
			"port:%d)\n", fman_idx, mac_idx);

	return ret;
}

static int capwap_cli_ifconfig(int argc, char *argv[])
{
	dump_usdpaa_netcfg(netcfg);
	return 0;
}

void *listener_fn(void * arg)
{
	/* Initialization required for connecting with cpu_hotplug daemon */
	struct worker *worker;
	struct sockaddr_un s_to_daemon, s_from_daemon;
	char buf[BUF_SIZE_MAX];
	char s_pid[SIZE_PID_MAX];
	int len, core_num, ret, n;
	unsigned int to_daemon, from_daemon;
	pid_t pid;
	/* Supporting maximum 32 cpu, thread on core_num >32 won't be restore*/
	u32 core_map = 0;

	pid = getpid();
	sprintf(s_pid, "/%d", pid);

	to_daemon = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (to_daemon < 0)
		perror("opening datagram socket");

	from_daemon = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (from_daemon < 0)
		perror("opening datagram socket");

	s_to_daemon.sun_family = AF_UNIX;
	strcpy(s_to_daemon.sun_path, S_APP_PATH);

	s_from_daemon.sun_family = AF_UNIX;
	strcpy(s_from_daemon.sun_path, s_pid);

	len = sizeof(s_from_daemon);

	unlink(s_from_daemon.sun_path);
	if (bind(from_daemon, (struct sockaddr *)&s_from_daemon, len) == -1)
		perror("bind failed");

	memset(buf, 0, BUF_SIZE_MAX);
	sprintf(buf, "%d", pid);

	len = sizeof(s_to_daemon);
	n = strlen(buf);

	/* register with usdpaa_cpu_hotplug daemon */
	ret = sendto(to_daemon, buf, n, 0,
			(const struct sockaddr *)&s_to_daemon, len);
	if (ret  == -1)
		perror("cpu hotplug daemon not running");

	while (1) {
		/* Check msgs from daemon */
		memset(buf, 0, BUF_SIZE_MAX);
		if (read(from_daemon, buf, BUF_SIZE_MAX) < 0)
			perror("cpu hotplug daemon not running");

		/* Process the received cmd */
		core_num = atoi(&buf[1]);
		switch (buf[0]) {
		case '+':
			/* check if a threads was running on core_num */
			if (core_map & (1 << core_num)) {
				/* if thread was running on core_num,
				 * start a thread on that core */
				core_map = core_map & ~(1 << core_num);
				worker = worker_new(core_num, 0);
				if (worker)
					worker_add(worker);
			}
			break;
		case '-':
			/* check if a thread is running on core_num,
			 * if yes kill it */
			worker = worker_find(core_num, 0);
			if (worker) {
				worker_free(worker);
				core_map = core_map | 1 << core_num;
			}
			break;
		}
	}
}

cli_cmd(help, capwap_cli_help);
cli_cmd(add, capwap_cli_add);
#ifdef CAPWAP_CGR
cli_cmd(cgr, capwap_cli_cgr);
#endif
cli_cmd(list, capwap_cli_list);
cli_cmd(macs, capwap_cli_macs);
cli_cmd(rm, capwap_cli_rm);
cli_cmd(promisc, capwap_cli_promisc);
cli_cmd(ifconfig, capwap_cli_ifconfig);
cli_cmd(loopback, capwap_cli_loopback);

extern int capwap_cli_fslbrctl(int argc, char *argv[]);
cli_cmd(fslbrctl, capwap_cli_fslbrctl);
#if 0
extern void dump_pcd_regs(void);
cli_cmd(dumppcd, dump_pcd_regs);
#endif
const char capwap_prompt[] = "capwap> ";

static inline struct fman_if *get_fif(int fm,
				      int port_idx,
				      enum fman_mac_type type)
{
	int idx;
	struct fm_eth_port_cfg *port_cfg;
	for (idx = 0; idx < netcfg->num_ethports; idx++) {
		port_cfg = &netcfg->port_cfg[idx];
		if ((fm == port_cfg->fman_if->fman_idx) &&
		    (type == port_cfg->fman_if->mac_type) &&
		    (port_idx == port_cfg->fman_if->mac_idx))
			return port_cfg->fman_if;
	}
	return NULL;
}

static struct fman_if *parse_eth_portarg(const char *p, int fm_idx)
{
	char *pch;
	int port_idx, port_type;
	pch = strtok((char *)p, ",");
	port_idx = atoi(pch);
	pch = strtok(NULL, ",");
	if (!pch)
		return NULL;
	port_type = atoi(pch);
	return get_fif(fm_idx, port_idx, port_type);
}

static struct fman_if *parse_offline_portarg(const char *p, int fm_idx)
{
	int port_idx;
	port_idx = atoi(p);
	return get_fif(fm_idx, port_idx, fman_offline);
}

int main(int argc, char *argv[])
{
	struct worker *worker, *tmpworker;
	const char *pcd_path = capwap_pcd_path;
	const char *cfg_path = capwap_cfg_path;
	const char *tunnel_path = tunnel_cfg_path;
	const char *envp;
	int loop;
	int rcode, cli_argc;
	char *cli, **cli_argv;
	const struct cli_table_entry *cli_cmd;
	pthread_t listener;

	rcode = of_init();
	if (rcode) {
		pr_err("of_init() failed\n");
		exit(EXIT_FAILURE);
	}

	ncpus = (unsigned long)sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus > 1) {
		capwap_args.first = 1;
		capwap_args.last = 1;
	}
	capwap_args.dma_sz = CAPWAP_DMA_MAP_SIZE;
	capwap_args.noninteractive = 0;
	app_conf.loop_back = false;

	rcode = argp_parse(&capwap_argp, argc, argv, 0, NULL, &capwap_args);
	if (unlikely(rcode != 0))
		return -rcode;

	/* Do global init that doesn't require portal access; */
	/* - load the config (includes discovery and mapping of MAC devices) */
	TRACE("Loading configuration\n");
	if (capwap_args.fm_pcd != NULL)
		pcd_path = capwap_args.fm_pcd;
	else {
		envp = getenv("DEF_PCD_PATH");
		if (envp != NULL)
			pcd_path = envp;
	}
	if (capwap_args.fm_cfg != NULL)
		cfg_path = capwap_args.fm_cfg;
	else {
		envp = getenv("DEF_CFG_PATH");
		if (envp != NULL)
			cfg_path = envp;
	}
	if (capwap_args.tunnel_cfg != NULL)
		tunnel_path = capwap_args.tunnel_cfg;
	else {
		envp = getenv("DEF_TUNNEL_PATH");
		if (envp != NULL)
			tunnel_path = envp;
	}

	/* Parse FMC policy and configuration files for the network
	 * configuration. This also "extracts" other settings into 'netcfg' that
	 * are not necessarily from the XML files, such as the pool channels
	 * that the application is allowed to use (these are currently
	 * hard-coded into the netcfg code). */
	netcfg = usdpaa_netcfg_acquire(pcd_path, cfg_path);
	if (!netcfg) {
		fprintf(stderr, "error: failed to load configuration\n");
		return -1;
	}
	if (!netcfg->num_ethports) {
		fprintf(stderr, "error: no network interfaces available\n");
		return -1;
	}

	rcode = tunnel_parse_cfgfile(tunnel_path);
	if (rcode){
		fprintf(stderr, "error: failed to parse tunnels configuration\n");
		return -1;
	}

	/* fm index */
	if (!capwap_args.fm) {
		fprintf(stderr, "Error : fm arg not set\n");
		return -1;
	}
	app_conf.fm = atoi(capwap_args.fm);
	/* CAPWAP eth port */
	if (!capwap_args.capwap_eth) {
		fprintf(stderr, "Error : capwap-eth arg not set\n");
		return -1;
	}
	app_conf.capwap_eth.interface = parse_eth_portarg(capwap_args.capwap_eth,
					    app_conf.fm);
	if (!app_conf.capwap_eth.interface) {
		fprintf(stderr, "Error : capwap-eth %s invalid\n",
			capwap_args.capwap_eth);
		return -1;
	}
	if (app_conf.capwap_eth.interface->mac_type == fman_mac_1g)
		app_conf.capwap_eth.type = e_FM_PORT_TYPE_RX;
	else if (app_conf.capwap_eth.interface->mac_type == fman_mac_10g)
		app_conf.capwap_eth.type = e_FM_PORT_TYPE_RX_10G;
	else {
		fprintf(stderr, "Error: capwap-eth wrong port type\n");
		return -1;
	}
	/* inbound offline port */
	if (!capwap_args.ib_op) {
		fprintf(stderr, "Error : ib-op arg not set\n");
		return -1;
	}
	app_conf.ib_op.interface = parse_offline_portarg(capwap_args.ib_op,
					       app_conf.fm);
	if (!app_conf.ib_op.interface) {
		fprintf(stderr, "Error : ib-op %s invalid\n",
			capwap_args.ib_op);
		return -1;
	}
	app_conf.ib_op.type = e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
	/* outbound offline port */
	if (!capwap_args.ob_op) {
		fprintf(stderr, "Error : ob-op arg not set\n");
		return -1;
	}
	app_conf.ob_op.interface = parse_offline_portarg(capwap_args.ob_op,
					       app_conf.fm);
	if (!app_conf.ob_op.interface) {
		fprintf(stderr, "Error : ob-op %s invalid\n",
			capwap_args.ob_op);
		return -1;
	}
	app_conf.ob_op.type = e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
	/* CAPWAP eth loopback */
	if (capwap_args.loopback)
		app_conf.loop_back = true;
	/* Use Case Mode */
	if (capwap_args.mode) {
		app_conf.mode = atoi(capwap_args.mode);
		if (app_conf.mode != 1 && app_conf.mode !=2) {
			fprintf(stderr, "Error: mode %s is not supported\n",
					capwap_args.mode);
			return -1;
		}
	} else {
		printf("Using default normal case mode\n");
		app_conf.mode = 1;
	}
	if (app_conf.mode == 2) {
		/* Non-CAPWAP eth port */
		if (!capwap_args.non_capwap_eth1 && !capwap_args.non_capwap_eth2) {
			fprintf(stderr, "Error : must set minimum one non-capwap-eth arg for offload mode\n");
			return -1;
		}
		if (capwap_args.non_capwap_eth1) {
			app_conf.non_capwap_eth1.interface = parse_eth_portarg(capwap_args.non_capwap_eth1,
					    app_conf.fm);
			if (!app_conf.non_capwap_eth1.interface) {
				fprintf(stderr, "Error : non-capwap-eth1 %s invalid\n",
					capwap_args.non_capwap_eth1);
				return -1;
			}
			if (app_conf.non_capwap_eth1.interface->mac_type == fman_mac_1g)
				app_conf.non_capwap_eth1.type = e_FM_PORT_TYPE_RX;
			else if (app_conf.non_capwap_eth1.interface->mac_type == fman_mac_10g)
				app_conf.non_capwap_eth1.type = e_FM_PORT_TYPE_RX_10G;
			else {
				fprintf(stderr, "Error: non-capwap-eth wrong port type\n");
				return -1;
			}
		}
		if (capwap_args.non_capwap_eth2) {
			app_conf.non_capwap_eth2.interface = parse_eth_portarg(capwap_args.non_capwap_eth2,
					    app_conf.fm);
			if (!app_conf.non_capwap_eth2.interface) {
				fprintf(stderr, "Error : non-capwap-eth1 %s invalid\n",
					capwap_args.non_capwap_eth2);
				return -1;
			}
			if (app_conf.non_capwap_eth2.interface->mac_type == fman_mac_1g)
				app_conf.non_capwap_eth2.type = e_FM_PORT_TYPE_RX;
			else if (app_conf.non_capwap_eth2.interface->mac_type == fman_mac_10g)
				app_conf.non_capwap_eth2.type = e_FM_PORT_TYPE_RX_10G;
			else {
				fprintf(stderr, "Error: non-capwap-eth wrong port type\n");
				return -1;
			}
		}
	}

	/* - initialise DPAA */
	rcode = qman_global_init();
	if (rcode)
		fprintf(stderr, "error: qman global init, continuing\n");
	rcode = bman_global_init();
	if (rcode)
		fprintf(stderr, "error: bman global init, continuing\n");
	rcode = init_pool_channels();
	if (rcode)
		fprintf(stderr, "error: no pool channels available\n");
	printf("Configuring for %d network interface%s\n",
		netcfg->num_ethports, netcfg->num_ethports > 1 ? "s" : "");
	/* - map DMA mem */
	TRACE("Initialising DMA mem\n");
	dma_mem_generic = dma_mem_create(DMA_MAP_FLAG_ALLOC, NULL,
					 capwap_args.dma_sz);
	if (!dma_mem_generic)
		fprintf(stderr, "error: dma_mem init, continuing\n");
	printf("Allocated DMA region size 0x%zx\n", capwap_args.dma_sz);

	/* create worker thread to handle listen to daemon */
	rcode = pthread_create(&listener, NULL, listener_fn, NULL);
	if (rcode)
		printf("creation of listener thread failed\n");

	/* Create the threads */
	TRACE("Starting %d threads for cpu-range '%d..%d'\n",
	      capwap_args.last - capwap_args.first + 1, capwap_args.first, capwap_args.last);
	for (loop = capwap_args.first; loop <= capwap_args.last; loop++) {
		worker = worker_new(loop, !primary);
		if (!worker) {
			rcode = -1;
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
				pr_info("Caught dead thread uid:%u (cpu %d)\n",
					worker->uid, worker->cpu);

		/* If non-interactive, have the CLI thread twiddle its thumbs
		 * between (infrequent) checks for dead threads. */
		if (capwap_args.noninteractive) {
			sleep(1);
			continue;
		}
		/* Get CLI input */
		cli = readline(capwap_prompt);
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
	finish_pool_channels();
#ifdef CAPWAP_CGR
	qman_release_cgrid_range(cgr_rx.cgrid, 2);
#endif
	usdpaa_netcfg_release(netcfg);
	of_finish();
	return rcode;
}
