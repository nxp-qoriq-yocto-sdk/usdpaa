#include "common.h"

/* Run-list. This isn't locked because it's built up by the app thread. Now
 * early-starting threads may enter sync_cpus() before late-starting threads are
 * in the list, but the list isn't iterated until the atomic counter reaches its
 * max, ie. once all threads are inside sync_cpus()s, implying the list is
 * complete. So no init/modification races -> no locks. */
static thread_data_t *run_list_head, *run_list_tail;
static atomic_t cpus_ready = 0;

/* Cpus call this routine to synchronise. The secondary cores signal their
 * readyness by incrementing "ready", the primary core polls
 * until "ready" hits the desired total. (Ie. except for one-off writes from
 * secondary cores, "ready" stays cache-local to cpu 0.) After incrementing
 * "ready", the secondary cores wait for the go-ahead by polling on their "kick"
 * signal, which cpu 0 sets once everyone is ready. (Ie. except for one-off
 * writes from cpu 0, the "waker" values stay cache-local to their respective
 * cpus.) The primary core has a "wait" and "release" interface, allowing it an
 * opportunity to do things while all other threads are paused "ready".
 *
 * The idea behind the per-thread "kicks" and the global "cpus_ready" is to
 * avoid bursts of coherency noise when tests are starting up or finishing, as
 * these would contaminate the results. This scheme involves a little coherency
 * action, but only for the one-off writes, the important thing is that the
 * polling should stay cache-local. */
void sync_secondary(thread_data_t *whoami)
{
	atomic_inc(&cpus_ready);
	/* secondary cpus wait for the "go ahead" */
	while (!whoami->kick)
		;
	whoami->kick = 0;
}
void sync_primary_wait(thread_data_t *whoami)
{
	atomic_inc(&cpus_ready);
	/* waits for the others to be ready */
	while (atomic_read(&cpus_ready) < whoami->total_cpus)
		;
}
void sync_primary_release(thread_data_t *whoami)
{
	thread_data_t *loop;
	atomic_set(&cpus_ready, 0);
	/* give the secondary cpus the "go ahead" */
	loop = run_list_head;
	while (loop) {
		loop->kick = 1;
		loop = loop->next;
	}
}

static __thread thread_data_t *__my_thread_data;

thread_data_t *my_thread_data(void)
{
	return __my_thread_data;
}

static void *thread_wrapper(void *arg)
{
	thread_data_t *tdata = (thread_data_t *)arg;
	cpu_set_t cpuset;
	int s;

	__my_thread_data = tdata;
	/* Set this thread affine to cpu */
	CPU_ZERO(&cpuset);
	CPU_SET(tdata->cpu, &cpuset);
	s = pthread_setaffinity_np(tdata->id, sizeof(cpu_set_t), &cpuset);
	if (s != 0) {
		handle_error_en(s, "pthread_setaffinity_np");
		goto end;
	}
	/* Bman must go first, otherwise the FQ allocator can't initialise */
	s = bman_thread_init(tdata->cpu);
	if (s) {
		fprintf(stderr, "bman_thread_init(%d) failed, ret=%d\n",
			tdata->cpu, s);
		goto end;
	}
	s = qman_thread_init(tdata->cpu);
	if (s) {
		fprintf(stderr, "qman_thread_init(%d) failed, ret=%d\n",
			tdata->cpu, s);
		goto end;
	}
	/* Synchronise, and have the master thread seed the FQ allocator prior
	 * to releasing the secondary threads. */
	if (tdata->am_master) {
		int loop, res = 0;
		sync_primary_wait(tdata);
		__fqalloc_init();
		/* FIXME: hard-coded */
		for (loop = 256; loop < 512; loop++) {
			res = qm_fq_free_flags(loop, QM_FQ_FREE_WAIT |
				((loop == 511) ? QM_FQ_FREE_WAIT_SYNC : 0));
			if (res) {
				fprintf(stderr, "qm_fq_free_flags(%d) failed, "
					"ret=%d\n", loop, res);
				break;
			}
		}
		if (!res)
			printf("Seeded FQIDs 256..511\n");
		sync_primary_release(tdata);
	} else
		sync_secondary(tdata);
	/* Invoke the application thread function */
	s = tdata->fn(tdata);
end:
	__my_thread_data = NULL;
	tdata->result = s;
	return NULL;
}

int run_threads_custom(struct thread_data *ctxs, int num_ctxs)
{
	int i, err;
	/* Create the threads */
	for (i = 0; i < num_ctxs; i++) {
		ctxs[i].next = NULL;
		ctxs[i].kick = 0;
		/* Add to the run_list */
		if (!run_list_head) {
			run_list_head = run_list_tail = &ctxs[i];
		} else {
			run_list_tail->next = &ctxs[i];
			run_list_tail = run_list_tail->next;
		}
		/* Create+start the thread */
		int res = pthread_create(&ctxs[i].id, NULL, thread_wrapper,
					&ctxs[i]);
		if (res != 0) {
			fprintf(stderr, "error starting thread %d, %d already "
				"started\n", i, i - 1);
			return res;
		}
	}
	/* Wait for them to join */
	err = 0;
	for (i = 0; i < num_ctxs; i++) {
		int res = pthread_join(ctxs[i].id, NULL);
		if (res != 0) {
			fprintf(stderr, "error joining thread %d\n", i);
			if (!err)
				err = res;
		}
	}
	run_list_head = run_list_tail = NULL;
	return err;
}

