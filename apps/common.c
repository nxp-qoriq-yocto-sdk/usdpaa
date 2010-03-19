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

/* Run-list. This isn't locked because it's built up by the app thread. Now
 * early-starting threads may enter sync_cpus() before late-starting threads are
 * in the list, but the list isn't iterated until the master thread has been
 * signalled by *all* threads (incl. late-stating ones), and as the master
 * thread is created first, there is no need for locking. */
static thread_data_t *run_list_head, *run_list_tail;

/* Synchronisation. The master thread's counter must hit n-1 (n is # of cpus)
 * before being signalled, the other threads' counters only need to hit 1 to be
 * signalled. The barrier works by having secondary threads increment the master
 * thread's counter (the last one signals) and then wait for the master thread
 * to signal them in return. This gives the master a window of opportunity in
 * which the other threads are all in the barrier waiting to get back out. */
void sync_secondary(thread_data_t *whoami)
{
	BUG_ON(whoami == run_list_head);
	/* Lock the master, increment his counter, and signal if everyone has
	 * reached the barrier */
	thread_kick_lock(&run_list_head->kick);
	if (++run_list_head->counter == (whoami->total_cpus - 1))
		thread_kick_signal(&run_list_head->kick);
	thread_kick_unlock(&run_list_head->kick);
	/* Wait for the master to signal us back */
	thread_kick_lock(&whoami->kick);
	if (!whoami->counter)
		thread_kick_wait(&whoami->kick);
	whoami->counter = 0;
	barrier();
	thread_kick_unlock(&whoami->kick);
}
void sync_primary_wait(thread_data_t *whoami)
{
	BUG_ON(whoami != run_list_head);
	/* Wait to be signalled that the secondaries are all past the barrier */
	thread_kick_lock(&whoami->kick);
	if (whoami->counter != (whoami->total_cpus - 1))
		thread_kick_wait(&whoami->kick);
	thread_kick_unlock(&whoami->kick);
}
void sync_primary_release(thread_data_t *whoami)
{
	thread_data_t *loop;
	BUG_ON(whoami != run_list_head);
	BUG_ON(whoami->counter != (whoami->total_cpus - 1));
	whoami->counter = 0;
	barrier();
	/* give the secondary cpus the "go ahead" */
	loop = whoami->next;
	while (loop) {
		thread_kick_lock(&loop->kick);
		BUG_ON(loop->counter);
		loop->counter = 1;
		thread_kick_signal(&loop->kick);
		thread_kick_unlock(&loop->kick);
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
	/* Synchronise to map shmem and init the FQ allocator. */
	sync_start_if_master(tdata) {
		s = fsl_shmem_setup();
		if (s)
			fprintf(stderr, "Continuing despite shmem failure\n");
		__fqalloc_init();
	}
	sync_end(tdata);
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
	struct thread_data *ctx;
	/* Create the threads */
	for (i = 0, ctx = &ctxs[0]; i < num_ctxs; i++, ctx++) {
		ctx->next = NULL;
		err = thread_kick_init(&ctx->kick);
		if (err) {
			fprintf(stderr, "error initialising thread locks\n");
			return err;
		}
		ctx->counter = 0;
		/* Add to the run_list */
		if (!i) {
			run_list_head = run_list_tail = ctx;
			ctx->am_master = 1;
		} else {
			run_list_tail->next = ctx;
			run_list_tail = run_list_tail->next;
			ctx->am_master = 0;
		}
		/* Create+start the thread */
		err = pthread_create(&ctx->id, NULL, thread_wrapper, ctx);
		if (err != 0) {
			fprintf(stderr, "error starting thread %d, %d already "
				"started\n", i, i - 1);
			return err;
		}
	}
	/* Wait for them to join */
	err = 0;
	for (i = 0, ctx = &ctxs[0]; i < num_ctxs; i++, ctx++) {
		int res = pthread_join(ctx->id, NULL);
		if (res != 0) {
			fprintf(stderr, "error joining thread %d\n", i);
			if (!err)
				err = res;
		}
	}
	run_list_head = run_list_tail = NULL;
	return err;
}

