#ifndef APPS_COMMON_H
#define APPS_COMMON_H

#include "compat.h"

#define MAX_THREADS 8

/* Per-thread data, including the pthread id */
typedef struct thread_data thread_data_t;
struct thread_data {
	/* Inputs to run_threads_custom() */
	int cpu;
	int index;
	int (*fn)(thread_data_t *ctx);
	int total_cpus;
	int am_master; /* only one should have this set */
	/* Value used within 'fn' - handle to the pthread; */
	pthread_t id;
	/* Stores fn() return value on return from run_threads_custom(); */
	int result;
	/* Internal state */
	volatile int kick;
	thread_data_t *next;
} ____cacheline_aligned;

/* Threads can determine their own thread_data_t using this; */
thread_data_t *my_thread_data(void);

/* API(s) used to kick off application cpu-affine threads and wait for them to
 * complete. */
int run_threads_custom(struct thread_data *ctxs, int num_ctxs);
static inline int run_threads(struct thread_data *ctxs, int num_ctxs,
			int first_cpu, int (*fn)(thread_data_t *))
{
	int loop;
	for (loop = 0; loop < num_ctxs; loop++) {
		ctxs[loop].cpu = first_cpu + loop;
		ctxs[loop].index = loop;
		ctxs[loop].fn = fn;
		ctxs[loop].total_cpus = num_ctxs;
		ctxs[loop].am_master = (loop == 0);
	}
	return run_threads_custom(ctxs, num_ctxs);
}

#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

/* Synchronise all threads. The master thread can do work between 'wait' and
 * 'release' knowing that the secondary threads are all spinning inside the
 * sync_secondary() function. */
void sync_secondary(thread_data_t *whoami);
void sync_primary_wait(thread_data_t *whoami);
void sync_primary_release(thread_data_t *whoami);

/* Or if the master has no special work to do, a simple sync */
static inline void sync_all(void)
{
	thread_data_t *tdata = my_thread_data();
	if (tdata->am_master) {
		sync_primary_wait(tdata);
		sync_primary_release(tdata);
	} else
		sync_secondary(tdata);
}


#endif /* !APPS_COMMON_H */

