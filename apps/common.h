#ifndef APPS_COMMON_H
#define APPS_COMMON_H

#include "compat.h"
#include <fsl_shmem.h>

/* System headers required for apps but not for drivers */
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/ip.h>

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
int run_threads_custom(struct thread_data *ctxs, int num_ctxs, int enable_macs);
static inline int run_threads(struct thread_data *ctxs, int num_ctxs,
			int first_cpu, int (*fn)(thread_data_t *),
			int enable_macs)
{
	int loop;
	for (loop = 0; loop < num_ctxs; loop++) {
		ctxs[loop].cpu = first_cpu + loop;
		ctxs[loop].index = loop;
		ctxs[loop].fn = fn;
		ctxs[loop].total_cpus = num_ctxs;
		ctxs[loop].am_master = (loop == 0);
	}
	return run_threads_custom(ctxs, num_ctxs, enable_macs);
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

/* Or write your code in the following way;
 *     sync_start_if_master(whoami) {
 *             ... stuff that should only happen on the master ...
 *     }
 *     sync_end(whoami);
 */
#define sync_start_if_master(whoami) \
	if (!(whoami)->am_master) \
		sync_secondary(whoami); \
	else if (sync_primary_wait(whoami),1)
#define sync_end(whoami) \
	if ((whoami)->am_master) \
		sync_primary_release(tdata);

/* Utility functions */
static inline int my_toul(const char *str, char **endptr, long toobig)
{
	unsigned long tmp = strtoul(str, endptr, 0);
	if ((tmp == ULONG_MAX) || (*endptr == str)) {
		fprintf(stderr, "error: can't parsing '%s'\n", str);
		exit(-1);
	}
	if (tmp >= toobig) {
		fprintf(stderr, "error: value %lu out of range\n", tmp);
		exit(-1);
	}
	return (int)tmp;
}

/* 64-bit atomics */
struct bigatomic {
	atomic_t upper;
	atomic_t lower;
};

static inline void bigatomic_set(struct bigatomic *b, int i)
{
	atomic_set(&b->upper, 0);
	atomic_set(&b->lower, i);
}
static inline u64 bigatomic_read(struct bigatomic *b)
{
	u32 upper, lower;
	do {
		upper = atomic_read(&b->upper);
		lower = atomic_read(&b->lower);
	} while (upper != atomic_read(&b->upper));
	return ((u64)upper << 32) | (u64)lower;
}
static inline void bigatomic_inc(struct bigatomic *b)
{
	if (atomic_inc_and_test(&b->lower))
		atomic_inc(&b->upper);
}

#endif /* !APPS_COMMON_H */

