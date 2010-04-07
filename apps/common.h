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

#ifndef APPS_COMMON_H
#define APPS_COMMON_H

#include "compat.h"
#include <fsl_shmem.h>
#include <fman.h>

/* This stuff shouldn't be part of the "compat" header because we don't assume
 * its presence in linux or LWE. */

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
	/* Value used within 'fn' - handle to the pthread; */
	pthread_t id;
	/* Stores fn() return value on return from run_threads_custom(); */
	int result;
	/* application-specific */
	void *appdata;
} ____cacheline_aligned;

/* Threads can determine their own thread_data_t using this; */
thread_data_t *my_thread_data(void);

/* API(s) used to kick off application cpu-affine threads and wait for them to
 * complete. 'am_master' is automatically set for the first thread (running on
 * the first cpu). */
int start_threads_custom(struct thread_data *ctxs, int num_ctxs);
static inline int start_threads(struct thread_data *ctxs, int num_ctxs,
			int first_cpu, int (*fn)(thread_data_t *))
{
	int loop;
	for (loop = 0; loop < num_ctxs; loop++) {
		ctxs[loop].cpu = first_cpu + loop;
		ctxs[loop].index = loop;
		ctxs[loop].fn = fn;
		ctxs[loop].total_cpus = num_ctxs;
	}
	return start_threads_custom(ctxs, num_ctxs);
}
int wait_threads(struct thread_data *ctxs, int num_ctxs);
static inline int run_threads(struct thread_data *ctxs, int num_ctxs,
			int first_cpu, int (*fn)(thread_data_t *))
{
	int ret = start_threads(ctxs, num_ctxs, first_cpu, fn);
	if (ret)
		return ret;
	return wait_threads(ctxs, num_ctxs);
}

#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

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

static inline void bigatomic_set(struct bigatomic *b, u64 i)
{
	atomic_set(&b->upper, i >> 32);
	atomic_set(&b->lower, i & 0xffffffff);
}
static inline u64 bigatomic_read(const struct bigatomic *b)
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

/* Spin for a few cycles without bothering anyone else */
static inline void cpu_spin(int cycles)
{
	uint64_t now = mfatb();
	while (mfatb() < (now + cycles))
		;
}

#endif /* !APPS_COMMON_H */

