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

#include "test.h"

static pthread_barrier_t barr;

void sync_all(void)
{
	pthread_barrier_wait(&barr);
}

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
	printf("This is the thread on cpu %d\n", tdata->cpu);

#if 0
	qman_test_high(tdata);
	calm_down();
	bman_test_high(tdata);
	calm_down();
#endif
	speed(tdata);
	calm_down();
	blastman(tdata);
	calm_down();

	printf("Leaving thread on cpu %d\n", tdata->cpu);
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
		fprintf(stderr, "usage: user_example [cpu-range]\n");
		fprintf(stderr, "where [cpu-range] is 'n' or 'm..n'\n");
		exit(-1);
	}

	/* map shmem */
	ret = fsl_shmem_setup();
	if (ret)
		handle_error_en(ret, "fsl_shmem_setup");

	/* Create the barrier used by sync_all() */
	ret = pthread_barrier_init(&barr, NULL, last - first + 1);
	if (ret != 0)
		handle_error_en(ret, "pthread_barrier_init");

	/* Create the threads */
	printf("Starting %d threads for cpu-range '%s'\n",
		last - first + 1, argv[1]);
	ret = run_threads(thread_data, last - first + 1, first, worker_fn);
	if (ret != 0)
		handle_error_en(ret, "run_threads");

	printf("Done\n");
	exit(EXIT_SUCCESS);
}
