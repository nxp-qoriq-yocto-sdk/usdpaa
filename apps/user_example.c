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

/************************************************************************
 * This program starts threads and makes them affine to cores.  Each
 * thread runs function thread_function.
 *
 * It creates num_threads threads.  The first is made affine to core 1,
 * the next to core 2, and so on.  To cause nothing else in user
 * space to be scheduled onto cores other than core 0, use the isolcpus
 * kernel parameter, e.g. "isolcpus=1-7".
 *************************************************************************/

#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_THREADS 8

#define handle_error_en(en, msg) \
  do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)

/* Per-thread data, including the pthread id */
typedef struct {
  pthread_t id;
  int index; /* count from 0 */
} thread_data_t;


/***************************************************************************
 * waste_clks1000
 *
 * This function should take quite close to 100*n cycles on a PowerPC,
 * assuming n is large and that nothing is trashing the caches.
 ***************************************************************************/

void waste_clks100(uint32_t n)
{
  int v1 = 1, i;

  for (i = 0; i < 10; i++) {

    asm volatile ("mtctr %0 \n"
		"1: or %1,%0,%0 \n" "or %0,%1,%1 \n"
		"or %1,%0,%0 \n" "or %0,%1,%1 \n"
		"or %1,%0,%0 \n" "or %0,%1,%1 \n"
		"or %1,%0,%0 \n" "or %0,%1,%1 \n"
		"or %1,%0,%0 \n" "or %0,%1,%1 \n"
		"bdnz 1b \n"
		:: "r" (n), "r" (v1) : "ctr");
  }

}


/***************************************************************************
 * thread_function
 *
 * This function is executed in each created thread.
 *
 * arg points to a thread_data_t object which in turn contains a thread
 * index, an integer counting from 0.
 *
 * The function sets the thread to be affine to core index + 1, where cores
 * are also counted from zero.
 ****************************************************************************/

static void *thread_function(void *arg)
{
  thread_data_t *tdata = (thread_data_t *) arg;
  int s;
  cpu_set_t cpuset;

  /* Set this thread affine to core index + 1 */
  CPU_ZERO(&cpuset);
  CPU_SET(tdata->index + 1, &cpuset);
  s = pthread_setaffinity_np(tdata->id, sizeof(cpu_set_t), &cpuset);
  if (s != 0) handle_error_en(s, "pthread_setaffinity_np");

  printf("This is %d\n", tdata->index);

  /* Do something-- to be replaced by something useful */
  waste_clks100(120000000); /* 10 sec @ 1.2 GHz */

  return NULL;
}


int main(int argc, char *argv[])
{
  int s, i, num_threads;
  thread_data_t thread_data[MAX_THREADS];

  num_threads = 7;

  /* Create the threads */

  for (i = 0; i < num_threads; i++) {
    thread_data[i].index = i;

    s = pthread_create(&thread_data[i].id, NULL, &thread_function,
		       &thread_data[i]);
    if (s != 0) handle_error_en(s, "pthread_create");
  }

  /* Wait for them to join */

  for (i = 0; i < num_threads; i++) {
    s = pthread_join(thread_data[i].id, NULL);
    if (s != 0) handle_error_en(s, "pthread_join");
  }

  exit(EXIT_SUCCESS);
}
