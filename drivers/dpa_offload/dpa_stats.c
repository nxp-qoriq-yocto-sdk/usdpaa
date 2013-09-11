/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
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

/*
 * DPA Stats user space library implementation
 */

#include <internal/of.h>
#include <linux/fsl_dpa_stats.h>
#include <usdpaa/dma_mem.h>
#include <sys/ioctl.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_usd.h>

#include "dpa_stats_ioctl.h"
#include "dpa_stats.h"
#include <error.h>
#include <pthread.h>
#include <search.h>
#include <internal/compat.h>

#define DPA_STATS_DEV_FILE_NAME	  "/dev/dpa_stats"

#define NUM_EVENTS_IN_READ	5
#define STATS_VAL_SIZE		4

/*
 * The device data structure is necessary so that the dpa_classifier library
 * can translate the "fmlib" handles into FM driver handles.
 */
typedef struct t_Device {
	uint32_t	id;
	int		fd;
	void		*h_UserPriv;
	uint32_t	owners;
} t_Device;

struct us_thread_data {
	pthread_t		id;
	struct list_head	node;
};

static int dpa_stats_devfd = -1;
pthread_t event_thread;
pthread_t control_thread;
pthread_t wk_thread;
volatile unsigned int us_threads = 0;
struct us_thread_data us_thread[MAX_NUM_OF_THREADS];
struct list_head us_thread_list;

/* Mutex to assure safe access to asynchronous user-space requests list */
static pthread_mutex_t async_us_reqs_lock = PTHREAD_MUTEX_INITIALIZER;
/* Mutex to assure safe access to asynchronous mixed requests list */
static pthread_mutex_t async_ks_reqs_lock = PTHREAD_MUTEX_INITIALIZER;
/* Mutex to assure safe access to free asynchronous requests pool */
static pthread_mutex_t async_reqs_pool = PTHREAD_MUTEX_INITIALIZER;

/* Global dpa_stats component */
struct dpa_stats *gbl_dpa_stats;

void *dpa_stats_event_thread(void *arg);
void *dpa_stats_worker_thread(void *arg);

int *copy_array(int const *src, size_t len)
{
	int *dst = malloc(len * sizeof(int));
	if (!dst)
		return NULL;
	memcpy(dst, src, len * sizeof(int));
	return dst;
}

enum req_type type_of_request(struct dpa_stats *dpa_stats,
			      int *cnts_ids, int cnts_ids_len)
{
	uint32_t i = 0;
	int found = 0;

	for (i = 0; i < cnts_ids_len; i++) {
		if (dpa_stats->cnts_cb[cnts_ids[i]].id !=
						DPA_OFFLD_INVALID_OBJECT_ID)
			found++;
	}

	if (found == 0)
		return KS_CNTS_ONLY;
	else
		if (found == cnts_ids_len)
			return US_CNTS_ONLY;
		else
			return MIXED_CNTS;
}

static void get_cnt_64bit_stats(struct dpa_stats_req *req_cb,
				struct stats_info *stats_info,
				void *stats, uint32_t idx, uint32_t mbr_off)
{
	uint64_t stats_val;
	uint32_t j = 0;

	for (j = 0; j < stats_info->stats_num; j++) {
		/* Get statistics value */
		stats_val = *((uint64_t *)(stats + stats_info->stats_off[j]));

		/* Check for rollover */
		if (stats_val < stats_info->last_stats[idx][j])
			stats_info->stats[idx][j] +=
				((unsigned long int)0xffffffff -
				stats_info->last_stats[idx][j]) + stats_val;
		else
			stats_info->stats[idx][j] += stats_val -
				stats_info->last_stats[idx][j];

		/* Store the current value as the last read value */
		stats_info->last_stats[idx][j] = stats_val;

		/* Write the memory location */
		*(uint32_t *)(req_cb->request_area + mbr_off + j *
			STATS_VAL_SIZE) = (uint32_t)stats_info->stats[idx][j];

		if (stats_info->reset)
			stats_info->stats[idx][j] = 0;
	}
}

static int get_cnt_traffic_mng_cq(struct dpa_stats_req *req,
				  struct dpa_stats_cnt_cb *cnt_cb,
				  unsigned int cnt_off)
{
	uint32_t mbr_off = 0, i;
	uint64_t stats_val[2];
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		/* Compute the corresponding offset for the counter member */
		mbr_off = cnt_off + i * cnt_cb->info.stats_num * STATS_VAL_SIZE;

		/* Retrieve statistics for the current member */
		err = qman_ceetm_cq_get_dequeue_statistics(
				(struct qm_ceetm_cq *)cnt_cb->obj[i], 0,
				&stats_val[1], &stats_val[0]);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve Traffic Manager Class"
				" Queue statistics for counter id %d\n",
				cnt_cb->id);
			return -EINVAL;
		}
		get_cnt_64bit_stats(req, &cnt_cb->info, &stats_val, i, mbr_off);
	}
	return 0;
}

int get_cnt_traffic_mng_ccg(struct dpa_stats_req *req,
			    struct dpa_stats_cnt_cb *cnt_cb,
			    unsigned int cnt_off)
{
	uint32_t mbr_off = 0, i = 0;
	uint64_t stats_val[2];
	int err = 0;

	for (i = 0; i < cnt_cb->members_num; i++) {
		/* Compute the corresponding offset for the counter member */
		mbr_off = cnt_off + i * cnt_cb->info.stats_num * STATS_VAL_SIZE;
		/* Retrieve statistics for the current member */
		err = qman_ceetm_ccg_get_reject_statistics(
				(struct qm_ceetm_ccg *)cnt_cb->obj[i], 0,
				&stats_val[1], &stats_val[0]);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve Traffic Manager Class"
				" Congestion Group statistics for counter id "
				"%d\n", cnt_cb->id);
			return -EINVAL;
		}
		get_cnt_64bit_stats(req, &cnt_cb->info, &stats_val, i, mbr_off);
	}
	return 0;
}


int check_cnt_traffic_mng_cq(struct qm_ceetm_cq *cq, int id)
{
	u64 bytes, frames;
	int err = 0;

	if (!cq) {
		error(0, EINVAL, "Parameter traffic_mng handle qm_ceetm_cq "
			"cannot be NULL for counter id %d", id);
		return -EINVAL;
	}
	err = qman_ceetm_cq_get_dequeue_statistics(cq, 0, &frames, &bytes);
	if (err != 0) {
		/* Invalid object provided */
		error(0, err, "Invalid Traffic Manager qm_ceetm_cq object for "
			"counter id %d\n", id);
		dpa_stats_remove_counter(id);
	}

	return err;
}

int check_cnt_traffic_mng_ccg(struct qm_ceetm_ccg *ccg, int id)
{
	u64 bytes, frames;
	int err = 0;

	if (!ccg) {
		error(0, EINVAL, "Parameter traffic_mng handle qm_ceetm_ccg "
			"cannot be NULL for counter id %d", id);
		return -EINVAL;
	}
	err = qman_ceetm_ccg_get_reject_statistics(ccg, 0, &frames, &bytes);

	if (err != 0) {
		/* Invalid object provided */
		error(0, err, "Invalid Traffic Manager qm_ceetm_ccg object for "
			"counter id %d\n", id);
		dpa_stats_remove_counter(id);
	}

	return err;
}

static int cnt_traffic_mng_to_stats(struct dpa_stats_cnt_cb *cnt_cb,
				    enum dpa_stats_cnt_sel cnt_sel)
{
	if (cnt_sel == DPA_STATS_CNT_NUM_OF_BYTES ||
	    cnt_sel == DPA_STATS_CNT_NUM_OF_PACKETS) {
		cnt_cb->info.stats_off[0] = cnt_sel * sizeof(uint64_t);
		cnt_cb->info.stats_num = 1;
	} else if (cnt_sel == DPA_STATS_CNT_NUM_ALL) {
		cnt_cb->info.stats_off[0] = DPA_STATS_CNT_NUM_OF_BYTES;
		cnt_cb->info.stats_off[1] =
			DPA_STATS_CNT_NUM_OF_PACKETS * sizeof(uint64_t);
		cnt_cb->info.stats_num = 2;
	} else {
		error(0, EINVAL, "Parameter cnt_sel %d must be in range (%d - "
		      "%d) for counter id %d\n", cnt_sel,
		      DPA_STATS_CNT_NUM_OF_BYTES,
		      DPA_STATS_CNT_NUM_ALL, cnt_cb->id);
		return -EINVAL;
	}
	return 0;
}

int dpa_stats_lib_init(void)
{
	int err = 0;

	if (dpa_stats_devfd >= 0) {
		error(0, EEXIST, "DPA Stats library is already initialized\n");
		return -EEXIST;
	}

	dpa_stats_devfd = open(DPA_STATS_DEV_FILE_NAME, O_RDWR);
	if (dpa_stats_devfd < 0) {
		error(0, errno, "Could not open /dev/dpa_stats\n");
		return -errno;
	}

	/* Initialize the thread for reading events: */
	err = pthread_create(&event_thread, NULL, dpa_stats_event_thread, NULL);

	if (err != 0) {
		error(0, -err, "Cannot create new event thread\n");
		return err;
	}

	return err;
}

void dpa_stats_lib_exit(void)
{
	if (dpa_stats_devfd < 0)
		return;
	close(dpa_stats_devfd);
	dpa_stats_devfd = -1;
}

static inline void block_sched_cnts(struct dpa_stats *dpa_stats,
				    int *cnts_ids, int cnts_ids_len)
{
	int i;

	pthread_mutex_lock(&dpa_stats->sched_cnt_lock);
	for (i = 0; i < cnts_ids_len; i++)
		dpa_stats->sched_cnt_ids[cnts_ids[i]] = true;
	pthread_mutex_unlock(&dpa_stats->sched_cnt_lock);
}

static inline void unblock_sched_cnts(struct dpa_stats *dpa_stats,
				      int *cnts_ids, int cnts_ids_len)
{
	int i;

	pthread_mutex_lock(&dpa_stats->sched_cnt_lock);
	for (i = 0; i < cnts_ids_len; i++)
		dpa_stats->sched_cnt_ids[cnts_ids[i]] = false;
	pthread_mutex_unlock(&dpa_stats->sched_cnt_lock);
}

static inline int cnt_is_sched(struct dpa_stats *dpa_stats, int cnt_id)
{
	int ret = 0;

	pthread_mutex_lock(&dpa_stats->sched_cnt_lock);
	ret = dpa_stats->sched_cnt_ids[cnt_id];
	pthread_mutex_unlock(&dpa_stats->sched_cnt_lock);

	return ret;
}

static int init_resources(struct dpa_stats *dpa_stats)
{
	struct dpa_stats_async_req *async_req;
	struct dpa_stats_req *req;
	uint32_t i;
	int err;

	/* Initialize list of free asynchronous requests structures */
	INIT_LIST_HEAD(&dpa_stats->async_req_pool);
	/* Initialize list of 'in-progress' asynchronous requests */
	INIT_LIST_HEAD(&dpa_stats->async_ks_reqs);
	/* Initialize list of free synchronous requests structures */
	INIT_LIST_HEAD(&dpa_stats->req_pool);

	INIT_LIST_HEAD(&dpa_stats->async_us_reqs);

	INIT_LIST_HEAD(&us_thread_list);

	/* Allocate asynchronous request internal structure */
	async_req = malloc(DPA_STATS_MAX_NUM_OF_REQUESTS * sizeof(*async_req));
	if (!async_req) {
		error(0, ENOMEM, "Cannot allocate memory for "
				"asynchronous request internal structure\n");
		return -ENOMEM;
	}
	for (i = 0; i < DPA_STATS_MAX_NUM_OF_REQUESTS; i++) {
		memset(&async_req[i], 0, sizeof(struct dpa_stats_async_req));
		list_add_tail(&async_req[i].node, &dpa_stats->async_req_pool);
	}

	/* Allocate request internal structure */
	req = malloc(DPA_STATS_MAX_NUM_OF_REQUESTS * sizeof(*req));
	if (!req) {
		error(0, ENOMEM, "Cannot allocate memory for "
		      "synchronous request internal structure\n");
		return -ENOMEM;
	}
	for (i = 0; i < DPA_STATS_MAX_NUM_OF_REQUESTS; i++) {
		memset(&req[i], 0, sizeof(*req));
		list_add_tail(&req[i].node, &dpa_stats->req_pool);
	}

	/* Allocate array to store counters control blocks */
	dpa_stats->cnts_cb = malloc(DPA_STATS_MAX_NUM_OF_COUNTERS *
				    sizeof(struct dpa_stats_cnt_cb));
	if (!dpa_stats->cnts_cb) {
		error(0, ENOMEM, "Cannot allocate memory to store %d internal "
		      "counter structures\n", DPA_STATS_MAX_NUM_OF_COUNTERS);
		return -ENOMEM;
	}
	memset(dpa_stats->cnts_cb, 0,
	      DPA_STATS_MAX_NUM_OF_COUNTERS * sizeof(struct dpa_stats_cnt_cb));

	/* Mark all the counters as being 'kernel-space' counters */
	for (i = 0; i < DPA_STATS_MAX_NUM_OF_COUNTERS; i++) {
		dpa_stats->cnts_cb[i].dpa_stats = dpa_stats;
		dpa_stats->cnts_cb[i].id = DPA_OFFLD_INVALID_OBJECT_ID;
		pthread_mutex_init(&dpa_stats->cnts_cb[i].lock, NULL);
	}

	/* Initialize user space worker threads control blocks: */
	for (i = 0; i < MAX_NUM_OF_THREADS; i++)
		list_add_tail(&us_thread[i].node, &us_thread_list);

	/* Initialize mutex required to protect access to scheduled counters */
	err = pthread_mutex_init(&dpa_stats->sched_cnt_lock, NULL);
	if (err != 0)
		error(0, err, "Failed to initialize DPA Stats mutex");

	return err;
}

static int free_resources(void)
{
	struct dpa_stats_async_req *async_req, *tmp;
	struct dpa_stats_req *req, *req_tmp;
	struct dpa_stats *dpa_stats;

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	pthread_mutex_lock(&async_reqs_pool);
	if (!list_empty(&dpa_stats->async_req_pool))
		list_for_each_entry_safe(async_req, tmp,
				&dpa_stats->async_req_pool, node)
			list_del(&async_req->node);

	if (!list_empty(&dpa_stats->req_pool))
		list_for_each_entry_safe(req, req_tmp,
				&dpa_stats->req_pool, node)
			list_del(&req->node);
	pthread_mutex_unlock(&async_reqs_pool);

	pthread_mutex_lock(&async_us_reqs_lock);
	if (!list_empty(&dpa_stats->async_us_reqs))
		list_for_each_entry_safe(async_req, tmp,
				&dpa_stats->async_us_reqs, node) {
			free(async_req->req->cnt_off);
			free(async_req->req->cnt_ids);
			async_req->req->cnt_off = NULL;
			async_req->req->cnt_ids = NULL;
			list_del(&async_req->req->node);
			async_req->req = NULL;
			list_del(&async_req->node);
		}
	pthread_mutex_unlock(&async_us_reqs_lock);

	/* Wait until all async request processing threads die: */
	while (us_threads) {};

	free(dpa_stats);
	gbl_dpa_stats = NULL;
	return 0;
}

static int check_us_get_counters_params(struct dpa_stats *dpa_stats,
					struct dpa_stats_cnt_request_params prm,
					int *cnts_len)
{
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	int cnt_id;
	uint32_t i = 0;

	/* Check user-provided cnts_len pointer */
	if (!cnts_len) {
		error(0, EINVAL, "Parameter cnts_len cannot be NULL\n");
		return -EINVAL;
	}

	/* Check user-provided params.cnts_ids pointer */
	if (!prm.cnts_ids) {
		error(0, EINVAL, "Parameter cnts_ids cannot be NULL\n");
		return -EINVAL;
	}

	*cnts_len = 0;

	for (i = 0; i < prm.cnts_ids_len; i++) {
		if (prm.cnts_ids[i] == DPA_OFFLD_INVALID_OBJECT_ID ||
		    prm.cnts_ids[i] > dpa_stats->config.max_counters) {
			error(0, EINVAL, "Counter id (cnt_ids[%d]) %d is not "
				"initialized or is greater than maximum counters"
				" %d\n", i, prm.cnts_ids[i],
				dpa_stats->config.max_counters);
			return -EINVAL;
		}
	}

	/* Calculate number of bytes occupied by the counters */
	for (i = 0; i < prm.cnts_ids_len; i++) {
		cnt_id = prm.cnts_ids[i];

		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[cnt_id];

		/* Acquire counter lock */
		pthread_mutex_lock(&cnt_cb->lock);

		/* Check if counter control block is initialized */
		if (cnt_cb->id == DPA_OFFLD_INVALID_OBJECT_ID) {
			error(0, EINVAL, "Counter id (cnt_ids[%d]) %d is "
				"not initialized\n", i, cnt_id);
			return -EINVAL;
		}

		*cnts_len += cnt_cb->bytes_num;
		pthread_mutex_unlock(&cnt_cb->lock);
	}

	/* Check user-provided parameters */
	if ((prm.storage_area_offset + *cnts_len) >
		dpa_stats->config.storage_area_len) {
		error(0, EINVAL, "Parameter storage_area_offset %d and counters"
			" length %d exceeds configured storage_area_len %d\n",
			prm.storage_area_offset, *cnts_len,
			dpa_stats->config.storage_area_len);
		return -EINVAL;
	}
	return 0;
}

static int treat_us_cnts_request(struct dpa_stats *dpa_stats,
				 struct dpa_stats_req *req_cb)
{
	struct dpa_stats_cnt_request_params params = req_cb->config;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < params.cnts_ids_len; i++) {
		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[req_cb->cnt_ids[i]];

		/* Acquire counter lock */
		pthread_mutex_lock(&cnt_cb->lock);

		cnt_cb->info.reset = req_cb->config.reset_cnts;

		/* Call counter's retrieve function */
		err = cnt_cb->f_get_cnt_stats(req_cb, cnt_cb,
							req_cb->bytes_num);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve statistics for "
			      "counter id %d\n", req_cb->cnt_ids[i]);
			pthread_mutex_unlock(&cnt_cb->lock);
			unblock_sched_cnts(dpa_stats,
					req_cb->cnt_ids, params.cnts_ids_len);
			return -EINVAL;
		}

		/*
		 * Update number of bytes and number of counters
		 * successfully written so far
		 */
		req_cb->bytes_num += cnt_cb->bytes_num;
		req_cb->cnts_num += 1;

		pthread_mutex_unlock(&cnt_cb->lock);
	}
	unblock_sched_cnts(dpa_stats, req_cb->cnt_ids, params.cnts_ids_len);
	return 0;
}

static int treat_mixed_cnts_request(struct dpa_stats *dpa_stats,
				    struct dpa_stats_req *req_cb)
{
	struct dpa_stats_cnt_request_params params = req_cb->config;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	uint32_t i = 0;
	int err = 0;

	for (i = 0; i < params.cnts_ids_len; i++) {
		/* Get counter's control block */
		cnt_cb = &dpa_stats->cnts_cb[req_cb->cnt_ids[i]];

		/* Acquire counter lock */
		pthread_mutex_lock(&cnt_cb->lock);

		/* If counter is kernel-space, it was already treated */
		if (cnt_cb->id == DPA_OFFLD_INVALID_OBJECT_ID) {
			pthread_mutex_unlock(&cnt_cb->lock);
			continue;
		}

		cnt_cb->info.reset = req_cb->config.reset_cnts;

		/* Call counter's retrieve function */
		err = cnt_cb->f_get_cnt_stats(req_cb, cnt_cb,
							req_cb->cnt_off[i]);
		if (err < 0) {
			error(0, EINVAL, "Cannot retrieve statistics for "
			      "counter id %d\n", req_cb->cnt_ids[i]);
			pthread_mutex_unlock(&cnt_cb->lock);
			unblock_sched_cnts(dpa_stats,
					req_cb->cnt_ids, params.cnts_ids_len);
			return -EINVAL;
		}
		pthread_mutex_unlock(&cnt_cb->lock);
	}
	unblock_sched_cnts(dpa_stats, req_cb->cnt_ids, params.cnts_ids_len);
	return 0;
}

static int process_async_req(struct dpa_stats_event_params *ev)
{
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_async_req *async_req = NULL;
	struct list_head *pos;
	struct us_thread_data *new_us_thread;
	bool found = false;
	int err;

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	BUG_ON(list_empty(&dpa_stats->async_ks_reqs));

	/* Search in the request group the request event */
	pthread_mutex_lock(&async_ks_reqs_lock);
	list_for_each(pos, &dpa_stats->async_ks_reqs) {
		async_req = list_entry(pos, struct dpa_stats_async_req, node);

		if (async_req->req->config.storage_area_offset ==
				ev->storage_area_offset) {
			list_del(&async_req->node);
			found = true;
			break;
		}
	}
	pthread_mutex_unlock(&async_ks_reqs_lock);

	if (!found) {
		error(0, EINVAL, "Cannot find event in the event list\n");
		return -EINVAL;
	}

	if (async_req->req->type == MIXED_CNTS) {
		/*
		 * Because the kernel-space counters of the request have been
		 * treated, remove the request from the kernel-space list and
		 * add it in the user-space list
		 */
		pthread_mutex_lock(&async_us_reqs_lock);
		list_add_tail(&async_req->node, &dpa_stats->async_us_reqs);

		/* If we can still create worker threads... */
		if (us_threads < MAX_NUM_OF_THREADS) {
			/* Create a new thread and pass the request to it */
			new_us_thread = list_entry(us_thread_list.next,
					struct us_thread_data, node);
			list_del(&new_us_thread->node);
			err = pthread_create(&new_us_thread->id,
					NULL, dpa_stats_worker_thread,
					new_us_thread);
			if (err != 0) {
				pthread_mutex_unlock(&async_us_reqs_lock);
				error(0, err,
					"Cannot create new worker thread\n");
				return err;
			}
			us_threads++;
		}
		pthread_mutex_unlock(&async_us_reqs_lock);
	} else {
		/*
		 * All the counters were treated, return the nodes to their
		 * pools
		 */
		pthread_mutex_lock(&async_reqs_pool);
		free(async_req->req->cnt_off);
		free(async_req->req->cnt_ids);
		async_req->req->cnt_off = NULL;
		async_req->req->cnt_ids = NULL;
		list_add_tail(&async_req->req->node, &dpa_stats->req_pool);
		async_req->req = NULL;
		list_add_tail(&async_req->node,  &dpa_stats->async_req_pool);
		pthread_mutex_unlock(&async_reqs_pool);

		ev->request_done(ev->dpa_stats_id,
				 ev->storage_area_offset,
				 ev->cnts_written,
				 ev->bytes_written);
	}

	return 0;
}

static int fill_req_params(struct dpa_stats			*dpa_stats,
			   struct dpa_stats_cnt_request_params  prm,
			   dpa_stats_request_cb			request_done,
			   struct dpa_stats_req			**req_cb)
{
	struct dpa_stats_req *req = NULL;

	if (list_empty(&dpa_stats->req_pool)) {
		error(0, EDOM, "Reached maximum supported number of "
		      "simultaneous requests\n");
		return -EDOM;
	}

	pthread_mutex_lock(&async_reqs_pool);
	/* Obtain a free request structure */
	req = list_entry(dpa_stats->req_pool.next, struct dpa_stats_req, node);
	list_del(&req->node);
	pthread_mutex_unlock(&async_reqs_pool);

	/* Save user-provided parameters */
	req->config.cnts_ids = prm.cnts_ids;
	req->config.reset_cnts = prm.reset_cnts;
	req->config.storage_area_offset = prm.storage_area_offset;
	req->config.cnts_ids_len = prm.cnts_ids_len;
	req->request_done = request_done;

	/* Set memory area where the request should write */
	req->request_area = dpa_stats->storage_area + prm.storage_area_offset;

	/* Synchronous request: store the provided pointer to array of ids */
	if (!request_done)
		req->cnt_ids = prm.cnts_ids;
	else {
		/*
		 * Asynchronous request: allocate an equal size array and copy
		 * the contents from the user-provided array of counters ids
		 */
		req->cnt_ids = copy_array(prm.cnts_ids, prm.cnts_ids_len);
		if (!req->cnt_ids) {
			error(0, ENOMEM, "Cannot copy array of counters ids\n");
			return -ENOMEM;
		}
	}

	/* Allocate and fill the counters offsets array */
	req->cnt_off = copy_array(prm.cnts_ids, prm.cnts_ids_len);
	if (!req->cnt_off) {
		error(0, ENOMEM, "Cannot copy array of counters ids\n");
		return -ENOMEM;
	}

	/* Determine and store the type of the request */
	req->type = type_of_request(dpa_stats, req->cnt_ids, prm.cnts_ids_len);

	*req_cb = req;

	return 0;
}

static int set_cnt_traffic_mng_cb(
		struct dpa_stats *dpa_stats,
		const struct dpa_stats_cnt_params *params, int id)
{
	struct dpa_stats_cnt_cb *cnt_cb = &dpa_stats->cnts_cb[id];
	int err;

	/* Check user-provided parameters */
	switch (params->traffic_mng_params.src) {
	case DPA_STATS_CNT_TRAFFIC_CLASS:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_cq;
		err = check_cnt_traffic_mng_cq((struct qm_ceetm_cq *)
				params->traffic_mng_params.traffic_mng, id);
		if (err != 0)
			return -err;
		break;
	case DPA_STATS_CNT_TRAFFIC_CG:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_ccg;
		err = check_cnt_traffic_mng_ccg((struct qm_ceetm_ccg *)
				params->traffic_mng_params.traffic_mng, id);
		if (err != 0)
			return -err;
		break;
	default:
		break;
	}

	/* Mark counter structure as 'being used' and fill parameters */
	cnt_cb->id = id;
	cnt_cb->sel = params->traffic_mng_params.cnt_sel;
	cnt_cb->members_num = 1;
	cnt_cb->type = params->type;
	cnt_cb->dpa_stats = dpa_stats;

	cnt_cb->obj[0] = params->traffic_mng_params.traffic_mng;

	/* Map Traffic Manager counter selection to CQ/CCG statistics */
	cnt_traffic_mng_to_stats(cnt_cb, cnt_cb->sel);

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
				STATS_VAL_SIZE * cnt_cb->info.stats_num;
	return 0;
}

static int set_cls_cnt_traffic_mng_cb(
		struct dpa_stats *dpa_stats,
		const struct dpa_stats_cls_cnt_params *params, int id)
{
	struct dpa_stats_cnt_cb *cnt_cb = &dpa_stats->cnts_cb[id];
	int err;
	uint32_t i;

	/* Check user-provided parameters */
	switch (params->traffic_mng_params.src) {
	case DPA_STATS_CNT_TRAFFIC_CLASS:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_cq;
		for (i = 0; i < params->class_members; i++) {
			err = check_cnt_traffic_mng_cq((struct qm_ceetm_cq *)
				params->traffic_mng_params.traffic_mng[i], id);
			if (err != 0)
				return -err;
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_CG:
		cnt_cb->f_get_cnt_stats = get_cnt_traffic_mng_ccg;
		for (i = 0; i < params->class_members; i++) {
			err = check_cnt_traffic_mng_ccg((struct qm_ceetm_ccg *)
				params->traffic_mng_params.traffic_mng[i], id);
			if (err != 0)
				return -err;
		}
		break;
	default:
		break;
	}

	/* Mark counter structure as 'being used' and fill parameters */
	cnt_cb->id = id;
	cnt_cb->sel = params->traffic_mng_params.cnt_sel;
	cnt_cb->members_num = params->class_members;
	cnt_cb->type = params->type;
	cnt_cb->dpa_stats = dpa_stats;

	for (i = 0; i < cnt_cb->members_num; i++)
		cnt_cb->obj[i] = params->traffic_mng_params.traffic_mng[i];

	/* Map Traffic Manager counter selection to CQ/CCG statistics */
	cnt_traffic_mng_to_stats(cnt_cb, cnt_cb->sel);

	/* Set number of bytes that will be written by this counter */
	cnt_cb->bytes_num = cnt_cb->members_num *
				STATS_VAL_SIZE * cnt_cb->info.stats_num;
	return 0;
}

int dpa_stats_init(const struct dpa_stats_params *params, int *dpa_stats_id)
{
	struct ioc_dpa_stats_params prm;
	struct dma_mem *map;
	struct dpa_stats *dpa_stats = NULL;
	int err = 0;

	if (!params || !dpa_stats_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized3\n");
		return -ENODEV;
	}

	memset(&prm, 0, sizeof(prm));

	/* Check if the user-provided storage area is DMA mapped */
	map = dma_mem_findv(params->storage_area);
	if (!map) {
		prm.stg_area_mapped = false;
		prm.virt_stg_area = params->storage_area;
	} else {
		prm.stg_area_mapped = true;
		prm.phys_stg_area = dma_mem_vtop(map, params->storage_area);
	}

	prm.dpa_stats_id = 0;
	prm.max_counters = params->max_counters;
	prm.storage_area_len = params->storage_area_len;

	/* Allocate dpa stats internal structure */
	dpa_stats = malloc(sizeof(struct dpa_stats));
	if (!dpa_stats) {
		error(0, ENOMEM, "Cannot allocate memory for internal DPA "
		     "Stats structure.\n");
		return -ENOMEM;
	}
	dpa_stats->storage_area = params->storage_area;

	/* Store parameters */
	dpa_stats->config = *params;

	/* Allocate and initialize internal structures */
	err = init_resources(dpa_stats);
	if (err < 0) {
		free_resources();
		return err;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_INIT, prm) < 0) {
		error(0, errno, "Couldn't initialize the DPA Stats instance\n");
		return -errno;
	}

	gbl_dpa_stats = dpa_stats;

	return 0;
}

int dpa_stats_free(int dpa_stats_id)
{
	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	if (dpa_stats_id < 0) {
		error(0, EINVAL, "Invalid DPA Stats identifier\n");
		return -EINVAL;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_FREE, &dpa_stats_id) < 0) {
		error(0, errno, "Could not free the DPA Stats instance\n");
		return -errno;
	}

	free_resources();

	return 0;
}

int dpa_stats_create_counter(int dpa_stats_id,
			     const struct dpa_stats_cnt_params *cnt_params,
			     int *dpa_stats_cnt_id)
{
	struct ioc_dpa_stats_cnt_params prm;
	struct dpa_stats *dpa_stats = NULL;
	struct t_Device *dev;
	bool is_us_cnt = false;
	uint32_t err = 0;

	if (dpa_stats_id < 0 || !cnt_params || !dpa_stats_cnt_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	memcpy(&prm.cnt_params, cnt_params, sizeof(prm.cnt_params));

	switch (cnt_params->type) {
	case DPA_STATS_CNT_CLASSIF_NODE:
		/* Translate Cc node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->classif_node_params.cc_node;
		prm.cnt_params.classif_node_params.cc_node = (void *)dev->id;
		break;
	case DPA_STATS_CNT_REASS:
		/* Translate Manip node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->reass_params.reass;
		prm.cnt_params.reass_params.reass = (void *)dev->id;
		break;
	case DPA_STATS_CNT_FRAG:
		/* Translate Manip node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->frag_params.frag;
		prm.cnt_params.frag_params.frag = (void *)dev->id;
		break;
	case DPA_STATS_CNT_POLICER:
		/* Translate Policer node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->plcr_params.plcr;
		prm.cnt_params.plcr_params.plcr = (void *)dev->id;
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		/* Notify the driver that counter is managed in user-space */
		prm.cnt_params.traffic_mng_params.cnt_sel |= DPA_STATS_US_CNT;
		is_us_cnt = true;
		break;
	default:
		break;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_CREATE_COUNTER, &prm) < 0) {
		error(0, errno, "Could not create counter\n");
		return -errno;
	}

	if (prm.cnt_id >= 0)
		*dpa_stats_cnt_id = prm.cnt_id;

	if (is_us_cnt) {
		/* Create user-space counter */
		switch (cnt_params->type) {
		case DPA_STATS_CNT_TRAFFIC_MNG:
			err = set_cnt_traffic_mng_cb(dpa_stats,
						     cnt_params, prm.cnt_id);
			if (err != 0) {
				error(0, EINVAL, "Cannot create Traffic Manager"
					" counter id %d\n", prm.cnt_id);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

int dpa_stats_create_class_counter(int dpa_stats_id,
			      const struct dpa_stats_cls_cnt_params *cnt_params,
			      int *dpa_stats_cnt_id)
{
	struct ioc_dpa_stats_cls_cnt_params prm;
	struct dpa_stats *dpa_stats = NULL;
	struct t_Device *dev;
	uint32_t i = 0, err = 0;
	bool is_us_cnt = false;

	if (dpa_stats_id < 0 || !cnt_params || !dpa_stats_cnt_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	memcpy(&prm.cnt_params, cnt_params, sizeof(*cnt_params));

	switch (cnt_params->type) {
	case DPA_STATS_CNT_CLASSIF_NODE:
		/* Translate Cc node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->classif_node_params.cc_node;
		prm.cnt_params.classif_node_params.cc_node = (void *)dev->id;
		break;
	case DPA_STATS_CNT_REASS:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Manip node handle to FMD type of handle */
			dev = (t_Device *)cnt_params->reass_params.reass[i];
			prm.cnt_params.reass_params.reass[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_FRAG:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Manip node handle to FMD type of handle */
			dev = (t_Device *)cnt_params->frag_params.frag[i];
			prm.cnt_params.frag_params.frag[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_POLICER:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Policer node handle to FMD type handles */
			dev = (t_Device *)cnt_params->plcr_params.plcr[i];
			prm.cnt_params.plcr_params.plcr[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_TRAFFIC_MNG:
		/* Notify the driver that counter is managed in user-space */
		prm.cnt_params.traffic_mng_params.cnt_sel |= DPA_STATS_US_CNT;
		is_us_cnt = true;
		break;
	default:
		break;
	}

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_CREATE_CLASS_COUNTER, &prm) < 0) {
		error(0, errno, "Could not create class counter\n");
		return -errno;
	}

	if (prm.cnt_id >= 0)
		*dpa_stats_cnt_id = prm.cnt_id;

	if (is_us_cnt) {
		/* Create user-space counter */
		switch (cnt_params->type) {
		case DPA_STATS_CNT_TRAFFIC_MNG:
			err = set_cls_cnt_traffic_mng_cb(dpa_stats,
							cnt_params, prm.cnt_id);
			if (err != 0) {
				error(0, EINVAL, "Cannot create Traffic Manager"
				      " counter id %d\n", prm.cnt_id);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

int dpa_stats_modify_class_counter(int dpa_stats_cnt_id,
		const struct dpa_stats_cls_member_params *params,
		int member_index)
{
	struct ioc_dpa_stats_cls_member_params prm;

	if (dpa_stats_cnt_id < 0 || !params || member_index < 0) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	prm.cnt_id = dpa_stats_cnt_id;
	prm.member_index = member_index;

	memcpy(&prm.params, params, sizeof(*params));

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_MODIFY_CLASS_COUNTER, &prm) < 0) {
		error(0, errno, "Could not modify class counter\n");
		return -errno;
	}
	return 0;
}

int dpa_stats_remove_counter(int dpa_stats_cnt_id)
{
	struct dpa_stats *dpa_stats = NULL;

	if (dpa_stats_cnt_id < 0) {
		error(0, EINVAL, "Invalid input parameter\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_REMOVE_COUNTER, &dpa_stats_cnt_id) < 0) {
		error(0, errno, "Could not remove this counter\n");
		return -errno;
	}

	/* Mark the equivalent 'user-space' counter structure as invalid */
	dpa_stats->cnts_cb[dpa_stats_cnt_id].id = DPA_OFFLD_INVALID_OBJECT_ID;
	memset(&dpa_stats->cnts_cb[dpa_stats_cnt_id].info, 0,
		sizeof(struct stats_info));

	return 0;
}

int dpa_stats_get_counters(struct dpa_stats_cnt_request_params params,
			   int *cnts_len,
			   dpa_stats_request_cb request_done)
{
	struct ioc_dpa_stats_cnt_request_params ioc_prm;
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_async_req *async_req = NULL;
	struct dpa_stats_req *req = NULL;
	struct us_thread_data *new_us_thread;
	int ret = 0;

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -EAGAIN;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	/* Obtain a new request internal structure and fill it */
	ret = fill_req_params(dpa_stats, params, request_done, &req);
	if (ret < 0)
		return ret;

	memcpy(&ioc_prm.req_params, &params, sizeof(params));
	ioc_prm.cnts_len = *cnts_len;
	ioc_prm.request_done = request_done;
	ioc_prm.req_params.cnts_ids = req->cnt_off;

	/* If counters request is asynchronous */
	if (request_done) {
		pthread_mutex_lock(&async_reqs_pool);
		if (list_empty(&dpa_stats->async_req_pool)) {
			error(0, EDOM, "Reached maximum supported number of "
			      "simultaneous asynchronous requests\n");
			pthread_mutex_unlock(&async_reqs_pool);
			return -EDOM;
		}
		/* Obtain a free asynchronous request structure */
		async_req = list_entry(dpa_stats->async_req_pool.next,
				       struct dpa_stats_async_req, node);
		list_del(&async_req->node);
		pthread_mutex_unlock(&async_reqs_pool);

		/* Store the request parameters */
		async_req->req = req;

		if (req->type != US_CNTS_ONLY) {
			/*
			 * The request is not only for user-space counters,
			 * so add it in the list that treats only us requests
			 */
			pthread_mutex_lock(&async_ks_reqs_lock);
			list_add_tail(&async_req->node,
						&dpa_stats->async_ks_reqs);
			pthread_mutex_unlock(&async_ks_reqs_lock);
		}
	}

	/* If request is 'us' type, then we need to check the parameters*/
	if (req->type == US_CNTS_ONLY) {
		/* Check user-provided parameters */
		ret = check_us_get_counters_params(dpa_stats, params, cnts_len);
		if (ret < 0)
			return ret;

		if (!request_done) { /* Synchronous request */
			block_sched_cnts(dpa_stats, params.cnts_ids,
				params.cnts_ids_len);
			ret =  treat_us_cnts_request(dpa_stats, req);
			if (ret < 0)
				return ret;

			/* Provide to the user the number of written bytes */
			*cnts_len = req->bytes_num;

			/* Return the request structure to the requests pool */
			free(req->cnt_off);
			req->cnt_off = NULL;
			pthread_mutex_lock(&async_reqs_pool);
			list_add_tail(&req->node, &dpa_stats->req_pool);
			pthread_mutex_unlock(&async_reqs_pool);
		} else {
			/*
			 * The request is only for user-space counters, so add
			 * it in the list that treats only user-space requests
			 */
			pthread_mutex_lock(&async_us_reqs_lock);
			list_add_tail(&async_req->node,
				      &dpa_stats->async_us_reqs);

			/* If we can still create worker threads... */
			if (us_threads < MAX_NUM_OF_THREADS) {
				/* Create a new thread and pass the request to it */
				new_us_thread = list_entry(us_thread_list.next,
						struct us_thread_data, node);
				list_del(&new_us_thread->node);
				ret = pthread_create(&new_us_thread->id,
						NULL, dpa_stats_worker_thread,
						new_us_thread);
				if (ret != 0) {
					pthread_mutex_unlock(&async_us_reqs_lock);
					error(0, ret,
						"Cannot create new worker thread\n");
					return ret;
				}
				us_threads++;
			}
			pthread_mutex_unlock(&async_us_reqs_lock);
		}
		return 0;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_GET_COUNTERS, &ioc_prm) < 0) {
		error(0, errno, "Could not create request\n");
		ret = -errno;
	}

	/* Provide to the user the number of written bytes */
	*cnts_len = ioc_prm.cnts_len;

	if (!request_done) {
		if (req->type == MIXED_CNTS) {
			ret = treat_mixed_cnts_request(dpa_stats, req);
			if (ret < 0)
				return ret;
		}

		/* Return the request structure to the free requests pool */
		pthread_mutex_lock(&async_reqs_pool);
		free(req->cnt_off);
		req->cnt_off = NULL;
		list_add_tail(&req->node, &dpa_stats->req_pool);
		pthread_mutex_unlock(&async_reqs_pool);
	}

	return ret;
}

int dpa_stats_reset_counters(int *cnts_ids, unsigned int cnts_ids_len)
{
	struct ioc_dpa_stats_cnts_reset_params ioc_prm;
	struct dpa_stats *dpa_stats = NULL;
	struct dpa_stats_cnt_cb *cnt_cb = NULL;
	uint32_t i;
	int ret;

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -EAGAIN;
	}

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return 0;
	}
	dpa_stats = gbl_dpa_stats;

	ioc_prm.cnts_ids = cnts_ids;
	ioc_prm.cnts_ids_len = cnts_ids_len;

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_RESET_COUNTERS, &ioc_prm) < 0) {
		error(0, errno, "Could not reset counters\n");
		return -errno;
	}

	block_sched_cnts(dpa_stats, cnts_ids, cnts_ids_len);

	/* Reset stored statistics for all 'user-space' counters */
	for (i = 0; i < ioc_prm.cnts_ids_len; i++) {
		cnt_cb = &dpa_stats->cnts_cb[cnts_ids[i]];
		/* Acquire counter lock */
		ret = pthread_mutex_trylock(&cnt_cb->lock);
		if (ret) {
			error(0, ret, "Counter id (cnt_ids[%d]) %d is in use\n",
				i, cnts_ids[i]);
			unblock_sched_cnts(dpa_stats,
					   cnts_ids, cnts_ids_len);
			return ret;
		}

		if (cnt_cb->id == DPA_OFFLD_INVALID_OBJECT_ID) {
			pthread_mutex_unlock(&cnt_cb->lock);
			continue;
		}
		memset(&cnt_cb->info.stats, 0, (MAX_NUM_OF_MEMBERS *
				MAX_NUM_OF_STATS * sizeof(uint64_t)));
		pthread_mutex_unlock(&cnt_cb->lock);
	}
	unblock_sched_cnts(dpa_stats, cnts_ids, cnts_ids_len);

	return 0;
}

void *dpa_stats_event_thread(void *arg)
{
	char buffer[NUM_EVENTS_IN_READ * sizeof(struct dpa_stats_event_params)];
	struct dpa_stats_event_params   *event_prm  = NULL;
	ssize_t buff_sz = 0;
	int err;

	/*
	* Read NUM_EVENTS_IN_READ from the advanced config interface.
	* This call is blocking and will put the thread to sleep if
	* there are no events available. It will return one or more
	* events if there are available.
	*/
	do {
		buff_sz = read(dpa_stats_devfd, buffer, (NUM_EVENTS_IN_READ *
				sizeof(*event_prm)));

		event_prm  = (struct dpa_stats_event_params *)buffer;

		/* Dispatch events */
		while (buff_sz >= sizeof(struct dpa_stats_event_params)) {
			err = process_async_req(event_prm);
			if (err < 0) {
				error(0, EINVAL, "Could not find and process "
					"asynchronous request\n");
				return NULL;
			}
			event_prm++;
			buff_sz -= sizeof(struct dpa_stats_event_params);
		}
	} while (1);
}

void *dpa_stats_worker_thread(void *arg)
{
	struct us_thread_data *this_thread = (struct us_thread_data *)arg;
	struct dpa_stats *dpa_stats;
	struct dpa_stats_async_req *async_req;
	struct dpa_stats_req *req;
	cpu_set_t cpuset;
	int ret;
	int cpu = 0;

	/* Sanity check */
	if (!gbl_dpa_stats) {
		error(0, EINVAL, "DPA Stats library is not initialized\n");
		return NULL;
	}
	dpa_stats = gbl_dpa_stats;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	ret = pthread_setaffinity_np(
			this_thread->id, sizeof(cpu_set_t), &cpuset);
	if (ret) {
		error(0, -ret, "(%d): Fail: pthread_setaffinity_np()\n", cpu);
		return NULL;
	}

	ret = qman_thread_init();
	if (ret) {
		error(0, -ret, "(%d): Fail: qman_thread_init()\n", cpu);
		return NULL;
	}

	pthread_mutex_lock(&async_us_reqs_lock);
	while (!list_empty(&dpa_stats->async_us_reqs)) {
		/* Get first element of the list */
		async_req = list_entry(dpa_stats->async_us_reqs.next,
				       struct dpa_stats_async_req, node);
		list_del(&async_req->node);
		pthread_mutex_unlock(&async_us_reqs_lock);

		req = async_req->req;
		if (req->type == US_CNTS_ONLY)
			/* Treat every counter from the request */
			ret = treat_us_cnts_request(dpa_stats, req);
		else
			/* Treat only user-space counters */
			ret = treat_mixed_cnts_request(dpa_stats, req);
		if (ret < 0) {
			error(0, EINVAL, "Cannot obtain counter values "
					"in asynchronous mode\n");
			req->bytes_num = ret;
		}

		/* Return the asynchronous request in the pool */
		free(async_req->req->cnt_off);
		free(async_req->req->cnt_ids);
		async_req->req->cnt_off = NULL;
		async_req->req->cnt_ids = NULL;
		pthread_mutex_lock(&async_reqs_pool);
		list_add_tail(&async_req->req->node,  &dpa_stats->req_pool);
		async_req->req = NULL;
		list_add_tail(&async_req->node,  &dpa_stats->async_req_pool);
		pthread_mutex_unlock(&async_reqs_pool);

		/* Call user-provided callback */
		req->request_done(0,
				req->config.storage_area_offset,
				req->cnts_num,
				req->bytes_num);

		/* Lock again the us_reqs queue to check for remaining work: */
		pthread_mutex_lock(&async_us_reqs_lock);
	}

	/* Die and put back the thread id to the pool */
	us_threads--;
	list_add_tail(&this_thread->node, &us_thread_list);
	pthread_mutex_unlock(&async_us_reqs_lock);

	ret = qman_thread_finish();
	if (ret)
		error(0, ret, "Failed to shut down QMan thread");
	pthread_exit(NULL);

	return NULL;
}
