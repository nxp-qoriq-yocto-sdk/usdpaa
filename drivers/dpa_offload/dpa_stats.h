/* Copyright (c) 2013 Freescale Semiconductor, Inc.
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
 * DPA Stats user space library internal API
 */
#ifndef __DPA_STATS_H
#define __DPA_STATS_H

#include <pthread.h>


#define MAX_NUM_OF_STATS	23
#define NUM_OF_CNT_TYPES	(DPA_STATS_CNT_TRAFFIC_MNG + 1)
#define MAX_NUM_OF_MEMBERS	DPA_STATS_MAX_NUM_OF_CLASS_MEMBERS
#define DPA_STATS_US_CNT	0x80000000
#define MAX_NUM_OF_THREADS	5


/* DPA Stats control block */
struct dpa_stats {
	struct dpa_stats_params config;	/* Configuration parameters */
	struct dpa_stats_cnt_cb *cnts_cb; /* Array of counters control blocks */
	struct list_head async_req_pool; /* List of free async request nodes */
	struct list_head async_ks_reqs; /* List of 'in-process' async requests*/
	struct list_head req_pool; /* List of free request nodes */
	struct list_head async_us_reqs;
		/* List of request that need to be treated in 'user-space' */
	void *storage_area; /* Storage area provided by application */
	bool sched_cnt_ids[DPA_STATS_MAX_NUM_OF_COUNTERS];
	pthread_mutex_t sched_cnt_lock;
};

/* DPA Stats type of request */
enum req_type {
	US_CNTS_ONLY = 0, /* Requested counters are all 'user-space' */
	KS_CNTS_ONLY,	  /* Requested counters are all 'kernel-space' */
	MIXED_CNTS	  /* Requested counters are both user and kernel space*/
};

/* DPA Stats request control block */
struct dpa_stats_req {
	struct dpa_stats_cnt_request_params config;
			/* Parameters provided to the request */
	int *cnt_ids; /* Pointer to library array of counter ids */
	int *cnt_off; /* Array to store the counters offsets relative to the
			storage area offset of the request */
	void *request_area;
		  /* Address in the storage area associated with this request */
	dpa_stats_request_cb request_done; /* Callback to notify upper layer */
	uint32_t bytes_num; /* Number of bytes written by this request */
	uint32_t cnts_num; /* Number of counters written by this request */
	enum req_type type; /* Type of request */
	struct list_head node; /* Pointer to other requests in the current set*/
};

/* DPA Stats asynchronous request control block */
struct dpa_stats_async_req {
	struct list_head node; /* Pointer to other async requests in the set */
	struct dpa_stats_req *req; /* Pointer to a request structure */
};

/* DPA Stats - statistics information */
struct stats_info {
	 /*
	  * Array of statistics offsets relative to
	  * corresponding statistics area
	  */
	unsigned int stats_off[MAX_NUM_OF_STATS];
	unsigned int stats_num; /* Number of statistics to retrieve */
	uint64_t stats[MAX_NUM_OF_MEMBERS][MAX_NUM_OF_STATS];
				/* Array to store statistics values */
	uint64_t last_stats[MAX_NUM_OF_MEMBERS][MAX_NUM_OF_STATS];
				/* Array to store previous statistics values */
	bool reset; /* Reset counter's statistics */
};

typedef int get_cnt_stats(struct dpa_stats_req *req_cb,
			  struct dpa_stats_cnt_cb *cnt_cb,
			  unsigned int cnt_off);
struct dpa_stats_cnt_cb {
	int id; /* A valid counter identifier represents an "user-space" counter
		   and an invalid one represents a "kernel-space" counter */
	struct dpa_stats *dpa_stats; /* Pointer to DPA Stats */
	pthread_mutex_t lock;
	enum dpa_stats_cnt_type type;
	enum dpa_stats_cnt_sel sel;
	unsigned int members_num;
	void *obj[MAX_NUM_OF_MEMBERS];
	uint32_t bytes_num; /* Number of bytes occupied by this counter */
	struct stats_info info; /* Counter's statistics information */
	get_cnt_stats *f_get_cnt_stats;
};

#endif /* __DPA_STATS_H */
