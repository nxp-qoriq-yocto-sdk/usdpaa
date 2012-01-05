/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
met:
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
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _FRA_H
#define _FRA_H

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>
#include <rman_interface.h>
#include <internal/compat.h>
#include <error.h>

#ifdef ENABLE_FRA_DEBUG
extern int debug_off;
#define FRA_DBG(fmt, args...) \
	do { \
		if (!debug_off) \
			fprintf(stderr, fmt"\n", ##args); \
	} while (0)
#else
#define FRA_DBG(fmt, args...)
#endif

#define CPU_SPIN_BACKOFF_CYCLES 512
extern __thread struct qman_fq local_fq;

struct ppac_interface;
struct distribution;
struct ppam_rx_hash;

struct tx_opt {
	int session;
	int txfqid;
};

struct dist_rx {
	struct qman_fq fq;
	struct tx_opt opt;
	struct distribution *dist;
};

struct dist_tx {
	struct qman_fq stfq;
	struct rman_outb_md md;
	struct qman_fq *fq;
	int session_count;
	struct distribution *dist;
};

struct dist_fwd {
	struct ppac_interface	*ppac_if;
};

enum handler_status {
	HANDLER_DONE,
	HANDLER_CONTINUE,
	HANDLER_ERROR
};

struct distribution {
	size_t sz;
	struct distribution *next;
	struct dist_cfg *cfg;
	enum handler_status (*handler)(struct distribution *dist,
				       struct tx_opt *opt,
				       const struct qm_fd *fd);
	union {
		struct dist_rx rx_hash[0];
		struct dist_tx tx[0];
		struct dist_fwd fwd[0];
	};
};

struct dist_order {
	struct list_head	node;
	struct distribution	*dist;
};

struct fra {
	struct list_head	dist_order_list;
	const struct fra_cfg	*cfg;
};

extern struct fra *fra;

void dist_rx_handler(struct dist_rx *rx, const struct qm_fd *fd);
void dist_tx_status_handler(struct dist_tx *tx, const struct qm_fd *fd);
void dist_fwd_from_handler(struct ppam_rx_hash *rx, const struct qm_fd *fd);

int fra_init(const struct fra_cfg *fra_cfg);
void fra_finish(void);

#endif /* _FRA_H */
