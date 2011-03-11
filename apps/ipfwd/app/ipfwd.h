/**
 \file ipfwd.h
 \brief Common datatypes, externs and hash-defines of IPv4 Forwarding
	 Application
 */
/*
 * Copyright (C) 2008-2011 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _IPFWD_H_
#define _IPFWD_H_

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>

#include "app_common.h"
#include "ip/ip.h"
#include "arp/arp.h"
#include "net/rt.h"
#include "ip/ip_rc.h"
#include "ip/ip_handler.h"
#include "dpa_dev/dpa_dev.h"
#include "ip/ip_common.h"
#include "ip/ip_hooks.h"
#include "ip/ip_protos.h"
#include "ip/ip_appconf.h"
#include "helper/helper.h"

#define ETHERNET_ADDR_MAGIC	0x0200
#define LINKLOCAL_NODES_2EXP	10
#define IFACE_COUNT		12
#define LINKLOCAL_NODES		(1 << LINKLOCAL_NODES_2EXP)
#define INITIAL_FRAME_COUNT	128
#define IP_RC_EXPIRE_JIFFIES	(20*60*JIFFY_PER_SEC)
#define IPSEC_MAX_NUM_FQS	9000
#define IP_DQRR_MAXFILL 15

#define IP_WAIT_TIMER_MS		20000
#define DVT0_DETECTED			1
#define DVT1_DETECTED			2

extern __PERCPU uint64_t atb_start;
extern volatile enum application_state ipsec_app_state;
extern int32_t num_fq_close_pending;
extern __PERCPU uint64_t total_cycles;

struct thread_data_t {
	/* Inputs to run_threads_custom() */
	int cpu;
	int index;
	int (*fn)(struct thread_data_t *ctx);
	int total_cpus;
	/* Value used within 'fn' - handle to the pthread; */
	pthread_t id;
	/* Stores fn() return value on return from run_threads_custom(); */
	int result;
	/* application-specific */
	void *appdata;
} ____cacheline_aligned;

/**
 \brief function to assist taking checkpoint for hybrid testing
 \param[in] NULL
 \param[out] NULL
 */
extern void ipsecfwd_performance_enter(void);

#ifdef STATS_TBD
/**
 \brief Initialize IPSec Statistics
 \param[in] void
 \param[out] struct ip_statistics_t *
 */
extern struct ip_statistics_t *ipfwd_stats_init(void);
#endif

/**
 \brief Context to be set per frame queue
 */
struct ip_fq_context_t {
	struct qman_fq fq; /**< Frame Queue Object */
	struct ip_context_t *ip_ctxt; /**< Pointer to private context */
} __attribute__((aligned(L1_CACHE_BYTES)));

/*State of ipsecfwd_hybrid application*/
enum application_state {
	INVALID,
	INITIALIZING,
	RUNNING,
	SHUTDOWN_PENDING,
	SHUTDOWN_SEC_RX_COMPLETE,
	SHUTDOWN_SEC_TX_COMPLETE,
	SHUTDOWN_TX_COMPLETE,
	SHUTDOWN_COMPLETE,
	RESET_PENDING,
	RESET_COMPLETE
};

extern int32_t g_key_split_flag;
extern struct qman_fq *g_splitkey_fq_from_sec;
extern struct qman_fq *g_splitkey_fq_to_sec;

extern struct dpa_buff_allocator *ipsec_buff_allocator;
extern bool dqrr_enter;
extern uint32_t num_proc_state;
extern uint32_t local_frames;
extern const struct qman_fq_cb ipfwd_rx_cb_err;
extern const struct qman_fq_cb ipfwd_tx_cb_err;
extern const struct qman_fq_cb ipfwd_tx_cb_confirm;
extern const struct qman_fq_cb ipfwd_rx_cb;
extern const struct qman_fq_cb ipfwd_rx_cb_pcd;
extern const struct qman_fq_cb ipsecfwd_tx_cb;
extern const struct qman_fq_cb ipfwd_tx_cb;
extern const struct qman_fq_cb ipfwd_split_key_cb;
extern uint32_t g_sec_fq_count;
extern int32_t pool_channel_id;
extern struct ipfwd_eth_t ipfwd_fq_range[MAX_NUM_PORTS];

/**
 \brief Check if destination IP address for own interface
 \param[in] ip_addr IP address
 \param[out] 0 if match found, else -ve value
 */
int32_t is_iface_ip(uint32_t ip_addr);

/**
 \brief Gets interface node corresponding to an ip address
 \param[in] ip_addr IP Address
 \return    interface node, On success
	    NULL,	    On failure
 */
struct node_t *ipfwd_get_iface_for_ip(uint32_t ip_addr);

/**
 \brief IPSecfwd Shutdown Complete handler
 */
extern void ip_shutdown_complete(uint32_t timer_id, void *p_data);

/**
 \brief Initialize all extern variables
 */
extern void ipsec_init(void);

extern void ip_shutdown_sec_rx_complete(uint32_t timer_id, void *p_data);

extern void ip_shutdown_sec_tx_complete(uint32_t timer_id, void *p_data);

extern void ip_shutdown_sec_tx(uint32_t timer_id, void *p_data);
/* Utility functions */
static inline int my_toul(const char *str, char **endptr, long toobig)
{
	unsigned long tmp = strtoul(str, endptr, 0);
	if ((tmp == ULONG_MAX) || (*endptr == str)) {
		fprintf(stderr, "error: can't parsing '%s'\n", str);
		exit(EXIT_FAILURE);
	}
	if (tmp >= toobig) {
		fprintf(stderr, "error: value %lu out of range\n", tmp);
		exit(EXIT_FAILURE);
	}
	return (int)tmp;
}

#endif
