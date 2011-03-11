/**
 \helper.h
 \brief helper functions
 */
/*
 * Copyright (C) 2010-2011 Freescale Semiconductor, Inc.
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
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <usdpaa/usdpaa_netcfg.h>

#include <stdbool.h>

#define MAX_NUM_FQ	1024
#define MAX_NUM_PORTS	12
volatile uint32_t g_num_dpa_eth_ports;
extern int lazy_init_bpool(u8 bpid);
/**
 \brief IPfwd FQ Range Info
*/
struct ipfwd_fq_range_t {
	uint32_t fq_start;
	uint32_t fq_count;
	uint32_t work_queue;		/**< Work Queue */
	uint32_t channel;		/**< Channel */
	struct qman_fq *fq[MAX_NUM_FQ];	/**< Array of QMan FQ structure */
};

struct ipfwd_eth_t {
	struct ipfwd_fq_range_t pcd;		/* PCD FQs */
	struct ipfwd_fq_range_t rx_def;		/* RX default FQs */
	struct ipfwd_fq_range_t rx_err;		/* RX error FQs */
	struct ipfwd_fq_range_t tx_err;		/* TX error FQs */
	struct ipfwd_fq_range_t tx_confirm;	/* TX confirm FQs */
	struct ipfwd_fq_range_t tx;		/* TX FQs */
	struct ether_addr mac_addr;
};

struct qman_orp_pcd {
	uint8_t reserved:2;
	uint8_t orprws:3; /**< Order Reservation Window Size 32*2^orprws */
	uint8_t oa:1; /**< Autoadvance of NESN Enabled */
	/**< ORWS Values
	0 = Disabled. Late arrivals always rejected.
	1 = Window size is 32 frames.
	2 = Window size is the same as the ORP restoration
		window size configured in the ORPRWS field.
	3 = Window size is 8192 frames. Late arrivals always accepted.
	*/
	uint8_t olws:2;
	uint8_t reserved2[3];
};

/**
 \brief	 Structure type for passing tail drop params
 \detail The number of bytes of data that can be in FQ is: TD_MANT * 2^TD_EXP.
 Also total number of bytes should be below: 0xE0000000
*/
struct td_param {
	uint16_t __reserved1:3;
	uint16_t mant:8;
	uint16_t exp:5;
	uint16_t flag;
	uint8_t cgr_id;
	qman_cb_cgr cgr_cb;
} __packed;

extern int init_interface(struct usdpaa_netcfg_info *cfg_ptr,
		      uint32_t *recv_channel_map,
		      struct qman_fq_cb *rx_default_cb,
		      struct qman_fq_cb *rx_pcd_cb,
		      struct qman_fq_cb *rx_err_cb,
		      struct qman_fq_cb *tx_cb,
		      struct qman_fq_cb *tx_confirm_cb,
		      struct qman_fq_cb *tx_err_cb, uint32_t priv_data_size);
