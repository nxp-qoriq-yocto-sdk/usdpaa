/* Copyright 2013 Freescale Semiconductor, Inc.
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
#ifndef __CRYPTO_QBMAN_H
#define __CRYPTO_QBMAN_H

#include "common.h"
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/dma_mem.h>

#define SEC40_FQ_BASE	       9000 /* start of FQ number for encryption FQ */
#define FQ_PER_CORE		  5 /* Number of flows for encryption as well
				       as decryption */
#define QMAN_WAIT_CYCLES       1000

enum SEC_MODE { DECRYPT, ENCRYPT }; /* enum to differentiate allocated memory
				       between fqs for encrypt/decryption */

/* storage and retire flags for FQ's(from SEC4.0 to software portal) object*/
struct fqs_t {
	uint32_t base;
	struct qman_fq *from_sec[FQ_PER_CORE];
	struct qman_fq *to_sec[FQ_PER_CORE];
	bool from_sec_retire[FQ_PER_CORE];
	bool to_sec_retire[FQ_PER_CORE];
};

struct sg_entry_priv_t {
	struct qm_sg_entry sgentry[2];
	uint32_t index;
	uint32_t reserved[7];
} __packed;

/* Create/Init routines */
int create_compound_fd(unsigned int buf_num, uint32_t output_buf_size,
		       uint32_t input_buf_capacity, uint32_t input_buf_length);
struct qman_fq *create_sec_frame_queue(uint32_t fq_id, dma_addr_t ctxt_a_addr,
				       uint32_t ctx_b);
int init_sec_frame_queues(enum SEC_MODE mode, struct fqs_t *fqs,
			  void *crypto_param, struct test_cb crypto_cb);
int init_sec_fq(uint32_t cpu_index, void *crypto_param,
		struct test_cb crypto_cb);

/* Runtime routines */
void enc_qman_poll(void);
void dec_qman_poll(void);
void do_enqueues(enum SEC_MODE mode, uint32_t cpu_index, long ncpus,
		 unsigned int buf_num);
int check_fd_status(unsigned int buf_num);

/* Handlers routines */
enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *qm, struct qman_fq *fq,
				 const struct qm_dqrr_entry *dqrr);
void cb_ern(struct qman_portal *qm, struct qman_fq *fq,
	    const struct qm_mr_entry *msg);
void cb_fqs(struct qman_portal *qm, struct qman_fq *fq,
	    const struct qm_mr_entry *msg);

/* Get/Set routines */
void get_pkts_to_sec(unsigned int buf_num, uint32_t cpu_index, long ncpus);
void set_enc_pkts_from_sec(void);
void set_dec_pkts_from_sec(void);
uint32_t get_dec_pkts_from_sec(void);
uint32_t get_enc_pkts_from_sec(void);
struct qm_fd *get_fd_base(void);

/* Free routines */
int free_sec_fq(uint8_t authnct);
int free_sec_frame_queues(struct qman_fq *fq[], bool fq_retire_flag[]);
void free_fd(unsigned int buf_num);

/* Debug routines */
void print_frame_desc(struct qm_fd *frame_desc);

#endif /* __CRYPTO_QBMAN_H */
