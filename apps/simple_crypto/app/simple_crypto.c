/**
  \file	simple_crypto.c
  \brief	Basic SEC 4.0 test application. It operates on user defined SEC
  parameters through CP application and reports throughput for
  various SEC 4.0 raw algorithm.
 */
/* Copyright (c) 2011 Freescale Semiconductor, Inc.
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

#include "simple_crypto.h"

#include <inttypes.h>

#define BITS_PER_BYTE (8)
#define BYTES_PER_WORD sizeof(int)
#define ONE_MEGA 1000000
#define QMAN_WAIT_CYCLES 1000

uint32_t g_cmd_params;	/* bit mask of all parameters provided by user */

/* user defined parameters through CP */
struct crypto_param *crypto_info;

/* Total number of buffers to send to CAAm block per iteration */
uint32_t total_buf_num;

/* refrence test vector consists of key, iv, plain text, cipher text etc*/
struct ref_vector_s ref_test_vector;

/* output buffer size(varies for authentication algos) */
uint32_t output_buf_size;
/* input buffer capacity(varies for authentication algos) */
uint32_t input_buf_capacity;
/* The size required for a buffer that can hold descriptors */
uint32_t job_desc_buf_size;
/* Total size of sg entry, i/p and o/p buffer required */
uint32_t total_size;

/* total number of encrypted frame(s) returned from SEC4.0 */
atomic_t enc_packet_from_sec;
/* total number of decrypted frame(s) returned from SEC4.0 */
atomic_t dec_packet_from_sec;

uint32_t ind;
struct qm_fd fd[BUFF_NUM_PER_CORE*8];	/* storage for frame descriptor */

/* start FQ no. for encryption flows */
uint32_t fq_base_encrypt = SEC40_FQ_BASE;
/* start FQ no. for decryption flows */
uint32_t fq_base_decrpyt = SEC40_FQ_BASE + 2 * FQ_COUNT;

/* storage for encryption FQ's(from SEC4.0 to software portal) object*/
struct qman_fq *enc_fq_from_sec[FQ_COUNT];
/* storage for encryption FQ's(from software portal to SEC4.0) object*/
struct qman_fq *enc_fq_to_sec[FQ_COUNT];
/* storage for decryption FQ's(from SEC4.0 to software portal) object*/
struct qman_fq *dec_fq_from_sec[FQ_COUNT];
/* storage for decryption FQ's(from software portal to SEC4.0) object*/
struct qman_fq *dec_fq_to_sec[FQ_COUNT];

/* retire flag associated with each of the frame queues */
static bool enc_fq_from_sec_retire[FQ_COUNT];
static bool enc_fq_to_sec_retire[FQ_COUNT];
static bool dec_fq_from_sec_retire[FQ_COUNT];
static bool dec_fq_to_sec_retire[FQ_COUNT];

uint8_t authnct;	/* processing authentication algorithm */

/* pool Channel Offset */
volatile int32_t pool_channel_offset;

static bool ctrl_error;

/* Number of active cpus */
long ncpus;

/* Counters to accumulate time taken for packet processing */
uint64_t enc_delta, dec_delta;

char algorithm[20];	/* string corresponding to integral value */
char mode_type[20];	/* string corresponding to integral value */

static void cb_ern(struct qman_portal *qm, struct qman_fq *fq,
		const struct qm_mr_entry *msg);

/* callback handler for dequeued frames and fq's(from SEC40) state change */
const struct qman_fq_cb sec40_rx_cb = { cb_dqrr, NULL, NULL, cb_fqs };

/* callback handler for fq's(to SEC40) state change */
const struct qman_fq_cb sec40_tx_cb = { NULL, cb_ern, NULL, cb_fqs };

/*
 * brief	Initialises the reference test vector for aes-cbc
 * details	Initializes key, length and other variables for the algorithm
 * return	void
 */
void init_rtv_aes_cbc(void)
{
	strcpy(algorithm, "AES_CBC");
	ref_test_vector.key =
		aes_cbc_reference_key[crypto_info->test_set - 1];
	ref_test_vector.iv.init_vec =
		aes_cbc_reference_iv[crypto_info->test_set - 1];
	ref_test_vector.length =
		aes_cbc_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		aes_cbc_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext =
		aes_cbc_reference_ciphertext[crypto_info->test_set - 1];
}

void init_rtv_tdes_cbc(void)
{
	strcpy(algorithm, "TDES_CBC");
	ref_test_vector.key =
		tdes_cbc_reference_key[crypto_info->test_set - 1];
	ref_test_vector.iv.init_vec =
		tdes_cbc_reference_iv[crypto_info->test_set - 1];
	ref_test_vector.length =
		tdes_cbc_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		tdes_cbc_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext =
		tdes_cbc_reference_ciphertext[crypto_info->test_set - 1];
}

void init_rtv_snow_f8(void)
{
	strcpy(algorithm, "SNOW_F8");
	ref_test_vector.key = snow_f8_reference_key[crypto_info->test_set - 1];
	ref_test_vector.iv.f8.count =
		snow_f8_reference_count[crypto_info->test_set - 1];
	ref_test_vector.iv.f8.bearer =
		snow_f8_reference_bearer[crypto_info->test_set - 1];
	ref_test_vector.iv.f8.direction =
		snow_f8_reference_dir[crypto_info->test_set - 1];
	ref_test_vector.length =
		snow_f8_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		snow_f8_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext =
		snow_f8_reference_ciphertext[crypto_info->test_set - 1];
}

void init_rtv_snow_f9(void)
{
	strcpy(algorithm, "SNOW_F9");
	ref_test_vector.key = snow_f9_reference_key[crypto_info->test_set - 1];
	ref_test_vector.iv.f9.count =
		snow_f9_reference_count[crypto_info->test_set - 1];
	ref_test_vector.iv.f9.fresh =
		snow_f9_reference_fresh[crypto_info->test_set - 1];
	ref_test_vector.iv.f9.direction =
		snow_f9_reference_dir[crypto_info->test_set - 1];
	ref_test_vector.length =
		snow_f9_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		snow_f9_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext = NULL;
	ref_test_vector.digest =
		snow_f9_reference_digest[crypto_info->test_set - 1];
	authnct = 1;
}

void init_rtv_kasumi_f8(void)
{
	strcpy(algorithm, "KASUMI_F8");
	ref_test_vector.key =
		kasumi_f8_reference_key[crypto_info->test_set - 1];
	ref_test_vector.iv.f8.count =
		kasumi_f8_reference_count[crypto_info->test_set - 1];
	ref_test_vector.iv.f8.bearer =
		kasumi_f8_reference_bearer[crypto_info->test_set - 1];
	ref_test_vector.iv.f8.direction =
		kasumi_f8_reference_dir[crypto_info->test_set - 1];
	ref_test_vector.length =
		kasumi_f8_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		kasumi_f8_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext =
		kasumi_f8_reference_ciphertext[crypto_info->test_set - 1];
}

void init_rtv_kasumi_f9(void)
{
	strcpy(algorithm, "KASUMI_F9");
	ref_test_vector.key =
		kasumi_f9_reference_key[crypto_info->test_set - 1];
	ref_test_vector.iv.f9.count =
		kasumi_f9_reference_count[crypto_info->test_set - 1];
	ref_test_vector.iv.f9.fresh =
		kasumi_f9_reference_fresh[crypto_info->test_set - 1];
	ref_test_vector.iv.f9.direction =
		kasumi_f9_reference_dir[crypto_info->test_set - 1];
	ref_test_vector.length =
		kasumi_f9_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		kasumi_f9_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext = NULL;
	ref_test_vector.digest =
		kasumi_f9_reference_digest[crypto_info->test_set - 1];
	authnct = 1;
}

void init_rtv_crc(void)
{
	strcpy(algorithm, "CRC");
	ref_test_vector.length =
		crc_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		crc_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext = NULL;
	ref_test_vector.digest =
		crc_reference_digest[crypto_info->test_set - 1];
	authnct = 1;
}

void init_rtv_hmac_sha1(void)
{
	strcpy(algorithm, "HMAC_SHA1");
	ref_test_vector.key =
		hmac_sha1_reference_key[crypto_info->test_set - 1];
	ref_test_vector.length =
		hamc_sha1_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		hmac_sha1_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext = NULL;
	ref_test_vector.digest =
		hamc_sha1_reference_digest[crypto_info->test_set - 1];
	authnct = 1;
}

void init_rtv_snow_f8_f9(void)
{
	strcpy(algorithm, "SNOW_F8_F9");
	ref_test_vector.length =
		snow_enc_f8_f9_reference_length[crypto_info->test_set - 1];
	ref_test_vector.plaintext =
		snow_enc_f8_f9_reference_plaintext[crypto_info->test_set - 1];
	ref_test_vector.ciphertext =
		snow_enc_f8_f9_reference_ciphertext[crypto_info->test_set - 1];
}

/* Function pointer to reference test vector for suported algos */
void (*init_ref_test_vector[])(void) = {
		init_rtv_aes_cbc,
		init_rtv_tdes_cbc,
		init_rtv_snow_f8,
		init_rtv_snow_f9,
		init_rtv_kasumi_f8,
		init_rtv_kasumi_f9,
		init_rtv_crc,
		init_rtv_hmac_sha1,
		init_rtv_snow_f8_f9 };

/*
 * brief	Create a compound frame descriptor understood by SEC 4.0
 * return	0 on success, otherwise -ve value
 */
static int create_compound_fd(void)
{
	uint8_t *in_buf, *out_buf;
	struct sg_entry_priv_t *sg_priv_and_data;
	struct qm_sg_entry *sg;
	uint32_t input_buf_length = 0;
	input_buf_capacity = crypto_info->buf_size;
	input_buf_length = crypto_info->buf_size;

	switch (crypto_info->algo) {
	case AES_CBC:
	case TDES_CBC:
	case SNOW_F8:
		output_buf_size = crypto_info->buf_size;
		break;
	case SNOW_F9:
		output_buf_size = SNOW_F9_DIGEST_SIZE;
		break;
	case KASUMI_F8:
		output_buf_size = crypto_info->buf_size;
		break;
	case KASUMI_F9:
		output_buf_size = KASUMI_F9_DIGEST_SIZE;
		break;
	case CRC:
		output_buf_size = CRC_DIGEST_SIZE;
		break;
	case HMAC_SHA1:
		output_buf_size = HMAC_SHA1_DIGEST_SIZE;
		break;
	case SNOW_F8_F9:
		output_buf_size = crypto_info->buf_size + SNOW_F9_DIGEST_SIZE;

		/* For this algorithm a	 Job Descriptor will be added to the
		 * head of the SEC frame. Increase the buffer capacity and
		 * length. The same buffer will be used for holding the
		 * plain-text data + encrypt job descriptor and later the
		 * encrypted data + SNOW F9 digest + decrypt job descriptor.
		 */
		input_buf_capacity += job_desc_buf_size + SNOW_F9_DIGEST_SIZE;
		input_buf_length += job_desc_buf_size;

		break;
	default:
		pr_err("%s: algorithm not supported\n", __func__);
		return -EINVAL;
	}

	for (ind = 0; ind < total_buf_num; ind++) {

		/* Allocate memory for scatter-gather entry and
		   i/p & o/p buffers */
		total_size = sizeof(struct sg_entry_priv_t) + output_buf_size
			+ input_buf_capacity;

		sg_priv_and_data = (struct sg_entry_priv_t *)dma_mem_memalign
			(L1_CACHE_BYTES, total_size);

		if (unlikely(!sg_priv_and_data)) {
			pr_err("Unable to allocate memory for buffer!\n");
			return -EINVAL;
		}
		memset(sg_priv_and_data, 0, total_size);

		/* Get the address of output and input buffers */
		out_buf = (uint8_t *)(sg_priv_and_data)
			+ sizeof(struct sg_entry_priv_t);
		in_buf = (uint8_t *)sg_priv_and_data + (total_size
				- input_buf_capacity);

		sg = (struct qm_sg_entry *)sg_priv_and_data;

		/* output buffer */
		qm_sg_entry_set64(sg, dma_mem_vtop(out_buf));
		sg->length = output_buf_size;

		/* input buffer */
		sg++;
		qm_sg_entry_set64(sg, dma_mem_vtop(in_buf));
		sg->length = input_buf_length;
		sg->final = 1;
		sg--;

		/* Frame Descriptor */
		fd[ind].addr_lo = dma_mem_vtop(sg);
		fd[ind]._format1 = qm_fd_compound;

		sg_priv_and_data->index = ind;
	}

	return 0;
}

static void *setup_preheader(uint32_t shared_desc_len, uint32_t pool_id,
		uint32_t pool_buf_size, uint8_t absolute, uint8_t add_buf)
{
	struct preheader_s *prehdr = NULL;

	prehdr = dma_mem_memalign(L1_CACHE_BYTES, 2*L1_CACHE_BYTES);
	memset(prehdr, 0, 2*L1_CACHE_BYTES);

	if (unlikely(!prehdr)) {
		pr_err("%s: dma_mem_memalign failed for preheader\n"
				, __func__);
		return NULL;
	}

	/* the shared descriptor length is 0, meaning that no shared
	   descriptor follows the preheader in the context A */
	prehdr->hi.field.idlen = shared_desc_len;
	prehdr->lo.field.abs = absolute;
	prehdr->lo.field.add_buf = add_buf;
	prehdr->lo.field.pool_id = pool_id;
	prehdr->lo.field.pool_buffer_size = pool_buf_size;

	return (void *)prehdr;

}

/*
 * brief	Create SEC 4.0 shared descriptor consists of sequence of
 *		commands to SEC 4.0 with necessary key, iv etc initialisation
 * param[in]	mode -	To check whether descriptor is for encryption or
 *		decryption
 * return	Shared descriptor pointer on success, otherwise NULL
 */
static void *setup_init_descriptor(bool mode)
{
	struct sec_descriptor_t *prehdr_desc;
	uint32_t *shared_desc = NULL;
	uint16_t shared_desc_len;
	int i, ret;

	prehdr_desc = dma_mem_memalign(L1_CACHE_BYTES,
				sizeof(struct sec_descriptor_t));
	if (unlikely(!prehdr_desc)) {
		pr_err("%s: dma_mem_memalign failed for preheader\n"
				, __func__);
		return NULL;
	}

	memset(prehdr_desc, 0, sizeof(struct sec_descriptor_t));

	shared_desc = (typeof(shared_desc))&prehdr_desc->deschdr;

	switch (crypto_info->algo) {
	case AES_CBC:
		ret = cnstr_shdsc_cbc_blkcipher(shared_desc, &shared_desc_len,
			ref_test_vector.key, AES_CBC_KEY_LEN * BITS_PER_BYTE,
			ref_test_vector.iv.init_vec,
			AES_CBC_IV_LEN * BITS_PER_BYTE,
			mode ? DIR_ENCRYPT : DIR_DECRYPT,
			OP_ALG_ALGSEL_AES, 0);
		break;

	case TDES_CBC:
		ret = cnstr_shdsc_cbc_blkcipher(shared_desc, &shared_desc_len,
			ref_test_vector.key, TDES_CBC_KEY_LEN * BITS_PER_BYTE,
			ref_test_vector.iv.init_vec,
			TDES_CBC_IV_LEN * BITS_PER_BYTE,
			mode ? DIR_ENCRYPT : DIR_DECRYPT,
			OP_ALG_ALGSEL_3DES, 0);
		break;

	case SNOW_F8:
		ret = cnstr_shdsc_snow_f8(shared_desc, &shared_desc_len,
			ref_test_vector.key, F8_KEY_LEN * BITS_PER_BYTE,
			mode ? DIR_ENCRYPT : DIR_DECRYPT,
			ref_test_vector.iv.f8.count,
			ref_test_vector.iv.f8.bearer,
			ref_test_vector.iv.f8.direction, 0);
		break;

	case SNOW_F9:
		if (DECRYPT == mode) {
			pr_err("%s: enc bit not selected as protect\n",
				__func__);
			return NULL;
		}

		ret = cnstr_shdsc_snow_f9(shared_desc, &shared_desc_len,
			ref_test_vector.key, F9_KEY_LEN * BITS_PER_BYTE,
			DIR_ENCRYPT, ref_test_vector.iv.f9.count,
			ref_test_vector.iv.f9.fresh,
			ref_test_vector.iv.f9.direction, 0,
			ref_test_vector.length);
		break;

	case KASUMI_F8:
		ret = cnstr_shdsc_kasumi_f8(shared_desc, &shared_desc_len,
			ref_test_vector.key, F8_KEY_LEN * BITS_PER_BYTE,
			mode ? DIR_ENCRYPT : DIR_DECRYPT,
			ref_test_vector.iv.f8.count,
			ref_test_vector.iv.f8.bearer,
			ref_test_vector.iv.f8.direction, 0);
		break;

	case KASUMI_F9:
		if (DECRYPT == mode) {
			pr_err("%s: enc bit not selected as protect\n",
				__func__);
			return NULL;
		}

		ret = cnstr_shdsc_kasumi_f9(shared_desc, &shared_desc_len,
			ref_test_vector.key, F9_KEY_LEN * BITS_PER_BYTE,
			DIR_ENCRYPT, ref_test_vector.iv.f9.count,
			ref_test_vector.iv.f9.fresh,
			ref_test_vector.iv.f9.direction, 0,
			ref_test_vector.length);
		break;

	case CRC:
		if (DECRYPT == mode) {
			pr_err("%s: enc bit not selected as"
				" protect\n", __func__);
			return NULL;
		}

		ret = cnstr_shdsc_crc(shared_desc, &shared_desc_len, 0);
		break;

	case HMAC_SHA1:
		if (DECRYPT == mode) {
			pr_err("%s: enc bit not selected as"
				" protect\n", __func__);
			return NULL;
		}

		ret = cnstr_shdsc_hmac(shared_desc, &shared_desc_len,
			ref_test_vector.key, OP_ALG_ALGSEL_SHA1, NULL, 0);
		break;

	default:
		pr_err("%s: algorithm not supported\n", __func__);
		return NULL;
	}

	if (ret)
		goto error;

	prehdr_desc->prehdr.hi.field.idlen = shared_desc_len;

	pr_debug("SEC4.0 %s shared descriptor:\n", algorithm);

	for (i = 0; i < shared_desc_len; i++)
		pr_debug("0x%x\n", *shared_desc++);

	return prehdr_desc;

error:
	pr_err("%s: %s shared descriptor initilization failed\n",
			__func__, algorithm);
	return NULL;
}

static void *setup_sec_descriptor(bool mode)
{
	void *descriptor = NULL;

	if (SNOW_F8_F9 == crypto_info->algo) {
		descriptor = setup_preheader
			(0, /* shared descriptor length is 0, meaning
			       there is no shared desc in context A*/
			 0, /* pool buffer id*/
			 0, /* pool buffer size*/
			 0, /* abs = 0 and add_buf = 0 means that the
			       output buffer is provided inside
			       compound frame*/
			 0); /* add_buf = 0*/

	} else {
		descriptor = setup_init_descriptor(mode);
	}
	return descriptor;
}

struct qman_fq *create_sec_frame_queue(uint32_t fq_id, uint16_t channel,
		uint16_t wq_id, dma_addr_t ctxt_a_addr, uint32_t ctx_b)
{
	struct qm_mcc_initfq fq_opts;
	struct qman_fq *fq;
	uint32_t flags;

	fq = (struct qman_fq *)dma_mem_memalign(L1_CACHE_BYTES,
			sizeof(struct qman_fq));
	if (unlikely(NULL == fq)) {
		pr_err("dma_mem_memalign failed in create_fqs for FQ ID:\n"
			"%u", fq_id);
		return NULL;
	}

	if (ctxt_a_addr) {
		flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_TO_DCPORTAL;
		fq->cb = sec40_tx_cb;
	} else {
		flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_NO_ENQUEUE;
		fq->cb = sec40_rx_cb;
	}

	if (unlikely(qman_create_fq(fq_id, flags, fq) != 0)) {
		pr_err("qman_create_fq failed for FQ ID: %u\n", fq_id);
		return NULL;
	}

	flags = QMAN_INITFQ_FLAG_SCHED;
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA;
	if (ctxt_a_addr) {
		fq_opts.we_mask |= QM_INITFQ_WE_CONTEXTB;
		qm_fqd_stashing_set64(&fq_opts.fqd, ctxt_a_addr);
		fq_opts.fqd.context_b = ctx_b;
	} else {
		uint32_t ctx_a_excl, ctx_a_len;
		ctx_a_excl = (QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_CTX);
		ctx_a_len = (1 << 2) | 1;
		fq_opts.fqd.context_a.hi = (ctx_a_excl << 24)
			| (ctx_a_len << 16);
	}

	fq_opts.fqd.dest.wq = wq_id;
	fq_opts.fqd.dest.channel = channel;

	if (unlikely(qman_init_fq(fq, flags, &fq_opts) != 0)) {
		pr_err("qm_init_fq failed for fq_id: %u\n", fq_id);
		return NULL;
	}

	return fq;
}

static int init_sec_frame_queues(enum SEC_MODE mode)
{
	uint32_t frame_q_base;
	uint32_t fq_from_sec, fq_to_sec;
	struct qman_fq **fq_from_sec_ptr, **fq_to_sec_ptr;
	void *ctxt_a;
	dma_addr_t addr;
	uint32_t pool_channel =
		(qm_channel_pool1 - 1) + pool_channel_offset;
	int i;

	ctxt_a = setup_sec_descriptor(mode);
	if (0 == ctxt_a) {
		pr_err("%s: Initializing shared descriptor failure!\n",
				__func__);
		return -1;
	}
	addr = dma_mem_vtop(ctxt_a);

	if (ENCRYPT == mode) {
		frame_q_base = fq_base_encrypt;
		fq_from_sec_ptr = enc_fq_from_sec;
		fq_to_sec_ptr = enc_fq_to_sec;
	} else {
		frame_q_base = fq_base_decrpyt;
		fq_from_sec_ptr = dec_fq_from_sec;
		fq_to_sec_ptr = dec_fq_to_sec;
	}

	for (i = 0; i < FQ_COUNT; i++) {
		fq_from_sec = frame_q_base++;
		fq_to_sec = frame_q_base++;

		fq_from_sec_ptr[i] =
			create_sec_frame_queue(fq_from_sec,
				pool_channel, 0, 0, 0);
		if (!fq_from_sec_ptr[i]) {
			pr_err("%s : Encrypt FQ(from SEC) %d"
				" couldn't be allocated, ID = %d\n",
				__func__, i, fq_from_sec);
			return -1;
		}

		fq_to_sec_ptr[i] =
			create_sec_frame_queue(fq_to_sec, qm_channel_caam,
				0, addr, fq_from_sec);
		if (!fq_to_sec_ptr[i]) {
			pr_err("%s : Encrypt FQ(to SEC) %d couldn't be"
				" allocated, ID = %d\n",
				__func__, i, fq_to_sec);
			return -1;
		}
	}
	return 0;
}

/*
 * brief	Initialize frame queues to enqueue and dequeue frames to SEC
 *		and from SEC respectively
 * param[in]	None
 * return	0 on success, otherwise -ve value
 */
static int init_sec_fq(void)
{

	if (init_sec_frame_queues(ENCRYPT)) {
		pr_err("%s: couldn't Initialize SEC 4.0 Encrypt Queues\n",
				__func__);
		return -1;
	}

	if (!authnct) {
		if (init_sec_frame_queues(DECRYPT)) {
			pr_err
				("%s: couldn't Initialize SEC 4.0 Decrypt"
					" Queues\n", __func__);
			return -1;
		}
	}

	pr_info("Initialized FQs\n");
	return 0;
}

void cb_fqs(struct qman_portal *qm, struct qman_fq *fq,
		const struct qm_mr_entry *msg)
{
	uint32_t fqid;
	uint32_t rem, offset;

	fqid = fq->fqid;

	if ((fqid >= fq_base_encrypt) && (fqid < fq_base_decrpyt)) {
		offset = fqid - fq_base_encrypt;
		rem = offset % 2;
		if (!rem)
			enc_fq_from_sec_retire[offset / 2] = true;
		else
			enc_fq_to_sec_retire[offset / 2] = true;
	} else if ((fqid >= fq_base_decrpyt)
			&& (fqid < (fq_base_decrpyt + 2 * FQ_COUNT))) {
		offset = fqid - fq_base_decrpyt;
		rem = offset % 2;
		if (!rem)
			dec_fq_from_sec_retire[offset / 2] = true;
		else
			dec_fq_to_sec_retire[offset / 2] = true;
	}
}

void free_fd(void)
{
	dma_addr_t addr;
	uint8_t *buf;

	for (ind = 0; ind < total_buf_num; ind++) {
		addr = qm_fd_addr_get64(&fd[ind]);
		buf = dma_mem_ptov(addr);
		dma_mem_free(buf, total_size);
	}
}

static int free_sec_frame_queues(struct qman_fq *fq[],
		bool *fq_retire_flag)
{
	int res, i;
	uint32_t flags;

	for (i = 0; i < FQ_COUNT; i++) {
		res = qman_retire_fq(fq[i], &flags);
		if (0 > res) {
			pr_err("qman_retire_fq failed for fq %d\n", i);
			return -EINVAL;
		}
		wait_event(NULL, *((unsigned char *)(fq_retire_flag) + i));

		if (flags & QMAN_FQ_STATE_BLOCKOOS) {
			pr_err("leaking frames for fq %d\n", i);
			return -1;
		}
		if (qman_oos_fq(fq[i])) {
			pr_err("qman_oos_fq failed for fq %d\n", i);
			return -EINVAL;
		}
		qman_destroy_fq(fq[i], 0);
	}

	return 0;
}

int free_sec_fq(void)
{
	if (unlikely(free_sec_frame_queues(enc_fq_from_sec,
		enc_fq_from_sec_retire) != 0)) {
		pr_err("free_sec_frame_queues failed for enc_fq_from_sec\n");
		return -1;
	}

	if (unlikely(free_sec_frame_queues(enc_fq_to_sec,
		enc_fq_to_sec_retire) != 0)) {
		pr_err("free_sec_frame_queues failed for enc_fq_to_sec\n");
		return -1;
	}

	if (!authnct) {
		if (unlikely(free_sec_frame_queues(dec_fq_from_sec,
			dec_fq_from_sec_retire) != 0)) {
			pr_err("free_sec_frame_queues failed for"
				" dec_fq_from_sec\n");
			return -1;
		}

		if (unlikely(free_sec_frame_queues(dec_fq_to_sec,
			dec_fq_to_sec_retire) != 0)) {
			pr_err("free_sec_frame_queues failed for"
				" dec_fq_to_sec\n");
			return -1;
		}
	}
	return 0;
}

/*
 * brief	Initialize input buffer plain text data	and set	output buffer
 *		as 0 in compound frame descriptor
 */
static void set_enc_buf(void)
{
	struct qm_sg_entry *sgentry;
	uint8_t *out_buf, *in_buf;
	uint8_t plain_data = 0;
	dma_addr_t addr;
	uint8_t *enc_job_descriptor = NULL;
	uint32_t i;

	for (ind = 0; ind < total_buf_num; ind++) {
		markpoint(1);

		addr = qm_fd_addr_get64(&fd[ind]);
		sgentry = dma_mem_ptov(addr);

		addr = qm_sg_entry_get64(sgentry);
		out_buf = dma_mem_ptov(addr);
		memset(out_buf, 0, output_buf_size);

		sgentry++;
		addr = qm_sg_entry_get64(sgentry);
		in_buf = dma_mem_ptov(addr);
		memset(in_buf, 0, input_buf_capacity);


		/* In case of SNOW_F8_F9 algorithm, a Job Descriptor must be
		 * inlined at the head of the input buffer. Set the encrypt
		 * job descriptor here.
		 */
		if (SNOW_F8_F9 == crypto_info->algo) {
			/* Update the input frame length. If this is not the
			 *  first iteration, the input len will remain set
			 *  from the decryption phase. The input len for
			 *  encrypt is different than for decrypt.
			 */

			sgentry->length = input_buf_capacity -
				SNOW_F9_DIGEST_SIZE;

			/* Update the out frame length. If this is not the
			 *  first iteration, the output len will remain set
			 *  from the decryption phase. The output len for
			 *  encrypt is different than for decrypt.
			 */
			sgentry--;
			sgentry->length = output_buf_size;

			/* Convert the descriptor to an array of uint8_t */
			enc_job_descriptor = (uint8_t *) snow_jdesc_enc_f8_f9;

			memcpy(in_buf, enc_job_descriptor, job_desc_buf_size);
		}

		/* Copy the input plain-text data */
		for (i = 0; i < crypto_info->buf_size; i++) {
			if (CIPHER == crypto_info->mode)
				memcpy(in_buf, ref_test_vector.plaintext,
					crypto_info->buf_size);
			else
				in_buf[i] = plain_data++;
		}
	}
}

/*
 * brief	Initialize input buffer as cipher text data and	set output
 *		buffer as 0 in compound frame descriptor
 */
static void set_dec_buf(void)
{

	struct qm_sg_entry *sg_out;
	struct qm_sg_entry *sg_in;

	uint32_t addr_lo;
	uint32_t length;
	uint16_t offset;
	uint8_t bpid;
	uint8_t *out_buf;
	dma_addr_t addr;

	for (ind = 0; ind < total_buf_num; ind++) {
		markpoint(4);

		addr = qm_fd_addr_get64(&fd[ind]);
		sg_out = dma_mem_ptov(addr);
		sg_in = sg_out + 1;

		addr_lo = sg_out->addr_lo;
		length = sg_out->length;
		offset = sg_out->offset;
		bpid = sg_out->bpid;

		sg_out->addr_lo = sg_in->addr_lo;
		sg_out->length = sg_in->length;
		sg_out->offset = sg_in->offset;
		sg_out->bpid = sg_in->bpid;

		sg_in->addr_lo = addr_lo;
		sg_in->length = length;
		sg_in->offset = offset;
		sg_in->bpid = bpid;

		addr = qm_sg_entry_get64(sg_out);
		out_buf = dma_mem_ptov(addr);
		memset(out_buf, 0, crypto_info->buf_size);
	}
}

static void set_dec_auth_buf(void)
{

	struct qm_sg_entry *sg_out;
	struct qm_sg_entry *sg_in;
	uint8_t *out_buf = NULL;
	uint8_t *in_buf = NULL;
	dma_addr_t addr;
	uint8_t *dec_job_descriptor = NULL;

	if (SNOW_F8_F9 != crypto_info->algo) {
		pr_err("%s: algorithm not supported\n", __func__);
		return;
	}

	for (ind = 0; ind < total_buf_num; ind++) {
		markpoint(4);

		addr = qm_fd_addr_get64(&fd[ind]);
		sg_out = dma_mem_ptov(addr);

		addr = qm_sg_entry_get64(sg_out);
		out_buf = dma_mem_ptov(addr);

		sg_in = sg_out + 1;

		addr = qm_sg_entry_get64(sg_in);
		in_buf = dma_mem_ptov(addr);
		memset(in_buf, 0, input_buf_capacity);

		/* Convert the descriptor to an array of uint8_t items */
		dec_job_descriptor = (uint8_t *) snow_jdesc_dec_f8_f9;

		/* A Job Descriptor must be inlined at the head of the input
		 * buffer. Set the decrypt job descriptor here. */
		memcpy(in_buf, dec_job_descriptor, job_desc_buf_size);
		in_buf += job_desc_buf_size;

		/* Validate that the output buffer size is equal with the
		 *  size of the reference cyphertext for decryption
		 */
		if (output_buf_size != (snow_dec_f8_f9_reference_length
					[crypto_info->test_set - 1]/8)) {
			pr_err("Invalid output buffer length\n");
			abort();
		}

		/* Use the reference encrypted data as input for decryption */
		memcpy(in_buf, snow_dec_f8_f9_reference_ciphertext
			[crypto_info->test_set - 1], output_buf_size);

		sg_in->length = output_buf_size + job_desc_buf_size;

		/* The output buffer will contain only the decoded F8 data */
		sg_out->length = crypto_info->buf_size;

		/* Clear the output buffer  */
		memset(out_buf, 0, sg_out->length);
	}
}

/*
 * brief	Bitwise comparison of two vectors
 * param[in]	left - The lefthand-side vector to enter the comparison
 * param[in]	right - The righthand-side vector to enter the comparison
 * param[in]	bitlength - The length(in bits) on which the comparison
 *		will be made
 * retval	0 if and only if the vectors are identical up to
 *		(including) the given bitlength.
 * pre		Neither of the buffer pointers is allowed to be NULL.
 * pre		Both buffers must be at least of size ceil
 *		(bitlength / sizeof(32)).
 */
static int test_vector_match(uint32_t *left, uint32_t *right,
		uint32_t bitlen)
{
	uint8_t reminder_bitlen;
	uint32_t bitmasks[32];
	uint32_t i;

	if (!left || !right) {
		pr_err("Wrong parameters to %s\n", __func__);
		abort();
	}

	/* initialize bitmasks */
	bitmasks[0] = 0xFFFFFFFF;
	for (i = 1; i <= 31; i++)
		bitmasks[i] = bitmasks[i - 1] >> 1;

	/* compare the full 32-bit quantities */
	for (i = 0; i < (bitlen >> 5); i++) {
		if (left[i] != right[i]) {
			pr_err
				("%s(): Bytes at offset %d don't match "
				 "(0x%x, 0x%x)\n", __func__, i, left[i],
				 right[i]);
			return -1;
		}
	}

	/* compare the reminder dword starting with its most significant
	 *  bits */
	reminder_bitlen = bitlen & 0x1F;
	if (reminder_bitlen) {
		/* compare left[bitlen >> 5] with right[bitlen >> 5]
		 *  on the remaining number of bits
		 */
		uint32_t left_last = left[bitlen >> 5];
		uint32_t right_last = right[bitlen >> 5];

		if ((left_last | bitmasks[reminder_bitlen])
				!= (right_last | bitmasks[reminder_bitlen])) {
			pr_err("%s(): Last bytes (%d) don't match on full"
				" %d bitlength\n", __func__, bitlen >> 5,
				reminder_bitlen);
			return -1;
		}
	}
	return 0;
}

/*
 * brief	Prints the Frame Descriptor on Console
 * param[in]	struct qm_fd * Pointer to the Frame Descriptor
 * return	None
 */
void print_frame_desc(struct qm_fd *frame_desc)
{
	uint8_t *v;
	dma_addr_t addr;
	uint32_t i;

	pr_err("Frame Description at address %p\n", (void *)frame_desc);
	if (!frame_desc) {
		pr_err(" - NULL pointer\n");
	} else {
		pr_err(" - debug	: %d\n", frame_desc->dd);
		pr_err(" - bpid	: %d\n", frame_desc->bpid);
		pr_err(" - address	: 0x%04x%08x\n",
				frame_desc->addr_hi, frame_desc->addr_lo);

		switch (frame_desc->format) {
		case 0:
			pr_err(" - format		: 0"
					" - Short single buffer FD\n");
			pr_err(" - offset	: %d\n", frame_desc->offset);
			pr_err(" - length	: %d\n", frame_desc->length20);
			break;
		case 1:
			pr_err(" - format	: 1 - Compound FD\n");
			pr_err(" - congestion weight	: %d\n",
					frame_desc->cong_weight);
			break;
		case 2:
			pr_err(" - format		: 2"
					" - Long single buffer FD\n");
			pr_err(" - length	: %d\n", frame_desc->length29);
			break;
		case 4:
			pr_err
				(" - format		: 4"
					" - Short multi buffer FD\n");
			pr_err(" - offset	: %d\n", frame_desc->offset);
			pr_err(" - length	: %d\n", frame_desc->length29);
			break;
		case 6:
			pr_err(" - format		: 6"
					" - Long multi buffer FD\n");
			pr_err(" - length	: %d\n", frame_desc->length29);
			break;
		default:
			pr_err
				(" - format		: INVALID"
				 " format %d\n", frame_desc->format);
		}

		pr_err(" - status/command	: 0x%08x\n", frame_desc->cmd);

		if (frame_desc->format == qm_fd_compound) {
			struct qm_sg_entry *sgentry;

			addr = qm_fd_addr_get64(frame_desc);
			sgentry = dma_mem_ptov(addr);

			pr_err
				(" - compound FD S/G list at 0x%04x%08x\n",
				 frame_desc->addr_hi, frame_desc->addr_lo);
			pr_err("   - SG Entry\n");
			pr_err
				("	- address	0x%04x%08x\n",
				 sgentry->addr_hi, sgentry->addr_lo);

			pr_err("      - F	     %d\n", sgentry->final);
			pr_err("      - E	     %d\n",
					sgentry->extension);
			pr_err("      - length	%d\n", sgentry->length);
			pr_err("      - bpid	  %d\n", sgentry->bpid);
			pr_err("      - offset	%d\n", sgentry->offset);

			pr_err("      - Output buffer data at 0x%04x%08x\n",
					sgentry->addr_hi, sgentry->addr_lo);
			addr = qm_sg_entry_get64(sgentry);
			v = dma_mem_ptov(addr);
			for (i = 0; i < output_buf_size; i++)
				pr_err("	0x%x\n", *v++);

			sgentry++;
			pr_err("   - Next SG Entry\n");
			pr_err
				("	- address	0x%04x%08x\n",
				 sgentry->addr_hi, sgentry->addr_lo);

			pr_err("      - F	     %d\n", sgentry->final);
			pr_err("      - E	     %d\n",
					sgentry->extension);
			pr_err("      - length	%d\n", sgentry->length);
			pr_err("      - bpid	  %d\n", sgentry->bpid);
			pr_err("      - offset	%d\n", sgentry->offset);

			pr_err("      - Input buffer data at 0x%04x%08x\n",
					sgentry->addr_hi, sgentry->addr_lo);
			addr = qm_sg_entry_get64(sgentry);
			v = dma_mem_ptov(addr);
			for (i = 0; i < crypto_info->buf_size; i++)
				pr_err("	0x%x\n", *v++);
		}
	}
}

/*
 * brief	Compare encrypted data returned by SEC 4.0 with	standard
 *		cipher text
 * param[in]	None
 * return	0 on success, otherwise -ve value
 */
static int test_enc_match(void)
{
	struct qm_sg_entry *sgentry;
	uint8_t *enc_buf;
	dma_addr_t addr;

	for (ind = 0; ind < total_buf_num; ind++) {
		addr = qm_fd_addr_get64(&fd[ind]);
		sgentry = dma_mem_ptov(addr);

		addr = qm_sg_entry_get64(sgentry);
		enc_buf = dma_mem_ptov(addr);

		if (test_vector_match((uint32_t *) enc_buf,
			authnct ? (uint32_t *)
			ref_test_vector.digest : (uint32_t *)
			ref_test_vector.ciphertext,
			authnct ? output_buf_size * BITS_PER_BYTE :
			ref_test_vector.length) != 0) {
			if (!authnct)
				pr_err("%s: Encrypted frame %d with"
						" CIPHERTEXT test vector"
						" doesn't"
						" match\n" , __func__,
						ind + 1);
			else
				pr_err("%s digest match failed\n", algorithm);

			print_frame_desc(&fd[ind]);
			return -1;
		}
	}
	if (!authnct)
		pr_info("All %s encrypted frame match found with cipher text\n",
				algorithm);
	else
		pr_info("All %s digest successfully matched\n", algorithm);

	return 0;
}

/*
 * brief	Compare decrypted data returned by SEC 4.0 with plain text
 *		input data
 * param[in]	None
 * return	0 on success, otherwise -ve value
 */
static int test_dec_match(void)
{
	struct qm_sg_entry *sgentry;
	uint8_t *dec_buf;
	uint8_t plain_data = 0;
	dma_addr_t addr;
	uint32_t i;

	for (ind = 0; ind < total_buf_num; ind++) {
		markpoint(5);

		addr = qm_fd_addr_get64(&fd[ind]);
		sgentry = dma_mem_ptov(addr);

		addr = qm_sg_entry_get64(sgentry);
		dec_buf = dma_mem_ptov(addr);
		if (CIPHER == crypto_info->mode) {
			if (test_vector_match((uint32_t *) dec_buf, (uint32_t *)
						ref_test_vector.plaintext,
						ref_test_vector.length) != 0) {
				pr_err("%s: Decrypted frame %d with"
						" PLAINTEXT test vector"
						" doesn't match\n",
						__func__, ind + 1);
				print_frame_desc(&fd[ind]);
				return -1;
			}
		} else {
			for (i = 0; i < crypto_info->buf_size; i++) {
				if (dec_buf[i] != plain_data) {
					pr_err("%s: %s decrypted frame %d"
						" doesn't match!\n" , __func__,
						algorithm, ind + 1);
					print_frame_desc(&fd[ind]);
					return -1;
				}
				plain_data++;
			}
		}
	}
	pr_info("All %s decrypted frame match found with plain text\n",
			algorithm);
	return 0;
}

/*
 * brief	Enqueue frames to SEC 4.0 on Encrypt/Decrypt FQ's
 * param[in]	mode - Encrypt/Decrypt
 * return	0 on success, otherwise -ve value
 */
static void do_enqueues(enum SEC_MODE mode, thread_data_t *tdata)
{
	struct qman_fq *fq_to_sec;
	uint32_t ret;
	int i = 0;
	int fq_ind;

	do {
		if (i >= crypto_info->buf_num_per_core)
			return;

		fq_ind = i*ncpus + (tdata->cpu + MAX_THREADS - 1)%MAX_THREADS;

		if (ENCRYPT == mode)
			fq_to_sec = enc_fq_to_sec[(fq_ind) % FQ_COUNT];
		else
			fq_to_sec = dec_fq_to_sec[(fq_ind) % FQ_COUNT];

		pr_debug("%s mode: Enqueue packet ->%d\n", mode ? "Encrypt" :
				"Decrypt\n", fq_ind);

		markpoint(2);

loop:
		ret = qman_enqueue(fq_to_sec, (struct qm_fd *)&fd[fq_ind], 0);

		if (unlikely(ret)) {
			uint64_t now, then = mfatb();
			do {
				now = mfatb();
			} while (now < (then + QMAN_WAIT_CYCLES));
			goto loop;
		}

		i++;
	} while (1);
}

/*
 * brief	Enqueue Rejection Notification Handler for SEC Tx FQ
 * param[in]	msg - Message Ring entry to be processed
 * param[out]	NULL
 */
static void cb_ern(struct qman_portal *qm, struct qman_fq *fq,
		const struct qm_mr_entry *msg)
{
	pr_err("%s: RC = %x, seqnum = %x\n", __func__,\
			msg->ern.rc, msg->ern.seqnum);
	/* TODO Add handling */
	return;
}


/*
 * brief	call back handler for dequeued frames; Counts number of
 *		dequeued packets returned by SEC 4.0 on Encrypt/Decrypt FQ's
 * param[in]	mode - Encrypt/Decrypt
 * return	None
 */
enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *qm, struct qman_fq *fq,
		const struct qm_dqrr_entry *dqrr)
{
	enum SEC_MODE mode = ENCRYPT;
	struct sg_entry_priv_t *sgentry_priv;
	dma_addr_t addr;

	markpoint(3);
	if ((dqrr->fqid >= fq_base_encrypt)
			&& (dqrr->fqid < fq_base_decrpyt)) {
		atomic_inc(&enc_packet_from_sec);
	} else if ((dqrr->fqid >= fq_base_decrpyt)
			&& (dqrr->fqid < (fq_base_decrpyt + 2 * FQ_COUNT))) {
		atomic_inc(&dec_packet_from_sec);
		mode = DECRYPT;
	} else {
		pr_err("%s: Invalid Frame Queue ID Returned by SEC = %d\n",
			__func__, dqrr->fqid);
		abort();
	}

	pr_debug("%s mode: Packet dequeued ->%llu\n", mode ? "Encrypt" :
		"Decrypt", mode ? atomic_read(&enc_packet_from_sec) :
		atomic_read(&dec_packet_from_sec));

	addr = qm_fd_addr_get64(&(dqrr->fd));
	sgentry_priv = dma_mem_ptov(addr);
	fd[sgentry_priv->index].status = dqrr->fd.status;

	return qman_cb_dqrr_consume;
}

/* Poll qman DQCR for encrypted frames */
static void enc_qman_poll(void)
{
	while (atomic_read(&enc_packet_from_sec) < total_buf_num)
		qman_poll();
	return;
}

/** Poll qman DQCR for decrypted frames */
static void dec_qman_poll(void)
{
	while (atomic_read(&dec_packet_from_sec) < total_buf_num)
		qman_poll();
	return;
}

/*
 * brief	Checks if the status received in FD from CAAM block is valid
 * param[in]	Void
 * param[in]	Void
 * return	0 - if status is correct (i.e. 0)
 *		-1 - if CAAM returned an error status (i.e. non 0)
 */
static int check_fd_status()
{
	for (ind = 0; ind < total_buf_num; ind++) {
		if (fd[ind].status) {
			pr_err("Bad status return from SEC\n");
			print_frame_desc(&fd[ind]);
			return -1;
		}
	}
	return 0;
}

/* Stats */
struct crypto_msg {
	/* The CLI thread sets this !=crypto_msg_none then waits on the barrier.
	 * The worker thread checks for !=crypto_msg_none in its polling loop,
	 * performs the desired function, and sets this ==crypto_msg_none
	 * before going into the barrier (releasing itself and the CLI thread).
	 */
	volatile enum crypto_msg_type {
		crypto_msg_none = 0,
				crypto_msg_quit,
				crypto_msg_dump_if_percpu,
				crypto_msg_dump_if_all,
				crypto_msg_reset_if_percpu,
				crypto_msg_printf_foobar
	} msg;
	pthread_barrier_t barr;
	/* ifs_percpu[] is copied to this by poc_msg_dump_* */
#ifdef CONFIG_FSL_QMAN_ADAPTIVE_EQCR_THROTTLE
	u32 ci_hist[8];
	u32 throt_hist[41];
#endif
} ____cacheline_aligned;

/*
 * brief	The OPTIONS field contains a pointer to a vector of struct
 *		argp_option's
 *
 * details	structure has the following fields
 *		name - The name of this option's long option (may be zero)
 *		key - The KEY to pass to the PARSER function when parsing this
 *		option,	and the name of this option's short option, if it is
 *		a printable ascii character
 *
 *		ARG - The name of this option's argument, if any;
 *
 *		FLAGS - Flags describing this option; some of them are:
 *			OPTION_ARG_OPTIONAL - The argument to this option is
 *					      optional
 *			OPTION_ALIAS	- This option is an alias for the
 *					      previous option
 *			OPTION_HIDDEN	    - Don't show this option in
 *						--help output
 *
 *		DOC - A documentation string for this option, shown in
 *			--help output
 *
 * note		An options vector should be terminated by an option with
 *		all fields zero
 */
static struct argp_option options[] = {
	{"mode", 'm', "TEST MODE", 0, "test mode: provide following number \
		\n 1 for perf \
			\n 2 for cipher \
			\n Following two combinations are valid only \
			and all options are mandatory: \
			\n\t -m 1 -s <buf_size> -n <buf_num_per_core> \
			-o <algo> \
			-l <itr_num> \
			\n\t -m 2 -t <test_set> -n <buf_num_per_core> \
			-o <algo> \
			-l <itr_num>\n", 0},
	{"testset", 't', "TEST SET", 0, "THIS OPTION IS VALID ONLY IN \
		CIPHER MODE \
			\n\t provide following test set number:- \
			\n\t test set for AES_CBC is 1 to 4 \
			\n\t test set for TDES_CBC is 1 to 2 \
			\n\t test set for SNOW_F8 is 1 to 5 \
			\n\t test set for SNOW_F9 is 1 to 5 \
			\n\t test set for KASUMI_F8 is 1 to 5 \
			\n\t test set for KASUMI_F9 is 1 to 5 \
			\n\t test set for CRC is 1 to 5 \
			\n\t test set for HMAC_SHA1 is 1 to 2 \
			\n\t test set for SNOW_F8_F9 is 1 to 1\n",
	0},
	{"bufsize", 's', "BUFFER SIZE", 0,
		"THIS OPTION IS VALID ONLY IN PERF MODE \
		\n\t Buffer size (64, 128 ...upto 6400) \
		\n\t For AES_CBC buffer size should be 16 byte aligned \
		\n\t For TDES_CBC buffer size should be 8 byte aligned\n",
	0},
	{"bufnum", 'n', "NUMBER OF BUFFERS per core", 0,
		"Number of buffers per core (1 to 800)\n", 0},
	{"itrnum", 'l', "NUMBER OF ITERATIONS", 0,
		"Number of iteration to repeat\n", 0},
	{"algo", 'o', "SEC 4.0 ALGORITHM", 0,
		"Cryptographic operation, provide following number \
			\n\t 1 for AES_CBC \
			\n\t 2 for TDES_CBC \
			\n\t 3 for SNOW_F8 \
			\n\t 4 for SNOW_F9 \
			\n\t 5 for KASUMI_F8 \
			\n\t 6 for KASUMI_F9 \
			\n\t 7 for CRC \
			\n\t 8 for HMAC_SHA1\
			\n\t 9 for SNOW_F8_F9", 0},
		{"ncpus", 'c', "NUMBER OF CPUS", 0,
			"Number of cpus to work for the \
			application (1 to 8) \n", 0},
		{0, 0, 0, 0, 0, 0}
};


/*
 * brief	Parse a single option
 *
 * param[in]	key - An integer specifying which option this is (taken	from
 *		the KEY field in each struct argp_option), or a special key
 *		specifying something else. We do not use any special key here
 *
 * param[in]	arg - For an option KEY, the string value of its argument, or
 *		NULL if it has none
 *
 * param[in]	state - A pointer to a struct argp_state, containing various
 *		useful information about the parsing state; used here are the
 *		INPUT field, which reflects the INPUT argument to argp_parse
 *
 * return	It should return either 0, meaning success, ARGP_ERR_UNKNOWN,
 *		meaning the given KEY wasn't recognized, or an errno value
 *		indicating some other error
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'm':
		crypto_info->mode = atoi(arg);
		g_cmd_params |= BMASK_SEC_TEST_MODE;
		pr_info("Test mode = %s\n", arg);
		break;

	case 't':
		crypto_info->test_set = atoi(arg);
		g_cmd_params |= BMASK_SEC_TEST_SET;
		pr_info("Test set = %d\n", crypto_info->test_set);
		break;

	case 's':
		crypto_info->buf_size = atoi(arg);
		g_cmd_params |= BMASK_SEC_BUFFER_SIZE;
		pr_info("Buffer size = %d\n", crypto_info->buf_size);
		break;

	case 'n':
		crypto_info->buf_num_per_core = atoi(arg);
		g_cmd_params |= BMASK_SEC_BUFFER_NUM;
		pr_info("Number of Buffers per core = %d\n",
				crypto_info->buf_num_per_core);
		break;

	case 'o':
		crypto_info->algo = atoi(arg);
		g_cmd_params |= BMASK_SEC_ALG;
		pr_info("SEC4.0 cryptographic operation = %s\n", arg);
		break;

	case 'l':
		crypto_info->itr_num = atoi(arg);
		g_cmd_params |= BMASK_SEC_ITR_NUM;
		pr_info("Number of iteration = %d\n", crypto_info->itr_num);
		break;

	case 'c':
		ncpus = atoi(arg);
		pr_info("Number of cpus = %ld\n", ncpus);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int validate_test_set(void)
{
	switch (crypto_info->algo) {
	case AES_CBC:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 5)
			return 0;
		else
			goto err;
	case TDES_CBC:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 3)
			return 0;
		else
			goto err;
	case SNOW_F8:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 6)
			return 0;
		else
			goto err;
	case SNOW_F9:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 6)
			return 0;
		else
			goto err;
	case KASUMI_F8:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 6)
			return 0;
		else
			goto err;
	case KASUMI_F9:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 6)
			return 0;
		else
			goto err;
	case CRC:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 6)
			return 0;
		else
			goto err;
	case HMAC_SHA1:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 3)
			return 0;
		else
			goto err;
	case SNOW_F8_F9:
		if (crypto_info->test_set > 0 &&
			crypto_info->test_set < 2)
			return 0;
		else
			goto err;
	default:
		pr_err("Invalid Parameters: Invalid SEC algorithm\n");
		return -EINVAL;
	}
err:
	pr_err("Invalid Parameters: Test set number is invalid\n");
	return -EINVAL;
}

/*
 * brief	Check SEC 4.0 parameters provided by user whether valid or not
 * param[in]	g_cmd_params - Bit mask of all parameters provided by user
 * return	0 on success, otherwise -ve value
 */
static int validate_params(void)
{
	if (!crypto_info) {
		pr_err("Crypto Info is NULL\n");
		return -EINVAL;
	}

	if ((PERF == crypto_info->mode)
			&& BMASK_SEC_PERF_MODE == g_cmd_params) {
		/* do nothing */
	} else if ((CIPHER == crypto_info->mode)
			&& g_cmd_params == BMASK_SEC_CIPHER_MODE) {
		if (validate_test_set() != 0) {
			pr_err("Invalid Parameters: Invalid test set\n");
			return -EINVAL;
		}
	} else {
		pr_err
			("Invalid Parameters: provide a valid combination"
			 " of mandatory arguments see --help option\n"
			 " g_cmd_params = %0x\n", g_cmd_params);
		return -EINVAL;
	}

	if (crypto_info->buf_num_per_core == 0 ||
		crypto_info->buf_num_per_core > BUFF_NUM_PER_CORE) {
		pr_err("Invalid Parameters: Invalid number of buffers "
				"see --help option\n");
		return -EINVAL;
	}

	if (crypto_info->buf_size == 0 || crypto_info->buf_size % 64 != 0
			|| crypto_info->buf_size > BUFF_SIZE) {
		pr_err("Invalid Parameters: Invalid number of buffers "
				"see --help option\n");
		return -EINVAL;
	}

	switch (crypto_info->algo) {
	case AES_CBC:
	case TDES_CBC:
	case SNOW_F8:
	case SNOW_F9:
	case KASUMI_F8:
	case KASUMI_F9:
	case CRC:
	case HMAC_SHA1:
	case SNOW_F8_F9:
		break;
	default:
		pr_err("Invalid Parameters: SEC algorithm not supported\n");
		return -EINVAL;
	}

	return 0;
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
	}
}

static pthread_barrier_t app_barrier;

/* This is not actually necessary, the threads can just start up without any
 * ordering requirement. The first cpu will initialise the interfaces before
 * enabling the MACs, and cpus/portals can come online in any order. On
 * simulation however, the initialising thread/cpu *crawls* because the
 * simulator spends most of its time simulating the other cpus in their tight
 * polling loops, whereas having those threads suspended in a barrier allows
 * the simulator to focus on the cpu doing the initialisation. On h/w this is
 * harmless but of no benefit. */

static int worker_fn(thread_data_t *tdata)
{
	int i = 1;
	int iterations = crypto_info->itr_num;
	/* Counters to record time */
	uint64_t atb_start_enc=0;
	uint64_t atb_start_dec=0;

	pr_debug("\nThis is the thread on cpu %d\n", tdata->cpu);

	if (!tdata->index) {
		if (unlikely(init_sec_fq() != 0)) {
			pr_err("%s: init_sec_fq() failure\n", __func__);
			abort();
		}
	}

	qman_static_dequeue_add(QM_SDQCR_CHANNELS_POOL(pool_channel_offset));

	while (iterations) {
		/* Set encryption buffer */
		if (!tdata->index) {
			if (crypto_info->itr_num < ONE_MEGA) {
				pr_info("Iteration %d started\n", i);
			} else {
				if (1 == (i % ONE_MEGA/10))
					pr_info("Iteration %d started."
							" working....\n", i);
			}
			set_enc_buf();
			atomic_set(&enc_packet_from_sec, 0);
		}

		if (EINVAL == pthread_barrier_wait(&app_barrier)) {
			pr_err("Encrypt mode: pthread_barrier_wait failed"
					"before enqueue\n");
			abort();
		}

		if (!tdata->index)
			/* encrypt mode: start time */
			atb_start_enc = mfatb();

		/* Send data to SEC40 for encryption/authentication */
		do_enqueues(ENCRYPT, tdata);

		if (!tdata->index)
			pr_debug("Encrypt mode: Total packet sent"
				 " to SEC = %lu\n", total_buf_num);

		/* Recieve encrypted or MAC data from SEC40 */
		enc_qman_poll();
		if (!tdata->index)
			pr_debug("Encrypt mode: Total packet returned from"
					" SEC = %lu\n", atomic_read
					(&enc_packet_from_sec));

		if (!tdata->index)
			/* accumulated time difference */
			enc_delta += (mfatb() - atb_start_enc);

		if (!tdata->index) {
			/* Test ciphertext or MAC generated by SEC40 */
			if (CIPHER == crypto_info->mode) {
				if (unlikely(check_fd_status() != 0)) {
					ctrl_error = 1;
					goto error2;
				}
				if (unlikely(test_enc_match() != 0)) {
					ctrl_error = 1;
					goto error2;
				}
			}

			/* Set decryption buffer */
			if (SNOW_F8_F9 == crypto_info->algo)
				set_dec_auth_buf();
			else if (!authnct)
				set_dec_buf();
			atomic_set(&dec_packet_from_sec, 0);
		}
error2:
		if (EINVAL == pthread_barrier_wait(&app_barrier)) {
			pr_err("Decrypt mode: pthread_barrier_wait failed"
					" before enqueue\n");
			abort();
		}

		if (ctrl_error)
			goto err_free_fq;

		if (authnct)
			goto result;

		if (!tdata->index)
			/* decrypt mode: start time */
			atb_start_dec = mfatb();

		/* Send data to SEC40 for decryption */
		do_enqueues(DECRYPT, tdata);

		if (!tdata->index)
			pr_debug("Decrypt mode: Total packet sent"
				 " to SEC = %lu\n", total_buf_num);

		/* Recieve decrypted data from SEC40 */
		dec_qman_poll();

		if (!tdata->index)
			pr_debug("Decrypt mode: Total packet returned from"
					" SEC = %lu\n", atomic_read
					(&dec_packet_from_sec));

		if (!tdata->index)
			/* accumulated time difference */
			dec_delta += (mfatb() - atb_start_dec);

		/* Test decrypted data with original plaintext */
		if (!tdata->index) {
			if (CIPHER == crypto_info->mode) {
				if (unlikely(check_fd_status() != 0)) {
					ctrl_error = 1;
					goto error2;
				}
			}
			if (unlikely(test_dec_match() != 0)) {
				ctrl_error = 1;
				goto error3;
			}
		}
error3:
		if (EINVAL == pthread_barrier_wait(&app_barrier)) {
			pr_err("pthread_barrier_wait failed after"
					" test_dec_match\n");
			abort();
		}

		if (ctrl_error)
			goto err_free_fq;

result:
		if (!tdata->index) {
			if (ONE_MEGA > crypto_info->itr_num) {
				pr_info("Iteration %d finished\n", i);
			} else {
				if (1 == (i % ONE_MEGA/10))
					pr_info("Iteration %d finished."
							" working....\n", i);
			}
		}

		iterations--;
		i++;
	}

err_free_fq:
	if (!tdata->index) {
		if (unlikely(free_sec_fq() != 0)) {
			pr_err("%s: free_sec_fq failed\n", __func__);
			abort();
		}
	}

	qman_static_dequeue_del(QM_SDQCR_CHANNELS_POOL(pool_channel_offset));

	calm_down();
	pr_debug("Leaving thread on cpu %d\n", tdata->cpu);
	return 0;
}

/* argp structure itself of argp parser */
static struct argp argp = { options, parse_opt, NULL, NULL, NULL, NULL, NULL };

/*
 * brief	Main function of SEC 4.0 Test Application
 * param[in]	argc - Argument count
 * param[in]	argv - Argument list pointer
 */
int main(int argc, char *argv[])
{
	thread_data_t thread_data[MAX_THREADS];
	struct crypto_msg appdata[MAX_THREADS];
	int loop;
	uint16_t enc_cycles_per_frame = 0;
	uint16_t dec_cycles_per_frame = 0;
	uint64_t cpu_freq;
	FILE *p_cpuinfo;
	char buf[255], cpu_f[20];

	pr_info("\nWelcome to FSL SEC 4.0 application!\n");

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	/* set default value 0 to crypto_param */
	crypto_info = malloc(sizeof(struct crypto_param));
	if (!crypto_info) {
		pr_err("Unable to get Crypto Info Buffer\n");
		exit(-ENOMEM);
	}

	/* Where the magic happens */
	argp_parse(&argp, argc, argv, 0, 0, crypto_info);

	if (validate_params() != 0) {
		pr_err("\nERROR: validate_params failed!\n");
		exit(-EINVAL);
	}

	/* Get the number of cores */
	if (ncpus < 1 && ncpus > 8) {
		pr_err("Invalid Parameters: Pass valid number of"
				" cpus (1 to 8)\n");
		exit(-EINVAL);
	}

	/*
	 * If number of active cpu's are less than required by user
	 * (with -c parameter)
	 */
	if (ncpus > sysconf(_SC_NPROCESSORS_ONLN)) {
		pr_err("Invalid Parameters: Number of cpu's given in"
				" argument is more than the active cpu's\n");
		exit(-EINVAL);
	}

	/* map shmem */
	if (unlikely(dma_mem_setup())) {
		pr_err("Shared memory initialization failed\n");
		exit(EXIT_FAILURE);
	}

	/* Create the threads */
	for (loop = 0; loop < ncpus; loop++) {
		struct crypto_msg *msg = &appdata[loop];
		memset(msg, 0, sizeof(*msg));
		pthread_barrier_init(&msg->barr, NULL, 2);
		thread_data[loop].appdata = msg;
	}

	/* Initialize barrier for all the threads! */
	if (unlikely(pthread_barrier_init(&app_barrier, NULL, ncpus))) {
		pr_err("unable to initialize pthread_barrier");
		exit(EXIT_FAILURE);
	}

	/* Store the number of bytes for the job descriptor.
	 * The SNOW_JDESC_ENC_F8_F9_LEN and SNOW_JDESC_DEC_F8_F9_LEN macros
	 * return the length in 32 bit words.
	 * Calculate the maximum between the encrypt and decrypt descriptors
	 * because the same compound FD will be used for both processes, so
	 * will allocate the memory area that can hold both descriptors.
	 */
	job_desc_buf_size = MAX(SNOW_JDESC_ENC_F8_F9_LEN,
			SNOW_JDESC_DEC_F8_F9_LEN);

	/* Read cpu frequency from /poc/cpuinfo */
	p_cpuinfo = fopen("/proc/cpuinfo", "rb");

	if (NULL == p_cpuinfo) {
		pr_err("ERROR opening file /proc/cpuinfo");
	} else {
		while (fgets(buf, 255, p_cpuinfo)) {
			if (strstr(buf, "clock")) {
				strncpy(cpu_f, &buf[9], 20);
				break;
			}
		}
	}

	cpu_freq = strtoul(cpu_f, NULL, 10); /* cpu_freq in MHz */
	if (ERANGE == errno || EINVAL == errno) {
		pr_err("could not read cpu frequency from /proc/cpuinfo\n");
		exit(EXIT_FAILURE);
	}

	/* TODO get pool_channel_offset through API */
	pool_channel_offset = 9;

	/* Calculate total number of buffers */
	total_buf_num = crypto_info->buf_num_per_core * ncpus;

	if (PERF == crypto_info->mode) {
		strcpy(mode_type, "PERF");
		crypto_info->test_set = 1;
	}

	init_ref_test_vector[crypto_info->algo - 1]();

	if (CIPHER == crypto_info->mode) {
		strcpy(mode_type, "CIPHER");
		crypto_info->buf_size =
			NO_OF_BYTES(ref_test_vector.length);
	}

	if (unlikely(create_compound_fd() != 0)) {
		pr_err("%s: create_compound_fd() failed!\n",
				__func__);
		exit(EXIT_FAILURE);
	}

	pr_info("Processing %s for %d Frames\n", algorithm, total_buf_num);
	pr_info("%s mode, buffer length = %d\n", mode_type,
			crypto_info->buf_size);
	pr_info("Number of iterations = %d\n", crypto_info->itr_num);
	pr_info("\nStarting threads for %ld cpus\n", ncpus);

	/* Starting threads on all active cpus */
	if (unlikely(start_threads(thread_data, ncpus,
					1, worker_fn))) {
		pr_err("start_threads failiure");
		exit(EXIT_FAILURE);
	}

	/* Wait for all the threads to finish */
	wait_threads(thread_data, ncpus);

	if (!ctrl_error) {
		enc_cycles_per_frame = (enc_delta) /
			(crypto_info->itr_num * total_buf_num);

		pr_info("%s: Throughput = %"PRIu64" Mbps\n",
			 authnct ? "Authenticate" : "Encrypt",
				(cpu_freq * BITS_PER_BYTE *
				crypto_info->buf_size) /
				enc_cycles_per_frame);

		if (!authnct) {
			dec_cycles_per_frame = (dec_delta) /
				(crypto_info->itr_num * total_buf_num);

			pr_info("%s: Throughput = %"PRIu64" Mbps\n",
				"Decrypt", (cpu_freq * BITS_PER_BYTE *
				crypto_info->buf_size) / dec_cycles_per_frame);
		}
		pr_info("SEC 4.0 TEST PASSED\n");
	} else {
		pr_info("TEST FAILED\n");
	}

	free_fd();
	markpoint(31);
	exit(EXIT_SUCCESS);
}
