/**
\file  simple_crypto.h
\brief Common datatypes, hash-defines of SEC 4.0_TEST Application
*/
/*
 * Copyright (C) 2011 Freescale Semiconductor, Inc.
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

#ifndef __SIMPLE_CRYPTO_H
#define __SIMPLE_CRYPTO_H

#include "compat.h"
#include <errno.h>
#include <stdbool.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include "fsl_sec/dcl.h"

#define INV_LWE_ID	255	/* Invalid LWE core ID */
#define SEC40_FQ_BASE	9000	/* start of FQ number for encryption FQ */
#define FQ_COUNT	6	/* Number of flows for encryption
				   as well as decryption */

#define	OUT_FRAME_INDEX	0	/* ouput frame index used to prepare
				   compound frame */
#define	IN_FRAME_INDEX	1	/* input frame index used to prepare
				   compound frame */

#define	HMAC_SHA1_DIGEST_SIZE	20	/* HMAC-SHA1 digest length(in bytes) */
/* SNOW 3G F9 MAC is generated in the context double word 0 with the MAC/ICV.
 * Since MAC is a 32-bit value, it is written to low-order bit locations
 * (right-justified) and the remaining bits are zeroized. Therefore, consider-
 * ing high-order 32-bit vaule as ZERO MAC size is taken as 8 bytes.
 */
#define	SNOW_F9_DIGEST_SIZE	4	/* SNOW-F9 digest length(bytes) */
#define	KASUMI_F9_DIGEST_SIZE	4	/* KASUMI-F9 digest length(bytes) */
#define	CRC_DIGEST_SIZE		8	/* CRC digest length(bytes) */

enum SEC_MODE { DECRYPT, ENCRYPT };

struct preheader_s {
	union {
		uint32_t word;
		struct {
			uint16_t rsvd63_48;
			unsigned int rsvd47_39:9;
			unsigned int idlen:7;
		} field;
	} __packed hi;

	union {
		uint32_t word;
		struct {
			unsigned int rsvd31_30:2;
			unsigned int fsgt:1;
			unsigned int lng:1;
			unsigned int offset:2;
			unsigned int abs:1;
			unsigned int add_buf:1;
			uint8_t pool_id;
			uint16_t pool_buffer_size;
		} field;
	} __packed lo;
} __packed;

struct init_descriptor_header_s {
	union {
		uint32_t word;
		struct {
			unsigned int ctype:5;
			unsigned int rsvd26_25:2;
			unsigned int dnr:1;
			unsigned int one:1;
			unsigned int start_idx:7;
			unsigned int zro:1;
			unsigned int rsvd14_12:3;
			unsigned int propogate_dnr:1;
			unsigned int share:3;
			unsigned int rsvd7:1;
			unsigned int desc_len:7;
		} field;
	} __packed command;
} __packed;

struct key_command_s {
	union {
		uint32_t word;
		struct {
			unsigned int ctype:5;
			unsigned int cls:2;
			unsigned int sgf:1;
			unsigned int imm:1;
			unsigned int enc:1;
			unsigned int rsvd21_18:4;
			unsigned int kdest:2;
			unsigned int rsvd15_10:6;
			unsigned int length:10;
		} field;
	} __packed command;
} __packed;

struct algorithm_operation_command_s {
	union {
		uint32_t word;
		struct {
			unsigned int ctype:5;
			unsigned int optype:3;
			uint8_t alg;
			unsigned int rsvd16_18:3;
			unsigned int aai:9;
			unsigned int as:2;
			unsigned int icv:1;
			unsigned int enc:1;
		} field;
	} __packed command;
} __packed;

/** SEC4.0 shared descriptor consist of commands that are executed in sequence.
 *  It is used to tell SEC 4.0 what to do.
 */
struct sec_descriptor_t {
	struct preheader_s prehdr;
	struct init_descriptor_header_s deschdr;
	struct key_command_s keycmd;
	uint32_t key[6];
	struct algorithm_operation_command_s opcmd;
	uint32_t rsv[15];	/* TODO: fill it for iv, LOAD, MATH,
				   FIFO LOAD etc. */
};

enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *qm, struct qman_fq *fq,
				 const struct qm_dqrr_entry *dqrr);

struct sg_entry_priv_t {
	struct qm_sg_entry sgentry[2];
	uint32_t index;
	uint32_t reserved[7];
} __packed;

void cb_fqs(struct qman_portal *qm, struct qman_fq *fq,
	    const struct qm_mr_entry *msg);

static int check_fd_status(void);

#define BMASK_SEC_TEST_MODE	0x00000001	/**< Bit mask for test Mode */
#define BMASK_SEC_TEST_SET	0x00000010	/**< Bit mask for test set */
#define BMASK_SEC_BUFFER_SIZE	0x00000100	/**< Bit mask for buffer size */
#define BMASK_SEC_BUFFER_NUM	0x00001000	/**< Bit mask for number of buffers */
#define BMASK_SEC_ALG		0x00010000	/**< Bit mask for SEC algo */
#define BMASK_SEC_ITR_NUM	0x00100000	/**< Bit mask for number of iteration */
#define BMASK_SEC_PERF_MODE	0x00111101	/**< valid combination in perf mode */
#define BMASK_SEC_CIPHER_MODE	0x00111011	/**< valid combination in cipher mode */

#define BUFF_NUM_PER_CORE	800	/**< Maximum number of buffers can be
						provided by user */
#define BUFF_SIZE               6400    /**< Maximum buffer size that can be
						provided by user */

/*
 * CIPHER test mode compare ciphertext generated by SEC4.0 whereas it has been
 * skipped in PERF test mode
 */
enum test_mode {
	PERF = 1,
	CIPHER
};

/* SEC4.0 cryptographic raw algorithm supported in the application */
enum sec_algo {
	AES_CBC = 1,
	TDES_CBC,
	SNOW_F8,
	SNOW_F9,
	KASUMI_F8,
	KASUMI_F9,
	CRC,
	HMAC_SHA1,
	SNOW_F8_F9
};

/*
 * This structure is for the user defined SEC parameters
 * given as CLI arguments
 */
struct crypto_param {
	enum test_mode mode;		/**< test mode */
	unsigned int test_set;		/**< test set number */
	unsigned int buf_size;		/**< buffer size */
	unsigned int buf_num_per_core;	/**< total number of buffers, max = 5000 */
	unsigned int itr_num;		/**< number of iteration to repeat SEC operation */
	enum sec_algo algo;		/**< SEC operation to perform */
	bool valid_params;		/**< valid parameters flag*/
};

#endif /* __SIMPLE_CRYPTO_H */
