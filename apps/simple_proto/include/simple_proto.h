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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __SIMPLE_PROTO_H
#define __SIMPLE_PROTO_H

#include <argp.h>
#include <inttypes.h>

#include <flib/rta.h>
#include <flib/desc.h>
#include <flib/protoshared.h>

#include <crypto/test_utils.h>
#include <crypto/sec.h>
#include <crypto/thread_priv.h>
#include <crypto/qman.h>

#include "test_vector.h"

/**
 * @def PDCP_CPLANE_TEST_ARRAY_OFFSET
 * @brief The following macro computes the index in the PDCP test vectors array
 * for control plane processing by using the following property of the
 * test array: for each ciphering algorithm, the various parameters that
 * can be given by the user are indexed by their actual values.
 * In short, this macro uses the linear property of the test vectors arrray.
 */
#define PDCP_CPLANE_TEST_ARRAY_OFFSET(crypto_info)		\
	(PDCP_CPLANE_OFFSET +					\
	((crypto_info)->proto_params.pdcp_params.cipher_alg *	\
	PDCP_AUTH_TYPE_INVALID * PDCP_DIR_INVALID +		\
	(crypto_info)->proto_params.pdcp_params.integrity_alg *	\
	PDCP_DIR_INVALID +					\
	(crypto_info)->proto_params.pdcp_params.downlink))

/**
 * @def PDCP_UPLANE_TEST_ARRAY_OFFSET
 * @brief The following macro computes the index in the PDCP test vectors array
 * for user plane processing by using the following property of the
 * test array: for each ciphering algorithm, the various parameters that
 * can be given by the user are indexed by their actual values.
 * In short, this macro uses the linear property of the test vectors arrray.
 */
#define PDCP_UPLANE_TEST_ARRAY_OFFSET(crypto_info)		\
	(PDCP_UPLANE_OFFSET +					\
	(crypto_info)->proto_params.pdcp_params.cipher_alg *	\
	2 * PDCP_DIR_INVALID +					\
	(crypto_info)->proto_params.pdcp_params.short_sn *	\
	PDCP_DIR_INVALID +					\
	(crypto_info)->proto_params.pdcp_params.downlink)

/**
 * @def PDCP_SHORT_MAC_TEST_ARRAY_OFFSET
 * @brief The following macro computes the index in the PDCP test vectors array
 * for Short MAC processing by using the following property of the
 * test array: for each integrity algorithm, the various parameters that
 * can be given by the user are indexed by their actual values.
 * In short, this macro uses the linear property of the test vectors arrray.
 */
#define PDCP_SHORT_MAC_TEST_ARRAY_OFFSET(crypto_info)		\
	(PDCP_SHORT_MAC_OFFSET +				\
	(crypto_info)->proto_params.pdcp_params.integrity_alg)

/**
 * WiMax parameter options specific defines
 */
#define BMASK_WIMAX_OFDMA_EN	0x80000000	/**< Enable OFDMa processing */
#define BMASK_WIMAX_FCS_EN	0x40000000	/**< Enable FCS in WiMax */
#define BMASK_WIMAX_AR_EN	0x20000000	/**< Enable AR in WiMax */

/**
 * PDCP parameter options specific defines
 */

#define	BMASK_PDCP_TYPE		0x80000000	/**< Type selected for PDCP */
#define	BMASK_PDCP_CIPHER	0x40000000	/**< Cipher seleced for PDCP */
#define	BMASK_PDCP_INTEGRITY	0x20000000	/**< Integrity selected for
						     PDCP */
#define	BMASK_PDCP_DIR_DL	0x10000000	/**< Downlink selected for
						     PDCP */
#define	BMASK_PDCP_SNS		0x08000000	/**< Short sequence number
						     selected for PDCP */

#define BMASK_PDCP_CPLANE_VALID	(BMASK_PDCP_TYPE | \
				 BMASK_PDCP_CIPHER | \
				 BMASK_PDCP_INTEGRITY)
#define BMASK_PDCP_UPLANE_VALID	(BMASK_PDCP_TYPE | BMASK_PDCP_CIPHER)
#define BMASK_PDCP_SHORT_MAC_VALID \
				(BMASK_PDCP_TYPE | BMASK_PDCP_INTEGRITY)

/**
 * @enum	sec_proto
 * @details	SEC security protocols supported in the application
 */
enum sec_proto {
	MACSEC = 1,
	WIMAX,
	PDCP
};

/**
 * @struct	runtime_param
 * @details	Structure used for the user defined SEC parameters
 *		given as CLI arguments
 */
struct runtime_param {
	uint32_t output_buf_size;
	uint32_t input_buf_capacity;
	uint32_t input_buf_length;
	uint32_t job_desc_buf_size;
};

struct macsec_params {};

struct wimax_params {
	bool ofdma;
	bool fcs;
	bool ar;
	int ar_len;
};

struct pdcp_params {
	enum pdcp_plane type;
	enum cipher_type_pdcp cipher_alg;
	enum auth_type_pdcp integrity_alg;
	bool downlink;
	bool short_sn;
};

union proto_params {
	struct macsec_params macsec_params;
	struct wimax_params wimax_params;
	struct pdcp_params pdcp_params;
};

/**
 * @struct	test_param
 * @details	Structure used to hold parameters for test
 */
struct test_param {
	enum test_mode mode;	/**< test mode */
	unsigned int test_set;	/**< test set number */
	unsigned int buf_size;	/**< buffer size */
	unsigned int buf_num;	/**< total number of buffers, max = 5000 */
	unsigned int itr_num;	/**< number of iteration to repeat SEC
				     operation */
	enum sec_proto proto;	/**< SEC operation to perform */
	union proto_params proto_params; /**< Protocol specific parameters */
	struct runtime_param rt;/**< runtime parameter */
	void (*set_enc_buf_cb)(struct qm_fd *, uint8_t*, struct test_param *);
				/**< callback used for setting per-protocol
				     parameters on the encap direction */
	void (*set_dec_buf_cb)(struct qm_fd *, uint8_t*, struct test_param *);
				/**< callback used for setting per-protocol
				     parameters on the decap direction */
	int (*test_enc_match_cb)(int, uint8_t*, struct test_param *);
				/**< callback used for validating the encap
				     result (per protocol) */
	int (*test_dec_match_cb)(int, uint8_t*, struct test_param *);
				/**< callback used for validating the encap
				     result (per protocol) */
	void (*test_cleanup)(struct test_param *);
				/**< callback used for cleaning up the resources
				     that were allocated during the test-run */
};

struct parse_input_t {
	uint32_t *cmd_params;
	uint32_t *proto_params;	/**< protocol specific parameters */
	struct test_param *crypto_info;
};


char mode_type[20];		/* string corresponding to integral value */
char protocol[100];		/* string corresponding to integral value */

/* init reference test vector routines */
void init_rtv_macsec_gcm_128(struct test_param *crypto_info);
void init_rtv_wimax_aes_ccm_128(struct test_param *crypto_info);
void init_rtv_wimax_cipher(uint test_set);
void init_rtv_pdcp(struct test_param *crypto_info);
void init_rtv_pdcp_c_plane(struct test_param *crypto_info);
void init_rtv_pdcp_u_plane(struct test_param *crypto_info);
void init_rtv_pdcp_short_mac(struct test_param *crypto_info);

/* test cleanup routines */
void test_cleanup_wimax(struct test_param *crypto_info);

/* prepare test buffers, fqs, fds routines */
void macsec_set_pn_constant(uint32_t *shared_desc, unsigned *shared_desc_len);
static void *setup_sec_descriptor(bool mode, void *params);
static void *setup_init_descriptor(bool mode, struct test_param *crypto_info);
static int set_buf_size(struct test_param *crypto_info);
int prepare_test_frames(struct test_param *crypto_info);
void set_enc_buf(void *params, struct qm_fd fd[]);
void set_dec_buf(void *params, struct qm_fd fd[]);

/* validate test routines */
static int validate_test_set(struct test_param *crypto_info);
static int validate_sec_era_version(void);
static int validate_params(uint32_t cmd_args, uint32_t proto_args,
			   struct test_param *crypto_info);
static int validate_macsec_opts(uint32_t g_proto_params,
				struct test_param *crypto_info);
static int validate_wimax_opts(uint32_t g_proto_params,
				struct test_param *crypto_info);
static int validate_pdcp_opts(uint32_t g_proto_params,
				struct test_param *crypto_info);
int test_enc_match(void *params, struct qm_fd fd[]);
int test_dec_match(void *params, struct qm_fd fd[]);
int test_enc_match_cb_wimax(int fd_ind, uint8_t *enc_buf,
			    struct test_param *crypto_info);
int test_dec_match_cb_wimax(int fd_ind, uint8_t *enc_buf,
			    struct test_param *crypto_info);
error_t parse_opt(int opt, char *arg, struct argp_state *state);
int (*validate_proto_opts[])(uint32_t, struct test_param*) = {
		NULL,
		validate_macsec_opts,
		validate_wimax_opts,
		validate_pdcp_opts
};

/* helper routines */
static void set_crypto_cbs(struct test_cb *crypto_cb);
int get_num_of_iterations(void *params);
inline int get_num_of_buffers(void *params);
inline enum test_mode get_test_mode(void *params);
inline uint8_t requires_authentication(void);
inline long get_num_of_cpus(void);
inline pthread_barrier_t get_thread_barrier(void);

#endif /* __SIMPLE_PROTO_H */
