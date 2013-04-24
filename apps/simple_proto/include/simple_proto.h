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

#define PDCP_MAP_PROTO_TO_ARRAY(x)	\
	((x) - PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_UL)

/**
 * @enum	sec_proto
 * @details	SEC security protocols supported in the application
 */
enum sec_proto {
	MACSEC = 1,
	WIMAX,
	PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_UL,
	PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_DL,
	PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_UL,
	PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_DL,
	PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_DL,
	PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_UL,
	PDCP_CTRL_PLANE_ZUC_E_ZUC_I_DL,
	PDCP_CTRL_PLANE_ZUC_E_ZUC_I_UL,
	PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_DL,
	PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_UL,
	PDCP_CTRL_PLANE_SNOW_F8_NULL_DL,
	PDCP_CTRL_PLANE_SNOW_F8_NULL_UL,
	PDCP_CTRL_PLANE_AES_CTR_NULL_DL,
	PDCP_CTRL_PLANE_AES_CTR_NULL_UL,
	PDCP_CTRL_PLANE_ZUC_E_NULL_DL,
	PDCP_CTRL_PLANE_ZUC_E_NULL_UL,
	PDCP_CTRL_PLANE_NULL_SNOW_F9_DL,
	PDCP_CTRL_PLANE_NULL_SNOW_F9_UL,
	PDCP_CTRL_PLANE_NULL_AES_CMAC_DL,
	PDCP_CTRL_PLANE_NULL_AES_CMAC_UL,
	PDCP_CTRL_PLANE_NULL_ZUC_I_DL,
	PDCP_CTRL_PLANE_NULL_ZUC_I_UL,
	PDCP_CTRL_PLANE_NULL_NULL_UL,
	PDCP_USER_PLANE_AES_CTR_UL_LONG_SN,
	PDCP_USER_PLANE_AES_CTR_DL_LONG_SN,
	PDCP_USER_PLANE_AES_CTR_UL_SHORT_SN,
	PDCP_USER_PLANE_AES_CTR_DL_SHORT_SN,
	PDCP_USER_PLANE_SNOW_F8_UL_LONG_SN,
	PDCP_USER_PLANE_SNOW_F8_DL_LONG_SN,
	PDCP_USER_PLANE_SNOW_F8_UL_SHORT_SN,
	PDCP_USER_PLANE_SNOW_F8_DL_SHORT_SN,
	PDCP_USER_PLANE_ZUC_E_UL_LONG_SN,
	PDCP_USER_PLANE_ZUC_E_DL_LONG_SN,
	PDCP_USER_PLANE_ZUC_E_UL_SHORT_SN,
	PDCP_USER_PLANE_ZUC_E_DL_SHORT_SN,
	PDCP_USER_PLANE_NULL_DL_LONG_SN,
	PDCP_USER_PLANE_NULL_DL_SHORT_SN,
	PDCP_SHORT_MAC_SNOW_F9,
	PDCP_SHORT_MAC_AES_CMAC,
	PDCP_SHORT_MAC_ZUC_I,
	PDCP_SHORT_MAC_NULL
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
	struct runtime_param rt;/**< runtime parameter */
	bool valid_params;	/**< valid parameters flag */
};

struct parse_input_t {
	uint32_t *cmd_params;
	struct test_param *crypto_info;
};

char mode_type[20];		/* string corresponding to integral value */
char protocol[20];		/* string corresponding to integral value */

/* init reference test vector routines */
void init_rtv_macsec_gcm_128(struct test_param *crypto_info);
void init_rtv_wimax_aes_ccm_128(struct test_param *crypto_info);
void init_rtv_wimax_cipher(uint test_set);

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
static int validate_params(uint32_t cmd_args, struct test_param *crypto_info);
static int validate_opt_param(struct test_param *crypto_info,
			      uint32_t *g_cmd_params, uint32_t param);
int test_enc_match(void *params, struct qm_fd fd[]);
int test_dec_match(void *params, struct qm_fd fd[]);
error_t parse_opt(int opt, char *arg, struct argp_state *state);

/* helper routines */
static void set_crypto_cbs(struct test_cb *crypto_cb);
int get_num_of_iterations(void *params);
inline int get_num_of_buffers(void *params);
inline enum test_mode get_test_mode(void *params);
inline uint8_t requires_authentication(void);
inline long get_num_of_cpus(void);
inline pthread_barrier_t get_thread_barrier(void);

#endif /* __SIMPLE_PROTO_H */
