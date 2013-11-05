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

#include "rsa.h"
#include "rsa_test_vector.h"

/* Forward declarations */
static error_t parse_opts(int, char *, struct argp_state *);
static void unregister_rsa(struct protocol_info *);

struct argp_option rsa_options[] = {
	{"form", 'b', "FORM",  0,
	 "Select RSA Decrypt Private Key form:"
	 "\n\t 1 = Form 1"
	 "\n\t 2 = Form 2 (not supported)"
	 "\n\t 3 = Form 3 (not supported)"
	 "\n"},
	{0}
};

/* Parser for RSA command line options */
static struct argp rsa_argp = {
	rsa_options, parse_opts
};

static struct argp_child argp_children = {
		&rsa_argp, 0, "RSA protocol options", 4};

int init_rtv_rsa_decrypt_form1(struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct rsa_ref_vector_s *ref_test_vector = proto->proto_vector;

	ref_test_vector->d_len =
		rsa_ref_private_exp_len[crypto_info->test_set - 1];

	ref_test_vector->n_ref =
		__dma_mem_memalign(L1_CACHE_BYTES, ref_test_vector->n_len);
	if (!ref_test_vector->n_ref)
		return -ENOMEM;
	memcpy(ref_test_vector->n_ref,
	       rsa_ref_modulus[crypto_info->test_set - 1],
	       ref_test_vector->n_len);

	ref_test_vector->d_ref =
		__dma_mem_memalign(L1_CACHE_BYTES, ref_test_vector->d_len);
	if (!ref_test_vector->d_ref)
		return -ENOMEM;
	memcpy(ref_test_vector->d_ref,
	       rsa_ref_private_exponent[crypto_info->test_set - 1],
	       ref_test_vector->d_len);
	return 0;
}

static void free_rsa_rtv(struct rsa_ref_vector_s *ref_test_vector)
{
	__dma_mem_free(ref_test_vector->f_ref);
	__dma_mem_free(ref_test_vector->g_ref);
	__dma_mem_free(ref_test_vector->e_ref);
	__dma_mem_free(ref_test_vector->n_ref);
	__dma_mem_free(ref_test_vector->d_ref);
}

static int init_ref_test_vector_rsa(struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct rsa_ref_vector_s *ref_test_vector = proto->proto_vector;
	struct rsa_params *rsa_params = proto->proto_params;

	ref_test_vector->e_len =
		rsa_ref_exponent_len[crypto_info->test_set - 1];
	ref_test_vector->f_len =
		rsa_ref_input_len[crypto_info->test_set - 1];
	ref_test_vector->n_len =
		rsa_ref_modulus_len[crypto_info->test_set - 1];

	ref_test_vector->f_ref =
		__dma_mem_memalign(L1_CACHE_BYTES, ref_test_vector->n_len);
	if (!ref_test_vector->f_ref)
		goto err;

	memcpy(ref_test_vector->f_ref,
	       rsa_ref_input[crypto_info->test_set - 1],
	       ref_test_vector->f_len);

	ref_test_vector->g_ref =
		__dma_mem_memalign(L1_CACHE_BYTES, ref_test_vector->n_len);
	if (!ref_test_vector->g_ref)
		goto err;

	ref_test_vector->e_ref =
		__dma_mem_memalign(L1_CACHE_BYTES, ref_test_vector->e_len);
	if (!ref_test_vector->e_ref)
		goto err;
	memcpy(ref_test_vector->e_ref,
	       rsa_ref_public_exponent[crypto_info->test_set - 1],
	       ref_test_vector->e_len);

	ref_test_vector->length = rsa_ref_length[crypto_info->test_set - 1];
	ref_test_vector->plaintext = ref_test_vector->f_ref;
	ref_test_vector->ciphertext = ref_test_vector->g_ref;

	switch (rsa_params->form) {
	case RSA_DECRYPT_FORM1:
		if (init_rtv_rsa_decrypt_form1(crypto_info))
			goto err;
		break;

	case RSA_DECRYPT_FORM2:
	case RSA_DECRYPT_FORM3:
		fprintf(stderr, "RSA Decrypt form %d not supported\n",
			rsa_params->form);
		return -EINVAL;

	default:
		fprintf(stderr, "Unknown RSA Decrypt Private Key form %d (should never reach here)\n",
			rsa_params->form);
		return -EINVAL;
	}
	return 0;
err:
	fprintf(stderr, "Not enough memory\n");
	free_rsa_rtv(ref_test_vector);
	return -ENOMEM;
}

static void *create_descriptor(bool mode, void *params)
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct protocol_info *proto = crypto_info->proto;
	struct rsa_ref_vector_s *ref_test_vector = proto->proto_vector;
	struct sec_descriptor_t *prehdr_desc;
	uint32_t *shared_desc = NULL;
	unsigned shared_desc_len = 0;
	int i;

	prehdr_desc = __dma_mem_memalign(L1_CACHE_BYTES,
					 sizeof(struct sec_descriptor_t));
	if (!prehdr_desc) {
		fprintf(stderr,
			"error: %s: dma_mem_memalign failed for preheader\n",
			__func__);
		return NULL;
	}

	/*
	 * Store the pointer to the descriptor for free'ing later on
	 */
	proto->descr = prehdr_desc;

	memset(prehdr_desc, 0, sizeof(struct sec_descriptor_t));
	shared_desc = (typeof(shared_desc))&prehdr_desc->descbuf;

	if (ENCRYPT == mode)
		cnstr_shdsc_rsa_encrypt(shared_desc,
					&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
					1,
					0, /* sgf */
					ref_test_vector->e_len,
					ref_test_vector->n_len,
					__dma_mem_vtop(ref_test_vector->f_ref),
					__dma_mem_vtop(ref_test_vector->g_ref),
					__dma_mem_vtop(ref_test_vector->n_ref),
					__dma_mem_vtop(ref_test_vector->e_ref),
					ref_test_vector->f_len);
	else
		cnstr_shdsc_rsa_decrypt_form1(shared_desc,
					&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
					1,
					0, /* sgf */
					ref_test_vector->d_len,
					ref_test_vector->n_len,
					__dma_mem_vtop(ref_test_vector->g_ref),
					__dma_mem_vtop(ref_test_vector->f_ref),
					__dma_mem_vtop(ref_test_vector->n_ref),
					__dma_mem_vtop(ref_test_vector->d_ref));

	prehdr_desc->prehdr.hi.word = shared_desc_len & SEC_PREHDR_SDLEN_MASK;

	pr_debug("SEC %s shared descriptor:\n", proto->name);

	for (i = 0; i < shared_desc_len; i++)
		pr_debug("0x%x\n", *shared_desc++);

	return prehdr_desc;
}

static int test_enc_match_cb_rsa(int fd_ind, uint8_t *enc_buf,
				struct test_param *crypto_info)
{
	struct rsa_ref_vector_s *ref_test_vector =
				crypto_info->proto->proto_vector;

	return test_vector_match((uint32_t *)ref_test_vector->ciphertext,
			(uint32_t *)rsa_ref_result[crypto_info->test_set - 1],
			ref_test_vector->n_len * BITS_PER_BYTE);
}

static int test_dec_match_cb_rsa(int fd_ind, uint8_t *dec_buf,
			    struct test_param *crypto_info)
{
	struct rsa_ref_vector_s *ref_test_vector =
				crypto_info->proto->proto_vector;
	int position = ref_test_vector->n_len - ref_test_vector->f_len;

	memcpy(ref_test_vector->plaintext,
	       &ref_test_vector->plaintext[position],
	       rsa_ref_input_len[crypto_info->test_set - 1]);
	return test_vector_match((uint32_t *)ref_test_vector->plaintext,
		(uint32_t *)rsa_ref_input[crypto_info->test_set - 1],
		ref_test_vector->f_len * BITS_PER_BYTE);
}

/**
 * @brief	Parse RSA related command line options
 *
 */
static error_t parse_opts(int key, char *arg, struct argp_state *state)
{
	struct parse_input_t *input = state->input;
	struct test_param *crypto_info = input->crypto_info;
	struct rsa_params *rsa_params;

	/*
	 * If the protocol was not selected, then it makes no sense to go
	 * further.
	 */
	if (!crypto_info->proto)
		return 0;

	rsa_params = crypto_info->proto->proto_params;
	switch (key) {
	case 'b':
		rsa_params->form = atoi(arg);
		fprintf(stdout, "RSA Decrypt form = %d\n", rsa_params->form);
		break;

	default:
		printf("%c", key);
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 * @brief	Check SEC parameters provided by user for RSA are valid
 *		or not.
 * @param[in]	g_proto_params - Bit mask of the optional parameters provided
 *		by user
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_rsa_opts(uint32_t g_proto_params,
				struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct rsa_params *rsa_params = proto->proto_params;

	if ((rsa_params->form < 1) || (rsa_params->form > 3)) {
		fprintf(stderr, "Unknown RSA Decrypt Private Key form %d\n",
			rsa_params->form);
		return -EINVAL;
	}

	proto->test_enc_match_cb = test_enc_match_cb_rsa;
	proto->test_dec_match_cb = test_dec_match_cb_rsa;

	return 0;
}

static int get_buf_size(struct test_param *crypto_info)
{
	return 2 * crypto_info->buf_size;
}

/**
 * @brief	Set buffer sizes for input/output frames
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int set_buf_size(struct test_param *crypto_info)
{
	struct runtime_param *p_rt = &(crypto_info->rt);

	p_rt->input_buf_capacity = crypto_info->buf_size;
	p_rt->input_buf_length = crypto_info->buf_size;

	crypto_info->rt.output_buf_size = crypto_info->buf_size;

	return 0;
}

/**
 * @brief	Verifies if user gave a correct test set
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_test_set(struct test_param *crypto_info)
{
	if ((crypto_info->test_set > 0) && (crypto_info->test_set < 3))
		return 0;

	fprintf(stderr, "error: Invalid Parameters: Test set number is invalid\n");
	return -EINVAL;
}

/**
 * @brief	Allocates the necessary structures for a protocol, sets the
 *		callbacks for the protocol and returns the allocated chunk.
 * @return	NULL if an error occurred, pointer to the protocol structure
 *		otherwise.
 */
struct protocol_info *register_rsa(void)
{
	struct protocol_info *proto_info = calloc(1, sizeof(*proto_info));

	if (!proto_info) {
		pr_err("failed to allocate protocol structure in %s",
		       __FILE__);
		return NULL;
	}

	SAFE_STRNCPY(proto_info->name, "RSA", sizeof(proto_info->name));
	proto_info->unregister = unregister_rsa;
	proto_info->argp_children = &argp_children;
	proto_info->init_ref_test_vector = init_ref_test_vector_rsa;
	proto_info->setup_sec_descriptor = create_descriptor;
	proto_info->get_buf_size = get_buf_size;
	proto_info->set_buf_size = set_buf_size;
	proto_info->validate_test_set = validate_test_set;
	proto_info->validate_opts = validate_rsa_opts;
	proto_info->proto_params = calloc(1, sizeof(struct rsa_params));
	if (!proto_info->proto_params) {
		pr_err("failed to allocate protocol parameters in %s",
		       __FILE__);
		goto err;
	}
	proto_info->proto_vector =
		calloc(1, sizeof(struct rsa_ref_vector_s));
	if (!proto_info->proto_vector) {
		pr_err("failed to allocate protocol test vector in %s",
		       __FILE__);
		goto err;
	}

	return proto_info;
err:
	free(proto_info->proto_vector);
	free(proto_info->proto_params);
	free(proto_info);
	return NULL;
}

/**
 * @brief	Deallocates the structures for a protocol (allocated on
 *		registration) and frees any other memory that was allocated
 *		during the protocol processing.
 * @param[in]	proto_info - protocol parameters
 * @return	None
 *
 */
void unregister_rsa(struct protocol_info *proto_info)
{
	if (!proto_info)
		return;

	if (proto_info->descr)
		__dma_mem_free(proto_info->descr);

	free_rsa_rtv((struct rsa_ref_vector_s *)proto_info->proto_vector);
	free(proto_info->proto_vector);
	free(proto_info->proto_params);
	free(proto_info);
}
