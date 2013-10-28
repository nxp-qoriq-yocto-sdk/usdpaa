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

#include "srtp.h"
#include "srtp_test_vector.h"

/* Forward declarations */
void unregister_srtp(struct protocol_info *);

int init_ref_test_vector(struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct srtp_ref_vector_s *ref_test_vector = proto->proto_vector;

	ref_test_vector->auth_key =
	    (uintptr_t)srtp_reference_auth_key[crypto_info->test_set - 1];
	ref_test_vector->auth_keylen =
	    srtp_reference_auth_keylen[crypto_info->test_set - 1];

	ref_test_vector->key =
	    (uintptr_t)srtp_reference_cipher_key[crypto_info->test_set - 1];
	ref_test_vector->cipher_keylen =
	    srtp_reference_cipher_keylen[crypto_info->test_set - 1];

	ref_test_vector->cipher_salt =
	    srtp_reference_cipher_salt[crypto_info->test_set - 1];
	ref_test_vector->n_tag =
	    srtp_reference_n_tag[crypto_info->test_set - 1];
	ref_test_vector->roc =
	    srtp_reference_roc[crypto_info->test_set - 1];
	ref_test_vector->seqnum =
	    srtp_reference_seq_num[crypto_info->test_set - 1];

	if (CIPHER == crypto_info->mode) {
		ref_test_vector->length =
		    srtp_reference_length[crypto_info->test_set - 1];
		ref_test_vector->plaintext =
		    srtp_reference_plaintext[crypto_info->test_set - 1];
		ref_test_vector->ciphertext =
		    srtp_reference_ciphertext[crypto_info->test_set - 1];
	}

	return 0;
}

static void *create_descriptor(bool mode, void *params)
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct protocol_info *proto = crypto_info->proto;
	struct srtp_ref_vector_s *ref_test_vector = proto->proto_vector;
	struct sec_descriptor_t *prehdr_desc;
	struct alginfo cipher_info, auth_info;
	uint32_t *shared_desc = NULL;
	unsigned shared_desc_len;
	int i;

	prehdr_desc = __dma_mem_memalign(L1_CACHE_BYTES,
					 sizeof(struct sec_descriptor_t));
	if (unlikely(!prehdr_desc)) {
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

	cipher_info.key = ref_test_vector->key;
	cipher_info.keylen = ref_test_vector->cipher_keylen;
	cipher_info.key_enc_flags = 0;
	auth_info.key = ref_test_vector->auth_key;
	auth_info.keylen = ref_test_vector->auth_keylen;
	auth_info.key_enc_flags = 0;
	if (ENCRYPT == mode)
		cnstr_shdsc_srtp_encap(shared_desc,
				       &shared_desc_len,
				       &auth_info,
				       &cipher_info,
				       ref_test_vector->n_tag,
				       ref_test_vector->roc,
				       ref_test_vector->cipher_salt);
	else
		cnstr_shdsc_srtp_decap(shared_desc,
				       &shared_desc_len,
				       &auth_info,
				       &cipher_info,
				       ref_test_vector->n_tag,
				       ref_test_vector->roc,
				       ref_test_vector->seqnum,
				       ref_test_vector->cipher_salt);

	prehdr_desc->prehdr.hi.word = shared_desc_len & SEC_PREHDR_SDLEN_MASK;

	pr_debug("SEC %s shared descriptor:\n", protocol);

	for (i = 0; i < shared_desc_len; i++)
		pr_debug("0x%x\n", *shared_desc++);

	return prehdr_desc;
}

/**
 * @brief	Check SEC parameters provided by user for SRTP are valid
 *		or not.
 * @param[in]	g_proto_params - Bit mask of the optional parameters provided
 *		by user
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_srtp_opts(uint32_t g_proto_params,
			      struct test_param *crypto_info)
{
	/* TODO - for future implementation of extension options and MKI */
	return 0;
}

static int get_buf_size(struct test_param *crypto_info)
{
	return 2 * crypto_info->buf_size + SRTP_MAX_ICV_SIZE;
}

/**
 * @brief	Set buffer sizes for input/output frames
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int set_buf_size(struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct srtp_ref_vector_s *ref_test_vector = proto->proto_vector;
	struct runtime_param *p_rt = &(crypto_info->rt);

	p_rt->input_buf_capacity = crypto_info->buf_size;
	p_rt->input_buf_length = crypto_info->buf_size;

	crypto_info->rt.output_buf_size =
			crypto_info->buf_size + ref_test_vector->n_tag;
	return 0;
}

/**
 * @brief	Verifies if user gave a correct test set
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_test_set(struct test_param *crypto_info)
{
	if (crypto_info->test_set == 1)
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
struct protocol_info *register_srtp(void)
{
	struct protocol_info *proto_info = calloc(1, sizeof(*proto_info));

	if (unlikely(!proto_info)) {
		pr_err("failed to allocate protocol structure in %s",
		       __FILE__);
		return NULL;
	}

	SAFE_STRNCPY(proto_info->name, "SRTP", sizeof(proto_info->name));
	proto_info->unregister = unregister_srtp;
	proto_info->init_ref_test_vector = init_ref_test_vector;
	proto_info->setup_sec_descriptor = create_descriptor;
	proto_info->get_buf_size = get_buf_size;
	proto_info->set_buf_size = set_buf_size;
	proto_info->validate_test_set = validate_test_set;
	proto_info->validate_opts = validate_srtp_opts;
	proto_info->proto_vector =
		calloc(1, sizeof(struct srtp_ref_vector_s));
	if (unlikely(!proto_info->proto_vector)) {
		pr_err("failed to allocate protocol test vector in %s",
		       __FILE__);
		goto err;
	}

	return proto_info;
err:
	free(proto_info->proto_vector);
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
void unregister_srtp(struct protocol_info *proto_info)
{
	if (!proto_info)
		return;

	if (proto_info->descr)
		__dma_mem_free(proto_info->descr);

	free(proto_info->proto_vector);
	free(proto_info);

}