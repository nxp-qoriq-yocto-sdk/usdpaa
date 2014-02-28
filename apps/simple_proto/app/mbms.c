/* Copyright 2014 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include "mbms.h"
#include "mbms_test_vector.h"

/* Forward declarations */
static error_t parse_opts(int, char *, struct argp_state *);
static void unregister_mbms(struct protocol_info *);

struct argp_option mbms_options[] = {
	{"type", 'z', "TYPE",  0,
	 "Select MBMS PDU type:"
	 "\n\t 0 = Type 0 PDU"
	 "\n\t 1 = Type 1 PDU"
	 "\n\t 2 = Type 3 PDU"
	 "\n"},
	{0}
};

/* Parser for MBMS command line options */
static struct argp mbms_argp = {
	mbms_options, parse_opts
};

static struct argp_child argp_children = {
		&mbms_argp , 0, "MBMS protocol options", 5};

int init_rtv_mbms(struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct mbms_params *mbms_params = proto->proto_params;
	struct mbms_ref_vector_s *ref_test_vector = proto->proto_vector;
	unsigned test_set = crypto_info->test_set - 1;

	switch (mbms_params->type) {
	case MBMS_PDU_TYPE0:
	case MBMS_PDU_TYPE1:
	case MBMS_PDU_TYPE3:
		break;

	default:
		fprintf(stderr, "Unknown MBMS PDU type %d (should never reach here)\n",
			mbms_params->type);
		return -EINVAL;
	}

	snprintf(proto->name, sizeof(proto->name), "MBMS PDU Type %d",
		 mbms_params->type);

	if (CIPHER == crypto_info->mode) {
		switch (mbms_params->type) {
		case MBMS_PDU_TYPE0:
			ref_test_vector->length =
				NO_OF_BITS(mbms_type0_test_data_len[test_set]);
			ref_test_vector->plaintext =
					mbms_type0_test_data[test_set];
			ref_test_vector->ciphertext =
					mbms_type0_test_data[test_set];
			break;

		case MBMS_PDU_TYPE1:
			ref_test_vector->length =
				NO_OF_BITS(mbms_type1_test_data_len[test_set]);
			ref_test_vector->plaintext =
					mbms_type1_test_data[test_set];
			ref_test_vector->ciphertext =
					mbms_type1_test_data[test_set];
			break;

		case MBMS_PDU_TYPE3:
			ref_test_vector->length =
				NO_OF_BITS(mbms_type3_test_data_len[test_set]);
			ref_test_vector->plaintext =
					mbms_type3_test_data[test_set];
			ref_test_vector->ciphertext =
					mbms_type3_test_data[test_set];
			break;
		default:
			return -EINVAL;
		}
	}

	crypto_info->authnct = 1;

	return 0;
}

static void set_enc_buf_cb(struct qm_fd *fd, uint8_t *buf,
			   struct test_param *crypto_info)
{
	struct qm_sg_entry *sgentry;
	struct protocol_info *proto = crypto_info->proto;
	struct mbms_ref_vector_s *ref_test_vector = proto->proto_vector;
	dma_addr_t addr, out_buf, in_buf;

	addr = qm_fd_addr(fd);

	/* set output buffer and length */
	sgentry = __dma_mem_ptov(addr);
	out_buf = addr + sizeof(struct sg_entry_priv_t);

	/*
	 * Set offset to point after the FMAN-like data
	 */
	sgentry++;
	sgentry->offset = MBMS_BUFFER_OFFSET;
	sgentry->length -= MBMS_BUFFER_OFFSET;

	in_buf = out_buf + crypto_info->rt.output_buf_size;
	buf = __dma_mem_ptov(in_buf);

	/*
	 * Copy FMAN-like data before the buffer data
	 */
	memcpy(buf, mbms_prebuffer_data,
	       sizeof(mbms_prebuffer_data));

	memcpy(buf + sgentry->offset, ref_test_vector->plaintext,
	       crypto_info->buf_size);
}

static int test_enc_match_cb(int fd_ind, uint8_t *enc_buf,
			     struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct mbms_ref_vector_s *ref_test_vector = proto->proto_vector;

	return test_vector_match((uint32_t *)enc_buf,
			(uint32_t *)ref_test_vector->ciphertext,
			crypto_info->rt.input_buf_length * BITS_PER_BYTE);
}

static void *create_descriptor(bool mode, void *params)
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct protocol_info *proto = crypto_info->proto;
	struct mbms_params *mbms_params = proto->proto_params;
	struct sec_descriptor_t *prehdr_desc;
	uint32_t *shared_desc = NULL;
	unsigned shared_desc_len = 0;
	unsigned preheader_len = 0;
	int i;

	switch (mbms_params->type) {
	case MBMS_PDU_TYPE0:
		prehdr_desc = __dma_mem_memalign(MBMS_TYPE0_DESC_ALIGN,
				sizeof(struct sec_descriptor_t));
		memset(prehdr_desc, 0, sizeof(struct sec_descriptor_t));
		break;

	case MBMS_PDU_TYPE1:
	case MBMS_PDU_TYPE3:
		prehdr_desc = __dma_mem_memalign(MBMS_TYPE1_DESC_ALIGN,
				2 * sizeof(struct sec_descriptor_t));
		memset(prehdr_desc, 0, 2 * sizeof(struct sec_descriptor_t));
		break;

	default:
		fprintf(stderr,
			"error: %s: Invalid MBMS PDU type %d\n",
			__func__, mbms_params->type);
		return NULL;
	}

	if (unlikely(!prehdr_desc)) {
		fprintf(stderr,
			"error: %s: dma_mem_memalign failed for preheader\n",
			__func__);
		return NULL;
	}

	shared_desc = (typeof(shared_desc))&prehdr_desc->descbuf;

	cnstr_shdsc_mbms(shared_desc,
			 &shared_desc_len,
			 1,
			 &preheader_len,
			 mbms_params->type);

	/*
	 * Store the pointer to the descriptor for free'ing later on
	 */
	proto->descr = prehdr_desc;

	prehdr_desc->prehdr.hi.word = preheader_len & SEC_PREHDR_SDLEN_MASK;

	pr_debug("SEC %s shared descriptor:\n", proto->name);

	for (i = 0; i < shared_desc_len; i++)
		pr_debug("0x%x\n", *shared_desc++);

	return prehdr_desc;
}

/**
 * @brief      Parse MBMS related command line options
 *
 */
static error_t parse_opts(int key, char *arg, struct argp_state *state)
{
	struct parse_input_t *input = state->input;
	uint32_t *p_proto_params = input->proto_params;
	struct test_param *crypto_info = input->crypto_info;
	struct mbms_params *mbms_params;

	/*
	 * If the protocol was not selected, then it makes no sense to go
	 * further.
	 */
	if (!crypto_info->proto)
		return 0;

	mbms_params = crypto_info->proto->proto_params;
	switch (key) {
	case 'z':
		mbms_params->type = atoi(arg);
		*p_proto_params |= BMASK_MBMS_TYPE;
		fprintf(stdout, "MBMS PDU type = %d\n", mbms_params->type);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 * @brief      Check SEC parameters provided by user for MBMS are valid
 *             or not.
 * @param[in]  g_proto_params - Bit mask of the optional parameters provided
 *             by user
 * @param[in]  crypto_info - test parameters
 * @return     0 on success, otherwise -EINVAL value
 */
static int validate_opts(uint32_t g_proto_params,
			 struct test_param *crypto_info)
{
	if (crypto_info->mode == PERF) {
		fprintf(stderr,
			"error: MBMS does not support PERF mode\n"
			"see --help option\n");
		return -EINVAL;
	}

	if ((BMASK_MBMS_VALID & g_proto_params) != BMASK_MBMS_VALID) {
		fprintf(stderr,
			"error: MBMS Invalid Parameters: Invalid type\n"
			"see --help option\n");
		return -EINVAL;
	}

	return 0;
}
static int get_buf_size(struct test_param *crypto_info)
{
	return 2 * crypto_info->buf_size + MBMS_BUFFER_OFFSET;
}

/**
 * @brief      Set buffer sizes for input/output frames
 * @param[in]  crypto_info - test parameters
 * @return     0 on success, otherwise -EINVAL value
 */
static int set_buf_size(struct test_param *crypto_info)
{
	struct runtime_param *p_rt = &(crypto_info->rt);

	p_rt->input_buf_capacity = crypto_info->buf_size + MBMS_BUFFER_OFFSET;
	p_rt->input_buf_length = crypto_info->buf_size;

	/*
	 * Because input buffer is right after output buffer, I need to align
	 * the end of the output buffer to the alignment required by the
	 * input buffer.
	 */
	p_rt->output_buf_size =
		((crypto_info->buf_size +  sizeof(struct sg_entry_priv_t) +
		 (MBMS_BUFFER_ALIGN - 1)) & ~(MBMS_BUFFER_ALIGN - 1)) -
		 sizeof(struct sg_entry_priv_t);

	return 0;
}

/**
 * @brief       Verifies if user gave a correct test set
 * @param[in]   crypto_info - test parameters
 * @return      0 on success, otherwise -EINVAL value
 */
static int validate_test_set(struct test_param *crypto_info)
{
	if (crypto_info->test_set == 1)
		return 0;

	fprintf(stderr, "error: Invalid Parameters: Test set number is invalid\n");
	return -EINVAL;
}

/**
 * @brief       Allocates the necessary structures for a protocol, sets the
 *              callbacks for the protocol and returns the allocated chunk.
 * @return      NULL if an error occurred, pointer to the protocol structure
 *              otherwise.
 */
struct protocol_info *register_mbms(void)
{
	struct protocol_info *proto_info = calloc(1, sizeof(*proto_info));

	if (unlikely(!proto_info)) {
		pr_err("failed to allocate protocol structure in %s",
		       __FILE__);
		return NULL;
	}

	SAFE_STRNCPY(proto_info->name, "MBMS", sizeof(proto_info->name));
	proto_info->unregister = unregister_mbms;
	proto_info->argp_children = &argp_children;
	proto_info->init_ref_test_vector = init_rtv_mbms;
	proto_info->setup_sec_descriptor = create_descriptor;
	proto_info->test_enc_match_cb = test_enc_match_cb;
	proto_info->buf_align = MBMS_BUFFER_ALIGN;
	proto_info->validate_opts = validate_opts;
	proto_info->get_buf_size = get_buf_size;
	proto_info->set_buf_size = set_buf_size;
	proto_info->validate_test_set = validate_test_set;
	proto_info->set_enc_buf_cb = set_enc_buf_cb;
	proto_info->proto_params = calloc(1, sizeof(struct mbms_params));
	if (unlikely(!proto_info->proto_params)) {
		pr_err("failed to allocate protocol parameters in %s",
		       __FILE__);
		goto err;
	}

	proto_info->proto_vector =
		calloc(1, sizeof(struct mbms_ref_vector_s));
	if (unlikely(!proto_info->proto_vector)) {
		pr_err("failed to allocate protocol test vector in %s",
		       __FILE__);
		goto err;
	}

	return proto_info;
err:
	free(proto_info->proto_params);
	free(proto_info->proto_vector);
	free(proto_info);
	return NULL;
}

/**
 * @brief       Deallocates the structures for a protocol (allocated on
 *              registration) and frees any other memory that was allocated
 *              during the protocol processing.
 * @param[in]   proto_info - protocol parameters
 * @return      None
 */
void unregister_mbms(struct protocol_info *proto_info)
{
	if (!proto_info)
		return;

	if (proto_info->descr)
		__dma_mem_free(proto_info->descr);

	free(proto_info->proto_vector);
	free(proto_info->proto_params);
	free(proto_info);
}

