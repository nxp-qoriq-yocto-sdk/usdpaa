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

#include "simple_proto.h"

pthread_barrier_t app_barrier;

struct ref_vector_s ref_test_vector;

long ncpus;

int32_t set_user_sec_era = -1;

enum rta_sec_era rta_sec_era = RTA_SEC_ERA_2;
/***********************************************/

/**
 * @brief	Initializes the reference test vector for MACsec
 * @details	Initializes key, length and other variables for the protocol
 * @param[in]	crypto_info - test parameters
 * @return	None
 */
void init_rtv_macsec_gcm_128(struct test_param *crypto_info)
{
	strcpy(protocol, "MACsec");
	ref_test_vector.key = macsec_reference_key[crypto_info->test_set - 1];

	/* set the MACsec pdb params for test */
	ref_test_vector.pdb.macsec.ethertype =
	    macsec_reference_sectag_etype[crypto_info->test_set - 1];
	ref_test_vector.pdb.macsec.tci_an =
	    macsec_reference_sectag_tcian[crypto_info->test_set - 1];
	ref_test_vector.pdb.macsec.pn =
	    macsec_reference_iv_pn[crypto_info->test_set - 1];
	ref_test_vector.pdb.macsec.sci =
	    macsec_reference_iv_sci[crypto_info->test_set - 1];

	if (CIPHER == crypto_info->mode) {
		ref_test_vector.length =
		    macsec_reference_length[crypto_info->test_set - 1];
		ref_test_vector.plaintext =
		    macsec_reference_plaintext[crypto_info->test_set - 1];
		ref_test_vector.ciphertext =
		    macsec_reference_ciphertext[crypto_info->test_set - 1];
	}
}

/**
 * @brief	Set PN constant in MACsec shared descriptor
 * @details	Inside this routine, context is erased, PN is read from
 *		descriptor buffer before operation is performed, and after the
 *		operation is updated in descriptor buffer and also saved in
 *		memory.The SEC automatically increments the PN inside the
 *		descriptor buffer after executing the MACsec PROTOCOL command,
 *		so the next packet that will be processed by SEC will be
 *		encapsulated/decapsulated with an incremented PN. This routine
 *		is needed for MACsec's tests using a single golden pattern
 *		packet reinjected for multiple times.
 * @param[in]	shared_desc - pointer to descriptor buffer
 * @param[in]	shared_desc_len - shared descriptor length
 * @return	None
 */
void macsec_set_pn_constant(uint32_t *shared_desc, unsigned *shared_desc_len)
{
	struct program prg;
	struct program *program = &prg;
	uint32_t op_line, tmp;
	uint32_t tmp_buf[64];
	int i, op_idx = 0, save_lines = 0;
	unsigned extra_instr = 3;

	/* to mute compiler warnings */
	prg.current_instruction = 0;

	for (i = 0; i < *shared_desc_len; i++) {
		tmp = shared_desc[i];
		if ((tmp & CMD_MASK) == CMD_OPERATION)
			op_idx = i;
	}

	if (!op_idx)
		/* there isn't an operation instruction in descbuf */
		return;

	if ((*shared_desc_len + extra_instr) > MAX_DESCRIPTOR_SIZE)
		/* we can't modify this descriptor; it will overflow */
		return;

	if (op_idx < *shared_desc_len - 1) {
		/* operation is not the last instruction in descbuf */
		save_lines = *shared_desc_len - 1 - op_idx;
		for (i = 0; i < save_lines; i++)
			tmp_buf[i] = shared_desc[op_idx + 1 + i];
	}

	/* save operation instruction */
	op_line = shared_desc[op_idx];

	/* RTA snippet code to update shared descriptor */
	program->buffer = shared_desc;
	program->current_pc = op_idx;

	MOVE(DESCBUF, 20, MATH0, 0, IMM(4), WAITCOMP);
	program->buffer[program->current_pc++] = op_line;
	MOVE(MATH0, 0, DESCBUF, 20, IMM(4), WAITCOMP);
	STORE(SHAREDESCBUF, 20, NONE, 4, 0);

	/* erase context in shared desc header */
	*shared_desc &= ~HDR_SAVECTX;

	/* update length in shared desc header */
	*shared_desc_len += extra_instr;
	*shared_desc &= ~HDR_SD_LENGTH_MASK;
	*shared_desc |= *shared_desc_len & HDR_SD_LENGTH_MASK;

	/* copy the rest of the instructions in buffer */
	for (i = 0; i < save_lines; i++)
		shared_desc[program->current_pc + i] = tmp_buf[i];
}

/* Function pointer to reference test vector for supported protocols */
void (*init_ref_test_vector[]) (struct test_param *crypto_info) = {
	init_rtv_macsec_gcm_128};

/**
 * @brief	Calculates output buffer size and creates compound FDs
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise error value
 */
int prepare_test_frames(struct test_param *crypto_info)
{
	int err = 0;

	if (PERF == crypto_info->mode) {
		strcpy(mode_type, "PERF");
		crypto_info->test_set = 1;
	}

	init_ref_test_vector[crypto_info->proto - 1] (crypto_info);

	if (CIPHER == crypto_info->mode) {
		strcpy(mode_type, "CIPHER");
		crypto_info->buf_size = NO_OF_BYTES(ref_test_vector.length);
	}

	err = set_buf_size(crypto_info);
	if (err)
		error(err, err, "error: set output buffer size");

	err = create_compound_fd(crypto_info->buf_num,
				 crypto_info->rt.output_buf_size,
				 crypto_info->rt.input_buf_capacity,
				 crypto_info->rt.input_buf_length);
	if (err)
		error(err, err, "error: create_compound_fd() failed");

	printf("Processing %s for %d Frames\n", protocol, crypto_info->buf_num);
	printf("%s mode, buffer length = %d\n", mode_type,
	       crypto_info->buf_size);
	printf("Number of iterations = %d\n", crypto_info->itr_num);
	printf("\nStarting threads for %ld cpus\n", ncpus);

	return err;
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

	switch (crypto_info->proto) {
	case MACSEC:
		crypto_info->rt.output_buf_size =
		    crypto_info->buf_size + MACSEC_ICV_SIZE +
		    MACSEC_SECTAG_SIZE;
		break;
	default:
		fprintf(stderr, "error: %s: protocol not supported\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief	Create SEC shared descriptor
 * @param[in]	mode -	To check whether descriptor is for encryption or
 *		decryption
 * @param[in]	crypto_info - test parameters
 * @return	Shared descriptor pointer on success, otherwise NULL
 */
static void *setup_init_descriptor(bool mode, struct test_param *crypto_info)
{
	struct sec_descriptor_t *prehdr_desc;
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

	memset(prehdr_desc, 0, sizeof(struct sec_descriptor_t));
	shared_desc = (typeof(shared_desc))&prehdr_desc->descbuf;

	switch (crypto_info->proto) {
	case MACSEC:
		if (ENCRYPT == mode)
			cnstr_shdsc_macsec_encap(shared_desc,
						 &shared_desc_len,
						 ref_test_vector.key,
						 MACSEC_KEY_SIZE,
						 ref_test_vector.pdb.macsec.sci,
						 ref_test_vector.pdb.macsec.
						 ethertype,
						 ref_test_vector.pdb.macsec.
						 tci_an,
						 ref_test_vector.pdb.macsec.pn);

		else
			cnstr_shdsc_macsec_decap(shared_desc,
						 &shared_desc_len,
						 ref_test_vector.key,
						 MACSEC_KEY_SIZE,
						 ref_test_vector.pdb.macsec.sci,
						 ref_test_vector.pdb.macsec.pn);
		macsec_set_pn_constant(shared_desc, &shared_desc_len);
		break;
	default:
		fprintf(stderr, "error: %s: protocol not supported\n",
			__func__);
		return NULL;
	}

	prehdr_desc->prehdr.hi.word = shared_desc_len & SEC_PREHDR_SDLEN_MASK;

	pr_debug("SEC %s shared descriptor:\n", protocol);

	for (i = 0; i < shared_desc_len; i++)
		pr_debug("0x%x\n", *shared_desc++);

	return prehdr_desc;
}

/**
 * @brief	Set parameters for descriptor init
 * @param[in]	mode - Encrypt/Decrypt
 * @param[in]	params - pointer to test parameters
 * @return	Shared descriptor pointer on success, otherwise NULL
 */
static void *setup_sec_descriptor(bool mode, void *params)
{
	return setup_init_descriptor(mode, (struct test_param *)params);
}

/**
 * @brief	Initialize input buffer plain text data and set output buffer
 *		as 0 in compound frame descriptor
 * @param[in]	params - test parameters
 * @param[in]	struct qm_fd - frame descriptors list
 * @return       None
 */
void set_enc_buf(void *params, struct qm_fd fd[])
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct qm_sg_entry *sgentry;
	uint8_t *buf;
	uint8_t plain_data = 0;
	dma_addr_t addr, out_buf, in_buf;
	uint32_t i, ind;

	for (ind = 0; ind < crypto_info->buf_num; ind++) {
		addr = qm_fd_addr(&fd[ind]);

		/* set output buffer and length */
		sgentry = __dma_mem_ptov(addr);
		sgentry->length = crypto_info->rt.output_buf_size;

		out_buf = addr + sizeof(struct sg_entry_priv_t);
		qm_sg_entry_set64(sgentry, out_buf);

		/* set input buffer and length */
		sgentry++;
		sgentry->length = crypto_info->rt.input_buf_capacity;

		in_buf = out_buf + crypto_info->rt.output_buf_size;
		qm_sg_entry_set64(sgentry, in_buf);

		/* Copy the input plain-text data */
		buf = __dma_mem_ptov(in_buf);
		if (CIPHER == crypto_info->mode)
			memcpy(buf, ref_test_vector.plaintext,
			       crypto_info->buf_size);
		else
			for (i = 0; i < crypto_info->buf_size; i++)
				buf[i] = plain_data++;
	}
}

/**
 * @brief	Initialize input buffer as cipher text data and set output
 *		buffer as 0 in compound frame descriptor
 * @param[in]	params - test parameters
 * @param[in]	struct qm_fd - frame descriptors list
 * @return       None
 */
void set_dec_buf(void *params, struct qm_fd fd[])
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct qm_sg_entry *sg_out;
	struct qm_sg_entry *sg_in;
	dma_addr_t addr;
	uint32_t length;
	uint16_t offset;
	uint8_t bpid;
	uint32_t ind;

	for (ind = 0; ind < crypto_info->buf_num; ind++) {
		addr = qm_fd_addr(&fd[ind]);
		sg_out = __dma_mem_ptov(addr);
		sg_in = sg_out + 1;

		addr = qm_sg_addr(sg_out);
		length = sg_out->length;
		offset = sg_out->offset;
		bpid = sg_out->bpid;

		qm_sg_entry_set64(sg_out, qm_sg_addr(sg_in));
		sg_out->length = sg_in->length;
		sg_out->offset = sg_in->offset;
		sg_out->bpid = sg_in->bpid;

		qm_sg_entry_set64(sg_in, addr);
		sg_in->length = length;
		sg_in->offset = offset;
		sg_in->bpid = bpid;
	}
}

/*****************************************************************************/
struct argp_option options[] = {
	{"mode", 'm', "TEST MODE", 0,
	 "\n\r\ttest mode: provide following number\n\r"
		"\t\t1 for perf\n\r"
		"\t\t2 for cipher\n\r"
		"\tFollowing two combinations are valid only\n\r"
		"\tand all options are mandatory:\n\r"
		"\t\t-m 1 -s <buf_size> -n <buf_num_per_core>\n\r"
		"\t\t-p <proto> -l <itr_num>\n\r"
		"\t\t-m 2 -t <test_set> -n <buf_num_per_core>\n\r"
		"\t\t-p <proto> -l <itr_num>\n"},
	{"proto", 'p', "PROTOCOL", 0,
	 "\n\r\tCryptographic operation to perform by SEC\n\r"
		"\tprovide following number\n\r"
		"\t\t1 for MACsec\n"},
	{"itrnum", 'l', "ITERATIONS", 0,
	 "\n\r\tNumber of iterations to repeat\n"},
	{"bufnum", 'n', "TOTAL BUFFERS", 0,
	 "\n\r\tTotal number of buffers(1-6400)\n\r"
		"\t\t Note: Both of Buffer size and buffer number\n\r"
		"\t\t cannot be greater than 3200 at the same time\n"},
	{"bufsize", 's', "BUFFER SIZE", 0,
	 "\n\r\tOPTION IS VALID ONLY IN PERF MODE\n\r"
		"\t\t Buffer size (64, 128 ...up to 6400)\n\r"
		"\t\t Note: Both of Buffer size and buffer number\n\r"
		"\t\t cannot be greater than 3200 at the same time\n"},
	{"ncpus", 'c', "CPUS", 0,
	 "\n\r\tOPTIONAL PARAMETER\n\r"
		"\tNumber of cpus to work for the\n\r"
		"\tapplication(1-8)\n", 0},
	{"testset", 't', "TEST SET", 0,
	 "\n\r\tOPTION IS VALID ONLY IN CIPHER MODE\n"},
	{"sec_era", 'e', "ERA", 0,
	 "\n\r\tOPTIONAL PARAMETER\n\r"
	 "\tSEC Era version on the targeted platform(2-5)\n", 0},
	{}
};

/**
 * @brief	The OPTIONS field contains a pointer to a vector of struct
 *		argp_option's
 *
 * @details	structure has the following fields
 *		name - The name of this option's long option (may be zero)
 *		key - The KEY to pass to the PARSER function when parsing this
 *		option,	and the name of this option's short option, if it is
 *		a printable ascii character
 *
 *		ARG - The name of this option's argument, if any;
 *
 *		FLAGS - Flags describing this option; some of them are:
 *			OPTION_ARG_OPTIONAL - The argument to this option is
 *				optional
 *			OPTION_ALIAS	- This option is an alias for the
 *				previous option
 *			OPTION_HIDDEN	    - Don't show this option in
 *				--help output
 *
 *		DOC - A documentation string for this option, shown in
 *			--help output
 *
 * @note	An options vector should be terminated by an option with
 *		all fields zero
 */

/**
 * @brief	Parse a single option
 *
 * @param[in]	opt - An integer specifying which option this is (taken	from
 *		the KEY field in each struct argp_option), or a special key
 *		specifying something else. We do not use any special key here
 *
 * @param[in]	arg - For an option KEY, the string value of its argument, or
 *		NULL if it has none
 *
 * @return	It should return either 0, meaning success, ARGP_ERR_UNKNOWN,
 *		meaning the given KEY wasn't recognized, or an errno value
 *		indicating some other error
 */
error_t parse_opt(int opt, char *arg, struct argp_state *state)
{
	struct parse_input_t *input = state->input;
	struct test_param *crypto_info = input->crypto_info;
	uint32_t *p_cmd_params = input->cmd_params;

	switch (opt) {
	case 'm':
		crypto_info->mode = atoi(arg);
		*p_cmd_params |= BMASK_SEC_TEST_MODE;
		printf("Test mode = %s\n", arg);
		break;

	case 't':
		crypto_info->test_set = atoi(arg);
		*p_cmd_params |= BMASK_SEC_TEST_SET;
		printf("Test set = %d\n", crypto_info->test_set);
		break;

	case 's':
		crypto_info->buf_size = atoi(arg);
		*p_cmd_params |= BMASK_SEC_BUFFER_SIZE;
		printf("Buffer size = %d\n", crypto_info->buf_size);
		break;

	case 'n':
		crypto_info->buf_num = atoi(arg);
		*p_cmd_params |= BMASK_SEC_BUFFER_NUM;
		printf("Number of Buffers per core = %d\n",
		       crypto_info->buf_num);
		break;

	case 'p':
		crypto_info->proto = atoi(arg);
		*p_cmd_params |= BMASK_SEC_ALG;
		printf("SEC cryptographic operation = %s\n", arg);
		break;

	case 'l':
		crypto_info->itr_num = atoi(arg);
		*p_cmd_params |= BMASK_SEC_ITR_NUM;
		printf("Number of iteration = %d\n", crypto_info->itr_num);
		break;

	case 'c':
		ncpus = atoi(arg);
		printf("Number of cpus = %ld\n", ncpus);
		break;

	case 'e':
		/* enum rta_sec_era starts from 0 */
		rta_sec_era = atoi(arg) - 1;
		set_user_sec_era = 1;
		printf("SEC Era version = %d\n", USER_SEC_ERA(rta_sec_era));
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 * @brief	Verifies if user gave a correct test set
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_test_set(struct test_param *crypto_info)
{
	switch (crypto_info->proto) {
	case MACSEC:
		if ((crypto_info->test_set > 0) && (crypto_info->test_set < 6))
			return 0;
		else
			goto err;
	default:
		fprintf(stderr,
			"error: Invalid Parameters: Invalid SEC protocol\n");
		return -EINVAL;
	}
err:
	fprintf(stderr,
		"error: Invalid Parameters: Test set number is invalid\n");
	return -EINVAL;
}

/**
 * @brief	Verifies if SEC Era version set by user is valid; in case the user
 *		didn't specify any era, the application with run w/ a default
 *		value
 * @return	0 on success, otherwise -1 value
 */
static int validate_sec_era_version()
{
	if (set_user_sec_era < 0) {
		printf("WARNING: Running with default SEC Era version 2!\n");
	} else {
		if ((rta_sec_era < RTA_SEC_ERA_1) ||
		    (rta_sec_era > MAX_SEC_ERA)) {
			fprintf(stderr,
				"error: Unsupported SEC Era version by RTA\n");
			return -1;
		}
		if (rta_sec_era < RTA_SEC_ERA_2) {
			printf("WARNING: Unsupported SEC Era version by"
			       " USDPAA\n");
		}
	}
	return 0;
}

/**
 * @brief	Check SEC parameters provided by user whether valid or not
 * @param[in]	g_cmd_params - Bit mask of all parameters provided by user
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_params(uint32_t g_cmd_params,
			   struct test_param *crypto_info)
{
	if ((PERF == crypto_info->mode) &&
	    BMASK_SEC_PERF_MODE == g_cmd_params) {
		/* do nothing */
	} else if ((CIPHER == crypto_info->mode) &&
		    g_cmd_params == BMASK_SEC_CIPHER_MODE) {
		if (validate_test_set(crypto_info) != 0) {
			fprintf(stderr,
				"error: Invalid Parameters: Invalid test set\n"
				"see --help option\n");
			return -EINVAL;
		}
	} else {
		fprintf(stderr,
			"error: Invalid Parameters: provide a valid"
			" combination of mandatory arguments\n"
			"see --help option\n");
		return -EINVAL;
	}

	if (crypto_info->buf_num == 0 || crypto_info->buf_num > BUFF_NUM) {
		fprintf(stderr,
			"error: Invalid Parameters: Invalid number of buffers"
			"\nsee --help option\n");
		return -EINVAL;
	}

	if (PERF == crypto_info->mode && (crypto_info->buf_size == 0 ||
					  crypto_info->buf_size %
					  L1_CACHE_BYTES != 0 ||
					  crypto_info->buf_size > BUFF_SIZE)) {
		fprintf(stderr,
			"error: Invalid Parameters: Invalid number of"
			" buffers\nsee --help option\n");
		return -EINVAL;
	}

	if (PERF == crypto_info->mode &&
	    (crypto_info->buf_num > BUFF_NUM / 2 &&
	     crypto_info->buf_size > BUFF_SIZE / 2)) {
		fprintf(stderr,
			"error: Both of number of buffers and buffer"
			" size\ncannot be more than 3200 at the same time\n"
			"see --help option\n");
		return -EINVAL;
	}

	if (validate_sec_era_version())
		return -EINVAL;

	switch (crypto_info->proto) {
	case MACSEC:
		break;
	default:
		fprintf(stderr,
			"error: Invalid Parameters: SEC protocol not supported"
			"\nsee --help option\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief	Compare encrypted data returned by SEC with	standard
 *		cipher text
 * @param[in]	params - test parameters
 * @param[in]	struct qm_fd - frame descriptor list
 * @return	    0 on success, otherwise -1 value
 */
int test_enc_match(void *params, struct qm_fd fd[])
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct qm_sg_entry *sgentry;
	uint8_t *enc_buf;
	dma_addr_t addr;
	uint32_t ind;

	for (ind = 0; ind < crypto_info->buf_num; ind++) {
		addr = qm_fd_addr_get64(&fd[ind]);
		sgentry = __dma_mem_ptov(addr);

		addr = qm_sg_entry_get64(sgentry);
		enc_buf = __dma_mem_ptov(addr);

		if (test_vector_match((uint32_t *)enc_buf,
				      (uint32_t *)ref_test_vector.ciphertext,
				      crypto_info->rt.output_buf_size *
				      BITS_PER_BYTE) != 0) {
			fprintf(stderr,
				"error: %s: Encrypted frame %d"
				" with CIPHERTEXT test vector doesn't"
				" match\n", __func__, ind + 1);

			return -1;
		}
	}

	printf("All %s encrypted frame match found with cipher text\n",
	       protocol);

	return 0;
}

/**
 * @brief	Compare decrypted data returned by SEC with plain text
 *		input data
 * @param[in]	params - test parameters
 * @param[in]	struct qm_fd - frame descriptor list
 * @return	0 on success, otherwise -1 value
 */
int test_dec_match(void *params, struct qm_fd fd[])
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct qm_sg_entry *sgentry;
	uint8_t *dec_buf;
	uint8_t plain_data = 0;
	dma_addr_t addr;
	uint32_t i, ind;

	for (ind = 0; ind < crypto_info->buf_num; ind++) {
		addr = qm_fd_addr_get64(&fd[ind]);
		sgentry = __dma_mem_ptov(addr);

		addr = qm_sg_entry_get64(sgentry);
		dec_buf = __dma_mem_ptov(addr);
		if (CIPHER == crypto_info->mode) {
			if (test_vector_match((uint32_t *)dec_buf, (uint32_t *)
					      ref_test_vector.plaintext,
					      ref_test_vector.length) != 0) {
				fprintf(stderr,
					"error: %s: Decrypted frame %d with"
					" PLAINTEXT test vector doesn't"
					" match\n", __func__, ind + 1);
				print_frame_desc(&fd[ind]);
				return -1;
			}
		} else {
			for (i = 0; i < crypto_info->buf_size; i++) {
				if (dec_buf[i] != plain_data) {
					fprintf(stderr,
						"error: %s: %s decrypted frame"
						" %d doesn't match!\n",
						 __func__, protocol, ind + 1);
					print_frame_desc(&fd[ind]);
					return -1;
				}
				plain_data++;
			}
		}
	}
	printf("All %s decrypted frame matches initial text\n", protocol);

	return 0;
}

/* argp structure itself of argp parser */
static struct argp argp = { options, parse_opt, NULL, NULL, NULL, NULL, NULL };

/**
 * @brief	Main function of SEC Test Application
 * @param[in]	argc - Argument count
 * @param[in]	argv - Argument list pointer
 */
int main(int argc, char *argv[])
{
	long num_online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct thread_data thread_data[num_online_cpus];
	int err;
	uint32_t g_cmd_params = 0, i;
	struct test_param crypto_info;
	struct parse_input_t input;
	struct test_cb crypto_cb;

	ncpus = num_online_cpus;

	input.cmd_params = &g_cmd_params;
	input.crypto_info = &crypto_info;

	/* Parse and check input arguments */
	argp_parse(&argp, argc, argv, 0, 0, &input);

	err = validate_params(g_cmd_params, &crypto_info);
	if (err)
		error(err, err, "error: validate_params failed!");

	/* Get the number of cores */
	if (ncpus < 1 || ncpus > num_online_cpus) {
		fprintf(stderr,
			"error: Invalid Parameters: Number of cpu's given in"
			" argument is more than the active cpu's\n");
		exit(-EINVAL);
	}

	printf("\nWelcome to FSL SEC application!\n");

	err = of_init();
	if (err)
		error(err, err, "error: of_init() failed");

	/* map DMA memory */
	dma_mem_generic = dma_mem_create(DMA_MAP_FLAG_ALLOC, NULL, 0x1000000);
	if (!dma_mem_generic) {
		pr_err("DMA memory initialization failed\n");
		exit(EXIT_FAILURE);
	}

	/* Initialize barrier for all the threads! */
	err = pthread_barrier_init(&app_barrier, NULL, ncpus);
	if (err)
		error(err, err, "error: unable to initialize pthread_barrier");

	err = qman_global_init();
	if (err)
		error(err, err, "error: qman global init failed");

	/* Prepare and create compound fds */
	err = prepare_test_frames(&crypto_info);
	if (err)
		error(err, err, "error: preparing test frames failed");

	set_crypto_cbs(&crypto_cb);

	for (i = 0; i < ncpus; i++) {
		thread_data[i].test_param = (void *)(&crypto_info);
		thread_data[i].test_cb = (void *)(&crypto_cb);
	}

	/* Starting threads on all active cpus */
	err = start_threads(thread_data, ncpus, 1, worker_fn);
	if (err)
		error(err, err, "error: start_threads failure");

	/* Wait for all the threads to finish */
	wait_threads(thread_data, ncpus);

	validate_test(crypto_info.itr_num, crypto_info.buf_num,
		      crypto_info.buf_size);

	free_fd(crypto_info.buf_num);
	of_finish();
	exit(EXIT_SUCCESS);
}

/**
 * @brief	Returns number of iterations for test
 * @param[in]	params - test parameters
 * @return	Number of iterations for test
 */
int get_num_of_iterations(void *params)
{
	return ((struct test_param *)params)->itr_num;
}

/**
 * @brief	Returns number of buffers for test
 * @param[in]	params - test parameters
 * @return	Number of buffers for test
 */
inline int get_num_of_buffers(void *params)
{
	return ((struct test_param *)params)->buf_num;
}

/**
 * @brief	Returns test mode - CIPHER/PERF
 * @param[in]	params - test parameters
 * @return	Test mode - CIPHER/PERF
 */
inline enum test_mode get_test_mode(void *params)
{
	return ((struct test_param *)params)->mode;
}

/**
 * @brief	Returns if test requires authentication
 * @param[in]	params - test parameters
 * @return	0 - doesn't require authentication/1 - requires authentication
 */
inline uint8_t requires_authentication(void)
{
	return 0;
}

/**
 * @brief	Returns number of cpus for test
 * @param[in]	params - test parameters
 * @return	Number of cpus for test
 */
inline long get_num_of_cpus(void)
{
	return ncpus;
}

/**
 * @brief	Returns thread barrier for test
 * @param[in]	None
 * @return	Thread barrier
 */
inline pthread_barrier_t get_thread_barrier(void)
{
	return app_barrier;
}

/**
 * @brief	Set specific callbacks for test
 * @param[in]	crypto_cb - structure that holds reference to test callbacks
 * @return	None
 */
static void set_crypto_cbs(struct test_cb *crypto_cb)
{
	crypto_cb->set_sec_descriptor = setup_sec_descriptor;
	crypto_cb->is_enc_match = test_enc_match;
	crypto_cb->is_dec_match = test_dec_match;
	crypto_cb->set_enc_buf = set_enc_buf;
	crypto_cb->set_dec_buf = set_dec_buf;
	crypto_cb->get_num_of_iterations = get_num_of_iterations;
	crypto_cb->get_num_of_buffers = get_num_of_buffers;
	crypto_cb->get_test_mode = get_test_mode;
	crypto_cb->get_num_of_cpus = get_num_of_cpus;
	crypto_cb->requires_authentication = requires_authentication;
	crypto_cb->get_thread_barrier = get_thread_barrier;
}
