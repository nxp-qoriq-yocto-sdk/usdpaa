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

static unsigned authnct = 0; /**< By default, do both encrypt & decrypt */

/***********************************************/

/**
 * @brief	Initializes the reference test vector for MACsec
 * @details	Initializes key, length and other variables for the protocol
 * @param[in]	crypto_info - test parameters
 * @return	None
 */
void init_rtv_macsec(struct test_param *crypto_info)
{
	struct macsec_params *macsec_params;

	macsec_params = &crypto_info->proto_params.macsec_params;
	if (macsec_params->cipher_alg == MACSEC_CIPHER_TYPE_GMAC) {
		crypto_info->test_set += MACSEC_GMAC_TEST_ID;
		authnct = 1;
	}

	strcpy(protocol, "MACsec");
	ref_test_vector.key =
		(uintptr_t)macsec_reference_key[crypto_info->test_set - 1];

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

void init_rtv_wimax_aes_ccm_128(struct test_param *crypto_info)
{
	strcpy(protocol, "WIMAX");
	ref_test_vector.key = (uintptr_t)malloc(WIMAX_KEY_SIZE);
	memcpy((uint8_t *)(uintptr_t)ref_test_vector.key,
	       wimax_reference_key[crypto_info->test_set - 1],
	       WIMAX_KEY_SIZE);

	if (CIPHER == crypto_info->mode)
		init_rtv_wimax_cipher(crypto_info->test_set);

	/* set the WiMAX PDB for test */
	memcpy(&ref_test_vector.pdb.wimax.pn,
	       &wimax_reference_pn[crypto_info->test_set - 1],
	       WIMAX_PN_SIZE);

	if (crypto_info->proto_params.wimax_params.ar) {
		ref_test_vector.pdb.wimax.decap_opts = WIMAX_PDBOPTS_AR;
		ref_test_vector.pdb.wimax.ar_len =
			crypto_info->proto_params.wimax_params.ar_len;
	}

	if (PERF == crypto_info->mode) {
		if (crypto_info->proto_params.wimax_params.ofdma)
			ref_test_vector.flags.wimax.protinfo =
				OP_PCL_WIMAX_OFDMA;
		else
			ref_test_vector.flags.wimax.protinfo =
				OP_PCL_WIMAX_OFDM;

		if (crypto_info->proto_params.wimax_params.fcs) {
			ref_test_vector.pdb.wimax.encap_opts =
				WIMAX_PDBOPTS_FCS;

			ref_test_vector.pdb.wimax.decap_opts |=
				WIMAX_PDBOPTS_FCS;
		}
	} else {
		ref_test_vector.pdb.wimax.encap_opts =
			wimax_reference_pdb_opts[crypto_info->test_set - 1];
		ref_test_vector.pdb.wimax.decap_opts |=
			wimax_reference_pdb_opts[crypto_info->test_set - 1];
		ref_test_vector.flags.wimax.protinfo =
			wimax_reference_protinfo[crypto_info->test_set - 1];
	}
}

void init_rtv_wimax_cipher(unsigned test_set)
{
	ref_test_vector.length =
	    wimax_reference_length[test_set - 1];

	ref_test_vector.plaintext =
		(uint8_t *)malloc(NO_OF_BYTES(ref_test_vector.length));
	memcpy(ref_test_vector.plaintext,
	       wimax_reference_gmh[test_set - 1],
	       WIMAX_GMH_SIZE);
	memcpy(ref_test_vector.plaintext + WIMAX_GMH_SIZE,
	       wimax_reference_payload[test_set - 1],
	       NO_OF_BYTES(ref_test_vector.length) - WIMAX_GMH_SIZE);

	ref_test_vector.ciphertext =
		(uint8_t *)malloc(NO_OF_BYTES(ref_test_vector.length) +
				  WIMAX_PN_SIZE +
				  WIMAX_ICV_SIZE +
				  WIMAX_FCS_SIZE);
	memcpy(ref_test_vector.ciphertext,
	       wimax_reference_enc_gmh[test_set - 1],
	       WIMAX_GMH_SIZE);
	memcpy(ref_test_vector.ciphertext + WIMAX_GMH_SIZE,
	       wimax_reference_enc_pn[test_set - 1],
	       WIMAX_PN_SIZE);
	memcpy(ref_test_vector.ciphertext + WIMAX_GMH_SIZE + WIMAX_PN_SIZE,
	       wimax_reference_enc_payload[test_set - 1],
	       NO_OF_BYTES(ref_test_vector.length) - WIMAX_GMH_SIZE);
	memcpy(ref_test_vector.ciphertext + WIMAX_PN_SIZE +
			NO_OF_BYTES(ref_test_vector.length),
	       wimax_reference_enc_icv[test_set - 1],
	       WIMAX_ICV_SIZE);
	memcpy(ref_test_vector.ciphertext +
	       WIMAX_PN_SIZE + NO_OF_BYTES(ref_test_vector.length) +
			WIMAX_ICV_SIZE,
	       wimax_reference_fcs[test_set - 1],
	       WIMAX_FCS_SIZE);
}

void test_cleanup_wimax(struct test_param *crypto_info)
{
	if (CIPHER == crypto_info->mode) {
		free(ref_test_vector.ciphertext);
		free(ref_test_vector.plaintext);
	}
	free((void *)ref_test_vector.key);
}

void set_enc_buf_cb_wimax(struct qm_fd *fd, uint8_t *buf,
			  struct test_param *crypto_info)
{
	uint8_t plain_data = 0;
	int i;

	/*
	 * Copy the input plain-text data.
	 * For WiMAX in PERF mode set the input plain-text data
	 * as GMH aware frames.
	 */
	if (CIPHER == crypto_info->mode) {
		memcpy(buf, ref_test_vector.plaintext, crypto_info->buf_size);
	} else {
		/* GMH Header Type bit shall be set to zero. */
		buf[0] &= 0x7f;
		/*
		 * Set CRC indicator bit to value one if FCS
		 * is included in the PDU.
		 */
		if (crypto_info->proto_params.wimax_params.fcs)
			buf[1] |= 0x40;
		/* Set the input frame length */
		buf[1] &= ~0x7;
		buf[1] |= (crypto_info->buf_size >> 8) & 0x7;
		buf[2] = crypto_info->buf_size & 0xFF;

		for (i = WIMAX_GMH_SIZE; i < crypto_info->buf_size; i++)
			buf[i] = plain_data++;
	}
}

int test_enc_match_cb_wimax(int fd_ind, uint8_t *enc_buf,
			    struct test_param *crypto_info)
{
	if ((fd_ind == 0) &&
	    (test_vector_match((uint32_t *)enc_buf,
			(uint32_t *)ref_test_vector.ciphertext,
			crypto_info->rt.output_buf_size * BITS_PER_BYTE) != 0))
		return -1;

	return 0;
}

int test_dec_match_cb_wimax(int fd_ind, uint8_t *dec_buf,
			    struct test_param *crypto_info)
{
	uint8_t plain_data = 0;
	int i;

	if (CIPHER == crypto_info->mode) {
		if ((fd_ind == 0) &&
		    (test_vector_match((uint32_t *)dec_buf,
				       (uint32_t *)ref_test_vector.plaintext,
				       ref_test_vector.length) != 0))
			return -1;
	} else
		for (i = WIMAX_GMH_SIZE; i < crypto_info->buf_size; i++)
			if (dec_buf[i] != plain_data++)
				return -1;

	return 0;
}

/*
 * NOTE: this function will be called iff HFN override is enabled; thus
 * no need to check if hfn_ov_en is true.
 */
void set_enc_buf_cb_pdcp(struct qm_fd *fd, uint8_t *buf,
			 struct test_param *crypto_info)
{
	int i;
	uint8_t plain_data = 0;
	uint8_t offset = 0;
	uint32_t fd_cmd;

	if (CIPHER == crypto_info->mode) {
		fd_cmd = PDCP_DPOVRD_HFN_OV_EN | ref_test_vector.pdb.pdcp.hfn;
		if (rta_sec_era > RTA_SEC_ERA_2)
			fd->status = fd_cmd;
		else {
			*(uint32_t *)buf = fd_cmd;
			offset = PDCP_P4080REV2_HFN_OV_BUFLEN;
		}
		memcpy(buf + offset, ref_test_vector.plaintext,
		       crypto_info->buf_size);
	} else {
		fd_cmd = PDCP_DPOVRD_HFN_OV_EN |
			 crypto_info->proto_params.pdcp_params.hfn_ov_val;
		if (rta_sec_era > RTA_SEC_ERA_2)
			fd->status = fd_cmd;
		else {
			*(uint32_t *)buf = fd_cmd;
			offset = PDCP_P4080REV2_HFN_OV_BUFLEN;
		}
		for (i = offset; i < crypto_info->buf_size; i++)
			buf[i] = plain_data++;
	}
}

/*
 * NOTE: this function will be called iff HFN override is enabled; thus
 * no need to check if hfn_ov_en is true.
 */
void set_dec_buf_cb_pdcp(struct qm_fd *fd, uint8_t *buf,
			 struct test_param *crypto_info)
{
	uint32_t fd_cmd;
	if (CIPHER == crypto_info->mode) {
		fd_cmd = PDCP_DPOVRD_HFN_OV_EN | ref_test_vector.pdb.pdcp.hfn;
		if (rta_sec_era > RTA_SEC_ERA_2)
			fd->status = fd_cmd;
		else
			*(uint32_t *)buf = fd_cmd;
	} else {
		fd_cmd = PDCP_DPOVRD_HFN_OV_EN |
			 crypto_info->proto_params.pdcp_params.hfn_ov_val;
		if (rta_sec_era > RTA_SEC_ERA_2)
			fd->status = fd_cmd;
		else
			*(uint32_t *)buf = fd_cmd;
	}
}

/*
 * NOTE: This function is called iff SEC ERA is 2 AND HFN override
 * is enabled.
 */
int test_enc_match_cb_pdcp(int fd_ind, uint8_t *enc_buf,
			    struct test_param *crypto_info)
{
	return test_vector_match((uint32_t *)(enc_buf +
					PDCP_P4080REV2_HFN_OV_BUFLEN),
				 (uint32_t *)ref_test_vector.ciphertext,
				 (crypto_info->rt.output_buf_size -
					PDCP_P4080REV2_HFN_OV_BUFLEN) *
				 BITS_PER_BYTE);
}

/*
 * NOTE: This function is called iff SEC ERA is 2 AND HFN override
 * is enabled.
 */
int test_dec_match_cb_pdcp(int fd_ind, uint8_t *dec_buf,
			    struct test_param *crypto_info)
{
	uint8_t plain_data = 0;
	int i;

	if (CIPHER == crypto_info->mode)
		return  test_vector_match(
				  (uint32_t *)(dec_buf +
					PDCP_P4080REV2_HFN_OV_BUFLEN),
				  (uint32_t *)ref_test_vector.plaintext,
				  ref_test_vector.length);
	else
		for (i = PDCP_P4080REV2_HFN_OV_BUFLEN;
		     i < crypto_info->buf_size;
		     i++)
			if (dec_buf[i] != plain_data++)
				return -1;

	return 0;
}

void init_rtv_pdcp(struct test_param *crypto_info)
{
	struct pdcp_params *pdcp_params =
			&crypto_info->proto_params.pdcp_params;

	switch (pdcp_params->type) {
	case PDCP_CONTROL_PLANE:
		init_rtv_pdcp_c_plane(crypto_info);
		break;

	case PDCP_DATA_PLANE:
		init_rtv_pdcp_u_plane(crypto_info);
		break;

	case PDCP_SHORT_MAC:
		init_rtv_pdcp_short_mac(crypto_info);
		break;

	default:
		fprintf(stderr, "Unknown PDCP PDU type %d"
			"(should never reach here)\n",
			pdcp_params->type);
		assert(0);
		return;
	}
}
void init_rtv_pdcp_c_plane(struct test_param *crypto_info)
{
	const int proto = PDCP_CPLANE_TEST_ARRAY_OFFSET(crypto_info);
	uint8_t *cipherkey, *authkey;

	strcpy(protocol, pdcp_test_params[proto].name);

	cipherkey = __dma_mem_memalign(L1_CACHE_BYTES, PDCP_MAX_KEY_LEN);
	memcpy(cipherkey, pdcp_test_crypto_key[proto], PDCP_MAX_KEY_LEN);

	authkey = __dma_mem_memalign(L1_CACHE_BYTES, PDCP_MAX_KEY_LEN);
	memcpy(authkey, pdcp_test_auth_key[proto], PDCP_MAX_KEY_LEN);

	ref_test_vector.cipher_alg = pdcp_test_params[proto].cipher_algorithm;
	ref_test_vector.dma_addr_key = __dma_mem_vtop(cipherkey);
	ref_test_vector.cipher_keylen = PDCP_MAX_KEY_LEN;

	ref_test_vector.auth_alg = pdcp_test_params[proto].integrity_algorithm;
	ref_test_vector.dma_addr_auth_key = __dma_mem_vtop(authkey);
	ref_test_vector.auth_keylen = PDCP_MAX_KEY_LEN;

	ref_test_vector.pdb.pdcp.bearer = pdcp_test_bearer[proto];
	ref_test_vector.pdb.pdcp.direction =
			pdcp_test_packet_direction[proto];

	ref_test_vector.pdb.pdcp.hfn = pdcp_test_hfn[proto];
	ref_test_vector.pdb.pdcp.hfn_threshold =
			pdcp_test_hfn_threshold[proto];

	if (CIPHER == crypto_info->mode) {
		ref_test_vector.length =
				NO_OF_BITS(pdcp_test_data_in_len[proto]);
		ref_test_vector.plaintext = pdcp_test_data_in[proto];
		ref_test_vector.ciphertext = pdcp_test_data_out[proto];
	}
}

void init_rtv_pdcp_u_plane(struct test_param *crypto_info)
{
	const int proto = PDCP_UPLANE_TEST_ARRAY_OFFSET(crypto_info);
	uint8_t *cipherkey;
	strcpy(protocol, pdcp_test_params[proto].name);

	cipherkey = __dma_mem_memalign(L1_CACHE_BYTES, PDCP_MAX_KEY_LEN);
	memcpy(cipherkey, pdcp_test_crypto_key[proto], PDCP_MAX_KEY_LEN);

	ref_test_vector.cipher_alg = pdcp_test_params[proto].cipher_algorithm;
	ref_test_vector.dma_addr_key = __dma_mem_vtop(cipherkey);
	ref_test_vector.cipher_keylen = PDCP_MAX_KEY_LEN;

	ref_test_vector.pdb.pdcp.bearer = pdcp_test_bearer[proto];
	ref_test_vector.pdb.pdcp.direction =
			pdcp_test_packet_direction[proto];
	ref_test_vector.pdb.pdcp.hfn = pdcp_test_hfn[proto];
	ref_test_vector.pdb.pdcp.hfn_threshold =
			pdcp_test_hfn_threshold[proto];
	ref_test_vector.pdb.pdcp.sns = pdcp_test_data_sn_size[proto];

	if (CIPHER == crypto_info->mode) {
		ref_test_vector.length =
				NO_OF_BITS(pdcp_test_data_in_len[proto]);
		ref_test_vector.plaintext = pdcp_test_data_in[proto];
		ref_test_vector.ciphertext = pdcp_test_data_out[proto];
	}
}

void init_rtv_pdcp_short_mac(struct test_param *crypto_info)
{
	const int proto = PDCP_SHORT_MAC_TEST_ARRAY_OFFSET(crypto_info);
	uint8_t *authkey;
	strcpy(protocol, pdcp_test_params[proto].name);

	authkey = __dma_mem_memalign(L1_CACHE_BYTES, PDCP_MAX_KEY_LEN);

	memcpy(authkey, pdcp_test_auth_key[proto], PDCP_MAX_KEY_LEN);

	ref_test_vector.auth_alg = pdcp_test_params[proto].integrity_algorithm;

	ref_test_vector.dma_addr_auth_key = __dma_mem_vtop(authkey);
	ref_test_vector.auth_keylen = PDCP_MAX_KEY_LEN;

	if (CIPHER == crypto_info->mode) {
		ref_test_vector.length =
				NO_OF_BITS(pdcp_test_data_in_len[proto]);
		ref_test_vector.plaintext = pdcp_test_data_in[proto];
		ref_test_vector.ciphertext = pdcp_test_data_out[proto];
	}

	authnct = 1;
}

void init_rtv_srtp(struct test_param *crypto_info)
{
	strcpy(protocol, "SRTP");
	ref_test_vector.auth_key =
	    (uintptr_t)srtp_reference_auth_key[crypto_info->test_set - 1];
	ref_test_vector.auth_keylen =
	    srtp_reference_auth_keylen[crypto_info->test_set - 1];

	ref_test_vector.key =
	    (uintptr_t)srtp_reference_cipher_key[crypto_info->test_set - 1];
	ref_test_vector.cipher_keylen =
	    srtp_reference_cipher_keylen[crypto_info->test_set - 1];

	ref_test_vector.pdb.srtp.cipher_salt =
	    srtp_reference_cipher_salt[crypto_info->test_set - 1];
	ref_test_vector.pdb.srtp.n_tag =
	    srtp_reference_n_tag[crypto_info->test_set - 1];
	ref_test_vector.pdb.srtp.roc =
	    srtp_reference_roc[crypto_info->test_set - 1];
	ref_test_vector.pdb.srtp.seqnum =
	    srtp_reference_seq_num[crypto_info->test_set - 1];

	if (CIPHER == crypto_info->mode) {
		ref_test_vector.length =
		    srtp_reference_length[crypto_info->test_set - 1];
		ref_test_vector.plaintext =
		    srtp_reference_plaintext[crypto_info->test_set - 1];
		ref_test_vector.ciphertext =
		    srtp_reference_ciphertext[crypto_info->test_set - 1];
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
	unsigned extra_instr = 4;

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

	/*
	 * Use CONTEXT2 to save the current value of PN. CONTEXT2 _should_ be
	 * unused by MACSEC protocol.
	 */
	MOVE(DESCBUF, 5 * 4, CONTEXT2, 0, IMM(4), WITH(0));
	program->buffer[program->current_pc++] = op_line;
	MOVE(CONTEXT2, 0, DESCBUF, 5 * 4, IMM(4), WITH(WAITCOMP));
	STORE(SHAREDESCBUF, 5 * 4, NONE, 4, 0);
	/* Wait for all bus transactions to finish before stopping. */
	JUMP(IMM(0), HALT_STATUS, ALL_TRUE, WITH(CALM));

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
	init_rtv_macsec,
	init_rtv_wimax_aes_ccm_128,
	init_rtv_pdcp,
	init_rtv_srtp
};

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
	case WIMAX:
		crypto_info->rt.output_buf_size = crypto_info->buf_size +
						WIMAX_PN_SIZE +
						WIMAX_ICV_SIZE;
		if ((CIPHER == crypto_info->mode) ||
		    crypto_info->proto_params.wimax_params.fcs)
			crypto_info->rt.output_buf_size += WIMAX_FCS_SIZE;
		break;

	case PDCP:
		switch (crypto_info->proto_params.pdcp_params.type) {
		case PDCP_CONTROL_PLANE:
		case PDCP_SHORT_MAC:
			crypto_info->rt.output_buf_size =
				crypto_info->buf_size + PDCP_MAC_I_LEN;
			break;

		case PDCP_DATA_PLANE:
			crypto_info->rt.output_buf_size = crypto_info->buf_size;
			break;

		default:
			fprintf(stderr, "error: %s: PDCP protocol type %d not"
				"supported\n",
				__func__,
				crypto_info->proto_params.pdcp_params.type);
			return -EINVAL;
		}

		if (crypto_info->proto_params.pdcp_params.hfn_ov_en &&
			rta_sec_era == RTA_SEC_ERA_2) {
			/* The input buffer is 4 bytes longer */
			p_rt->input_buf_capacity +=
					PDCP_P4080REV2_HFN_OV_BUFLEN;
			p_rt->input_buf_length += PDCP_P4080REV2_HFN_OV_BUFLEN;

			crypto_info->rt.output_buf_size +=
					PDCP_P4080REV2_HFN_OV_BUFLEN;
		}

		break;

	case SRTP:
		crypto_info->rt.output_buf_size =
			   crypto_info->buf_size + SRTP_MAX_ICV_SIZE;
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
	struct alginfo cipher_info, auth_info;
	uint32_t *shared_desc = NULL;
	unsigned shared_desc_len;
	unsigned sw_hfn_ov = 0;
	int i, hfn_val;

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
		cipher_info.key = ref_test_vector.key;
		cipher_info.keylen = MACSEC_KEY_SIZE;
		cipher_info.key_enc_flags = 0;
		cipher_info.algtype =
			crypto_info->proto_params.macsec_params.cipher_alg;
		if (ENCRYPT == mode)
			cnstr_shdsc_macsec_encap(shared_desc,
						 &shared_desc_len,
						 &cipher_info,
						 ref_test_vector.pdb.macsec.sci,
						 ref_test_vector.pdb.macsec.
						 ethertype,
						 ref_test_vector.pdb.macsec.
						 tci_an,
						 ref_test_vector.pdb.macsec.pn);

		else
			cnstr_shdsc_macsec_decap(shared_desc,
						 &shared_desc_len,
						 &cipher_info,
						 ref_test_vector.pdb.macsec.sci,
						 ref_test_vector.pdb.macsec.pn);
		macsec_set_pn_constant(shared_desc, &shared_desc_len);
		break;
	case WIMAX:
		cipher_info.key = ref_test_vector.key;
		cipher_info.keylen = WIMAX_KEY_SIZE;
		cipher_info.key_enc_flags = 0;
		if (ENCRYPT == mode)
			cnstr_shdsc_wimax_encap(shared_desc,
					&shared_desc_len,
					ref_test_vector.pdb.wimax.encap_opts,
					ref_test_vector.pdb.wimax.pn,
					ref_test_vector.flags.wimax.protinfo,
					&cipher_info);
		else
			cnstr_shdsc_wimax_decap(shared_desc,
					&shared_desc_len,
					ref_test_vector.pdb.wimax.decap_opts,
					ref_test_vector.pdb.wimax.pn,
					ref_test_vector.pdb.wimax.ar_len,
					ref_test_vector.flags.wimax.protinfo,
					&cipher_info);
		break;

	case PDCP:
		cipher_info.algtype = ref_test_vector.cipher_alg;
		cipher_info.key = ref_test_vector.dma_addr_key;
		cipher_info.keylen = ref_test_vector.cipher_keylen;
		cipher_info.key_enc_flags = 0;

		auth_info.algtype = ref_test_vector.auth_alg;
		auth_info.key = ref_test_vector.dma_addr_auth_key;
		auth_info.keylen = ref_test_vector.auth_keylen;
		auth_info.key_enc_flags = 0;

		sw_hfn_ov = ((rta_sec_era == RTA_SEC_ERA_2) &&
			(crypto_info->proto_params.pdcp_params.hfn_ov_en));
		hfn_val = crypto_info->proto_params.pdcp_params.hfn_ov_en ?
			  crypto_info->proto_params.pdcp_params.hfn_ov_val :
			  ref_test_vector.pdb.pdcp.hfn;

		switch (crypto_info->proto_params.pdcp_params.type) {
		case PDCP_CONTROL_PLANE:
			if (ENCRYPT == mode)
				cnstr_shdsc_pdcp_c_plane_encap(shared_desc,
					&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
					1,
					hfn_val,
					ref_test_vector.pdb.pdcp.bearer,
					ref_test_vector.pdb.pdcp.direction,
					ref_test_vector.pdb.pdcp.hfn_threshold,
					&cipher_info,
					&auth_info,
					sw_hfn_ov);
			else
				cnstr_shdsc_pdcp_c_plane_decap(shared_desc,
					&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
					1,
					hfn_val,
					ref_test_vector.pdb.pdcp.bearer,
					ref_test_vector.pdb.pdcp.direction,
					ref_test_vector.pdb.pdcp.hfn_threshold,
					&cipher_info,
					&auth_info,
					sw_hfn_ov);
			break;

		case PDCP_DATA_PLANE:

			if (ENCRYPT == mode)
				cnstr_shdsc_pdcp_u_plane_encap(shared_desc,
					&shared_desc_len,
/*
* This is currently hardcoded. The application doesn't allow for
* proper retrieval of PS.
*/
					1,
					ref_test_vector.pdb.pdcp.sns,
					hfn_val,
					ref_test_vector.pdb.pdcp.bearer,
					ref_test_vector.pdb.pdcp.direction,
					ref_test_vector.pdb.pdcp.hfn_threshold,
					&cipher_info,
					sw_hfn_ov);
			else
				cnstr_shdsc_pdcp_u_plane_decap(shared_desc,
					&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
*/
					1,
					ref_test_vector.pdb.pdcp.sns,
					hfn_val,
					ref_test_vector.pdb.pdcp.bearer,
					ref_test_vector.pdb.pdcp.direction,
					ref_test_vector.pdb.pdcp.hfn_threshold,
					&cipher_info,
					sw_hfn_ov);
			break;

		case PDCP_SHORT_MAC:
			if (ENCRYPT == mode)
				cnstr_shdsc_pdcp_short_mac(shared_desc,
					&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
					1,
					&auth_info);
			break;
		}
		break;

	case SRTP:
		cipher_info.key = ref_test_vector.key;
		cipher_info.keylen = ref_test_vector.cipher_keylen;
		cipher_info.key_enc_flags = 0;
		auth_info.key = ref_test_vector.auth_key;
		auth_info.keylen = ref_test_vector.auth_keylen;
		auth_info.key_enc_flags = ENC;
		if (ENCRYPT == mode)
			cnstr_shdsc_srtp_encap(shared_desc,
					&shared_desc_len,
					&auth_info,
					&cipher_info,
					ref_test_vector.pdb.srtp.n_tag,
					ref_test_vector.pdb.srtp.roc,
					ref_test_vector.pdb.srtp.cipher_salt);
		else
			cnstr_shdsc_srtp_decap(shared_desc,
					&shared_desc_len,
					&auth_info,
					&cipher_info,
					ref_test_vector.pdb.srtp.n_tag,
					ref_test_vector.pdb.srtp.roc,
					ref_test_vector.pdb.srtp.seqnum,
					ref_test_vector.pdb.srtp.cipher_salt);
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

		buf = __dma_mem_ptov(in_buf);

		if (crypto_info->set_enc_buf_cb)
			crypto_info->set_enc_buf_cb(&fd[ind], buf, crypto_info);
		else
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

		if (crypto_info->set_dec_buf_cb) {
			uint8_t *buf =  __dma_mem_ptov(addr);
			crypto_info->set_dec_buf_cb(&fd[ind], buf, crypto_info);
		}
	}
}

/*****************************************************************************/
struct argp_option options[] = {
	{"mode", 'm', "TEST MODE", 0,
	"Test mode:"
	"\n\t1 for perf"
	"\n\t2 for cipher"
	"\n\nFollowing two combinations are valid only"
	" and all options are mandatory:"
	"\n-m 1 -s <buf_size> -n <buf_num_per_core> -p <proto> -l <itr_num>"
	"\n-m 2 -t <test_set> -n <buf_num_per_core> -p <proto> -l <itr_num>"
	"\n"},
	{"proto", 'p', "PROTOCOL", 0,
	"Cryptographic operation to perform by SEC:"
	"\n 1 for MACsec"
	"\n 2 for WiMAX"
	"\n 3 for PDCP"
	"\n 4 for SRTP"
	"\n"},
	{"itrnum", 'l', "ITERATIONS", 0,
	"Number of iterations to repeat"
	"\n"},
	{"bufnum", 'n', "TOTAL BUFFERS", 0,
	"Total number of buffers (1-6400)."
	" Both of Buffer size and buffer number"
	" cannot be greater than 3200 at the same time."
	"\n"},
	{"bufsize", 's', "BUFSIZE", 0,
	"OPTION IS VALID ONLY IN PERF MODE"
	"\n\nBuffer size (64, 128 ... up to 6400)."
	" Note: Both of Buffer size and buffer number"
	" cannot be greater than 3200 at the same time."
	"\nThe WiMAX frame size, including the FCS if"
	" present, must be shorter than 2048 bytes."
	"\n"},
	{"ncpus", 'c', "CPUS", 0,
	"OPTIONAL PARAMETER"
	"\n\nNumber of cpus to work for the application(1-8)"
	"\n"},
	{"testset", 't', "TEST SET", 0,
	"OPTION IS VALID ONLY IN CIPHER MODE"
	"\n"},
	{"sec_era", 'e', "ERA", 0,
	"OPTIONAL PARAMETER"
	"\n\nSEC Era version on the targeted platform(2-5)"
	"\n"},
	{0}
};

/**
 * @brief	Parse MACSEC related command line options
 *
 */
static error_t macsec_parse_opts(int key, char *arg, struct argp_state *state)
{
	struct parse_input_t *input = state->input;
	struct test_param *crypto_info = input->crypto_info;
	struct macsec_params *macsec_params;

	macsec_params =  &crypto_info->proto_params.macsec_params;
	switch (key) {
	case 'o':
		macsec_params->cipher_alg = atoi(arg);
		printf("MACSEC processing = %d\n", macsec_params->cipher_alg);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 * @brief	Parse WiMAX related command line options
 *
 */
static error_t wimax_parse_opts(int key, char *arg, struct argp_state *state)
{
	struct parse_input_t *input = state->input;
	uint32_t *p_proto_params = input->proto_params;
	struct test_param *crypto_info = input->crypto_info;

	switch (key) {
	case 'a':
		*p_proto_params |= BMASK_WIMAX_OFDMA_EN;
		fprintf(stdout, "WiMAX OFDMa selected\n");
		break;

	case 'f':
		*p_proto_params |= BMASK_WIMAX_FCS_EN;
		fprintf(stdout, "WiMAX FCS enabled\n");
		break;

	case 'w':
		*p_proto_params |= BMASK_WIMAX_AR_EN;
		crypto_info->proto_params.wimax_params.ar_len = atoi(arg);
		fprintf(stdout, "Anti-Replay Length = %d\n", atoi(arg));
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 * @brief	Parse PDCP related command line options
 *
 */
static error_t pdcp_parse_opts(int key, char *arg, struct argp_state *state)
{
	struct parse_input_t *input = state->input;
	struct test_param *crypto_info = input->crypto_info;
	struct pdcp_params *pdcp_params;
	uint32_t *p_proto_params = input->proto_params;

	pdcp_params = &crypto_info->proto_params.pdcp_params;
	switch (key) {
	case 'y':
		pdcp_params->type = atoi(arg);
		*p_proto_params |= BMASK_PDCP_TYPE;
		fprintf(stdout, "PDCP type = %d\n", pdcp_params->type);
		break;

	case 'r':
		pdcp_params->cipher_alg = atoi(arg);
		*p_proto_params |= BMASK_PDCP_CIPHER;
		break;

	case 'i':
		pdcp_params->integrity_alg = atoi(arg);
		*p_proto_params |= BMASK_PDCP_INTEGRITY;
		break;

	case 'd':
		pdcp_params->downlink = 1;
		*p_proto_params |= BMASK_PDCP_DIR_DL;
		break;

	case 'x':
		pdcp_params->sn_size = atoi(arg);
		*p_proto_params |= BMASK_PDCP_SN_SIZE;
		break;

	case 'v':
		pdcp_params->hfn_ov_val = atoi(arg);
		*p_proto_params |= BMASK_PDCP_HFN_OV_EN;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

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
	int i;
	const struct argp *pr_argp;

	switch (opt) {
	case ARGP_KEY_INIT:
		/*
		 * in case ARGP_NO_HELP flag is not set, glibc adds an
		 * internal parser as root argp; the struct argp passed by our
		 * program is copied as the first child of the new root arg.
		 */
		if (!(state->flags & ARGP_NO_HELP))
			pr_argp = state->root_argp->children[0].argp;
		else
			pr_argp = state->root_argp;

		for (i = 0; pr_argp->children[i].argp; i++)
			state->child_inputs[i] = input;
		break;
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
		if ((crypto_info->test_set > 0) && (crypto_info->test_set < 5))
			return 0;
		goto err;
	case WIMAX:
		if ((crypto_info->test_set > 0) && (crypto_info->test_set < 5))
			return 0;
		else
			goto err;

	case PDCP:
	case SRTP:
		if (crypto_info->test_set == 1)
			return 0;
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
 * @brief	Check SEC parameters provided by user for MACSEC are valid
 *		or not.
 * @param[in]	g_proto_params - Bit mask of the optional parameters provided
 *		by user
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_macsec_opts(uint32_t g_proto_params,
				struct test_param *crypto_info)
{
	struct macsec_params *macsec_params;

	macsec_params = &crypto_info->proto_params.macsec_params;

	if ((macsec_params->cipher_alg == MACSEC_CIPHER_TYPE_GMAC) &&
	    (rta_sec_era < RTA_SEC_ERA_5)) {
		fprintf(stderr,
			"error: Unsupported MACsec algorithm for SEC ERAs 2-4\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief	Check SEC parameters provided by user for WiMAX are valid
 *		or not.
 * @param[in]	g_proto_params - Bit mask of the optional parameters provided
 *		by user
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_wimax_opts(uint32_t g_proto_params,
				struct test_param *crypto_info)
{
	unsigned int ar_len;

	/* Only anti-replay is allowed CIPHER mode */
	if ((CIPHER == crypto_info->mode) &&
	    ((g_proto_params & BMASK_WIMAX_AR_EN) != g_proto_params)) {
		fprintf(stderr,
			"error: WiMAX Invalid Parameters: only anti-replay is"
			" allowed in CIPHER mode\n"
			"see --help option\n");
			return -EINVAL;
	}

	if ((PERF == crypto_info->mode) &&
	    (crypto_info->buf_size > WIMAX_MAX_FRAME_SIZE)) {
		fprintf(stderr,
			"error: WiMAX Invalid Parameters: Invalid buffer size\n"
			"see --help option\n");
		return -EINVAL;
	}

	/*
	 * For WiMAX in CIPHER mode only the first frame
	 * from the first iteration can be verified if it is matching
	 * with the corresponding test vector, due to
	 * the PN incrementation by SEC for each frame processed.
	 */
	if (CIPHER == crypto_info->mode && crypto_info->itr_num != 1) {
		crypto_info->itr_num = 1;
		printf("WARNING: Running WiMAX in CIPHER mode"
		       " with only one iteration\n");
	}

	if (g_proto_params & BMASK_WIMAX_AR_EN) {
		ar_len = crypto_info->proto_params.wimax_params.ar_len;
		if ((ar_len > 64) || (ar_len < 0)) {
			fprintf(stderr,
				"error: WiMAX Anti-Replay window length cannot"
				" be greater than 64 packets\n"
				"see --help option\n");
			return -EINVAL;
		}
	}

	/* Copy the params to the relevant structure */
	crypto_info->proto_params.wimax_params.ofdma =
			g_proto_params & BMASK_WIMAX_OFDMA_EN ? 1 : 0;
	crypto_info->proto_params.wimax_params.fcs =
			g_proto_params & BMASK_WIMAX_FCS_EN ? 1 : 0;
	crypto_info->proto_params.wimax_params.ar =
			g_proto_params & BMASK_WIMAX_AR_EN ? 1 : 0;

	/* Set the WiMAX cleanup callback */
	crypto_info->test_cleanup = test_cleanup_wimax;

	/* Set the WiMAX encap callback */
	crypto_info->set_enc_buf_cb = set_enc_buf_cb_wimax;

	/* Set the WiMAX test callbacks */
	crypto_info->test_enc_match_cb = test_enc_match_cb_wimax;
	crypto_info->test_dec_match_cb = test_dec_match_cb_wimax;

	return 0;
}

/**
 * @brief	Check SEC parameters provided by user for PDCP are valid
 *		or not.
 * @param[in]	g_proto_params - Bit mask of the optional parameters provided
 *		by user
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_pdcp_opts(uint32_t g_proto_params,
				struct test_param *crypto_info)
{
	struct pdcp_params *pdcp_params;
	int invalid = 0;

	pdcp_params = &crypto_info->proto_params.pdcp_params;

	switch (pdcp_params->type) {
	case PDCP_CONTROL_PLANE:
		if ((BMASK_PDCP_CPLANE_VALID & g_proto_params) !=
		     BMASK_PDCP_CPLANE_VALID)
			invalid = 1;
		break;

	case PDCP_DATA_PLANE:
		if ((BMASK_PDCP_UPLANE_VALID & g_proto_params) !=
		     BMASK_PDCP_UPLANE_VALID)
			invalid = 1;
		break;

	case PDCP_SHORT_MAC:
		if ((BMASK_PDCP_SHORT_MAC_VALID & g_proto_params) !=
		     BMASK_PDCP_SHORT_MAC_VALID)
			invalid = 1;
		break;

	default:
		invalid = 1;
		break;
	}

	if (invalid) {
		fprintf(stderr,
			"error: PDCP Invalid Parameters: Invalid type\n"
			"see --help option\n");
		return -EINVAL;
	}

	if (g_proto_params & BMASK_PDCP_CIPHER) {
		switch (pdcp_params->cipher_alg) {
		case PDCP_CIPHER_TYPE_NULL:
		case PDCP_CIPHER_TYPE_SNOW:
		case PDCP_CIPHER_TYPE_AES:
			break;

		case PDCP_CIPHER_TYPE_ZUC:
			if (rta_sec_era < RTA_SEC_ERA_5) {
				fprintf(stderr,
					"error: PDCP Invalid Parameters: "
					"Invalid cipher algorithm\n"
					"see --help option\n");
				return -EINVAL;
			}
			break;

		default:
			fprintf(stderr,
				"error: PDCP Invalid Parameters: "
				"Invalid cipher algorithm\n"
				"see --help option\n");
			return -EINVAL;
		}
	}

	if (g_proto_params & BMASK_PDCP_INTEGRITY) {
		switch (pdcp_params->integrity_alg) {
		case PDCP_AUTH_TYPE_NULL:
		case PDCP_AUTH_TYPE_SNOW:
		case PDCP_AUTH_TYPE_AES:
			break;

		case PDCP_AUTH_TYPE_ZUC:
			if (rta_sec_era < RTA_SEC_ERA_5) {
				fprintf(stderr,
					"error: PDCP Invalid Parameters: "
					"Invalid integrity algorithm\n"
					"see --help option\n");
				return -EINVAL;
			}
			break;

		default:
			fprintf(stderr,
				"error: PDCP Invalid Parameters: "
				"Invalid integrity algorithm\n"
				"see --help option\n");
			return -EINVAL;
		}
	}

	if (g_proto_params & BMASK_PDCP_SN_SIZE) {
		switch (pdcp_params->type) {
		case PDCP_DATA_PLANE:
			break;

		default:
			fprintf(stderr,
				"error: PDCP Invalid Parameters: "
				"Invalid sequence number for type\n"
				"see --help option\n");
			return -EINVAL;
		}
	}

	if (g_proto_params & BMASK_PDCP_HFN_OV_EN) {
		switch (pdcp_params->type) {
		case PDCP_CONTROL_PLANE:
		case PDCP_DATA_PLANE:
			break;

		default:
			fprintf(stderr,
				"error: PDCP Invalid Parameters: "
				"Invalid HFN override for type\n"
				"see --help option\n");
			return -EINVAL;
		}
		pdcp_params->hfn_ov_en = 1;

		/* Set the PDCP encap/decap callbacks, for modifying the FD */
		crypto_info->set_enc_buf_cb = set_enc_buf_cb_pdcp;
		crypto_info->set_dec_buf_cb = set_dec_buf_cb_pdcp;

		/*
		 * For ERA2, the in/out frames are not identical with the test
		 * vector. Override the callbacks here.
		 */
		if (rta_sec_era == RTA_SEC_ERA_2) {
			crypto_info->test_enc_match_cb = test_enc_match_cb_pdcp;
			crypto_info->test_dec_match_cb = test_dec_match_cb_pdcp;
		}
	} else {
		pdcp_params->hfn_ov_en = 0;
	}

	return 0;
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

/**
 * @brief	Check SEC parameters provided by user whether valid or not
 * @param[in]	g_cmd_params - Bit mask of all parameters provided by user
 * @param[in]	g_proto_params - Bit mask of protocol specific parameters, as
 *		provided by the user
 * @param[in]	crypto_info - test parameters
 * @return	0 on success, otherwise -EINVAL value
 */
static int validate_params(uint32_t g_cmd_params, uint32_t g_proto_params,
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
			" mode for testing (CIPHER or PERF)\n"
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
	case WIMAX:
	case PDCP:
	case SRTP:
		return validate_proto_opts[crypto_info->proto]
					(g_proto_params, crypto_info);
	default:
		fprintf(stderr,
			"error: Invalid Parameters: SEC protocol not"
			" supported\nsee --help option\n");
		return -EINVAL;
	}
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

		if (crypto_info->test_enc_match_cb) {
			if (crypto_info->test_enc_match_cb(ind, enc_buf,
							   crypto_info))
				goto err;
		} else {
			if (test_vector_match((uint32_t *)enc_buf,
					(uint32_t *)ref_test_vector.ciphertext,
					crypto_info->rt.output_buf_size *
						BITS_PER_BYTE) != 0)
				goto err;
		}
	}

	printf("All %s encrypted frame match found with cipher text\n",
	       protocol);

	return 0;

err:
	fprintf(stderr,
		"error: %s: Encapsulated frame %d"
		" doesn't match with test vector\n",
		__func__, ind + 1);

	return -1;
}

/**
 * @brief     Compare decrypted data returned by SEC with plain text
 *            input data.
 * @details   WiMAX decapsulated output frame contains the decapsulation
 *            Generic Mac Header (EC is set to zero, length is reduced
 *            as appropiate and HCS is recomputed). For performance mode,
 *            plaintext input packets are not GMH aware and a match between
 *            decapsulation output frames and encapsulation input frames
 *            cannot be guaranteed at GMH level.
 * @param[in] params       test parameters
 * @param[in] struct qm_fd frame descriptor list
 * @return                 0 on success, otherwise -1
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

		if (crypto_info->test_dec_match_cb) {
			if (crypto_info->test_dec_match_cb(ind,
							   dec_buf,
							   crypto_info))
				goto err;
		} else {
			if (CIPHER == crypto_info->mode) {
				if (test_vector_match((uint32_t *)dec_buf,
					(uint32_t *)ref_test_vector.plaintext,
					ref_test_vector.length) != 0)
					goto err;
			} else {
				for (i = 0; i < crypto_info->buf_size; i++) {
					if (dec_buf[i] != plain_data)
						goto err;
					plain_data++;
				}
			}
		}
	}
	printf("All %s decrypted frame matches initial text\n", protocol);

	return 0;

err:
	if (CIPHER == crypto_info->mode)
		fprintf(stderr,
			"error: %s: Decapsulated frame"
			" %d doesn't match with"
			" test vector\n",
			__func__, ind + 1);
	else
		fprintf(stderr,
			"error: %s: %s decrypted frame"
			" %d doesn't match!\n",
			 __func__, protocol, ind + 1);

	print_frame_desc(&fd[ind]);
	return -1;
}

struct argp_option macsec_options[] = {
	{"algo", 'o', "CIPHER TYPE",  0,
	 "OPTIONAL PARAMETER"
	 "\n\nSelect between GCM/GMAC processing (default: GCM)"
	 "\n0 = GCM"
	 "\n1 = GMAC"
	 "\n"},
	{0}
};

struct argp_option wimax_options[] = {
	{"ofdma", 'a', 0, 0,
	 "OPTIONAL PARAMETER"
	 "\n\nEnable OFDMa processing (default: OFDM)\n"},
	{"fcs", 'f', 0, 0,
	 "OPTIONAL PARAMETER"
	 "\n\nEnable FCS calculation (default: off)\n"},
	{"ar_len", 'w', "ARWIN", 0,
	 "OPTIONAL PARAMETER"
	 "\nSet anti-replay window length\n"},
	{0}
};

struct argp_option pdcp_options[] = {
	{"type", 'y', "TYPE",  0,
	 "Select PDCP PDU type:"
	 "\n\t 0 = Control Plane"
	 "\n\t 1 = User Plane"
	 "\n\t 2 = Short MAC"
	 "\n"},
	{"cipher", 'r', "CIPHER",  0,
	 "Ciphering algorithm:"
	 "\n0 = NULL     (EEA0)"
	 "\n1 = SNOW f8  (EEA1)"
	 "\n2 = AES-CTR  (EEA2)"
	 "\n3 = ZUC-E    (EEA3) (ERA >= 5)"
	 "\n"},
	{"integrity", 'i', "INTEGRITY",  0,
	"For PDCP Control Plane & Short MAC only"
	"\n\nSelect PDCP integrity algorithm:"
	 "\n0 = NULL     (EIA0)"
	 "\n1 = SNOW f9  (EIA1)"
	 "\n2 = AES-CMAC (EIA2)"
	 "\n3 = ZUC-I    (EIA3) (ERA >= 5)"
	 "\n"},
	{"direction", 'd', 0, 0,
	 "OPTIONAL PARAMETER"
	 "\n\nInput PDU is for downlink direction"
	 "\n"},
	{"snlen", 'x', "SNLEN", 0,
	 "For PDCP User Plane only"
	 "\n\nSelect PDCP PDU Sequence Number length:"
	 "\n0 = 12 bit Sequence Number PDU"
	 "\n1 = 7 bit Sequence Number PDU"
	 "\n2 = 15 bit Sequence Number PDU"
	 "\n"},
	{"hfn_ov", 'v', "HFN_OV_VAL", 0,
	 "OPTIONAL PARAMETER"
	 "\n\nEnable HFN override mechanism (only for Control & Data Plane)"
	 "\n"},
	{0}
};

/* Parser for MACsec command line options */
static struct argp macsec_argp = {
	macsec_options, macsec_parse_opts
};

/* Parser for WiMAX command line options */
static struct argp wimax_argp = {
	wimax_options, wimax_parse_opts
};

/* Parser for PDCP command line options */
static struct argp pdcp_argp = {
	pdcp_options, pdcp_parse_opts
};

/*
 * "Children" structure for splitting the command line options on a
 * per-protocol basis
 */
static struct argp_child argp_children[] = {
	{ &wimax_argp, 0, "WiMAX protocol options", 1},
	{ &pdcp_argp , 0, "PDCP protocol options", 2},
	{ &macsec_argp, 0, "MACsec protocol options", 3},
	{ 0 }
};

/* argp structure itself of argp parser */
static struct argp argp = { options, parse_opt, NULL, NULL,
				argp_children, NULL, NULL };

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
	uint32_t g_cmd_params = 0, g_proto_params = 0, i;
	struct test_param crypto_info;
	struct parse_input_t input;
	struct test_cb crypto_cb;

	ncpus = num_online_cpus;

	memset(&crypto_info, 0x00, sizeof(struct test_param));
	input.cmd_params = &g_cmd_params;
	input.proto_params = &g_proto_params;
	input.crypto_info = &crypto_info;

	/* Parse and check input arguments */
	argp_parse(&argp, argc, argv, 0, 0, &input);

	err = validate_params(g_cmd_params, g_proto_params, &crypto_info);
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

	if (crypto_info.test_cleanup)
		crypto_info.test_cleanup(&crypto_info);

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
	return authnct;
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
