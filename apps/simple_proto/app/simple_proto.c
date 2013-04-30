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

uint8_t pdb_opts;       /**< Protocol Data Block Options */

uint16_t pdb_ar_len;    /**< Protocol Data Block Anti-Replay Length */

static unsigned authnct = 0; /**< By default, do both encrypt & decrypt */

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

	if (pdb_ar_len) {
		ref_test_vector.pdb.wimax.decap_opts = WIMAX_PDBOPTS_AR;
		ref_test_vector.pdb.wimax.ar_len = pdb_ar_len;
	}

	if (PERF == crypto_info->mode) {
		switch (pdb_opts) {
		case 1:
			ref_test_vector.pdb.wimax.encap_opts =
				WIMAX_PDBOPTS_FCS;
			ref_test_vector.pdb.wimax.decap_opts |=
				WIMAX_PDBOPTS_FCS;
			ref_test_vector.flags.wimax.protinfo =
				OP_PCL_WIMAX_OFDM;
			break;
		case 2:
			ref_test_vector.pdb.wimax.encap_opts =
				WIMAX_PDBOPTS_FCS;
			ref_test_vector.pdb.wimax.decap_opts |=
				WIMAX_PDBOPTS_FCS;
			ref_test_vector.flags.wimax.protinfo =
				OP_PCL_WIMAX_OFDMA;
			break;
		default:
			ref_test_vector.flags.wimax.protinfo =
				OP_PCL_WIMAX_OFDM;
			break;
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

void init_rtv_pdcp_c_plane(struct test_param *crypto_info)
{
	const int proto = PDCP_MAP_PROTO_TO_ARRAY(crypto_info->proto);
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
	const int proto = PDCP_MAP_PROTO_TO_ARRAY(crypto_info->proto);
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
	ref_test_vector.pdb.pdcp.sns = pdcp_test_data_sns[proto];

	if (CIPHER == crypto_info->mode) {
		ref_test_vector.length =
				NO_OF_BITS(pdcp_test_data_in_len[proto]);
		ref_test_vector.plaintext = pdcp_test_data_in[proto];
		ref_test_vector.ciphertext = pdcp_test_data_out[proto];
	}
}

void init_rtv_pdcp_short_mac(struct test_param *crypto_info)
{
	const int proto = PDCP_MAP_PROTO_TO_ARRAY(crypto_info->proto);
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
	init_rtv_macsec_gcm_128,
	init_rtv_wimax_aes_ccm_128,
	/* PDCP Control Plane w/AES CTR enc. + AES CMAC int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/AES CTR enc. + AES CMAC int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/AES CTR enc. + SNOW f9 int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/AES CTR enc. + SNOW f9 int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/SNOW f8 enc. + SNOW f9 int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/SNOW f8 enc. + SNOW f9 int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/ZUC enc. + ZUC int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/ZUC enc. + ZUC int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/SNOW f8 + AES CMAC int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/SNOW f8 + AES CMAC int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/SNOW f8 enc. + NULL int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/SNOW f8 enc. + NULL int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/AES CTR enc. + NULL int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/AES CTR enc. + NULL int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/ZUC enc. + NULL int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/ZUC enc. + NULL int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/NULL enc. + SNOW f9 int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/NULL enc. + SNOW f9 int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/NULL enc. + AES CMAC int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/NULL enc. + AES CMAC int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/NULL enc. + ZUC int. DL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/NULL enc. + ZUC int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP Control Plane w/NULL enc. + NULL int. UL */
	init_rtv_pdcp_c_plane,
	/* PDCP User Plane w/AES CTR enc. UL LONG SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/AES CTR enc. DL LONG SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/AES CTR enc. UL SHORT SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/AES CTR enc. DL SHORT SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/SNOW f8 enc. UL LONG SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/SNOW f8 enc. DL LONG SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/SNOW f8 enc. UL SHORT SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/SNOW f8 enc. DL SHORT SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/ZUC enc. UL LONG SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/ZUC enc. DL LONG SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/ZUC enc. UL SHORT SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/ZUC enc. DL SHORT SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/NULL enc. DL LONG SN */
	init_rtv_pdcp_u_plane,
	/* PDCP User Plane w/NULL enc. DL SHORT SN */
	init_rtv_pdcp_u_plane,
	/* PDCP Short MAC-I w/SNOW f9 int. */
	init_rtv_pdcp_short_mac,
	/* PDCP Short MAC-I w/AES CMAC int. */
	init_rtv_pdcp_short_mac,
	/* PDCP Short MAC-I w/ZUC int. */
	init_rtv_pdcp_short_mac,
	/* PDCP Short MAC-I w/NULL int. */
	init_rtv_pdcp_short_mac
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
		if ((CIPHER == crypto_info->mode) || (pdb_opts != 0))
			crypto_info->rt.output_buf_size += WIMAX_FCS_SIZE;
		break;

	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_UL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_DL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_NULL_NULL_UL:
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_DL:
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_UL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_DL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_DL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_UL:
		crypto_info->rt.output_buf_size =
			crypto_info->buf_size + PDCP_MAC_I_LEN;
		break;

	case PDCP_USER_PLANE_AES_CTR_UL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_UL_SHORT_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_SHORT_SN:
	case PDCP_USER_PLANE_NULL_DL_LONG_SN:
	case PDCP_USER_PLANE_NULL_DL_SHORT_SN:
	case PDCP_USER_PLANE_ZUC_E_UL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_UL_SHORT_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_SHORT_SN:
		crypto_info->rt.output_buf_size = crypto_info->buf_size;
		break;

	case PDCP_SHORT_MAC_SNOW_F9:
	case PDCP_SHORT_MAC_AES_CMAC:
	case PDCP_SHORT_MAC_NULL:
	case PDCP_SHORT_MAC_ZUC_I:
		crypto_info->rt.output_buf_size =
				crypto_info->buf_size +
				PDCP_MAC_I_LEN;
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
	struct alginfo alginfo;
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
		alginfo.key = ref_test_vector.key;
		alginfo.keylen = MACSEC_KEY_SIZE;
		if (ENCRYPT == mode)
			cnstr_shdsc_macsec_encap(shared_desc,
						 &shared_desc_len,
						 &alginfo,
						 ref_test_vector.pdb.macsec.sci,
						 ref_test_vector.pdb.macsec.
						 ethertype,
						 ref_test_vector.pdb.macsec.
						 tci_an,
						 ref_test_vector.pdb.macsec.pn);

		else
			cnstr_shdsc_macsec_decap(shared_desc,
						 &shared_desc_len,
						 &alginfo,
						 ref_test_vector.pdb.macsec.sci,
						 ref_test_vector.pdb.macsec.pn);
		macsec_set_pn_constant(shared_desc, &shared_desc_len);
		break;
	case WIMAX:
		alginfo.key = ref_test_vector.key;
		alginfo.keylen = WIMAX_KEY_SIZE;
		if (ENCRYPT == mode)
			cnstr_shdsc_wimax_encap(shared_desc,
					&shared_desc_len,
					ref_test_vector.pdb.wimax.encap_opts,
					ref_test_vector.pdb.wimax.pn,
					ref_test_vector.flags.wimax.protinfo,
					&alginfo);
		else
			cnstr_shdsc_wimax_decap(shared_desc,
					&shared_desc_len,
					ref_test_vector.pdb.wimax.decap_opts,
					ref_test_vector.pdb.wimax.pn,
					ref_test_vector.pdb.wimax.ar_len,
					ref_test_vector.flags.wimax.protinfo,
					&alginfo);
		break;

	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_UL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_DL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_NULL_NULL_UL:
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_DL:
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_UL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_DL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_DL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_UL:
		if (ENCRYPT == mode)
			cnstr_shdsc_pdcp_c_plane_encap(shared_desc,
				&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
				1,
				ref_test_vector.pdb.pdcp.hfn,
				ref_test_vector.pdb.pdcp.bearer,
				ref_test_vector.pdb.pdcp.direction,
				ref_test_vector.pdb.pdcp.hfn_threshold,
				(struct alginfo *)&((struct alginfo){
					ref_test_vector.cipher_alg,
					ref_test_vector.dma_addr_key,
					ref_test_vector.cipher_keylen
				}),
				(struct alginfo *)&((struct alginfo){
					ref_test_vector.auth_alg,
					ref_test_vector.dma_addr_auth_key,
					ref_test_vector.auth_keylen
				}),
				0);
		else
			cnstr_shdsc_pdcp_c_plane_decap(shared_desc,
				&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
				1,
				ref_test_vector.pdb.pdcp.hfn,
				ref_test_vector.pdb.pdcp.bearer,
				ref_test_vector.pdb.pdcp.direction,
				ref_test_vector.pdb.pdcp.hfn_threshold,
				(struct alginfo *)&((struct alginfo){
					ref_test_vector.cipher_alg,
					ref_test_vector.dma_addr_key,
					ref_test_vector.cipher_keylen
				}),
				(struct alginfo *)&((struct alginfo){
					ref_test_vector.auth_alg,
					ref_test_vector.dma_addr_auth_key,
					ref_test_vector.auth_keylen
				}),
				0);
		break;

	case PDCP_USER_PLANE_AES_CTR_UL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_UL_SHORT_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_SHORT_SN:
	case PDCP_USER_PLANE_NULL_DL_LONG_SN:
	case PDCP_USER_PLANE_NULL_DL_SHORT_SN:
	case PDCP_USER_PLANE_ZUC_E_UL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_UL_SHORT_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_SHORT_SN:

		if (ENCRYPT == mode)
			cnstr_shdsc_pdcp_u_plane_encap(shared_desc,
				&shared_desc_len,
/*
* This is currently hardcoded. The application doesn't allow for
* proper retrieval of PS.
*/
				1,
				ref_test_vector.pdb.pdcp.sns,
				ref_test_vector.pdb.pdcp.hfn,
				ref_test_vector.pdb.pdcp.bearer,
				ref_test_vector.pdb.pdcp.direction,
				ref_test_vector.pdb.pdcp.hfn_threshold,
				(struct alginfo *)&((struct alginfo){
					ref_test_vector.cipher_alg,
					ref_test_vector.dma_addr_key,
					ref_test_vector.cipher_keylen
				}),
				0);
		else
			cnstr_shdsc_pdcp_u_plane_decap(shared_desc,
				&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
*/
				1,
				ref_test_vector.pdb.pdcp.sns,
				ref_test_vector.pdb.pdcp.hfn,
				ref_test_vector.pdb.pdcp.bearer,
				ref_test_vector.pdb.pdcp.direction,
				ref_test_vector.pdb.pdcp.hfn_threshold,
				(struct alginfo *)&((struct alginfo){
				ref_test_vector.cipher_alg,
				ref_test_vector.dma_addr_key,
				ref_test_vector.cipher_keylen
			}),
			0);
		break;

	case PDCP_SHORT_MAC_SNOW_F9:
	case PDCP_SHORT_MAC_AES_CMAC:
	case PDCP_SHORT_MAC_NULL:
	case PDCP_SHORT_MAC_ZUC_I:
		if (ENCRYPT == mode)
			cnstr_shdsc_pdcp_short_mac(shared_desc,
				&shared_desc_len,
/*
 * This is currently hardcoded. The application doesn't allow for
 * proper retrieval of PS.
 */
				1,
				(struct alginfo *)&((struct alginfo){
					ref_test_vector.auth_alg,
					ref_test_vector.dma_addr_auth_key,
					ref_test_vector.auth_keylen
				}));
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
		"\t\t 1 for MACsec\n"
		"\t\t 2 for WiMAX\n"
		"\t\t For PDCP Control Plane:\n"
		"\t\t\t 3 AES CTR + AES CMAC UL\n"
		"\t\t\t 4 AES CTR + AES CMAC DL\n"
		"\t\t\t 5 AES CTR + SNOW f9 UL\n"
		"\t\t\t 6 AES CTR + SNOW f9 DL\n"
		"\t\t\t 7 SNOW f8 + SNOW f9 DL\n"
		"\t\t\t 8 SNOW f8 + SNOW f9 UL\n"
		"\t\t\t 9 ZUC-E + ZUC-I DL*\n"
		"\t\t\t10 ZUC-E + ZUC-I UL*\n"
		"\t\t\t11 SNOW f8 + AES CMAC DL\n"
		"\t\t\t12 SNOW f8 + AES CMAC UL\n"
		"\t\t\t13 SNOW f8 + NULL DL\n"
		"\t\t\t14 SNOW f8 + NULL UL\n"
		"\t\t\t15 AES CTR + NULL DL\n"
		"\t\t\t16 AES CTR + NULL UL\n"
		"\t\t\t17 ZUC-E + NULL DL*\n"
		"\t\t\t18 ZUC-E + NULL UL*\n"
		"\t\t\t19 NULL + SNOW f9 DL\n"
		"\t\t\t20 NULL + SNOW f9 UL\n"
		"\t\t\t21 NULL + AES CMAC DL\n"
		"\t\t\t22 NULL + AES CMAC UL\n"
		"\t\t\t23 NULL + ZUC-I DL*\n"
		"\t\t\t24 NULL + ZUC-I UL*\n"
		"\t\t\t25 NULL + NULL UL\n"
		"\t\t For PDCP User Plane:\n"
		"\t\t\t26 AES CTR Long SN UL\n"
		"\t\t\t27 AES CTR Long SN DL\n"
		"\t\t\t28 AES CTR Short SN UL\n"
		"\t\t\t29 AES CTR Short SN DL\n"
		"\t\t\t30 SNOW f8 Long SN UL\n"
		"\t\t\t31 SNOW f8 Long SN DL\n"
		"\t\t\t32 SNOW f8 Short SN UL\n"
		"\t\t\t33 SNOW f8 Short SN DL\n"
		"\t\t\t34 ZUC-E Long SN UL*\n"
		"\t\t\t35 ZUC-E Long SN DL*\n"
		"\t\t\t36 ZUC-E Short SN UL*\n"
		"\t\t\t37 ZUC-E Short SN DL*\n"
		"\t\t\t38 NULL Long SN DL\n"
		"\t\t\t39 NULL Short SN DL\n"
		"\t\tFor PDCP Short MAC-I:\n"
		"\t\t\t40 SNOW f9\n"
		"\t\t\t41 AES CMAC\n"
		"\t\t\t42 ZUC-I*\n"
		"\t\t\t43 NULL\n"
		"\n\n"
		"\t\t * Only available for platforms with SEC>=5.3\n"},
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
	{"pdb_opts", 'o', "PDB OPTIONS", 0,
	 "\n\r\tOPTIONAL PARAMETER VALID ONLY IN PERF MODE\n\r"
		"\t\t SEC PDB options: provide following number\n\r"
		"\t\t 0 - WiMAX without FCS\n\r"
		"\t\t 1 - WiMAX with FCS for OFDM\n\r"
		"\t\t 2 - WiMAX with FCS for OFDMA\n"
	},
	{"pdb_ar_len", 'r', "ANTI REPLAY LENGTH", 0,
	 "\n\r\tPROTOCOL OPTIONAL PARAMETER\n\r"
		"\t\t Note: Anti-Replay Window Length\n\r"
		"\t\t cannot be greater than 64 packets\n"},
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

	case 'o':
		pdb_opts = atoi(arg);
		*p_cmd_params |= BMASK_SEC_PDB_OPTS;
		fprintf(stdout, "PDB Options = %d\n", pdb_opts);
		break;

	case 'r':
		pdb_ar_len = atoi(arg);
		*p_cmd_params |= BMASK_SEC_PDB_ARLEN;
		fprintf(stdout, "Anti-Replay Length = %d\n", pdb_ar_len);
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
	case WIMAX:
		if ((crypto_info->test_set > 0) && (crypto_info->test_set < 5))
			return 0;
		else
			goto err;

	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_UL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_DL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_NULL_NULL_UL:
	case PDCP_USER_PLANE_AES_CTR_UL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_UL_SHORT_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_SHORT_SN:
	case PDCP_USER_PLANE_NULL_DL_LONG_SN:
	case PDCP_USER_PLANE_NULL_DL_SHORT_SN:
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_DL:
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_UL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_DL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_DL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_UL:
	case PDCP_USER_PLANE_ZUC_E_UL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_UL_SHORT_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_SHORT_SN:
	case PDCP_SHORT_MAC_SNOW_F9:
	case PDCP_SHORT_MAC_AES_CMAC:
	case PDCP_SHORT_MAC_NULL:
	case PDCP_SHORT_MAC_ZUC_I:
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
 * @brief     Verifies if user gave a valid combination of optional arguments.
 * @param[in] crypto_info  Pointer to test_param structure.
 * @param[in] g_cmd_params Pointer to Bit mask of all parameters
 *                         provided by user.
 * @param[in] param        User parameter to be checked.
 * @return                 0 on success, otherwise -EINVAL value.
 */
static int validate_opt_param(struct test_param *crypto_info,
			      uint32_t *g_cmd_params, uint32_t param)
{
	if ((*g_cmd_params & param) == 0)
		return 0;

	switch (crypto_info->proto) {
	case WIMAX:
		if ((BMASK_SEC_PDB_OPTS == param) &&
		    (CIPHER == crypto_info->mode))
			return -EINVAL;
		break;
	case MACSEC:
	default:
		return -EINVAL;
	}
	*g_cmd_params &= ~param;
	return 0;
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
	if (validate_opt_param(crypto_info, &g_cmd_params,
			       BMASK_SEC_PDB_OPTS) != 0) {
		fprintf(stderr, "error: Invalid Parameters: provide"
			" a valid combination of optional arguments\n"
			"see --help option\n");
		return -EINVAL;
	}

	if (validate_opt_param(crypto_info, &g_cmd_params,
			       BMASK_SEC_PDB_ARLEN) != 0) {
		fprintf(stderr, "error: Invalid Parameters: provide"
			" a valid combination of optional arguments\n"
			"see --help option\n");
		return -EINVAL;
	}

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
	case WIMAX:
		if ((pdb_ar_len > 64) || (pdb_ar_len < 0)) {
			fprintf(stderr,
				"error: WiMAX Anti-Replay window length cannot"
				" be greater than 64 packets\n"
				"see --help option\n");
			return -EINVAL;
		} else {
			break;
		}

	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_AES_CTR_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_AES_CTR_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_DL:
	case PDCP_CTRL_PLANE_SNOW_F8_NULL_UL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_DL:
	case PDCP_CTRL_PLANE_AES_CTR_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_DL:
	case PDCP_CTRL_PLANE_NULL_SNOW_F9_UL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_DL:
	case PDCP_CTRL_PLANE_NULL_AES_CMAC_UL:
	case PDCP_CTRL_PLANE_NULL_NULL_UL:
	case PDCP_USER_PLANE_AES_CTR_UL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_LONG_SN:
	case PDCP_USER_PLANE_AES_CTR_UL_SHORT_SN:
	case PDCP_USER_PLANE_AES_CTR_DL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_LONG_SN:
	case PDCP_USER_PLANE_SNOW_F8_UL_SHORT_SN:
	case PDCP_USER_PLANE_SNOW_F8_DL_SHORT_SN:
	case PDCP_USER_PLANE_NULL_DL_LONG_SN:
	case PDCP_USER_PLANE_NULL_DL_SHORT_SN:
	case PDCP_SHORT_MAC_SNOW_F9:
	case PDCP_SHORT_MAC_AES_CMAC:
	case PDCP_SHORT_MAC_NULL:
		break;
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_DL:
	case PDCP_CTRL_PLANE_ZUC_E_ZUC_I_UL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_DL:
	case PDCP_CTRL_PLANE_ZUC_E_NULL_UL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_DL:
	case PDCP_CTRL_PLANE_NULL_ZUC_I_UL:
	case PDCP_USER_PLANE_ZUC_E_UL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_LONG_SN:
	case PDCP_USER_PLANE_ZUC_E_UL_SHORT_SN:
	case PDCP_USER_PLANE_ZUC_E_DL_SHORT_SN:
	case PDCP_SHORT_MAC_ZUC_I:
		if (rta_sec_era >= RTA_SEC_ERA_5)
			break;

	default:
		fprintf(stderr,
			"error: Invalid Parameters: SEC protocol not supported"
			"\nsee --help option\n");
		return -EINVAL;
	}

	switch (pdb_opts) {
	case 0:
	case 1:
	case 2:
		break;
	default:
		fprintf(stderr, "error: Invalid Protocol Data Block"
			" value\nsee --help option\n");
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
		} else if (WIMAX == crypto_info->proto) {
			plain_data = WIMAX_GMH_SIZE;
			for (i = WIMAX_GMH_SIZE;
			     i < (crypto_info->buf_size - WIMAX_GMH_SIZE);
			     i++) {
				if (dec_buf[i] != plain_data) {
					fprintf(stderr, "error: %s: %s"
						" decrypted frame %d doesn't"
						" match!\n", __func__,
						protocol, ind + 1);
					print_frame_desc(&fd[ind]);
					return -1;
				}
				plain_data++;
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
