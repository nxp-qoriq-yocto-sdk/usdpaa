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

#include <usdpaa/dma_mem.h>
#include <fsl_sec/desc.h>
#include <fsl_sec/dcl.h>
#include "ipsec_sec.h"
#include "net/frame_desc.h"
#include "app_common.h"

/**
 \brief Initializes the SEC40 descriptor
	for encapsulation with preheader and Initialization descriptor
 \param[in] sa Pointer to the SA Info structure
 \param[in] outer_ip_header Pointer to the IP Header
 \param[in] next_header
 \param[in] ealg Encryption Algo Info
 \param[in] aalg Authentication Algo Info
 \return Pointer to the IPSec Encap SEC40 descriptor structure
 */
void *create_encapsulation_sec_descriptor(struct ipsec_tunnel_t *sa,
					  struct iphdr *outer_ip_header,
					  uint8_t next_header,
					  struct app_ctrl_sa_algo *ealg,
					  struct app_ctrl_sa_algo *aalg)
{
	struct ipsec_encap_descriptor_t *preheader_initdesc;
	uint16_t desc_len;
	struct iphdr iphdr;
	struct ipsec_encap_pdb pdb;
	struct cipherparams cipher;
	struct authparams auth;
	unsigned char *buff_start = NULL;
	int ret;

	preheader_initdesc = dma_mem_memalign(L1_CACHE_BYTES,
			sizeof(struct ipsec_encap_descriptor_t));
	if (preheader_initdesc == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left\n", __func__);
		return NULL;
	}
	memset(preheader_initdesc, 0, sizeof(struct ipsec_encap_descriptor_t));

	desc_len = (sizeof(struct ipsec_encap_descriptor_t) -
		    sizeof(struct preheader_t)) / sizeof(uint32_t);

	pr_debug("Desc Len in %s is %x\n", __func__, desc_len);

	buff_start =
	    (unsigned char *)preheader_initdesc + sizeof(struct preheader_t);
	memcpy(&iphdr, outer_ip_header, sizeof(iphdr));
	memset(&pdb, 0, sizeof(struct ipsec_encap_pdb));
	pdb.seq_num = sa->seq_num;
	pdb.spi = sa->spi;
	pdb.ip_hdr_len = 20;
	pdb.options = PDBOPTS_ESPCBC_TUNNEL | PDBOPTS_ESPCBC_INCIPHDR |
			PDBOPTS_ESPCBC_IPHDRSRC | PDBOPTS_ESPCBC_IVSRC;
	pdb.hmo_cbc.dttl = 1;
#ifdef ENABLE_CKSUM_SEC
	pdb.options |= PDBOPTS_ESPCBC_CKSUM;
#endif
	switch (ealg->alg_type) {
	case AES_CBC:
		cipher.algtype = CIPHER_TYPE_IPSEC_AESCBC;
		break;
	case TRIP_DES_CBC:
		cipher.algtype = CIPHER_TYPE_IPSEC_3DESCBC;
		break;
	default:
		fprintf(stderr, "error: %s: Unsupported Encryption"
			" Algorithm\n", __func__);
		return NULL;
	}
	cipher.key = (uint8_t *)ealg->alg_key;
	cipher.keylen = ealg->alg_key_len * 8;	/* Encryption keysize in bits */

	if (aalg->alg_type == HMAC_SHA1) {
		auth.algtype = AUTH_TYPE_IPSEC_SHA1HMAC_96;
	} else {
		fprintf(stderr, "error: %s: Unsupported Authentication"
			" Algorithm\n", __func__);
		return NULL;
	}
	auth.key = (uint8_t *)aalg->alg_key_ptr;
	auth.keylen = aalg->alg_key_len * 8;	/* SHA1 keysize in bits */

	/* Now construct */
	ret = cnstr_shdsc_ipsec_encap((uint32_t *) buff_start, &desc_len,
						 &pdb, (uint8_t *)&iphdr,
						 &cipher, &auth);

	if (ret)
		return NULL;

	*(buff_start + 5) = next_header;

	preheader_initdesc->prehdr.hi.field.idlen = desc_len;
	preheader_initdesc->prehdr.lo.field.offset = 1;

/* TBD: Remove hardcoding */
	preheader_initdesc->prehdr.lo.field.pool_id = 9;
	preheader_initdesc->prehdr.lo.field.pool_buffer_size =
		(uint16_t)(DMA_MEM_BP3_SIZE);

	return preheader_initdesc;
}

/**
 \brief Initializes the SEC40 descriptor for Decapsulation with preheader and
	Initialization descriptor
 \param[in] sa Pointer to the SA Info structure
 \param[in] ealg Encryption Algo Info
 \param[in] aalg Authentication Algo Info
 \return Pointer to the IPSec Encap SEC40 descriptor structure
 */
void
*create_decapsulation_sec_descriptor(struct ipsec_tunnel_t *sa,
				     struct app_ctrl_sa_algo *ealg,
				     struct app_ctrl_sa_algo *aalg)
{
	struct ipsec_decap_descriptor_t *preheader_initdesc;
	uint16_t desc_len;
	struct ipsec_decap_pdb pdb;
	struct cipherparams cipher;
	struct authparams auth;
	unsigned char *buff_start = NULL;

	int ret;

	preheader_initdesc = dma_mem_memalign(L1_CACHE_BYTES,
			sizeof(struct ipsec_encap_descriptor_t));
	if (preheader_initdesc == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left\n", __func__);
		return NULL;
	}
	memset(preheader_initdesc, 0, sizeof(struct ipsec_decap_descriptor_t));

	desc_len = (sizeof(struct ipsec_decap_descriptor_t) -
		    sizeof(struct preheader_t)) / sizeof(uint32_t);

	buff_start =
	    (unsigned char *)preheader_initdesc + sizeof(struct preheader_t);

	memset(&pdb, 0, sizeof(struct ipsec_decap_pdb));
	pdb.seq_num = sa->seq_num;
	pdb.ip_hdr_len = 20;
	pdb.options = PDBOPTS_ESPCBC_TUNNEL | PDBOPTS_ESPCBC_OUTFMT |
			 PDBOPTS_ESPCBC_ARSNONE;
	switch (ealg->alg_type) {
	case AES_CBC:
		cipher.algtype = CIPHER_TYPE_IPSEC_AESCBC;
		break;
	case TRIP_DES_CBC:
		cipher.algtype = CIPHER_TYPE_IPSEC_3DESCBC;
		break;
	default:
		fprintf(stderr, "error: %s: Unsupported Encryption"
			" Algorithm\n", __func__);
		return NULL;
	}
	cipher.key = (uint8_t *)ealg->alg_key;
	cipher.keylen = ealg->alg_key_len * 8;	/* Decryption keysize in bits */

	if (aalg->alg_type == HMAC_SHA1) {
		auth.algtype = AUTH_TYPE_IPSEC_SHA1HMAC_96;
	} else {
		fprintf(stderr, "error: %s: Unsupported Authentication"
			" Algorithm\n", __func__);
		return NULL;
	}
	auth.key = (uint8_t *)aalg->alg_key_ptr;
	auth.keylen = aalg->alg_key_len * 8;	/* SHA1 keysize in bits */

	/* Now construct */
	ret = cnstr_shdsc_ipsec_decap((uint32_t *) buff_start,
					       &desc_len,
					       &pdb, &cipher, &auth);
	if (ret)
		return NULL;

	preheader_initdesc->prehdr.hi.field.idlen = desc_len;
	/* 1 burst length to be reserved */
	preheader_initdesc->prehdr.lo.field.offset = 1;

/* TBD: Remove hardcoding */
	preheader_initdesc->prehdr.lo.field.pool_id = 9;
	preheader_initdesc->prehdr.lo.field.pool_buffer_size =
		(uint16_t)(DMA_MEM_BP3_SIZE);

	return preheader_initdesc;
}
