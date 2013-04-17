/*
 * Copyright (C) 2011 - 2012 Freescale Semiconductor, Inc.
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
					  uint8_t next_header)
{
	struct ipsec_encap_descriptor_t *preheader_initdesc;
	uint16_t desc_len;
	struct ipsec_encap_pdb pdb;
	struct cipherparams cipher;
	struct authparams auth;
	unsigned char *buff_start = NULL;
	int ret;

	preheader_initdesc = __dma_mem_memalign(L1_CACHE_BYTES,
				sizeof(struct ipsec_encap_descriptor_t));
	if (preheader_initdesc == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left\n", __func__);
		return NULL;
	}
	memset(preheader_initdesc, 0, sizeof(struct ipsec_encap_descriptor_t));

	buff_start = (unsigned char *)&preheader_initdesc->descbuf;

	memset(&pdb, 0, sizeof(struct ipsec_encap_pdb));
	pdb.ip_nh = next_header;
	pdb.seq_num = sa->seq_num;
	pdb.spi = sa->spi;
	pdb.ip_hdr_len = 20;
	pdb.options = PDBOPTS_ESPCBC_TUNNEL | PDBOPTS_ESPCBC_INCIPHDR |
			PDBOPTS_ESPCBC_IPHDRSRC | PDBOPTS_ESPCBC_IVSRC;
	pdb.hmo.dttl = 1;
	pdb.options |= PDBOPTS_ESPCBC_CKSUM;

	cipher.algtype = sa->ealg->alg_type;
	cipher.key = (uint8_t *)sa->ealg->alg_key;
	cipher.keylen = (sa->ealg)->alg_key_len * 8;	/* Encryption keysize in bits */

	auth.algtype = sa->aalg->alg_type;
	auth.key = (uint8_t *)sa->aalg->alg_key_ptr;
	auth.keylen = sa->aalg->alg_key_len * 8;	/* SHA1 keysize in bits */

	/* Now construct */
	ret = cnstr_shdsc_ipsec_encap((uint32_t *) buff_start, &desc_len,
				      &pdb, (uint8_t *)outer_ip_header,
				      &cipher, &auth);
	if (ret)
		return NULL;

	pr_debug("Desc len in %s is %x\n", __func__, desc_len);

	preheader_initdesc->prehdr.hi.field.idlen = desc_len;
	preheader_initdesc->prehdr.lo.field.offset = 1;

	preheader_initdesc->prehdr.lo.field.pool_id = sec_bpid;
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
*create_decapsulation_sec_descriptor(struct ipsec_tunnel_t *sa)
{
	struct ipsec_decap_descriptor_t *preheader_initdesc;
	uint16_t desc_len;
	struct ipsec_decap_pdb pdb;
	struct cipherparams cipher;
	struct authparams auth;
	unsigned char *buff_start = NULL;
	int ret;

	preheader_initdesc = __dma_mem_memalign(L1_CACHE_BYTES,
				sizeof(struct ipsec_encap_descriptor_t));
	if (preheader_initdesc == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left\n", __func__);
		return NULL;
	}
	memset(preheader_initdesc, 0, sizeof(struct ipsec_decap_descriptor_t));

	buff_start = (unsigned char *)&preheader_initdesc->descbuf;

	memset(&pdb, 0, sizeof(struct ipsec_decap_pdb));
	pdb.seq_num = sa->seq_num;
	pdb.ip_hdr_len = 20;
	pdb.options = PDBOPTS_ESPCBC_TUNNEL | PDBOPTS_ESPCBC_OUTFMT |
			 PDBOPTS_ESPCBC_ARSNONE;

	cipher.algtype = sa->ealg->alg_type;
	cipher.key = (uint8_t *)sa->ealg->alg_key;
	cipher.keylen = sa->ealg->alg_key_len * 8;	/* Decryption keysize in bits */

	auth.algtype = sa->aalg->alg_type;
	auth.key = (uint8_t *)sa->aalg->alg_key_ptr;
	auth.keylen = sa->aalg->alg_key_len * 8;	/* SHA1 keysize in bits */

	/* Now construct */
	ret = cnstr_shdsc_ipsec_decap((uint32_t *) buff_start,
					       &desc_len,
					       &pdb, &cipher, &auth);
	if (ret)
		return NULL;

	pr_debug("Desc len in %s is %x\n", __func__, desc_len);

	preheader_initdesc->prehdr.hi.field.idlen = desc_len;
	/* 1 burst length to be reserved */
	preheader_initdesc->prehdr.lo.field.offset = 1;

	preheader_initdesc->prehdr.lo.field.pool_id = sec_bpid;
	preheader_initdesc->prehdr.lo.field.pool_buffer_size =
		(uint16_t)(DMA_MEM_BP3_SIZE);

	return preheader_initdesc;
}
