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

#include "ipsecfwd.h"
#include <usdpaa/fsl_qman.h>
#include "ipsec/ipsec_init.h"
#include "ipsec/ipsec_sec.h"
#include "ipsec/ipsec_common.h"
#include "ipsec/ipsec_encap.h"
#include <fsl_sec/desc.h>
#include <fsl_sec/dcl.h>
#include <usdpaa/dma_mem.h>

int32_t g_key_split_flag;
struct qman_fq *g_splitkey_fq_from_sec;
struct qman_fq *g_splitkey_fq_to_sec;
void *g_split_key;

/* TBD redeclared here (also in ipcsend.c) */
unsigned char def_auth_key[] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
	0x33, 0x34
};

/**
 \brief Creates Split key Job Queue Descriptor Buffer
 \param[IN] NULL
 \param[OUT] Split Key Job Queue Descriptor buffer
 */
void *create_split_key_sec_descriptor(void)
{
	struct ipsec_encap_descriptor_t *preheader_initdesc;

	preheader_initdesc = dma_mem_memalign(L1_CACHE_BYTES,
			sizeof(struct ipsec_encap_descriptor_t));
	if (preheader_initdesc == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left for"
			" Descriptor\n", __func__);
		return NULL;
	}
	memset(preheader_initdesc, 0, sizeof(struct ipsec_encap_descriptor_t));

	preheader_initdesc->prehdr.lo.field.offset = 1;

	return preheader_initdesc;
}

/**
 \brief Creates and initialized the FQs related to a tunnel
 \param[IN] NULL
 \param[OUT] 0 on success
 */
int32_t init_split_key_fqs(void)
{
	uint32_t flags;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	uint32_t ctx_a_excl;
	uint32_t ctx_a_len;
	void *ctxt_a;

	flags = QMAN_FQ_FLAG_NO_ENQUEUE | QMAN_FQ_FLAG_LOCKED;
	fq = dma_mem_memalign(L1_CACHE_BYTES, sizeof(struct qman_fq));
	if (unlikely(NULL == fq)) {
		fprintf(stderr, "error: %s: malloc failed in create_fqs"
			" for FQ ID: %u\n", __func__, KEY_SPLIT_FQ_FROM_SEC);
		return -ENOMEM;
	}

	memset(fq, 0, sizeof(struct qman_fq));
	g_splitkey_fq_from_sec = fq;
	fq->cb = ipfwd_split_key_cb;

	if (unlikely(0 != qman_create_fq(KEY_SPLIT_FQ_FROM_SEC, flags, fq))) {
		fprintf(stderr, "error: %s: qman_create_fq failed for"
			" FQ ID: %u\n", __func__, KEY_SPLIT_FQ_FROM_SEC);
		return -EINVAL;
	}

	flags = QMAN_INITFQ_FLAG_SCHED | QMAN_INITFQ_FLAG_LOCAL;
	opts.we_mask =
	    QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.wq = 1;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING | QM_FQCTRL_HOLDACTIVE;
	ctx_a_excl = (QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_CTX);
	ctx_a_len = (1 << 2) | 1;
	opts.fqd.context_a.hi = (ctx_a_excl << 24) | (ctx_a_len << 16);

	if (unlikely(0 != qman_init_fq(fq, flags, &opts))) {
		fprintf(stderr, "error: %s: Unable to initialize ingress FQ"
			" for SEC4.0\n", __func__);
		return -1;
	}

	flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_TO_DCPORTAL;

	fq = dma_mem_memalign(L1_CACHE_BYTES, sizeof(struct qman_fq));
	if (unlikely(NULL == fq)) {
		fprintf(stderr, "error: %s: malloc failed in create_fqs"
			" for FQ ID\n", __func__);
		return -ENOMEM;
	}

	memset(fq, 0, sizeof(struct qman_fq));
	g_splitkey_fq_to_sec = fq;
	fq->cb = ipfwd_split_key_cb;

	if (unlikely(0 != qman_create_fq(KEY_SPLIT_FQ_TO_SEC, flags, fq))) {
		fprintf(stderr, "error: %s: qman_create_fq failed"
			" for FQ ID\n", __func__);
		return -EINVAL;
	}

	ctxt_a = create_split_key_sec_descriptor();
	if (ctxt_a == NULL) {
		fprintf(stderr, "error: %s: Unable to create job descriptor"
			" for split key\n", __func__);
		return -ENOMEM;
	}
	flags = QMAN_INITFQ_FLAG_SCHED;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA |
	    QM_INITFQ_WE_CONTEXTB;
	opts.fqd.context_a.hi = 0;
	opts.fqd.context_a.lo = dma_mem_vtop(ctxt_a);
	opts.fqd.context_b = KEY_SPLIT_FQ_FROM_SEC;
	opts.fqd.dest.channel = qm_channel_caam;
	opts.fqd.dest.wq = 0;

	if (unlikely(0 != qman_init_fq(fq, flags, &opts))) {
		fprintf(stderr, "error: %s: Unable to Init CAAM Egress FQ\n",
			__func__);
		return -EINVAL;
	}
	return 0;
}

int destroy_split_key_fqs(void)
{
	uint32_t flags;
	struct qman_fq *fq;

	fq = g_splitkey_fq_to_sec;

	if (qman_retire_fq(fq, &flags)) {
		fprintf(stderr, "error: %s: qman_retire_fq failed for fq %d\n",
			__func__, fq->fqid);
		return -1;
	}
	if (0 > qman_oos_fq(fq)) {
		fprintf(stderr, "error: %s: Moving FQID: %u to OOS failed\n",
			__func__, g_splitkey_fq_from_sec->fqid);
		return -1;
	}
	qman_destroy_fq(fq, 0);
	free(fq);

	fq = g_splitkey_fq_from_sec;

	if (0 > qman_retire_fq(fq, &flags)) {
		fprintf(stderr, "error: %s: qman_retire_fq failed for fq %d\n",
			__func__, fq->fqid);
		return -1;
	}
	if (0 > qman_oos_fq(fq)) {
		fprintf(stderr, "error: %s: Moving FQID: %u to OOS failed\n",
			__func__, g_splitkey_fq_from_sec->fqid);
		return -1;
	}
	qman_destroy_fq(fq, 0);
	free(fq);
	return 0;
}

int generate_splitkey(void)
{
	struct qm_sg_entry *sg;
	void *alg_key, *job_desc;
	struct qm_fd fd;
	uint16_t bufsize;

	job_desc = dma_mem_memalign(L1_CACHE_BYTES, 256);
	if (job_desc == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left for"
			" Job Desc\n", __func__);
		return -ENOMEM;
	}
	memset(job_desc, 0, 256);

	g_split_key = dma_mem_memalign(L1_CACHE_BYTES, 60);
	if (g_split_key == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left for"
			" split key\n", __func__);
		free(job_desc);
		return -ENOMEM;
	}
	memset(g_split_key, 0, 60);

	alg_key = dma_mem_memalign(L1_CACHE_BYTES, 60);
	if (alg_key == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left for"
			" Auth Algo key\n", __func__);
		free(job_desc);
		free(g_split_key);
		return -ENOMEM;
	}

	bufsize = 256;
	memcpy(alg_key, def_auth_key, 20);
	pr_debug("ipsec_tunnel_create: before cnstr_jobdesc_mdsplitkey\n");
	if (0 != cnstr_jobdesc_mdsplitkey(job_desc, &bufsize,
				alg_key, OP_ALG_ALGSEL_SHA1,
				g_split_key)) {
		fprintf(stderr, "error: %s: Unable to create Job descriptor\n",
			__func__);
		free(job_desc);
		free(g_split_key);
		return -EINVAL;
	}

	pr_debug("ipsec_tunnel_create: after cnstr_jobdesc_mdsplitkey\n");

	sg = dma_mem_memalign(L1_CACHE_BYTES, 2*sizeof(struct qm_sg_entry));
	if (sg == NULL) {
		fprintf(stderr, "error: %s: No More Buffers left for Auth"
			" Algo key\n", __func__);
		free(job_desc);
		free(g_split_key);
		free(alg_key);
		return -ENOMEM;
	}

	memset(sg, 0, 2*sizeof(struct qm_sg_entry));
	qm_sg_entry_set64(sg, dma_mem_vtop(g_split_key));
	sg->length = 60;

	/* Create Job Desc */
	pr_debug(stderr, "After cnstr_jobdesc_mdsplitkey: %d\n", bufsize);

	/* input buffer */
	sg++;
	qm_sg_entry_set64(sg, dma_mem_vtop(job_desc));
	sg->length = bufsize * 4;
	sg->final = 1;
	sg--;

	qm_fd_addr_set64(&fd, dma_mem_vtop(sg));
	fd.bpid = 0;
	fd._format1 = qm_fd_compound;
	fd.cong_weight = 0;
	fd.cmd = 0;

	g_key_split_flag = 0;

	/* Enqueue on the FQ */
	/* NB: the use of QMAN_ENQUEUE_FLAG_WAIT is prohibited in LWE
	 * applications. To avoid thrashing, we implement a throttled poll for
	 * retrying the enqueue. */
loop:
	if (qman_enqueue(g_splitkey_fq_to_sec, &fd, 0)) {
		uint64_t now, then = mfatb();
		do {
			now = mfatb();
		} while (now < (then + 1000));
		goto loop;
	}

	/* Dequeue the reponse */
	while (g_key_split_flag == 0)
		qman_poll();

	dma_mem_free(alg_key, 20);
	dma_mem_free(job_desc, 256);
	dma_mem_free(sg, 2*sizeof(struct qm_sg_entry));

	return 0;
}
