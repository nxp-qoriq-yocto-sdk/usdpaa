/*
 * SEC Descriptor Construction Library
 * Basic job descriptor construction
 */
/* Copyright (c) 2009, 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <usdpaa/compat.h>
#include <fsl_sec/dcl.h>
#include <internal/compat.h>

static const uint8_t mdkeylen[] = { 16, 20, 28, 32, 48, 64 };

/**
 * cnstr_seq_jobdesc() - Construct simple sequence job descriptor
 * Returns: 0 (for now)
 *
 * @jobdesc - pointer to a buffer to build the target job descriptor
 *            within
 * @jobdescsz - size of target job descriptor buffer
 * @shrdesc - pointer to pre-existing shared descriptor to use with
 *            this job
 * @shrdescsz - size of pre-existing shared descriptor
 * @inbuf - pointer to input frame
 * @insize - size of input frame
 * @outbuf - pointer to output frame
 * @outsize - size of output frame
 *
 * Constructs a simple job descriptor that contains 3 references:
 *   (1) A shared descriptor to do the work. This is normally assumed
 *       to be some sort of a protocol sharedesc, but can be any sharedesc.
 *   (2) A packet/frame for input data
 *   (3) A packet/frame for output data
 *
 * The created descriptor is always a simple reverse-order descriptor,
 * and has no provisions for other content specifications.
 **/
int cnstr_seq_jobdesc(uint32_t *jobdesc, uint16_t *jobdescsz,
		      uint32_t *shrdesc, uint16_t shrdescsz,
		      void *inbuf, uint32_t insize,
		      void *outbuf, uint32_t outsize)
{
	uint32_t *next;

	/*
	 * Basic structure is
	 * - header (assume sharing, reverse order)
	 * - sharedesc physical address
	 * - SEQ_OUT_PTR
	 * - SEQ_IN_PTR
	 */

	/* Make running pointer past where header will go */
	next = jobdesc;
	next++;

	/* Insert sharedesc */
	*next++ = (uint32_t) shrdesc;

	/* Sequence pointers */
	next = cmd_insert_seq_out_ptr(next, outbuf, outsize, PTR_DIRECT);
	next = cmd_insert_seq_in_ptr(next, inbuf, insize, PTR_DIRECT);

	/* Now update header */
	*jobdescsz = next - jobdesc;	/* add 1 to include header */
	cmd_insert_hdr(jobdesc, shrdescsz, *jobdescsz, SHR_SERIAL,
		       SHRNXT_SHARED, ORDER_REVERSE, DESC_STD);

	return 0;
}
EXPORT_SYMBOL(cnstr_seq_jobdesc);

/**
 * Construct a blockcipher request as a single job
 *
 * @descbuf - pointer to buffer for descriptor construction
 * @bufsz - size of constructed descriptor (as output)
 * @data_in - input message
 * @data_out - output message
 * @datasz - size of message
 * @key - cipher key
 * @keylen - size of cipher key
 * @iv - cipher IV
 * @ivlen - size of cipher IV
 * @dir - DIR_ENCRYPT or DIR_DECRYPT
 * @cipher - algorithm from OP_ALG_ALGSEL_
 * @clear - clear descriptor buffer before construction
 **/
int cnstr_jobdesc_blkcipher_cbc(uint32_t *descbuf, uint16_t *bufsz,
				uint8_t *data_in, uint8_t *data_out,
				uint32_t datasz,
				uint8_t *key, uint32_t keylen,
				uint8_t *iv, uint32_t ivlen,
				enum algdir dir, uint32_t cipher, uint8_t clear)
{
	uint32_t *start;
	uint16_t startidx, endidx;
	uint32_t mval;

	start = descbuf++;	/* save start for eventual header write */

	if (!descbuf)
		return -1;

	if (clear)
		memset(start, 0, (*bufsz * sizeof(uint32_t)));

	startidx = descbuf - start;
	descbuf = cmd_insert_seq_in_ptr(descbuf, data_in, datasz, PTR_DIRECT);

	descbuf = cmd_insert_seq_out_ptr(descbuf, data_out, datasz, PTR_DIRECT);

	descbuf = cmd_insert_load(descbuf, iv, LDST_CLASS_1_CCB,
				  0, LDST_SRCDST_BYTE_CONTEXT, 0, (ivlen >> 3),
				  ITEM_REFERENCE);

	descbuf = cmd_insert_key(descbuf, key, keylen, PTR_DIRECT,
				 KEYDST_KEYREG, KEY_CLEAR, ITEM_REFERENCE,
				 ITEM_CLASS1);

	mval = 0;
	descbuf = cmd_insert_math(descbuf, MATH_FUN_SUB, MATH_SRC0_SEQINLEN,
				  MATH_SRC1_IMM, MATH_DEST_VARSEQINLEN,
				  4, 0, 0, 0, &mval);

	descbuf = cmd_insert_math(descbuf, MATH_FUN_ADD, MATH_SRC0_SEQINLEN,
				  MATH_SRC1_IMM, MATH_DEST_VARSEQOUTLEN,
				  4, 0, 0, 0, &mval);

	descbuf = cmd_insert_alg_op(descbuf, OP_TYPE_CLASS1_ALG, cipher,
				    OP_ALG_AAI_CBC, MDSTATE_COMPLETE,
				    ICV_CHECK_OFF, dir);

	descbuf = cmd_insert_seq_fifo_load(descbuf, LDST_CLASS_1_CCB,
					   FIFOLDST_VLF,
					   (FIFOLD_TYPE_MSG |
					    FIFOLD_TYPE_LAST1), 0);

	descbuf = cmd_insert_seq_fifo_store(descbuf, LDST_CLASS_1_CCB,
					    FIFOLDST_VLF,
					    FIFOST_TYPE_MESSAGE_DATA, 0);

	/* Now update the header with size/offsets */
	endidx = descbuf - start;
	cmd_insert_hdr(start, 1, endidx, SHR_NEVER, SHRNXT_LENGTH,
		       ORDER_FORWARD, DESC_STD);

	*bufsz = endidx;

	return 0;
}
EXPORT_SYMBOL(cnstr_jobdesc_blkcipher_cbc);


/**
 * Generate an MDHA split key - cnstr_jobdesc_mdsplitkey()
 *
 * @descbuf - pointer to buffer to hold constructed descriptor
 *
 * @bufsiz - pointer to size of descriptor once constructed
 *
 * @key - HMAC key to generate ipad/opad from. Size is determined
 *        by cipher:
 *	  - OP_ALG_ALGSEL_MD5    = 16
 *	  - OP_ALG_ALGSEL_SHA1   = 20
 *	  - OP_ALG_ALGSEL_SHA224 = 28 (broken)
 *	  - OP_ALG_ALGSEL_SHA256 = 32
 *	  - OP_ALG_ALGSEL_SHA384 = 48 (broken)
 *	  - OP_ALG_ALGSEL_SHA512 = 64
 *
 * @cipher - HMAC algorithm selection, one of OP_ALG_ALGSEL_
 *
 * @padbuf - buffer to store generated ipad/opad. Should be 2x
 *           the HMAC keysize for chosen cipher rounded up to the
 *           nearest 16-byte boundary (16 bytes = AES blocksize)
 **/
int cnstr_jobdesc_mdsplitkey(uint32_t *descbuf, uint16_t *bufsize,
			     uint8_t *key, uint32_t cipher, uint8_t *padbuf)
{
	uint32_t *start;
	uint16_t startidx, endidx;
	uint8_t keylen, storelen;

	start = descbuf++;
	startidx = descbuf - start;

	/* Pick key length from cipher submask as an enum */
	keylen = mdkeylen[(cipher & OP_ALG_ALGSEL_SUBMASK) >>
			  OP_ALG_ALGSEL_SHIFT];

	storelen = keylen * 2;

	/* Load the HMAC key */
	descbuf = cmd_insert_key(descbuf, key, keylen * 8, PTR_DIRECT,
				 KEYDST_KEYREG, KEY_CLEAR, ITEM_REFERENCE,
				 ITEM_CLASS2);

	/*
	 * Select HMAC op with init only, this sets up key unroll
	 * Have DECRYPT selected here, although MDHA doesn't care
	 */
	descbuf = cmd_insert_alg_op(descbuf, OP_TYPE_CLASS2_ALG, cipher,
				    OP_ALG_AAI_HMAC, MDSTATE_INIT,
				    ICV_CHECK_OFF, DIR_DECRYPT);

	/* FIFO load of 0 to kickstart MDHA (this will generate pads) */
	descbuf = cmd_insert_fifo_load(descbuf, 0, 0, LDST_CLASS_2_CCB,
				       0, FIFOLD_IMM, 0,
				       (FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2));

	/* Wait for store to complete before proceeding */
	/* This is a tapeout1 dependency */
	descbuf = cmd_insert_jump(descbuf, JUMP_TYPE_LOCAL, CLASS_2,
				  JUMP_TEST_ALL, 0, 1, NULL);

	/* Now store the split key pair with that specific type */
	descbuf = cmd_insert_fifo_store(descbuf, padbuf, storelen,
					LDST_CLASS_2_CCB, 0, 0, 0,
					FIFOST_TYPE_SPLIT_KEK);

	endidx = descbuf - start;
	cmd_insert_hdr(start, 1, endidx, SHR_NEVER, SHRNXT_LENGTH,
		       ORDER_FORWARD, DESC_STD);

	*bufsize = endidx;

	return 0;
}
EXPORT_SYMBOL(cnstr_jobdesc_mdsplitkey);

/* FIXME: clear-written reg content should perhaps be defined in desc.h */
static const uint32_t clrw_imm = 0x00210000;
