/*
 * CAAM Descriptor Construction Library
 * Descriptor Disassembler
 *
 * This is EXPERIMENTAL and incomplete code. It assumes BE32 for the
 * moment, and much functionality remains to be filled in
 */
/* Copyright (c) 2008 - 2009, 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <usdpaa/compat.h>
#include <fsl_sec/sec.h>
#include <flib/desc.h>

#include <internal/compat.h>

#define MAX_LEADER_LEN 31 /* offset + raw + instruction-name-length */
#define DPTINT		   pr_info

/* Descriptor header/shrheader share enums */
static const char *deschdr_share[] = {
	"never", "wait", "serial", "always", "defer",
};

/* KEY/SEQ_KEY instruction-specific class enums */
static const char *key_class[] = {
	"<rsvd>", "class1", "class2", "<rsvd>",
};

/* LOAD/STORE instruction-specific class enums */
static const char *ldst_class[] = {
	"class-ind-ccb", "class-1-ccb", "class-2-ccb", "deco",
};

/* FIFO_LOAD/FIFO_STORE instruction-specific class enums */
static const char *fifoldst_class[] = {
	"skip", "class1", "class2", "both",
};

/* KEY/SEQ_KEY instruction destination enums */
static const char *key_dest[] = {
	"keyreg", "pk-e", "af-sbox", "md-split",
};

/* FIFO_STORE/SEQ_FIFO_STORE output data type enums */
static const char *fifo_output_data_type[] = {
	"pk-a0", "pk-a1", "pk-a2", "pk-a3",
	"pk-b0", "pk-b1", "pk-b2", "pk-b3",
	"pk-n", "<rsvd>", "<rsvd>", "<rsvd>",
	"pk-a", "pk-b", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"afha-s-jdk", "afha-s-tdk", "pkha-e-jdk", "pkha-e-tdk",
	"keyreg-jdk", "keyreg-tdk", "mdsplit-jdk", "mdsplit-tdk",
	"outfifo-jdk", "outfifo-tdk", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"msgdata", "<rsvd>", "<rsvd>", "<rsvd>",
	"rng-ref", "rng-outfifo", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "seqfifo-skip",
};

/* LOAD/STORE instruction source/destination by class */
static const char *ldstr_srcdst[4][0x80] = {
{
	/* Class-independent CCB destination set */
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "cha-ctrl", "irq-ctrl",
	"clrw", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "info-fifo", "<rsvd>",
	"indata-fifo", "<rsvd>", "output-fifo", "<rsvd>",
},
{
	/* Class1 CCB destination set */
	"class1-mode", "class1-keysz", "class1-datasz", "class1-icvsz",
	"<rsvd>", "<rsvd>", "<rsvd>",  "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "aadsz",
	"class1-ivsz", "<rsvd>", "<rsvd>", "class1-altdsz",
	"pk-a-sz", "pk-b-sz", "pk-n-sz", "pk-e-sz",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"class1-ctx", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"class1-key", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
},
{
	/* Class2 CCB destination set */
	"class2-mode", "class2-keysz", "class2-datasz", "class2-ivsz",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"class2-ctx", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"class2-key", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>",  "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
},
{
	/* DECO destination set */
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "deco-ctrl", "deco-povrd",
	"deco-math0", "deco-math1", "deco-math2", "deco-math3",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"descbuf", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
} };

/* JUMP instruction destination type enums */
static const char *jump_types[] = {
	"local", "nonlocal", "halt", "halt-user",
};

/* JUMP instruction test enums */
static const char *jump_tests[] = {
	"all", "!all", "any", "!any",
};

/* LOAD_FIFO/SEQ_LOAD_FIFO instruction PK input type enums */
static const char *load_pkha_inp_types[] = {
	"a0", "a1", "a2", "a3",
	"b0", "b1", "b2", "b3",
	"n", "<rsvd>", "<rsvd>", "<rsvd>",
	"a", "b", "<rsvd>", "<rsvd>",
};

/* LOAD_FIFO/SEQ_LOAD_FIFO instruction non-PK input type enums */
static const char *load_inp_types[] = {
	"<rsvd>", "<rsvd>", "msgdata", "msgdata1->2",
	"iv", "bitlendata",
};

/* MOVE instruction source enums */
static const char *move_src[] = {
	"class1-ctx", "class2-ctx", "out-fifo", "descbuf",
	"math0", "math1", "math2", "math3",
	"inp-fifo",
};

/* MOVE instruction destination enums */
static const char *move_dst[] = {
	"class1-ctx", "class2-ctx", "output-fifo", "descbuf",
	"math0", "math1", "math2", "math3",
	"class1-inp-fifo", "class2-inp-fifo", "<rsvd>", "<rsvd>",
	"pk-a", "class1-key", "class2-key", "<rsvd>",
};

/* MATH instruction source 0 enumerations */
static const char *math_src0[] = {
	"math0", "math1", "math2", "math3",
	"imm", "<rsvd>", "<rsvd>", "<rsvd>",
	"seqin", "seqout", "vseqin", "vseqout",
	"0" "<rsvd>", "<rsvd>", "<rsvd>",
};

/* MATH instruction source1 enumerations (not same as src0) */
static const char *math_src1[] = {
	"math0", "math1", "math2", "math3",
	"imm", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "inp-fifo", "out-fifo",
	"1" "<rsvd>", "<rsvd>", "<rsvd>",
};

/* MATH instruction destination enumerations */
static const char *math_dest[] = {
	"math0", "math1", "math2", "math3",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"seqin", "seqout", "vseqin", "vseqout",
	"<rsvd>", "<rsvd>", "<rsvd>", "<none>",
};

/* MATH instruction function enumerations */
static const char *math_fun[] = {
	"add", "addc", "sub", "subb",
	"or", "and", "xor", "lsh",
	"rsh", "lshd", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
};

/* SIGNATURE instruction type enumerations */
static const char *sig_type[] = {
	"final", "final-restore", "final-nonzero", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "imm-2", "imm-3",
	"imm-4", "<rsvd>", "<rsvd>", "<rsvd>",
};

/* OPERATION instruction unidirectional protocol enums */
static const char *unidir_pcl[] = {
	"<rsvd> ", "ikev1-prf ", "ikev2-prf ", "<rsvd> ",
	"<rsvd> ", "<rsvd> ", "<rsvd> ", "<rsvd> ",
	"ssl3.0-prf ", "tls1.0-prf ", "tls1.1-prf ", "<rsvd> ",
	"dtls1.0-prf ", "blob ", "<rsvd> ", "<rsvd> ",
	"<rsvd> ", "<rsvd> ", "<rsvd> ", "<rsvd> ",
	"pk-pargen ", "dsa-sign ", "dsa-verify ", "<rsvd> ",
	"<rsvd> ", "<rsvd> ", "<rsvd> ", "<rsvd> ",
	"<rsvd> ", "<rsvd> ", "<rsvd> ", "<rsvd> ",
};

/* OPERATION instruction protocol info cipher types - IPSec/SRTP */
static const char *ipsec_pclinfo_cipher[] = {
	"<rsvd>", "des", "des", "3des",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"aes-cbc", "aes-ctr", "aes-ccm8", "aes-ccm12",
	"aes-ccm16", "<rsvd>", "aes-gcm8", "aes-gcm12",
	"aes-gcm16", "<rsvd>", "aes-xts", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
};

/* OPERATION instruction protocol info authentication types - IPSec/SRTP */
static const char *ipsec_pclinfo_auth[] = {
	"<none>", "hmac-md5-96", "hmac-sha1-96", "<rsvd>",
	"<rsvd>", "aes-xcbcmac-96", "hmac-md5-128", "hmac-sha1-160",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"hmac-sha2-256-128", "hmac-sha2-384-192",
	"hmac-sha2-512-256", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
};

/* OPERATION instruction PKHA algorithmic functions (PKHA_MODE_LS) */
static const char *pk_function[] = {
	"<rsvd>", "clrmem", "a+b%n", "a-b%n",
	"b-a%n", "a*b%n", "a^e%n", "a%n",
	"a^-1%n", "ecc-p1+p2", "ecc-p1+p1", "ecc-e*p1",
	"monty-const", "crt-const", "gcd(a,n)", "miller-rabin",
	"cpymem-n-sz", "cpymem-src-sz", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
	"<rsvd>", "<rsvd>", "<rsvd>", "<rsvd>",
};

static const char *pk_srcdst[] = {
	"a",
	"b",
	"e", /* technically not legal for a source, legal as dest */
	"n",
};

/*
 * Simple hexdumper for use by the disassembler. Displays 32-bit
 * words on a line-by-line bases with an offset shown,. and an
 * optional indentation/description string to prefix each line with.
 *
 * descdata	- data to dump
 * size		- size of buffer in words
 * wordsperline - number of words to display per line, minimum 1.
 *		  4 is a practical maximum using an 80-character line
 * indentstr	- points to a string to ident or identify each line
 */
void desc_hexdump(uint32_t *descdata,
		  uint32_t  size,
		  uint32_t  wordsperline,
		  int8_t    *leader)
{
	int i, idx, rem, line;

	idx = 0;
	rem = size;

	while (rem) {
		DPTINT("%s[%02d] ", leader, idx);
		if ((uint32_t)rem <= wordsperline)
			line = rem;
		else
			line = wordsperline;

		for (i = 0; i < line; i++) {
			DPTINT("0x%08x ", descdata[idx]);
			rem--; idx++;
		}
		DPTINT("\n");
	};
}
EXPORT_SYMBOL(desc_hexdump);

static void show_shrhdr(uint32_t *hdr)
{
	DPTINT("   shrdesc: stidx=%d share=%s ",
	      (*hdr & HDR_START_IDX_MASK) >> HDR_START_IDX_SHIFT,
	      deschdr_share[(*hdr >> HDR_SD_SHARE_SHIFT) & HDR_SD_SHARE_MASK]);

	if (*hdr & HDR_DNR)
		DPTINT("noreplay ");

	if (*hdr & HDR_SAVECTX)
		DPTINT("savectx ");

	if (*hdr & HDR_PROP_DNR)
		DPTINT("propdnr ");

	DPTINT("len=%d\n", *hdr & HDR_DESCLEN_SHR_MASK);
}

static void show_hdr(uint32_t *hdr)
{
	if (*hdr & HDR_SHARED) {
		DPTINT("   jobdesc: shrsz=%d ",
		      (*hdr & HDR_START_IDX_MASK) >> HDR_START_IDX_SHIFT);
	} else {
		DPTINT("   jobdesc: stidx=%d ",
		      (*hdr & HDR_START_IDX_MASK) >> HDR_START_IDX_SHIFT);
	}
	DPTINT("share=%s ",
	      deschdr_share[(*hdr >> HDR_SD_SHARE_SHIFT) & HDR_SD_SHARE_MASK]);

	if (*hdr & HDR_DNR)
		DPTINT("noreplay ");

	if (*hdr & HDR_TRUSTED)
		DPTINT("trusted ");

	if (*hdr & HDR_MAKE_TRUSTED)
		DPTINT("mktrusted ");

	if (*hdr & HDR_SHARED)
		DPTINT("getshared ");

	if (*hdr & HDR_REVERSE)
		DPTINT("reversed ");

	DPTINT("len=%d\n", *hdr & HDR_DESCLEN_MASK);
}

static void show_key(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t keylen, *keydata;

	keylen = *cmd & KEY_LENGTH_MASK;
	keydata = cmd + 1; /* point to key or pointer */

	DPTINT("       key: %s->%s len=%d ",
	      key_class[(*cmd & CLASS_MASK) >> CLASS_SHIFT],
	      key_dest[(*cmd & KEY_DEST_MASK) >> KEY_DEST_SHIFT],
	      keylen);

	if (*cmd & KEY_SGF)
		DPTINT("s/g ");

	if (*cmd & KEY_ENC)
		DPTINT("enc ");

	if (*cmd & KEY_IMM)
		DPTINT("imm ");

	DPTINT("\n");
	if (*cmd & KEY_IMM) {
		desc_hexdump(keydata, keylen >> 2, 4, leader);
		(*idx) += keylen >> 2;
	} else {
		DPTINT("%s@0x%08x\n", leader, *keydata);
		(*idx)++; /* key pointer follows instruction */
	}
	(*idx)++;
}

static void show_seq_key(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t keylen, *keydata;

	keylen	= *cmd & KEY_LENGTH_MASK;
	keydata = cmd + 1;

	DPTINT("    seqkey: %s->%s len=%d ",
	      key_class[(*cmd & CLASS_MASK) >> CLASS_SHIFT],
	      key_dest[(*cmd & KEY_DEST_MASK) >> KEY_DEST_SHIFT],
	      keylen);

	if (*cmd & KEY_VLF)
		DPTINT("vlf ");

	if (*cmd & KEY_ENC)
		DPTINT("enc ");

	if (*cmd & KEY_IMM)
		DPTINT("imm ");

	DPTINT("\n");
	if (*cmd & KEY_IMM) {
		desc_hexdump(keydata, keylen >> 2, 4, leader);
		(*idx) += keylen >> 2;
	} else {
		DPTINT("%s@0x%08x\n", leader, *keydata);
		(*idx)++;
	}
	(*idx)++;
}

static void show_load(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t ldlen, *lddata;
	uint8_t class;

	ldlen  = *cmd & LDST_LEN_MASK;
	lddata = cmd + 1; /* point to key or pointer */

	class = (*cmd & CLASS_MASK) >> CLASS_SHIFT;
	DPTINT("	ld: %s->%s len=%d offs=%d",
	      ldst_class[class],
	      ldstr_srcdst[class][(*cmd & LDST_SRCDST_MASK) >>
				  LDST_SRCDST_SHIFT],
	      (*cmd & LDST_LEN_MASK),
	      (*cmd & LDST_OFFSET_MASK) >> LDST_OFFSET_SHIFT);

	if (*cmd & LDST_SGF)
		DPTINT(" s/g");

	if (*cmd & LDST_IMM)
		DPTINT(" imm");

	DPTINT("\n");

	/*
	 * Special case for immediate load to DECO control. In this case
	 * only, the immediate value is the bits in offset/length, NOT
	 * the data following the instruction, so, skip the trailing
	 * data processing step.
	 */

	if (((*cmd & LDST_CLASS_MASK) ==  LDST_CLASS_DECO) &&
	    ((*cmd & LDST_SRCDST_MASK) == LDST_SRCDST_WORD_DECOCTRL)) {
		(*idx)++;
		return;
	}

	if (*cmd & LDST_IMM) {
		desc_hexdump(lddata, ldlen >> 2, 4, leader);
		(*idx) += ldlen >> 2;
	} else {
		DPTINT("%s@0x%08x\n", leader, *lddata);
		(*idx)++;
	}
	(*idx)++;
}

static void show_seq_load(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint8_t class;

	class = (*cmd & CLASS_MASK) >> CLASS_SHIFT;
	DPTINT("     seqld: %s->%s len=%d offs=%d",
	      ldst_class[class],
	      ldstr_srcdst[class][(*cmd & LDST_SRCDST_MASK) >>
				  LDST_SRCDST_SHIFT],
	      (*cmd & LDST_LEN_MASK),
	      (*cmd & LDST_OFFSET_MASK) >> LDST_OFFSET_SHIFT);

	if (*cmd & LDST_VLF)
		DPTINT(" vlf");

	DPTINT("\n");
	(*idx)++;
}

static void show_fifo_load(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t *trdata, len;

	len  = *cmd & FIFOLDST_LEN_MASK;
	trdata = cmd + 1;

	DPTINT("    fifold: %s",
	      fifoldst_class[(*cmd & CLASS_MASK) >> CLASS_SHIFT]);

	if ((*cmd & FIFOLD_TYPE_PK_MASK) == FIFOLD_TYPE_PK)
		DPTINT(" pk-%s",
		      load_pkha_inp_types[(*cmd & FIFOLD_TYPE_PK_TYPEMASK) >>
					  FIFOLD_TYPE_SHIFT]);
	else {
		DPTINT(" %s",
		      load_inp_types[(*cmd & FIFOLD_TYPE_MSG_MASK) >>
				     FIFOLD_CONT_TYPE_SHIFT]);

		if (*cmd & FIFOLD_TYPE_LAST2)
			DPTINT("-last2");

		if (*cmd & FIFOLD_TYPE_LAST1)
			DPTINT("-last1");

		if (*cmd & FIFOLD_TYPE_FLUSH1)
			DPTINT("-flush1");
	}

	DPTINT(" len=%d", len);

	if (*cmd & FIFOLDST_SGF_MASK)
		DPTINT(" s/g");

	if (*cmd & FIFOLD_IMM_MASK)
		DPTINT(" imm");

	if (*cmd & FIFOLDST_EXT_MASK)
		DPTINT(" ext");

	(*idx)++; /* Bump index either to extension or next instruction */

	DPTINT("\n");
	if (*cmd & FIFOLD_IMM) {
		desc_hexdump(trdata, len >> 2, 4, leader);
		(*idx) += len >> 2;
	} else { /* is just trailing pointer */
		DPTINT("%s@0x%08x\n", leader, *trdata);
		(*idx)++;
	}

	if (*cmd & FIFOLDST_EXT) {
		DPTINT("%sextlen=%d\n", leader, *(++trdata));
		(*idx)++;
	}
}

static void show_seq_fifo_load(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t *trdata, len;

	len  = *cmd & FIFOLDST_LEN_MASK;
	trdata = cmd + 1;

	DPTINT(" seqfifold: %s",
	      fifoldst_class[(*cmd & CLASS_MASK) >> CLASS_SHIFT]);

	if ((*cmd & FIFOLD_TYPE_PK_MASK) == FIFOLD_TYPE_PK)
		DPTINT(" pk-%s",
		      load_pkha_inp_types[(*cmd * FIFOLD_TYPE_PK_TYPEMASK) >>
					  FIFOLD_TYPE_SHIFT]);
	else {
		DPTINT(" %s",
		      load_inp_types[(*cmd & FIFOLD_TYPE_MSG_MASK) >>
				     FIFOLD_CONT_TYPE_SHIFT]);

		if (*cmd & FIFOLD_TYPE_LAST2)
			DPTINT("-last2");

		if (*cmd & FIFOLD_TYPE_LAST1)
			DPTINT("-last1");

		if (*cmd & FIFOLD_TYPE_FLUSH1)
			DPTINT("-flush1");
	}

	DPTINT(" len=%d", len);

	if (*cmd & FIFOLDST_VLF_MASK)
		DPTINT(" vlf");

	if (*cmd & FIFOLD_IMM_MASK)
		DPTINT(" imm");

	if (*cmd & FIFOLDST_EXT_MASK)
		DPTINT(" ext");

	DPTINT("\n");

	(*idx)++;

	if (*cmd & FIFOLD_IMM) {
		desc_hexdump(trdata, len >> 2, 4, leader);
		(*idx) += len >> 2;
	}

	if (*cmd & FIFOLDST_EXT) {
		DPTINT("%sextlen=%d\n", leader, *(++trdata));
		(*idx)++;
	}
}

static void show_store(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t stlen, *stdata;
	uint8_t class;

	class = (*cmd & CLASS_MASK) >> CLASS_SHIFT;
	stlen  = *cmd & LDST_LEN_MASK;
	stdata = cmd + 1;

	DPTINT("       str: %s %s len=%d offs=%d\n",
	      ldst_class[class],
	      ldstr_srcdst[class]
			  [(*cmd & LDST_SRCDST_MASK) >> LDST_SRCDST_SHIFT],
	      (*cmd & LDST_LEN_MASK) >> LDST_LEN_SHIFT,
	      (*cmd & LDST_OFFSET_MASK) >> LDST_OFFSET_SHIFT);

	if (*cmd & LDST_SGF)
		DPTINT(" s/g");

	if (*cmd & LDST_IMM)
		DPTINT(" imm");

	(*idx)++;

	if (*cmd & LDST_IMM) {
		desc_hexdump(stdata, stlen >> 2, 4, leader);
		(*idx) += stlen >> 2;
	} else {
		DPTINT("%s@0x%08x\n", leader, *stdata);
		(*idx)++;
	}
}

static void show_seq_store(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint8_t class;

	class = (*cmd & CLASS_MASK) >> CLASS_SHIFT;

	DPTINT("    seqstr: %s %s len=%d offs=%d\n",
	      ldst_class[class],
	      ldstr_srcdst[class]
			  [(*cmd & LDST_SRCDST_MASK) >> LDST_SRCDST_SHIFT],
	      (*cmd & LDST_LEN_MASK) >> LDST_LEN_SHIFT,
	      (*cmd & LDST_OFFSET_MASK) >> LDST_OFFSET_SHIFT);

	if (*cmd & LDST_VLF)
		DPTINT(" vlf");

	if (*cmd & LDST_IMM)
		DPTINT(" imm");

	(*idx)++;
}

static void show_fifo_store(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t *trdata, len;

	len  = *cmd & FIFOLDST_LEN_MASK;
	trdata = cmd + 1;

	DPTINT("   fifostr: %s %s len=%d",
	      fifoldst_class[(*cmd & CLASS_MASK) >> CLASS_SHIFT],
	      fifo_output_data_type[(*cmd & FIFOST_TYPE_MASK) >>
				    FIFOST_TYPE_SHIFT], len);

	if (*cmd & FIFOLDST_SGF_MASK)
		DPTINT(" s/g");

	if (*cmd & FIFOST_CONT_MASK)
		DPTINT(" cont");

	if (*cmd & FIFOLDST_EXT_MASK)
		DPTINT(" ext");

	DPTINT("\n");
	(*idx)++;

	if (*cmd & FIFOST_IMM) {
		desc_hexdump(trdata, len >> 2, 4, leader);
		(*idx) += len >> 2;
	} else {
		DPTINT("%s@0x%08x\n", leader, *trdata);
		(*idx)++;
	}

	if (*cmd & FIFOLDST_EXT) {
		DPTINT("%sextlen=%d\n", leader, *(++trdata));
		(*idx)++;
	}
}

static void show_seq_fifo_store(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t pcmd, *trdata, len;

	len  = *cmd & FIFOLDST_LEN_MASK;
	trdata = cmd + 1;

	DPTINT("seqfifostr: %s %s len=%d",
	      fifoldst_class[(*cmd & CLASS_MASK) >> CLASS_SHIFT],
	      fifo_output_data_type[(*cmd & FIFOST_TYPE_MASK) >>
				    FIFOST_TYPE_SHIFT], len);

	if (*cmd & FIFOLDST_VLF_MASK)
		DPTINT(" vlf");

	if (*cmd & FIFOST_CONT_MASK)
		DPTINT(" cont");

	if (*cmd & FIFOLDST_EXT_MASK)
		DPTINT(" ext");

	DPTINT("\n");
	pcmd = *cmd;
	(*idx)++; /* Bump index either to extension or next instruction */

	if (pcmd & FIFOST_IMM) {
		desc_hexdump(trdata, len >> 2, 4, leader);
		(*idx) += len >> 2;
	}

	if (pcmd & FIFOLDST_EXT) {
		DPTINT("%sextlen=%d\n", leader, *(++trdata));
		(*idx)++;
	}
}

static void show_move(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	DPTINT("      move: %s->%s len=%d offs=%d",
	      move_src[(*cmd & MOVE_SRC_MASK) >> MOVE_SRC_SHIFT],
	      move_dst[(*cmd & MOVE_DEST_MASK) >> MOVE_DEST_SHIFT],
	      (*cmd & MOVE_LEN_MASK) >> MOVE_LEN_SHIFT,
	      (*cmd & MOVE_OFFSET_MASK) >> MOVE_OFFSET_SHIFT);

	if (*cmd & MOVE_WAITCOMP)
		DPTINT("wait ");

	DPTINT("\n");
	(*idx)++;
}

/* need a BUNCH of these decoded... */
static void decode_bidir_pcl_op(uint32_t *cmd)
{
	switch (*cmd & OP_PCLID_MASK) {
	case OP_PCLID_IPSEC:
		DPTINT("ipsec %s %s ",
		      ipsec_pclinfo_cipher[(*cmd & OP_PCL_IPSEC_CIPHER_MASK) >>
					   8],
		      ipsec_pclinfo_auth[(*cmd & OP_PCL_IPSEC_AUTH_MASK)]);
		break;

	case OP_PCLID_SRTP:
		DPTINT("srtp %s %s ",
		      ipsec_pclinfo_cipher[(*cmd & OP_PCL_IPSEC_CIPHER_MASK) >>
		      8],
		      ipsec_pclinfo_auth[(*cmd & OP_PCL_IPSEC_AUTH_MASK)]);
		break;

	case OP_PCLID_MACSEC:
		DPTINT("macsec ");
		if ((*cmd & OP_PCLINFO_MASK) == OP_PCL_MACSEC)
			DPTINT("aes-ccm-8 ");
		else
			DPTINT("<rsvd 0x%04x> ", *cmd & OP_PCLINFO_MASK);
		break;

	case OP_PCLID_WIFI:
		DPTINT("wifi ");
		if ((*cmd & OP_PCLINFO_MASK) == OP_PCL_WIFI)
			DPTINT("aes-gcm-16 ");
		else
			DPTINT("<rsvd 0x%04x> ", *cmd & OP_PCLINFO_MASK);
		break;

	case OP_PCLID_WIMAX:
		DPTINT("wimax ");
		switch (*cmd & OP_PCLINFO_MASK) {
		case OP_PCL_WIMAX_OFDM:
			DPTINT("ofdm ");
			break;

		case OP_PCL_WIMAX_OFDMA:
			DPTINT("ofdma ");
			break;

		default:
			DPTINT("<rsvd 0x%04x> ", *cmd & OP_PCLINFO_MASK);
		}
		break;

	case OP_PCLID_SSL30:
		DPTINT("ssl3.0 ");
		DPTINT("pclinfo=0x%04x ", *cmd & OP_PCLINFO_MASK);
		break;

	case OP_PCLID_TLS10:
		DPTINT("tls1.0 ");
		DPTINT("pclinfo=0x%04x ", *cmd & OP_PCLINFO_MASK);
		break;

	case OP_PCLID_TLS11:
		DPTINT("tls1.1 ");
		DPTINT("pclinfo=0x%04x ", *cmd & OP_PCLINFO_MASK);
		break;

	case OP_PCLID_TLS12:
		DPTINT("tls1.2 ");
		DPTINT("pclinfo=0x%04x ", *cmd & OP_PCLINFO_MASK);
		break;

	case OP_PCLID_DTLS10:
		DPTINT("dtls ");
		DPTINT("pclinfo=0x%04x ", *cmd & OP_PCLINFO_MASK);
		break;
	}
}

static void decode_class12_op(uint32_t *cmd)
{
	/* Algorithm type */
	switch (*cmd & OP_ALG_ALGSEL_MASK) {
	case OP_ALG_ALGSEL_AES:
		DPTINT("aes ");
		break;

	case OP_ALG_ALGSEL_DES:
		DPTINT("des ");
		break;

	case OP_ALG_ALGSEL_3DES:
		DPTINT("3des ");
		break;

	case OP_ALG_ALGSEL_ARC4:
		DPTINT("arc4 ");
		break;

	case OP_ALG_ALGSEL_MD5:
		DPTINT("md5 ");
		break;

	case OP_ALG_ALGSEL_SHA1:
		DPTINT("sha1 ");
		break;

	case OP_ALG_ALGSEL_SHA224:
		DPTINT("sha224 ");
		break;

	case OP_ALG_ALGSEL_SHA256:
		DPTINT("sha256 ");
		break;

	case OP_ALG_ALGSEL_SHA384:
		DPTINT("sha384 ");
		break;

	case OP_ALG_ALGSEL_SHA512:
		DPTINT("sha512 ");
		break;

	case OP_ALG_ALGSEL_RNG:
		DPTINT("rng ");
		break;

	case OP_ALG_ALGSEL_SNOW_F8:
		DPTINT("snow f8");
		break;

	case OP_ALG_ALGSEL_SNOW_F9:
		DPTINT("snow f9");
		break;

	case OP_ALG_ALGSEL_KASUMI:
		DPTINT("kasumi ");
		break;

	case OP_ALG_ALGSEL_CRC:
		DPTINT("crc ");
		break;

	default:
		DPTINT("<rsvd> ");
	}

	/* Additional info */
	switch (*cmd & OP_ALG_ALGSEL_MASK) {
	case OP_ALG_ALGSEL_AES:
		switch (*cmd & OP_ALG_AAI_MASK) {
		case OP_ALG_AAI_CTR_MOD128:
			DPTINT("ctr128 ");
			break;

		case OP_ALG_AAI_CTR_MOD8:
			DPTINT("ctr8 ");
			break;

		case OP_ALG_AAI_CTR_MOD16:
			DPTINT("ctr16 ");
			break;

		case OP_ALG_AAI_CTR_MOD24:
			DPTINT("ctr24 ");
			break;

		case OP_ALG_AAI_CTR_MOD32:
			DPTINT("ctr32 ");
			break;

		case OP_ALG_AAI_CTR_MOD40:
			DPTINT("ctr40 ");
			break;

		case OP_ALG_AAI_CTR_MOD48:
			DPTINT("ctr48 ");
			break;

		case OP_ALG_AAI_CTR_MOD56:
			DPTINT("ctr56 ");
			break;

		case OP_ALG_AAI_CTR_MOD64:
			DPTINT("ctr64 ");
			break;

		case OP_ALG_AAI_CTR_MOD72:
			DPTINT("ctr72 ");
			break;

		case OP_ALG_AAI_CTR_MOD80:
			DPTINT("ctr80 ");
			break;

		case OP_ALG_AAI_CTR_MOD88:
			DPTINT("ctr88 ");
			break;

		case OP_ALG_AAI_CTR_MOD96:
			DPTINT("ctr96 ");
			break;

		case OP_ALG_AAI_CTR_MOD104:
			DPTINT("ctr104 ");
			break;

		case OP_ALG_AAI_CTR_MOD112:
			DPTINT("ctr112 ");
			break;

		case OP_ALG_AAI_CTR_MOD120:
			DPTINT("ctr120 ");
			break;

		case OP_ALG_AAI_CBC:
			DPTINT("cbc ");
			break;

		case OP_ALG_AAI_ECB:
			DPTINT("ecb ");
			break;

		case OP_ALG_AAI_CFB:
			DPTINT("cfb ");
			break;

		case OP_ALG_AAI_OFB:
			DPTINT("ofb ");
			break;

		case OP_ALG_AAI_XTS:
			DPTINT("xts ");
			break;

		case OP_ALG_AAI_CMAC:
			DPTINT("cmac ");
			break;

		case OP_ALG_AAI_XCBC_MAC:
			DPTINT("xcbc-mac ");
			break;

		case OP_ALG_AAI_CCM:
			DPTINT("ccm ");
			break;

		case OP_ALG_AAI_GCM:
			DPTINT("gcm ");
			break;

		case OP_ALG_AAI_CBC_XCBCMAC:
			DPTINT("cbc-xcbc-mac ");
			break;

		case OP_ALG_AAI_CTR_XCBCMAC:
			DPTINT("ctr-xcbc-mac ");
			break;

		case OP_ALG_AAI_DK:
			DPTINT("dk ");
			break;
		}
		break;

	case OP_ALG_ALGSEL_DES:
	case OP_ALG_ALGSEL_3DES:
		switch (*cmd & OP_ALG_AAI_MASK) {
		case OP_ALG_AAI_CBC:
			DPTINT("cbc ");
			break;

		case OP_ALG_AAI_ECB:
			DPTINT("ecb ");
			break;

		case OP_ALG_AAI_CFB:
			DPTINT("cfb ");
			break;

		case OP_ALG_AAI_OFB:
			DPTINT("ofb ");
			break;

		case OP_ALG_AAI_CHECKODD:
			DPTINT("chkodd ");
			break;
		}
		break;

	case OP_ALG_ALGSEL_RNG:
		switch (*cmd & OP_ALG_AAI_MASK) {
		case OP_ALG_AAI_RNG:
			DPTINT("rng ");
			break;

		case OP_ALG_AAI_RNG_NZB:
			DPTINT("rng-no0 ");
			break;

		case OP_ALG_AAI_RNG_OBP:
			DPTINT("rngodd ");
			break;
		}
		break;

	case OP_ALG_ALGSEL_KASUMI:
		switch (*cmd & OP_ALG_AAI_MASK) {
		case OP_ALG_AAI_F8:
			DPTINT("f8 ");
			break;

		case OP_ALG_AAI_F9:
			DPTINT("f9 ");
			break;

		case OP_ALG_AAI_GSM:
			DPTINT("gsm ");
			break;

		case OP_ALG_AAI_EDGE:
			DPTINT("edge ");
			break;
		}
		break;

	case OP_ALG_ALGSEL_CRC:
		switch (*cmd & OP_ALG_AAI_MASK) {
		case OP_ALG_AAI_802:
			DPTINT("802 ");
			break;

		case OP_ALG_AAI_3385:
			DPTINT("3385 ");
			break;

		case OP_ALG_AAI_CUST_POLY:
			DPTINT("custom-poly ");
			break;

		case OP_ALG_AAI_DIS:
			DPTINT("dis ");
			break;

		case OP_ALG_AAI_DOS:
			DPTINT("dos ");
			break;

		case OP_ALG_AAI_DOC:
			DPTINT("doc ");
			break;
		}
		break;

	case OP_ALG_ALGSEL_MD5:
	case OP_ALG_ALGSEL_SHA1:
	case OP_ALG_ALGSEL_SHA224:
	case OP_ALG_ALGSEL_SHA256:
	case OP_ALG_ALGSEL_SHA384:
	case OP_ALG_ALGSEL_SHA512:
		switch (*cmd & OP_ALG_AAI_MASK) {
		case OP_ALG_AAI_HMAC:
			DPTINT("hmac ");
			break;

		case OP_ALG_AAI_SMAC:
			DPTINT("smac ");
			break;

		case OP_ALG_AAI_HMAC_PRECOMP:
			DPTINT("hmac-pre ");
			break;
		}
		break;

	default:
		DPTINT("unknown-aai ");
	}

	if (*cmd & OP_ALG_TYPE_MASK) {
		switch (*cmd & OP_ALG_AS_MASK) {
		case OP_ALG_AS_UPDATE:
			DPTINT("update ");
			break;

		case OP_ALG_AS_INIT:
			DPTINT("init ");
			break;

		case OP_ALG_AS_FINALIZE:
			DPTINT("final ");
			break;

		case OP_ALG_AS_INITFINAL:
			DPTINT("init-final ");
			break;
		}
	}

	if (*cmd & OP_ALG_ICV_MASK)
		DPTINT("icv ");

	if (*cmd & OP_ALG_DIR_MASK)
		DPTINT("enc ");
	else
		DPTINT("dec ");

}

static void show_op_pk_clrmem_args(uint32_t inst)
{
	if (inst & OP_ALG_PKMODE_A_RAM)
		DPTINT("a ");

	if (inst & OP_ALG_PKMODE_B_RAM)
		DPTINT("b ");

	if (inst & OP_ALG_PKMODE_E_RAM)
		DPTINT("e ");

	if (inst & OP_ALG_PKMODE_N_RAM)
		DPTINT("n ");
}

static void show_op_pk_modmath_args(uint32_t inst)
{
	if (inst & OP_ALG_PKMODE_MOD_IN_MONTY)
		DPTINT("inmont ");

	if (inst & OP_ALG_PKMODE_MOD_OUT_MONTY)
		DPTINT("outmont ");

	if (inst & OP_ALG_PKMODE_MOD_F2M)
		DPTINT("poly ");

	if (inst & OP_ALG_PKMODE_MOD_R2_IN)
		DPTINT("r2%%n-inp ");

	if (inst & OP_ALG_PKMODE_PRJECTV)
		DPTINT("prj ");

	if (inst & OP_ALG_PKMODE_TIME_EQ)
		DPTINT("teq ");

	if (inst & OP_ALG_PKMODE_OUT_A)
		DPTINT("->a ");
	else
		DPTINT("->b ");
}

static void show_op_pk_cpymem_args(uint32_t inst)
{
	uint8_t srcregix, dstregix, srcsegix, dstsegix;

	srcregix = (inst & OP_ALG_PKMODE_SRC_REG_MASK) >>
		   OP_ALG_PKMODE_SRC_REG_SHIFT;
	dstregix = (inst & OP_ALG_PKMODE_DST_REG_MASK) >>
		   OP_ALG_PKMODE_DST_REG_SHIFT;
	srcsegix = (inst & OP_ALG_PKMODE_SRC_SEG_MASK) >>
		   OP_ALG_PKMODE_SRC_SEG_SHIFT;
	dstsegix = (inst & OP_ALG_PKMODE_DST_SEG_MASK) >>
		   OP_ALG_PKMODE_DST_SEG_SHIFT;

	DPTINT("%s[%d]->%s[%d] ", pk_srcdst[srcregix], srcsegix,
	      pk_srcdst[dstregix], dstsegix);
}

static void show_op(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	DPTINT(" operation: ");

	switch (*cmd & OP_TYPE_MASK) {
	case OP_TYPE_UNI_PROTOCOL:
		DPTINT("uni-pcl ");
		DPTINT("%s ",
		      unidir_pcl[(*cmd & OP_PCLID_MASK) >> OP_PCLID_SHIFT]);
		break;

	case OP_TYPE_PK:
		DPTINT("pk %s ",
		      pk_function[*cmd & OP_ALG_PK_FUN_MASK]);
		switch (*cmd & OP_ALG_PK_FUN_MASK) {
		case OP_ALG_PKMODE_CLEARMEM:
			show_op_pk_clrmem_args(*cmd);
			break;

		case OP_ALG_PKMODE_MOD_ADD:
		case OP_ALG_PKMODE_MOD_SUB_AB:
		case OP_ALG_PKMODE_MOD_SUB_BA:
		case OP_ALG_PKMODE_MOD_MULT:
		case OP_ALG_PKMODE_MOD_EXPO:
		case OP_ALG_PKMODE_MOD_REDUCT:
		case OP_ALG_PKMODE_MOD_INV:
		case OP_ALG_PKMODE_MOD_ECC_ADD:
		case OP_ALG_PKMODE_MOD_ECC_DBL:
		case OP_ALG_PKMODE_MOD_ECC_MULT:
		case OP_ALG_PKMODE_MOD_MONT_CNST:
		case OP_ALG_PKMODE_MOD_CRT_CNST:
		case OP_ALG_PKMODE_MOD_GCD:
		case OP_ALG_PKMODE_MOD_PRIMALITY:
			show_op_pk_modmath_args(*cmd);
			break;

		case OP_ALG_PKMODE_COPY_NSZ:
		case OP_ALG_PKMODE_COPY_SSZ:
			show_op_pk_cpymem_args(*cmd);
			break;
		}
		break;

	case OP_TYPE_CLASS1_ALG:
		DPTINT("cls1-op ");
		decode_class12_op(cmd);
		break;

	case OP_TYPE_CLASS2_ALG:
		DPTINT("cls2-op ");
		decode_class12_op(cmd);
		break;

	case OP_TYPE_DECAP_PROTOCOL:
		DPTINT("decap ");
		decode_bidir_pcl_op(cmd);
		break;

	case OP_TYPE_ENCAP_PROTOCOL:
		DPTINT("encap ");
		decode_bidir_pcl_op(cmd);
		break;
	}
	DPTINT("\n");
	(*idx)++;
}

static void show_signature(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	DPTINT(" signature: %s\n",
	      sig_type[(*cmd & SIGN_TYPE_MASK) >> SIGN_TYPE_SHIFT]);
	(*idx)++;

	/* Process 8 word signature */
	desc_hexdump(cmd + 1, 8, 4, leader);
	idx += 8;
}

static void show_jump(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t cond;
	int8_t relidx, offset;

	DPTINT("      jump: %s %s %s",
	      fifoldst_class[(*cmd & CLASS_MASK) >> CLASS_SHIFT],
	      jump_types[(*cmd & JUMP_TYPE_MASK) >> JUMP_TYPE_SHIFT],
	      jump_tests[(*cmd & JUMP_TEST_MASK) >> JUMP_TEST_SHIFT]);

	cond = (*cmd & (JUMP_COND_MASK & ~JUMP_JSL));
	if (!(*cmd & JUMP_JSL)) {
		if (cond & JUMP_COND_PK_0)
			DPTINT(" pk-0");

		if (cond & JUMP_COND_PK_GCD_1)
			DPTINT(" pk-gcd=1");

		if (cond & JUMP_COND_PK_PRIME)
			DPTINT(" pk-prime");

		if (cond & JUMP_COND_MATH_N)
			DPTINT(" math-n");

		if (cond & JUMP_COND_MATH_Z)
			DPTINT(" math-z");

		if (cond & JUMP_COND_MATH_C)
			DPTINT(" math-c");

		if (cond & JUMP_COND_MATH_NV)
			DPTINT(" math-nv");
	} else {
		if (cond & JUMP_COND_JQP)
			DPTINT(" jq-pend");

		if (cond & JUMP_COND_SHRD)
			DPTINT(" share-skip");

		if (cond & JUMP_COND_SELF)
			DPTINT(" share-ctx");

		if (cond & JUMP_COND_CALM)
			DPTINT(" complete");

		if (cond & JUMP_COND_NIP)
			DPTINT(" no-input");

		if (cond & JUMP_COND_NIFP)
			DPTINT(" no-infifo");

		if (cond & JUMP_COND_NOP)
			DPTINT(" no-output");

		if (cond & JUMP_COND_NCP)
			DPTINT(" no-ctxld");
	}

	relidx = *idx; /* sign extend index to compute relative instruction */
	offset = *cmd & JUMP_OFFSET_MASK;
	if ((*cmd & JUMP_TYPE_MASK) == JUMP_TYPE_LOCAL) {
		DPTINT(" ->%d [%02d]\n", offset, relidx + offset);
		(*idx)++;
	} else {
		DPTINT(" ->@0x%08x\n", (*idx + 1));
		*idx += 2;
	}
}

static void show_math(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	uint32_t mathlen;

	mathlen	 = *cmd & MATH_LEN_MASK;

	DPTINT("      math: %s.%s.%s->%s len=%d ",
	      math_src0[(*cmd & MATH_SRC0_MASK) >> MATH_SRC0_SHIFT],
	      math_fun[(*cmd & MATH_FUN_MASK) >> MATH_FUN_SHIFT],
	      math_src1[(*cmd & MATH_SRC1_MASK) >> MATH_SRC1_SHIFT],
	      math_dest[(*cmd & MATH_DEST_MASK) >> MATH_DEST_SHIFT],
	      mathlen);

	if (*cmd & MATH_IFB)
		DPTINT("imm4 ");
	if (*cmd & MATH_NFU)
		DPTINT("noflag ");
	if (*cmd & MATH_STL)
		DPTINT("stall ");

	DPTINT("\n");
	(*idx)++;

	if  (((*cmd & MATH_SRC0_MASK) == MATH_SRC0_IMM) ||
	     ((*cmd & MATH_SRC1_MASK) == MATH_SRC1_IMM)) {
		desc_hexdump(cmd + 1, 1, 4, leader);
		(*idx)++;
	};
};

static void show_seq_in_ptr(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	DPTINT("  seqinptr:");
	if (*cmd & SQIN_RBS)
		DPTINT(" rls-buf");
	if (*cmd & SQIN_INL)
		DPTINT(" imm");
	if (*cmd & SQIN_SGF)
		DPTINT(" s/g");
	if (*cmd & SQIN_PRE) {
		DPTINT(" PRE");
	} else {
		DPTINT(" @0x%08x", *(cmd + 1));
		(*idx)++;
	}
	if (*cmd & SQIN_EXT)
		DPTINT(" EXT");
	else
		DPTINT(" %d", *cmd & 0xffff);
	if (*cmd & SQIN_RTO)
		DPTINT(" RTO");
	DPTINT("\n");
	(*idx)++;
}

static void show_seq_out_ptr(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	DPTINT(" seqoutptr:");
	if (*cmd & SQOUT_SGF)
		DPTINT(" s/g");
	if (*cmd & SQOUT_PRE) {
		DPTINT(" PRE");
	} else {
		DPTINT(" @0x%08x", *(cmd + 1));
		(*idx)++;
	}
	if (*cmd & SQOUT_EXT)
		DPTINT(" EXT");
	else
		DPTINT(" %d", *cmd & 0xffff);
	DPTINT("\n");
	(*idx)++;
}

static void show_illegal_inst(uint32_t *cmd, uint8_t *idx, int8_t *leader)
{
	DPTINT("<illegal-instruction>\n");
	(*idx)++;
}

/* Handlers for each instruction based on CTYPE as an enumeration */
static void (*inst_disasm_handler[])(uint32_t *, uint8_t *, int8_t *) = {
	show_key,
	show_seq_key,
	show_load,
	show_seq_load,
	show_fifo_load,
	show_seq_fifo_load,
	show_illegal_inst,
	show_illegal_inst,
	show_illegal_inst,
	show_illegal_inst,
	show_store,
	show_seq_store,
	show_fifo_store,
	show_seq_fifo_store,
	show_illegal_inst,
	show_move,
	show_op,
	show_illegal_inst,
	show_signature,
	show_illegal_inst,
	show_jump,
	show_math,
	show_illegal_inst, /* header */
	show_illegal_inst, /* shared header */
	show_illegal_inst,
	show_illegal_inst,
	show_illegal_inst,
	show_illegal_inst,
	show_illegal_inst,
	show_illegal_inst,
	show_seq_in_ptr,
	show_seq_out_ptr,
};

/**
 * caam_desc_disasm() - Top-level descriptor disassembler
 * @desc - points to the descriptor to disassemble. First command
 *	   must be a header, or shared header, and the overall size
 *	   is determined by this. Does not handle a QI preheader as
 *	   it's first command, and cannot yet follow links in a list
 *	   of descriptors
 * @opts - selects options for output:
 *	   DISASM_SHOW_OFFSETS - displays the index/offset of each
 *				 instruction in the descriptor. Helpful
 *				 for visualizing flow control changes
 *	   DISASM_SHOW_RAW     - displays value of each instruction
 **/
void caam_desc_disasm(uint32_t *desc, uint32_t opts)
{
	uint8_t len, idx, stidx;
	int8_t emptyleader[MAX_LEADER_LEN], pdbleader[MAX_LEADER_LEN];

	stidx  = 0;

	/*
	 * Build up padded leader strings for non-instruction content
	 * These get used for pointer and PDB content dumps
	 */
	emptyleader[0] = 0;
	pdbleader[0] = 0;

	/* Offset leader is a 5-char string, e.g. "[xx] " */
	if (opts & DISASM_SHOW_OFFSETS) {
		strcat((char *)emptyleader, "	  ");
		strcat((char *)pdbleader, "	");
	}

	/* Raw instruction leader is an 11-char string, e.g. "0xnnnnnnnn " */
	if (opts & DISASM_SHOW_RAW) {
		strcat((char *)emptyleader, "		");
		strcat((char *)pdbleader, "	      ");
	}

	/* Finish out leaders. Instruction names use a 12-char space */
	strcat((char *)emptyleader, "		 ");
	strcat((char *)pdbleader, "	(pdb): ");

	/*
	 * Now examine our descriptor, starting with it's header.
	 * First word must be header or shared header, or we quit
	 * under the assumption that a bad desc pointer was passed.
	 * If we have a valid header, save off indices and size for
	 * determining descriptor area boundaries
	 */
	switch (*desc & CMD_MASK) {
	case CMD_SHARED_DESC_HDR:
		if (opts & DISASM_SHOW_OFFSETS)
			DPTINT("[%02d] ", 0);
		if (opts & DISASM_SHOW_RAW)
			DPTINT("0x%08x ", desc[0]);
		show_shrhdr(desc);
		len   = *desc & HDR_DESCLEN_SHR_MASK;
		stidx = (*desc & HDR_START_IDX_MASK) >> HDR_START_IDX_SHIFT;

		if (stidx == 0)
			stidx++;

		/*
		 * Show PDB area (that between header and startindex)
		 * Improve PDB content dumps later...
		 */
		if (stidx > 1) /* >1 means real PDB data exists */
			desc_hexdump(&desc[1], stidx - 1, 4,
				     (int8_t *)pdbleader);

		idx = stidx;
		break;

	case CMD_DESC_HDR:
		if (opts & DISASM_SHOW_OFFSETS)
			DPTINT("[%02d] ", 0);
		if (opts & DISASM_SHOW_RAW)
			DPTINT("0x%08x ", desc[0]);
		show_hdr(desc);
		len   = *desc & HDR_DESCLEN_MASK;
		stidx = (*desc & HDR_START_IDX_MASK) >> HDR_START_IDX_SHIFT;

		/* Start index of 0 really just means 1, so fix */
		if (stidx == 0)
			stidx++;

		/* Skip sharedesc pointer if SHARED, else display PDB */
		if (*desc & HDR_SHARED) {
			stidx = 2; /* just skip past sharedesc ptr */
			DPTINT("%s sharedesc->0x%08x\n", emptyleader, desc[1]);
		} else
			if (stidx > 1) /* >1 means real PDB data exists */
				desc_hexdump(&desc[1], stidx - 1, 4,
					     (int8_t *)pdbleader);

		idx = stidx;
		break;

	default:
		DPTINT("caam_desc_disasm(): no header: 0x%08x\n",
		      *desc);
		return;
	}

	/* Header verified, now process sequential instructions */
	while (idx < len) {
		if (opts & DISASM_SHOW_OFFSETS)
			DPTINT("[%02d] ", idx);
		if (opts & DISASM_SHOW_RAW)
			DPTINT("0x%08x ", desc[idx]);
		inst_disasm_handler[(desc[idx] & CMD_MASK) >> CMD_SHIFT]
				    (&desc[idx], &idx, emptyleader);
	}
}
EXPORT_SYMBOL(caam_desc_disasm);
