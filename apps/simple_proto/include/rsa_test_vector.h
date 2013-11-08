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


#ifndef RSA_TEST_VECTOR_H_
#define RSA_TEST_VECTOR_H_

#include <inttypes.h>
#include <usdpaa/compat.h>

#define RSA_MAX_LENGTH	384

/**
 * Structure which defines a RSA test vector.
 */
struct rsa_ref_vector_s {
	union {
		uintptr_t key;			/**< Used when the key contents
						     are supposed to be copied
						     by RTA as immediate in the
						     created descriptor. */
		dma_addr_t dma_addr_key;	/**< Used when a pointer to
						     the key is supposed to be
						     used as-is by RTA in the
						     created descriptor. */
	};
	unsigned char cipher_alg;
	unsigned short cipher_keylen;
	unsigned char auth_alg;
	union {
		uintptr_t auth_key;		/**< Used when the key contents
						     are supposed to be copied
						     by RTA as immediate in the
						     created descriptor. */
		dma_addr_t dma_addr_auth_key;	/**< Used when a pointer to
						     the key is supposed to be
						     used as-is by RTA in the
						     created descriptor. */
	};
	unsigned short auth_keylen;
	uint32_t length;
	uint8_t *plaintext;
	uint8_t *ciphertext;
	/*
	 * NOTE: Keep members above unchanged!
	 */
	uint32_t options;
	uint8_t *f_ref;
	uint8_t *g_ref;
	uint8_t *n_ref;
	uint8_t *e_ref;
	uint8_t *d_ref;
	uint32_t f_len;
	uint32_t e_len;
	uint32_t n_len;
	uint32_t d_len;
};

/* RSA Test Vectors - generated using GMP as the underlying math library */
static uint8_t rsa_ref_input[][RSA_MAX_LENGTH] = {
	/* Test set 1 */
	{0x69, 0x77, 0x6a, 0x88, 0xd1, 0x4d, 0x0f, 0xbd, 0x6c, 0x88, 0x6a, 0x61,
	 0x13, 0xa1, 0x7b, 0x88, 0x36, 0x05, 0x09, 0x07, 0x29, 0x7e, 0x20, 0x08,
	 0x33, 0x5c, 0xbf, 0xe3, 0xb1, 0x76, 0xd7, 0x75, 0x6b, 0x46, 0xf2, 0x42,
	 0x62, 0xd8, 0x0b, 0x00, 0x98, 0x08, 0x97, 0x75, 0x90, 0x2e, 0x1b, 0x07,
	 0xb5, 0x27, 0x47, 0xa9, 0xf1, 0xdd, 0x7e, 0x1a, 0xa0, 0xab, 0x2e, 0x28,
	 0x8b, 0xfa, 0xbf, 0xcd, 0x07, 0x9a, 0x29, 0xd9, 0xb1, 0x97, 0xe8, 0x1e,
	 0xfe, 0x78, 0xde, 0x71, 0xff, 0x20, 0xe7, 0xc8, 0x7f, 0xff, 0x89, 0x04,
	 0x5c, 0x26, 0xec, 0xc3, 0xb2, 0x57, 0x84, 0x1c, 0xb0, 0xbe, 0xb0, 0x50,
	 0x49, 0x2b, 0x5c, 0x97, 0xe0, 0xee, 0x40, 0x07, 0xf5, 0x8f, 0x0f, 0xc3,
	 0xf7, 0x33, 0xa5, 0xd7, 0x5f, 0x23, 0x94, 0x71, 0x19, 0x97, 0xd1, 0x07,
	 0x57, 0x43, 0x47, 0x8e, 0x3f, 0x84, 0x52, 0x96},
	/* Test set 2 */
	{0x4b, 0x6e, 0x00, 0x23, 0x87, 0x9d, 0x95, 0xfa, 0x35, 0xbe, 0x3a, 0x03,
	 0x58, 0x2b, 0x6a, 0x46, 0x63, 0x95, 0x0c, 0x8a, 0xf4, 0xa4, 0x56, 0x35,
	 0x25, 0xc0, 0xe7, 0xe7, 0xe9, 0x6b, 0x17, 0x77, 0x5a, 0x90, 0x4d, 0xbc,
	 0xb9, 0x9b, 0xd6, 0x98, 0x97, 0xf8, 0xc8, 0x89, 0x18, 0xa3, 0xf0, 0xfc,
	 0x87, 0x13, 0x36, 0xcf, 0xcf, 0xa3, 0x27, 0x9b, 0x4d, 0x64, 0x75, 0x13,
	 0xd3, 0x6a, 0xc5, 0x47, 0x34, 0x65, 0x6a, 0x82, 0xc2, 0x8b, 0xc6, 0x1d,
	 0xd8, 0x5c, 0xe4, 0x85, 0x7e, 0x68, 0x03, 0x00, 0x08, 0x48, 0xc8, 0x26,
	 0x19, 0xf2, 0x32, 0xc2, 0xa4, 0xcf, 0xb6, 0x5b, 0x49, 0x55, 0x4e, 0xf5,
	 0xf1, 0xcc, 0x8c, 0x44, 0xb4, 0x66, 0xef, 0x43, 0xf0, 0x3f, 0x35, 0xa4,
	 0x59, 0xca, 0x2a, 0x1c, 0x58, 0xf0, 0x65, 0xca, 0xdf, 0x6a, 0x29, 0x76,
	 0x86, 0xc5, 0x4c, 0x93, 0xfe, 0xd8, 0x1c, 0x5e, 0xd4, 0x69, 0x65, 0xde,
	 0x00, 0xf4, 0x29, 0x04, 0x23, 0xfb, 0x9a, 0x21, 0xea, 0x54, 0x6e, 0x01,
	 0x1d, 0xa4, 0x60, 0x99, 0x2b, 0x57, 0xa3, 0xfc, 0x21, 0x05, 0x43, 0x21,
	 0x80, 0xbd, 0xf5, 0x88, 0x1f, 0xd8, 0xb8, 0x9b, 0x23, 0xfc, 0x9f, 0xba,
	 0x1d, 0xe8, 0xd0, 0xde, 0x68, 0xd7, 0x84, 0xdb, 0xad, 0x5d, 0xe2, 0x7d,
	 0x30, 0x79, 0x4b, 0x16, 0x8b, 0x24, 0xad, 0x08, 0x90, 0xc8, 0xc6, 0x29,
	 0xa2, 0x8e, 0xe5, 0x56, 0xa8, 0x93, 0x46, 0xe6, 0xa4, 0x55, 0x5b, 0x4c,
	 0x25, 0x37, 0x2d, 0xfe, 0xf1, 0x0e, 0x25, 0x76, 0x47, 0x76, 0x7a, 0x37,
	 0xe1, 0xea, 0x69, 0x45, 0x1d, 0xb7, 0x24, 0x56, 0xb7, 0x3f, 0x27, 0x67,
	 0x91, 0xf2, 0x05, 0x65, 0xd3, 0xf0, 0xb4, 0x53, 0xda, 0x89, 0xd2, 0x53,
	 0xf8, 0xa9, 0x07, 0x50, 0x7a, 0xda, 0x7c, 0x27, 0xf4, 0x1b, 0xf4, 0x8d,
	 0xed, 0xff, 0x3d, 0xc5, 0xc1, 0xb1, 0x12, 0x15, 0x70, 0xe3, 0x4c, 0x4c,
	 0x33, 0xb3, 0xe0, 0x71, 0x34, 0x89, 0x8b, 0x2e, 0x10, 0xd7, 0xf8, 0x8f,
	 0x79, 0x46, 0x1b, 0xb5, 0xe5, 0xac, 0x74, 0x2e, 0x03, 0x1e, 0x60, 0xa6,
	 0x2d, 0xc3, 0x0f, 0xc1, 0xbd, 0xf7, 0x3e, 0xb8, 0xfd, 0x1d, 0xfd, 0xbd,
	 0x85, 0xfc, 0x1f, 0x36, 0x18, 0xc8, 0x7f, 0xd2, 0x4d, 0xcf, 0xae, 0x65,
	 0x4f, 0xad, 0x3f, 0x70, 0x99, 0xf8, 0xad, 0xca, 0xcd, 0xcb, 0x20, 0xc1,
	 0xa1, 0x2e, 0x3e, 0x73, 0xb5, 0x03, 0x07, 0xef, 0x80, 0x9c, 0xfb, 0x52,
	 0x4c, 0xaf, 0xff, 0x7d, 0x3c, 0x8e, 0xa3, 0xee, 0x22, 0x01, 0xa2, 0x89,
	 0xba, 0x8a, 0xfe, 0x0d, 0xc1, 0x2a, 0x26, 0x6d, 0xdc, 0x1d, 0x27, 0x74,
	 0x71, 0xa2, 0x79, 0xf6, 0x2e, 0x3c, 0xec, 0x39, 0xfa, 0x47, 0x41, 0xb5,
	 0xfb, 0x25, 0x48, 0x2b, 0xa9, 0x40, 0x0b, 0x94, 0xe9, 0x1e, 0xa7, 0xac}
};

static uint8_t rsa_ref_public_exponent[][RSA_MAX_LENGTH] = {
	/* Test set 1 */
	{0x01, 0x00, 0x01},
	/* Test set 2 */
	{0x01, 0x00, 0x01}
};

static uint32_t rsa_ref_length[] = {1024, 3072};

static uint32_t rsa_ref_exponent_len[] = {3, 3};
static uint32_t rsa_ref_modulus_len[] = {128, 384};
static uint32_t rsa_ref_input_len[] = {128, 384};
static uint32_t rsa_ref_private_exp_len[] = {128, 384};

static uint8_t rsa_ref_private_exponent[][RSA_MAX_LENGTH] = {
	/* Test set 1 */
	{0x24, 0x60, 0x78, 0x21, 0x34, 0xAF, 0x09, 0x0B, 0xC8, 0xBE, 0xFF, 0x89,
	 0x90, 0xEA, 0x2E, 0xE7, 0x42, 0x20, 0x95, 0x88, 0x50, 0xBB, 0x0B, 0x72,
	 0x9D, 0x86, 0x4F, 0xDD, 0x62, 0x81, 0x90, 0x92, 0x17, 0xA1, 0xD0, 0x4A,
	 0x4D, 0xDF, 0xA3, 0xEE, 0x12, 0xA7, 0xAA, 0x97, 0x0F, 0x94, 0x16, 0x57,
	 0xBB, 0xEF, 0x3C, 0x2B, 0xFB, 0x76, 0xA6, 0x77, 0xF3, 0x24, 0x2D, 0x6C,
	 0x17, 0x76, 0x87, 0xE0, 0x39, 0x64, 0xCE, 0x6C, 0xF5, 0x51, 0x2D, 0x6E,
	 0x2A, 0x20, 0x2C, 0xAA, 0x3E, 0xF7, 0xCD, 0x1A, 0x73, 0xC9, 0xB9, 0x86,
	 0x57, 0x2D, 0x4A, 0xB1, 0x80, 0x6F, 0xCE, 0xE7, 0x81, 0x94, 0xCF, 0xF6,
	 0xB5, 0x8F, 0x84, 0x1C, 0x41, 0x82, 0x6C, 0xDD, 0xCC, 0xF1, 0xE4, 0xC8,
	 0x88, 0xBF, 0x15, 0xB9, 0x18, 0xA8, 0xFD, 0xB4, 0x9B, 0x6C, 0xE3, 0x37,
	 0x86, 0x40, 0xE7, 0x02, 0xEE, 0xA5, 0xEB, 0x81},
	/* Test set 2 */
	{0x0D, 0x23, 0x52, 0xCC, 0xDD, 0x72, 0x13, 0x6D, 0x6A, 0xE3, 0xC2, 0x0F,
	 0xFF, 0xEE, 0x8F, 0x03, 0x67, 0x5E, 0xDF, 0x01, 0x53, 0x27, 0x00, 0x32,
	 0xBE, 0xE5, 0x55, 0x19, 0x48, 0xAD, 0x77, 0xBE, 0x9E, 0xAE, 0x28, 0xD4,
	 0x45, 0x2C, 0x44, 0xB9, 0x67, 0xFD, 0x77, 0x5E, 0xE3, 0xB5, 0x62, 0x52,
	 0x82, 0x75, 0xE1, 0x9E, 0x0B, 0xA4, 0xA0, 0xBB, 0x39, 0xA8, 0x1C, 0x16,
	 0x05, 0x46, 0xA6, 0xF6, 0x43, 0x09, 0xD7, 0x55, 0xD7, 0x5D, 0x97, 0x2D,
	 0xD7, 0x30, 0x4B, 0x51, 0x73, 0xA5, 0x24, 0xDB, 0x81, 0xD7, 0xFB, 0x1A,
	 0x86, 0x05, 0xD9, 0x82, 0x42, 0xC3, 0x29, 0xBD, 0x1F, 0x8A, 0x49, 0x14,
	 0xF4, 0xD6, 0xB2, 0x94, 0x56, 0xB5, 0x58, 0x94, 0xCE, 0x5C, 0x47, 0x6E,
	 0x54, 0x15, 0x1A, 0x3D, 0x40, 0xD5, 0x90, 0x6A, 0x20, 0xC7, 0x67, 0x01,
	 0x7F, 0xF8, 0xB3, 0xFC, 0x14, 0x0C, 0x1C, 0x38, 0x7E, 0x4E, 0xB2, 0x88,
	 0xA1, 0x03, 0x29, 0x5C, 0x93, 0x51, 0x27, 0x22, 0x5D, 0x31, 0x7A, 0xFE,
	 0x61, 0xE3, 0xBB, 0x07, 0x98, 0xA0, 0x95, 0xA8, 0x3E, 0x4A, 0xE4, 0x29,
	 0xF0, 0xD7, 0xF0, 0x72, 0xE9, 0x58, 0xB7, 0x0E, 0x22, 0xEC, 0xBE, 0x57,
	 0xF5, 0xD1, 0x35, 0xB6, 0xE7, 0x86, 0x02, 0x4D, 0x61, 0xC4, 0xAF, 0x27,
	 0xE9, 0x63, 0x25, 0x3B, 0x13, 0x1B, 0x42, 0x08, 0xE6, 0x4D, 0xF6, 0xC3,
	 0x76, 0x46, 0xB7, 0xDA, 0xF9, 0x12, 0x57, 0xCD, 0x5A, 0xBA, 0x8F, 0xC7,
	 0xE4, 0x36, 0x1E, 0x1A, 0xE6, 0xA2, 0x14, 0x10, 0xE3, 0x95, 0x82, 0x0A,
	 0x25, 0x51, 0x14, 0xC2, 0x4E, 0x10, 0x6B, 0x46, 0xBD, 0x97, 0x03, 0x44,
	 0x94, 0x1B, 0xC8, 0x46, 0x8D, 0x52, 0xA0, 0xE5, 0x05, 0xF4, 0xC6, 0x8C,
	 0x24, 0x4F, 0x89, 0x0C, 0xD4, 0xA4, 0x5B, 0x4E, 0x1F, 0x07, 0xC0, 0x5F,
	 0x36, 0x43, 0xB7, 0x17, 0x6F, 0x5F, 0x91, 0x4C, 0xB1, 0x42, 0xA4, 0x81,
	 0x4B, 0x48, 0x07, 0x3D, 0xE3, 0xE9, 0x0D, 0xF0, 0xDC, 0xED, 0x26, 0xEB,
	 0xE4, 0x16, 0x51, 0xC5, 0x5D, 0xFC, 0xE9, 0xAC, 0x50, 0xF2, 0xDA, 0x38,
	 0x3B, 0xB9, 0xB1, 0x07, 0xC3, 0x38, 0x4A, 0x68, 0xF9, 0xBB, 0x7C, 0xF3,
	 0xB0, 0x64, 0xDE, 0x49, 0x8E, 0x3C, 0x8B, 0xD3, 0x0F, 0x81, 0x0D, 0x7D,
	 0x29, 0xB9, 0xD3, 0xC4, 0x99, 0x6D, 0x64, 0x8F, 0x23, 0x17, 0x65, 0x28,
	 0xDE, 0xB8, 0x23, 0x2E, 0x8F, 0x6F, 0x49, 0xAA, 0xF9, 0x88, 0x9B, 0xF1,
	 0xBC, 0x64, 0x0B, 0x01, 0x05, 0x9C, 0xB4, 0x3E, 0xBA, 0x3F, 0x4B, 0x16,
	 0x0E, 0x94, 0x53, 0x8C, 0x27, 0xF9, 0x88, 0xD0, 0x27, 0x77, 0x3E, 0x6E,
	 0x6B, 0x7C, 0xC7, 0x3D, 0x8B, 0x4A, 0xD9, 0xE2, 0x9C, 0xF1, 0xA6, 0xCD,
	 0xCB, 0x53, 0xAF, 0xFB, 0x12, 0x6D, 0xD7, 0x37, 0x14, 0x97, 0x2D, 0xA1}
};

static uint8_t rsa_ref_modulus[][RSA_MAX_LENGTH] = {
	/* Test set 1 */
	{0xAF, 0xF8, 0x12, 0xC6, 0xB9, 0x2E, 0xE4, 0xEB, 0x3F, 0x9E, 0x33, 0x68,
	 0x3C, 0xD6, 0xF4, 0x76, 0x88, 0xA6, 0xBA, 0xDB, 0xC3, 0x4B, 0x6F, 0x70,
	 0xDD, 0x2C, 0x78, 0x18, 0x88, 0xA2, 0x69, 0x21, 0x2F, 0x50, 0x31, 0x34,
	 0xF2, 0xF5, 0xFB, 0x45, 0x48, 0x71, 0x05, 0x30, 0xF1, 0x78, 0xD1, 0x6F,
	 0xFB, 0x4B, 0x5B, 0xBE, 0x3C, 0x5D, 0x75, 0x0D, 0x41, 0xE9, 0x2F, 0x3E,
	 0x99, 0x7B, 0xB7, 0x93, 0x0E, 0x9E, 0x15, 0x0B, 0xB1, 0x63, 0xC5, 0x11,
	 0x51, 0xB6, 0x61, 0x2D, 0xE9, 0xDD, 0x28, 0xAA, 0xA2, 0x36, 0xC4, 0xA7,
	 0x77, 0x0B, 0x8E, 0x8D, 0xCE, 0xFB, 0xDA, 0xE5, 0xB9, 0x0F, 0x20, 0x68,
	 0x0C, 0xB9, 0x05, 0x40, 0xB2, 0x36, 0x83, 0xCE, 0x2C, 0x16, 0x74, 0x7E,
	 0x7D, 0x0C, 0x5F, 0xD3, 0xEF, 0xEE, 0xD4, 0x0A, 0x72, 0xA3, 0x16, 0xDD,
	 0xE7, 0xD3, 0xD3, 0xF7, 0x33, 0x8B, 0x3C, 0xD7},
	/* Test set 2 */
	{0x74, 0x6A, 0xE2, 0x3D, 0x34, 0x6F, 0xE6, 0x81, 0xCF, 0x95, 0x02, 0x34,
	 0xF5, 0x4A, 0x09, 0x34, 0xB1, 0xDA, 0x48, 0xD5, 0x4A, 0xEA, 0x1A, 0x16,
	 0xF3, 0xAE, 0x2C, 0x88, 0xB6, 0xFD, 0xF0, 0x14, 0xB6, 0xA5, 0x92, 0xB4,
	 0xC0, 0x31, 0x13, 0xFE, 0xC7, 0x55, 0x67, 0x4C, 0x64, 0xF1, 0x1E, 0x0A,
	 0x69, 0x3C, 0xEC, 0x0F, 0x69, 0x74, 0x97, 0x2F, 0x92, 0x75, 0xE2, 0x4E,
	 0x69, 0x62, 0xDD, 0x24, 0x34, 0x9D, 0xA4, 0x55, 0x3E, 0x01, 0xE3, 0x52,
	 0x0B, 0xD7, 0xA8, 0x8E, 0xD9, 0x0B, 0xC9, 0x31, 0xEF, 0xC8, 0x83, 0x57,
	 0x20, 0x45, 0xC3, 0xA3, 0x62, 0x59, 0xDF, 0x9C, 0xA2, 0x86, 0x0B, 0x53,
	 0xB1, 0x35, 0x48, 0xCB, 0x04, 0x59, 0xB1, 0x6E, 0xDD, 0x49, 0x2A, 0x51,
	 0x88, 0x37, 0xE0, 0x83, 0xA3, 0x0E, 0x94, 0xB0, 0x27, 0x5F, 0xA9, 0xE9,
	 0xCF, 0xE5, 0x00, 0x06, 0xEC, 0x7C, 0x10, 0x38, 0x4C, 0xAC, 0xD1, 0x98,
	 0x48, 0x67, 0x5E, 0x47, 0x0C, 0xCC, 0x2A, 0x36, 0x25, 0x83, 0xF3, 0xCF,
	 0xB5, 0xDC, 0xB9, 0xEB, 0x5B, 0xCC, 0xFD, 0x65, 0xE6, 0x5B, 0x2F, 0xEF,
	 0x01, 0x4F, 0xA7, 0xC3, 0xF9, 0x33, 0xEF, 0x11, 0xA6, 0xEF, 0x91, 0x66,
	 0x76, 0x00, 0xAD, 0x12, 0x0A, 0xB1, 0x48, 0x87, 0x45, 0x6F, 0xC3, 0x84,
	 0x3D, 0xDB, 0x1F, 0xA4, 0xE8, 0xD2, 0x12, 0xB2, 0x56, 0xE8, 0xC6, 0xDF,
	 0x9F, 0x7B, 0x07, 0xDC, 0xD3, 0x04, 0x23, 0xDA, 0x6A, 0xAC, 0xB3, 0x3F,
	 0xBB, 0x41, 0x67, 0x8B, 0x03, 0xAB, 0x3C, 0x47, 0x0B, 0xFB, 0x62, 0x04,
	 0x88, 0xEC, 0xBA, 0x1C, 0xFC, 0x27, 0xF9, 0xB0, 0x6C, 0x79, 0x43, 0x27,
	 0x1E, 0xD2, 0x22, 0xE8, 0x00, 0x70, 0xAD, 0x07, 0xF2, 0x15, 0x02, 0x85,
	 0xF2, 0xC4, 0x8C, 0xFF, 0x2E, 0x7F, 0x82, 0x75, 0x74, 0x8D, 0x97, 0x37,
	 0x9D, 0x57, 0x15, 0x8D, 0xEB, 0x13, 0xB7, 0x3A, 0x4C, 0x83, 0x8B, 0xFE,
	 0x72, 0x7D, 0x9A, 0x37, 0xF5, 0x4A, 0x9F, 0x3C, 0xF9, 0x0D, 0xB9, 0x12,
	 0xE6, 0xD7, 0x5A, 0x11, 0x89, 0x69, 0x1A, 0xED, 0xFB, 0x62, 0xAD, 0x9B,
	 0x5C, 0xE0, 0xDF, 0xC9, 0xF2, 0x31, 0x20, 0x0D, 0xDF, 0x90, 0x6B, 0x5C,
	 0x39, 0xDA, 0xB2, 0xD5, 0x2B, 0x25, 0xDD, 0x3A, 0x32, 0x45, 0xB9, 0x37,
	 0x83, 0xC1, 0x9E, 0x08, 0xE4, 0x5E, 0xE7, 0x99, 0x91, 0x7D, 0xBB, 0x78,
	 0xAA, 0xCD, 0x42, 0x96, 0x34, 0x37, 0xC4, 0x03, 0xCD, 0x8F, 0xCB, 0x43,
	 0xEB, 0x11, 0x80, 0x70, 0x3E, 0x8A, 0xC9, 0x2A, 0xC0, 0xE7, 0xFF, 0x72,
	 0xFA, 0xD3, 0x10, 0x57, 0xD5, 0x03, 0x27, 0x86, 0x89, 0xC7, 0xD8, 0xB4,
	 0xB7, 0x7B, 0x6D, 0x86, 0xC3, 0x13, 0xCC, 0xDC, 0x0E, 0xDB, 0x88, 0x5E,
	 0xD5, 0xA9, 0x11, 0xAA, 0xD8, 0x6B, 0x36, 0x67, 0x54, 0xF4, 0x68, 0x8B}
};

static uint8_t rsa_ref_result[][RSA_MAX_LENGTH] = {
	/* Test set 1 */
	{0x62, 0x5A, 0xE3, 0xE6, 0x1F, 0xC0, 0xB2, 0xAB, 0x28, 0xA5, 0xEB, 0xCA,
	 0xEA, 0x0E, 0xED, 0x5B, 0xF7, 0x04, 0xA5, 0xB5, 0x48, 0x94, 0x3D, 0xE4,
	 0x21, 0xD6, 0x3E, 0x57, 0x9D, 0xC5, 0x83, 0x06, 0xD5, 0xA3, 0x71, 0xBF,
	 0xBF, 0xF9, 0x56, 0xCA, 0x25, 0x42, 0xF1, 0x09, 0x13, 0xCA, 0xC8, 0x51,
	 0x9F, 0x69, 0x4F, 0xA8, 0x3D, 0x06, 0xA2, 0xC1, 0xC2, 0x23, 0xE8, 0xC2,
	 0xF7, 0xCF, 0x28, 0x6E, 0x66, 0x44, 0x52, 0x8A, 0xCC, 0x80, 0x4F, 0xDD,
	 0xCB, 0xFA, 0x3E, 0x0E, 0x6B, 0x51, 0x44, 0x45, 0x2A, 0xC0, 0x93, 0x14,
	 0x15, 0xDD, 0x01, 0xFB, 0x30, 0xC0, 0xF4, 0xB1, 0x8E, 0xD0, 0xAA, 0x83,
	 0xCC, 0x8D, 0x02, 0x8D, 0xA0, 0xAC, 0xA7, 0x9C, 0x17, 0x37, 0xC7, 0x6F,
	 0x8D, 0x7E, 0x0D, 0xF9, 0xFA, 0x4D, 0x5D, 0xCA, 0xFA, 0x0F, 0x99, 0x3B,
	 0xEB, 0x9C, 0xDE, 0x8C, 0x84, 0x6F, 0x34, 0xC1},
	/* Test set 2 */
	{0x19, 0x3A, 0x8A, 0x09, 0x89, 0xCD, 0xB1, 0x17, 0x80, 0xDE, 0xAF, 0xFF,
	 0x68, 0xA7, 0x9B, 0x08, 0xA6, 0x76, 0xEE, 0x6A, 0xFD, 0x7B, 0x0A, 0x23,
	 0xA5, 0x03, 0x36, 0xCD, 0xE6, 0x60, 0xFB, 0x57, 0xFC, 0x51, 0x3A, 0x63,
	 0x45, 0x39, 0x20, 0xE0, 0x27, 0xC0, 0x93, 0xC6, 0x6F, 0x1F, 0x4A, 0xF0,
	 0xF1, 0x4A, 0x21, 0xD4, 0xA5, 0x28, 0xB7, 0x1D, 0xE8, 0x3D, 0x43, 0x93,
	 0xF4, 0xB8, 0x79, 0x9F, 0x6D, 0xE6, 0x22, 0xF5, 0xF1, 0x8B, 0x89, 0xCD,
	 0xBA, 0xCC, 0xE2, 0x65, 0xF6, 0x23, 0xAC, 0x1F, 0xB4, 0x5E, 0xB9, 0x30,
	 0x84, 0x49, 0x03, 0x4F, 0xB2, 0x1B, 0x4B, 0xD1, 0x43, 0x43, 0xE0, 0x2A,
	 0x45, 0xF6, 0xF2, 0xFD, 0xEF, 0x41, 0xA0, 0x97, 0x23, 0xB2, 0xC9, 0x70,
	 0x4B, 0x39, 0x7E, 0xC9, 0xC3, 0x2F, 0x47, 0x56, 0xFD, 0x02, 0xE6, 0xDB,
	 0xA9, 0xE3, 0x11, 0x55, 0x77, 0xED, 0x3F, 0xE8, 0x8F, 0x7C, 0x75, 0x29,
	 0x02, 0xCC, 0x3D, 0x49, 0x75, 0x26, 0xD1, 0x6F, 0x13, 0x02, 0x79, 0xC4,
	 0xCB, 0x89, 0xA7, 0x17, 0x6B, 0x3C, 0x4B, 0xB0, 0xD0, 0x52, 0xCC, 0xA1,
	 0x67, 0xEA, 0xD7, 0x78, 0xE6, 0x3C, 0xD5, 0x48, 0xF1, 0x86, 0x6C, 0xB9,
	 0x59, 0xAD, 0x33, 0x69, 0xD7, 0x3B, 0x21, 0xF0, 0x4C, 0x9D, 0x57, 0xC2,
	 0xE0, 0xF2, 0x2C, 0x63, 0x70, 0x30, 0x71, 0x52, 0x97, 0x5F, 0x74, 0x1A,
	 0x27, 0xA5, 0xEA, 0x46, 0x15, 0xF7, 0xBD, 0xC6, 0x6B, 0xF2, 0x01, 0x8A,
	 0x60, 0xC1, 0x58, 0x08, 0x20, 0x02, 0x63, 0xB8, 0xE1, 0xD0, 0x3F, 0x9D,
	 0xED, 0xD4, 0xFA, 0xF4, 0xD3, 0x5C, 0x1F, 0x1B, 0x7D, 0x0B, 0xC9, 0xF0,
	 0xA1, 0xAA, 0xF3, 0x9C, 0x59, 0x6D, 0x90, 0x05, 0x2C, 0x1C, 0x37, 0x0B,
	 0xE4, 0xD3, 0xFC, 0x50, 0xAF, 0x6F, 0x98, 0x23, 0xBE, 0x36, 0x8F, 0x16,
	 0xC3, 0xE1, 0x74, 0x3F, 0xB3, 0xD8, 0xE6, 0x2D, 0xB2, 0xB0, 0x80, 0x7F,
	 0x81, 0xAE, 0x58, 0x42, 0x39, 0x1A, 0x98, 0xAD, 0x41, 0x9D, 0xFD, 0xD2,
	 0x45, 0x16, 0x57, 0x3A, 0x00, 0xAC, 0x79, 0x7A, 0x3B, 0xAD, 0x4C, 0x78,
	 0x10, 0x3B, 0x5C, 0x11, 0x79, 0x2C, 0xB3, 0xB7, 0x0C, 0x39, 0x02, 0x97,
	 0x30, 0xD1, 0xA0, 0x42, 0xD5, 0x08, 0xCA, 0x62, 0x2A, 0x76, 0xCA, 0xBE,
	 0x15, 0x4A, 0x0A, 0x5D, 0xB0, 0xF3, 0xFA, 0x5C, 0x65, 0x42, 0x19, 0x51,
	 0x6B, 0x40, 0xF9, 0x01, 0x76, 0x03, 0x44, 0x69, 0x05, 0x60, 0x46, 0x03,
	 0xEC, 0x27, 0xED, 0xA2, 0x7F, 0xB8, 0x33, 0xF0, 0x53, 0x0A, 0x3C, 0xEE,
	 0x8F, 0xDF, 0x24, 0x3E, 0x3D, 0xC5, 0x5A, 0x52, 0x4C, 0xF7, 0xBB, 0x2F,
	 0x24, 0x97, 0xF6, 0x72, 0xB0, 0xB9, 0x3D, 0xEA, 0x76, 0x76, 0x02, 0xA8,
	 0xB1, 0x28, 0xFD, 0x3E, 0xAD, 0xD8, 0x60, 0x69, 0x21, 0x38, 0x41, 0xD5}
};

#endif /* RSA_TEST_VECTOR_H_ */