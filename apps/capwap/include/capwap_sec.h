/* Copyright (c) 2014 Freescale Semiconductor, Inc.
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
#ifndef __CAPWAP_SEC_H
#define __CAPWAP_SEC_H

/*
 * DTLS Cipher Protinfo
 */
enum dtls_prot_type {
	CIPHER_TYPE_DTLS_DES_CBC_SHA_160 = 0,	/**< DES_CBC_SHA_160 ciphersuite     */
	CIPHER_TYPE_DTLS_DES_CBC_MD5_128,	/**< DES_CBC_MD5_128 ciphersuite     */
	CIPHER_TYPE_DTLS_3DES_CBC_MD5_128,	/**< 3DES_CBC_MD5_128 ciphersuite    */
	CIPHER_TYPE_DTLS_3DES_CBC_SHA_160,	/**< 3DES_CBC_SHA_160 ciphersuite    */
	CIPHER_TYPE_DTLS_3DES_CBC_SHA_384,	/**< 3DES_CBC_SHA_384 ciphersuite    */
	CIPHER_TYPE_DTLS_3DES_CBC_SHA_224,	/**< 3DES_CBC_SHA_224 ciphersuite    */
	CIPHER_TYPE_DTLS_3DES_CBC_SHA_512,	/**< 3DES_CBC_SHA_512 ciphersuite    */
	CIPHER_TYPE_DTLS_3DES_CBC_SHA_256,	/**< 3DES_CBC_SHA_256 ciphersuite    */
	CIPHER_TYPE_DTLS_AES_256_CBC_SHA_160,	/**< AES_256_CBC_SHA_160 ciphersuite */
	CIPHER_TYPE_DTLS_AES_256_CBC_SHA_384,	/**< AES_256_CBC_SHA_384 ciphersuite */
	CIPHER_TYPE_DTLS_AES_256_CBC_SHA_224,	/**< AES_256_CBC_SHA_224 ciphersuite */
	CIPHER_TYPE_DTLS_AES_256_CBC_SHA_512,	/**< AES_256_CBC_SHA_512 ciphersuite */
	CIPHER_TYPE_DTLS_AES_256_CBC_SHA_256,	/**< AES_256_CBC_SHA_256 ciphersuite */
	CIPHER_TYPE_DTLS_AES_128_CBC_SHA_160,	/**< AES_128_CBC_SHA_160 ciphersuite */
	CIPHER_TYPE_DTLS_AES_128_CBC_SHA_384,	/**< AES_128_CBC_SHA_384 ciphersuite */
	CIPHER_TYPE_DTLS_AES_128_CBC_SHA_224,	/**< AES_128_CBC_SHA_224 ciphersuite */
	CIPHER_TYPE_DTLS_AES_128_CBC_SHA_512,	/**< AES_128_CBC_SHA_512 ciphersuite */
	CIPHER_TYPE_DTLS_AES_128_CBC_SHA_256,	/**< AES_128_CBC_SHA_256 ciphersuite */
	CIPHER_TYPE_DTLS_AES_192_CBC_SHA_160,	/**< AES_192_CBC_SHA_160 ciphersuite */
	CIPHER_TYPE_DTLS_AES_192_CBC_SHA_384,	/**< AES_192_CBC_SHA_384 ciphersuite */
	CIPHER_TYPE_DTLS_AES_192_CBC_SHA_224,	/**< AES_192_CBC_SHA_224 ciphersuite */
	CIPHER_TYPE_DTLS_AES_192_CBC_SHA_512,	/**< AES_192_CBC_SHA_512 ciphersuite */
	CIPHER_TYPE_DTLS_AES_192_CBC_SHA_256	/**< AES_192_CBC_SHA_256 ciphersuite */
};

typedef enum e_split_key_hash_alg {
	e_SPLIT_KEY_HASH_ALG_MD5_128 = 0,	/**< Split-Key hashing algorithm MD5-128 */
	e_SPLIT_KEY_HASH_ALG_SHA_160,	/**< Split-Key hashing algorithm SHA-160 */
	e_SPLIT_KEY_HASH_ALG_SHA_224,	/**< Split-Key hashing algorithm SHA-224 */
	e_SPLIT_KEY_HASH_ALG_SHA_256,	/**< Split-Key hashing algorithm SHA-256 */
	e_SPLIT_KEY_HASH_ALG_SHA_384,	/**< Split-Key hashing algorithm SHA-384 */
	e_SPLIT_KEY_HASH_ALG_SHA_512	/**< Split-Key hashing algorithm SHA-512 */
} e_split_key_hash_alg;

/* Split Key Size for each hash alg */
static uint16_t split_key_size[] = {
	16, 20, 32, 32, 64, 64};

enum cypher_alg {
	DES = 0,
	TRIPLE_DES,
	AES
};
/* Cypher Key size for each cyper alg */
static uint16_t cypher_key_size[] = {
	8, 16, 16};

struct cypher_suite {
	enum e_split_key_hash_alg auth_type;
	enum cypher_alg cypher_type;
};

/* Auth type for each ciphtersuite */
static struct cypher_suite alg_suite[] = {
	{e_SPLIT_KEY_HASH_ALG_SHA_160,	DES},	/**< DES_CBC_SHA_160 ciphersuite     */
	{e_SPLIT_KEY_HASH_ALG_MD5_128,	DES},	/**< DES_CBC_MD5_128 ciphersuite     */
	{e_SPLIT_KEY_HASH_ALG_MD5_128,	TRIPLE_DES},	/**< 3DES_CBC_MD5_128 ciphersuite    */
	{e_SPLIT_KEY_HASH_ALG_SHA_160,	TRIPLE_DES},	/**< 3DES_CBC_SHA_160 ciphersuite    */
	{e_SPLIT_KEY_HASH_ALG_SHA_384,	TRIPLE_DES},	/**< 3DES_CBC_SHA_384 ciphersuite    */
	{e_SPLIT_KEY_HASH_ALG_SHA_224,	TRIPLE_DES},	/**< 3DES_CBC_SHA_224 ciphersuite    */
	{e_SPLIT_KEY_HASH_ALG_SHA_512,	TRIPLE_DES},	/**< 3DES_CBC_SHA_512 ciphersuite    */
	{e_SPLIT_KEY_HASH_ALG_SHA_256,	TRIPLE_DES},	/**< 3DES_CBC_SHA_256 ciphersuite    */
	{e_SPLIT_KEY_HASH_ALG_SHA_160,	AES},	/**< AES_256_CBC_SHA_160 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_384,	AES},	/**< AES_256_CBC_SHA_384 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_224,	AES},	/**< AES_256_CBC_SHA_224 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_512,	AES},	/**< AES_256_CBC_SHA_512 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_256,	AES},	/**< AES_256_CBC_SHA_256 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_160,	AES},	/**< AES_128_CBC_SHA_160 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_384,	AES},	/**< AES_128_CBC_SHA_384 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_224,	AES},	/**< AES_128_CBC_SHA_224 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_512,	AES},	/**< AES_128_CBC_SHA_512 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_256,	AES},	/**< AES_128_CBC_SHA_256 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_160,	AES},	/**< AES_192_CBC_SHA_160 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_384,	AES},	/**< AES_192_CBC_SHA_384 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_224,	AES},	/**< AES_192_CBC_SHA_224 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_512,	AES},	/**< AES_192_CBC_SHA_512 ciphersuite */
	{e_SPLIT_KEY_HASH_ALG_SHA_256,	AES},	/**< AES_192_CBC_SHA_256 ciphersuite */
};

#endif /* __CAPWAP_SEC_H */
