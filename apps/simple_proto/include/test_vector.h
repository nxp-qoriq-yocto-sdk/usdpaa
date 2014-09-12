/* Copyright 2013 Freescale Semiconductor, Inc.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef	__SIMPLE_PROTO_TEST_VECTOR_H
#define	__SIMPLE_PROTO_TEST_VECTOR_H

/** test vector structure which holds essential initialization vector, key etc;
 *  and cipher/plain text to compare with encapsulated/decapsulated data
 *  generated by SEC
 */
struct ref_vector_s {
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
};

#endif /* __SIMPLE_PROTO_TEST_VECTOR_H */
