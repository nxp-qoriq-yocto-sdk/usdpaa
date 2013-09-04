/* Copyright (c) 2013 Freescale Semiconductor, Inc.
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

#include <inttypes.h>

#include <usdpaa/fman.h>
#include <fsl_fman.h>
#include <internal/of.h>

struct __fman_if {
	struct fman_if __if;
	char node_path[PATH_MAX];
	uint64_t regs_size;
	void *ccsr_map;
	struct list_head node;
};

#define ETH_ADDR_TO_UINT64(eth_addr)                  \
	(uint64_t)(((uint64_t)(eth_addr)[0] << 40) |   \
	((uint64_t)(eth_addr)[1] << 32) |   \
	((uint64_t)(eth_addr)[2] << 24) |   \
	((uint64_t)(eth_addr)[3] << 16) |   \
	((uint64_t)(eth_addr)[4] << 8) |    \
	((uint64_t)(eth_addr)[5]))

#define HASH_CTRL_MCAST_EN	0x00000100
#define GROUP_ADDRESS		0x0000010000000000LL
#define HASH_CTRL_ADDR_MASK	0x0000003F

static uint32_t get_mac_hash_code(uint64_t eth_addr)
{
	uint64_t	mask1, mask2;
	uint32_t	xorVal = 0;
	uint8_t		i, j;

	for (i=0; i<6; i++) {
		mask1 = eth_addr & (uint64_t)0x01;
		eth_addr >>= 1;

		for (j=0; j<7; j++) {
			mask2 = eth_addr & (uint64_t)0x01;
			mask1 ^= mask2;
			eth_addr >>= 1;
		}

		xorVal |= (mask1 << (5-i));
	}

	return xorVal;
}

int memac_add_hash_mac_addr(const struct fman_if *p, uint8_t *eth)
{
	uint64_t eth_addr;
	void *hashtable_ctrl;
	uint32_t hash;

	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	eth_addr = ETH_ADDR_TO_UINT64(eth);
	
	if (!(eth_addr & GROUP_ADDRESS))
		return -1;

	hash = get_mac_hash_code(eth_addr) & HASH_CTRL_ADDR_MASK;
	hash = hash | HASH_CTRL_MCAST_EN;

	hashtable_ctrl = &((struct memac_regs *)__if->ccsr_map)->hashtable_ctrl;
	out_be32(hashtable_ctrl, hash);

	return 0;
}