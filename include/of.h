/* Copyright (c) 2010 Freescale Semiconductor, Inc.
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

#ifndef __OF_H
#define	__OF_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>	/* PATH_MAX */
#include <string.h>	/* strcmp(), strcasecmp() */

#define of_prop_cmp	strcmp
#define of_compat_cmp	strncasecmp

struct device_node
{
	char	*name;
	char	 full_name[PATH_MAX];

	uint8_t	 _property[64];
};

struct device_node *of_get_parent(const struct device_node *dev_node);

void *of_get_property(struct device_node *from, const char *name, size_t *lenp)
	__attribute__((nonnull(2)));

uint32_t of_n_addr_cells(const struct device_node *dev_node);
uint32_t of_n_size_cells(const struct device_node *dev_node);

const uint32_t *of_get_address(struct device_node	*dev_node,
			       size_t			 index,
			       uint64_t			*size,
			       uint32_t			*flags);

uint64_t of_translate_address(struct device_node *dev_node, const u32 *addr)
	__attribute__((nonnull));

struct device_node *of_find_compatible_node(const struct device_node	*from,
					    const char			*type,
					    const char			*compatible)
	__attribute__((nonnull(3)));

#define for_each_compatible_node(dev_node, type, compatible)			\
	for (dev_node = of_find_compatible_node(NULL, type, compatible);	\
	     dev_node != NULL;							\
	     dev_node = of_find_compatible_node(NULL, type, compatible))

struct device_node *of_find_node_by_phandle(phandle ph);

bool of_device_is_available(struct device_node *dev_node);
bool of_device_is_compatible(struct device_node *dev_node, const char *compatible);

#endif	/*  __OF_H */
