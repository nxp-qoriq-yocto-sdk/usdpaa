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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "compat.h"
#include "of.h"

#define OF_DEFAULT_NA 1
#define OF_DEFAULT_NS 1

static uint8_t			current;
static struct device_node	current_node[16],
				root = {
	.full_name	= "/",
	.name		= root.full_name
};

static char *of_basename(const char *full_name)
{
	char	*name;

	name = strrchr(full_name, '/');
	if (unlikely(name == NULL))
		return NULL;
	if (name != full_name)
		name++;
	return name;
}

struct device_node *of_get_parent(const struct device_node *dev_node)
{
	struct device_node	*_current_node;

	if (dev_node == NULL)
		dev_node = &root;

	*(_current_node = current_node + current) = *dev_node;
	_current_node->name = strrchr(_current_node->full_name, '/');
	if (unlikely(_current_node->name == NULL))
		return NULL;
	if (_current_node->name == _current_node->full_name)
		return &root;

	*_current_node->name = 0;
	_current_node->name = of_basename(_current_node->full_name);
	if (unlikely(_current_node->name == NULL))
		return NULL;

	current = (current + 1) % ARRAY_SIZE(current_node);
	return _current_node;
}

void *of_get_property(struct device_node *dev_node, const char *name, size_t *lenp)
{
	int	 _errno;
	char	 command[PATH_MAX];
	FILE	*of_sh;
	void	*_property;

	assert(name != NULL);

	if (dev_node == NULL)
		dev_node = &root;

	_property = NULL;

	snprintf(command, sizeof(command), "of.sh %s \"%s\" \"%s\"",
		 __func__, dev_node->full_name, name);

	of_sh = popen(command, "r");
	if (unlikely(of_sh == NULL))
		goto _return;

	_errno = fread(dev_node->_property,
		       sizeof(*dev_node->_property), sizeof(dev_node->_property), of_sh);
	if (unlikely(_errno < 0))
		goto _return_pclose;

	_property = dev_node->_property;
	if (lenp != NULL)
		*lenp = _errno * sizeof(*dev_node->_property);

_return_pclose:
	pclose(of_sh);
_return:
	return _property;
}

uint32_t of_n_addr_cells(const struct device_node *dev_node)
{
	struct device_node	*parent_node;
	size_t			 lenp;
	const uint32_t		*na;

	if (dev_node == NULL)
		dev_node = &root;

	do {
		parent_node = of_get_parent(dev_node);

		na = of_get_property(parent_node, "#address-cells", &lenp);
		if (na != NULL) {
			assert(lenp == sizeof(uint32_t));

			return *na;
		}
	} while (parent_node != &root);

	return OF_DEFAULT_NA;
}

uint32_t of_n_size_cells(const struct device_node *dev_node)
{
	struct device_node	*parent_node;
	size_t			 lenp;
	const uint32_t		*ns;

	if (dev_node == NULL)
		dev_node = &root;

	do {
		parent_node = of_get_parent(dev_node);

		ns = of_get_property(parent_node, "#size-cells", &lenp);
		if (ns != NULL) {
			assert(lenp == sizeof(uint32_t));

			return *ns;
		}
	} while (parent_node != &root);

	return OF_DEFAULT_NS;
}

static void of_bus_default_count_cells(const struct device_node	*dev_node,
				       uint32_t			*addr,
				       uint32_t			*size)
{
	if (dev_node == NULL)
		dev_node = &root;

	if (addr != NULL)
		*addr = of_n_addr_cells(dev_node);
	if (size != NULL)
		*size = of_n_size_cells(dev_node);
}

const uint32_t *of_get_address(struct device_node	*dev_node,
			       size_t			 index,
			       uint64_t			*size,
			       uint32_t			*flags)
{
	const uint32_t	*uint32_prop;
	size_t		 lenp;
	uint32_t	 na, ns;

	assert(dev_node != NULL);

	of_bus_default_count_cells(dev_node, &na, &ns);

	uint32_prop = of_get_property(dev_node, "reg", &lenp);
	if (unlikely(uint32_prop == NULL))
		return NULL;
	assert((lenp % ((na + ns) * sizeof(uint32_t))) == 0);

	uint32_prop += (na + ns) * index;
	if (size != NULL)
		for (*size = 0; ns > 0; ns--, na++)
			*size = (*size << 32) + uint32_prop[na];
	return uint32_prop;
}

uint64_t of_translate_address(struct device_node *dev_node, const u32 *addr)
{
	uint32_t	 na;
	uint64_t	 phys_addr, tmp_addr;
	const uint32_t	*regs_addr;

	assert(dev_node != NULL);

	phys_addr = *addr;
	do {
		dev_node = of_get_parent(dev_node);
		if (unlikely(dev_node == NULL)) {
			phys_addr = 0;
			break;
		}

		regs_addr = of_get_address(dev_node, 0, NULL, NULL);
		if (regs_addr == NULL)
			break;

		na = of_n_addr_cells(dev_node);
		for (tmp_addr = 0; na > 0; na--, regs_addr++)
			tmp_addr = (tmp_addr << 32) + *regs_addr;
		phys_addr += tmp_addr;

	} while (dev_node != &root);

	return phys_addr;
}

struct device_node *of_find_compatible_node(const struct device_node	*from,
					    const char			*type,
					    const char			*compatible)
{
	char			 command[PATH_MAX], *_errno;
	FILE			*of_sh;
	struct device_node	*dev_node, *_current_node;
	static uint8_t		 node = 1;

	assert(compatible != NULL);

	if (from == NULL)
		from = &root;

	dev_node = NULL;

	snprintf(command, sizeof(command), "of.sh %s \"%s\" \"%s\" %d",
		 __func__, from->full_name, compatible, node++);

	of_sh = popen(command, "r");
	if (unlikely(of_sh == NULL))
		goto _return;

	_current_node = current_node + current;
	_errno = fgets(_current_node->full_name, sizeof(_current_node->full_name), of_sh);
	if (unlikely(_errno == NULL)) {
		if (feof(of_sh))
			node = 1;
		goto _return_pclose;
	}

	_current_node->name = of_basename(_current_node->full_name);
	if (_current_node->name == NULL)
		goto _return_pclose;

	dev_node = _current_node;
	current = (current + 1) % ARRAY_SIZE(current_node);

_return_pclose:
	pclose(of_sh);
_return:
	return dev_node;
}

struct device_node *of_find_node_by_phandle(phandle ph)
{
	char			 command[PATH_MAX], *_errno;
	FILE			*of_sh;
	struct device_node	*dev_node, *_current_node;

	dev_node = NULL;

	snprintf(command, sizeof(command), "of.sh %s %c",
		 __func__, *((char *)&ph + sizeof(ph) - sizeof(char)));

	of_sh = popen(command, "r");
	if (unlikely(of_sh == NULL))
		goto _return;

	_current_node = current_node + current;
	_errno = fgets(_current_node->full_name, sizeof(_current_node->full_name), of_sh);
	if (unlikely(_errno == NULL))
		goto _return_pclose;

	_current_node->name = of_basename(_current_node->full_name);
	if (_current_node->name == NULL)
		goto _return_pclose;

	dev_node = _current_node;
	current = (current + 1) % ARRAY_SIZE(current_node);

_return_pclose:
	pclose(of_sh);
_return:
	return dev_node;
}
