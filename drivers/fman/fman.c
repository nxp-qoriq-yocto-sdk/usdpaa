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
#include <sys/mman.h>	/* mmap()/munmap() */

#include "compat.h"
#include "of.h"

int __mac_enable_all(void)
{
	int			 _errno, dev_mem_fd;
	void			*dev_mem;
	struct device_node	*dpa_node, *mac_node;
	const phandle		*mac_phandle;
	size_t			 lenp;
	const uint32_t		*regs_addr;
	uint64_t		 phys_addr, regs_size;

	dev_mem_fd = open("/dev/mem", O_RDWR);
	if (unlikely(dev_mem_fd < 0)) {
		fprintf(stderr, "%s:%hu:%s(): open(/dev/mem) = %d (%s)\n",
			__FILE__, __LINE__, __func__, -errno, strerror(errno));
		return dev_mem_fd;
	}

	_errno = 0;
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-init") {
		if (of_device_is_available(dpa_node) == false)
			continue;

		printf("Found %s...\n", dpa_node->full_name);

		mac_phandle = of_get_property(dpa_node, "fsl,fman-mac", &lenp);
		if (unlikely(mac_phandle == NULL)) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, fsl,fman-mac) failed\n",
				__FILE__, __LINE__, __func__, dpa_node->full_name);
			continue;
		}
		assert(lenp == sizeof(phandle));

		mac_node = of_find_node_by_phandle(*mac_phandle);
		if (unlikely(mac_node == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_find_node_by_phandle(fsl,fman-mac) failed\n",
				__FILE__, __LINE__, __func__);
			continue;
		}

		regs_addr = of_get_address(mac_node, 0, &regs_size, NULL);
		if (unlikely(regs_addr == NULL)) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_get_address(%s) failed\n",
				__FILE__, __LINE__, __func__, mac_node->full_name);
			continue;
		}

		phys_addr = of_translate_address(mac_node, regs_addr);
		if (unlikely(phys_addr == 0)) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_translate_address(%s) failed\n",
				__FILE__, __LINE__, __func__, mac_node->full_name);
			continue;
		}

		dev_mem = mmap(NULL, regs_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev_mem_fd,
			       phys_addr);
		if (unlikely(dev_mem == MAP_FAILED)) {
			fprintf(stderr, "%s:%hu:%s(): mmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__, -errno, strerror(errno));
			continue;
		}

		if (of_device_is_compatible(mac_node, "fsl,fman-1g-mac"))
			out_be32(dev_mem + 0x100, in_be32(dev_mem + 0x100) | 0x5);
		else if (of_device_is_compatible(mac_node, "fsl,fman-10g-mac"))
			out_be32(dev_mem + 8, in_be32(dev_mem + 8) | 3);
		else
			fprintf(stderr, "%s:%hu:%s: %s:0x%09llx: unknown MAC type\n",
				__FILE__, __LINE__, __func__, mac_node->full_name, phys_addr);


		_errno = munmap(dev_mem, regs_size);
		if (unlikely(_errno < 0)) {
			fprintf(stderr, "%s:%hu:%s(): mmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__, -errno, strerror(errno));
		}

		printf("\t...using %s:0x%09llx\n", mac_node->full_name, phys_addr);
	}

	close(dev_mem_fd);

	return _errno;
}
