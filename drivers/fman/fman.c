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

#include <compat.h>
#include <of.h>
#include <fman.h>

struct fman_mac {
	char node_path[PATH_MAX];
	uint64_t regs_size;
	void *dev_mem;
	enum {
		fman_mac_1g,
		fman_mac_10g
	} mac_type;
	struct list_head list_node;
};

static int dev_mem_fd = -1;
static LIST_HEAD(macs);

int __mac_init(void)
{
	int			 _errno;
	struct device_node	*dpa_node, *mac_node;
	const uint32_t		*regs_addr;
	uint64_t		phys_addr;
	const phandle		*mac_phandle;
	struct fman_mac		*mac;
	size_t			 lenp;

	assert(dev_mem_fd == -1);

	dev_mem_fd = open("/dev/mem", O_RDWR);
	if (unlikely(dev_mem_fd < 0)) {
		fprintf(stderr, "%s:%hu:%s(): open(/dev/mem) = %d (%s)\n",
			__FILE__, __LINE__, __func__, -errno, strerror(errno));
		return dev_mem_fd;
	}

	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-init") {
		if (of_device_is_available(dpa_node) == false)
			continue;

		mac = malloc(sizeof(*mac));
		if (!mac) {
			_errno = -ENOMEM;
			goto err;
		}
		strncpy(mac->node_path, dpa_node->full_name, PATH_MAX - 1);
		mac->node_path[PATH_MAX - 1] = '\0';

		mac_phandle = of_get_property(dpa_node, "fsl,fman-mac", &lenp);
		if (unlikely(mac_phandle == NULL)) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, fsl,fman-mac) failed\n",
				__FILE__, __LINE__, __func__, dpa_node->full_name);
			goto err;
		}
		assert(lenp == sizeof(phandle));

		mac_node = of_find_node_by_phandle(*mac_phandle);
		if (unlikely(mac_node == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_find_node_by_phandle(fsl,fman-mac) failed\n",
				__FILE__, __LINE__, __func__);
			goto err;
		}

		regs_addr = of_get_address(mac_node, 0, &mac->regs_size, NULL);
		if (unlikely(regs_addr == NULL)) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_get_address(%s) failed\n",
				__FILE__, __LINE__, __func__,
				mac_node->full_name);
			goto err;
		}

		phys_addr = of_translate_address(mac_node, regs_addr);
		if (unlikely(phys_addr == 0)) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_translate_address(%s) failed\n",
				__FILE__, __LINE__, __func__,
				mac_node->full_name);
			goto err;
		}

		mac->dev_mem = mmap(NULL, mac->regs_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				dev_mem_fd, phys_addr);
		if (unlikely(mac->dev_mem == MAP_FAILED)) {
			_errno = -ENOMEM;
			fprintf(stderr, "%s:%hu:%s(): mmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__,
				-errno, strerror(errno));
			goto err;
		}

		if (of_device_is_compatible(mac_node, "fsl,fman-1g-mac"))
			mac->mac_type = fman_mac_1g;
		else if (of_device_is_compatible(mac_node, "fsl,fman-10g-mac"))
			mac->mac_type = fman_mac_10g;
		else {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s: %s:0x%09llx: unknown MAC type\n",
				__FILE__, __LINE__, __func__,
				mac_node->full_name, phys_addr);
			goto err;
		}

		printf("Found %s\n", dpa_node->full_name);
		list_add(&mac->list_node, &macs);
	}

	return 0;
err:
	free(mac);
	__mac_finish();
	return _errno;
}

void __mac_finish(void)
{
	struct fman_mac *mac, *tmpmac;

	assert(dev_mem_fd != -1);

	list_for_each_entry_safe(mac, tmpmac, &macs, list_node) {
		int _errno;
		/* disable Rx and Tx */
		if (mac->mac_type == fman_mac_1g)
			out_be32(mac->dev_mem + 0x100,
				in_be32(mac->dev_mem + 0x100) & ~(u32)0x5);
		else
			out_be32(mac->dev_mem + 8,
				in_be32(mac->dev_mem + 8) & ~(u32)3);
		/* release the mapping */
		_errno = munmap(mac->dev_mem, mac->regs_size);
		if (unlikely(_errno < 0))
			fprintf(stderr, "%s:%hu:%s(): munmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__,
				-errno, strerror(errno));
		printf("Tearing down %s\n", mac->node_path);
		list_del(&mac->list_node);
		free(mac);
	}

	close(dev_mem_fd);
	dev_mem_fd = -1;
}

int __mac_enable_all(void)
{
	struct fman_mac *mac;

	assert(dev_mem_fd != -1);

	/* enable Rx and Tx */
	list_for_each_entry(mac, &macs, list_node) {
		if (mac->mac_type == fman_mac_1g)
			out_be32(mac->dev_mem + 0x100,
				in_be32(mac->dev_mem + 0x100) | 0x5);
		else
			out_be32(mac->dev_mem + 8,
				in_be32(mac->dev_mem + 8) | 3);
	}
	return 0;
}

int __mac_disable_all(void)
{
	struct fman_mac *mac;

	assert(dev_mem_fd != -1);

	list_for_each_entry(mac, &macs, list_node) {
		/* only disable Rx, not Tx */
		if (mac->mac_type == fman_mac_1g)
			out_be32(mac->dev_mem + 0x100,
				in_be32(mac->dev_mem + 0x100) & ~(u32)0x4);
		else
			out_be32(mac->dev_mem + 8,
				in_be32(mac->dev_mem + 8) & ~(u32)2);
	}

	return 0;
}
