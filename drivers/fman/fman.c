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

/* The exported "struct fman_if" type contains the subset of fields we want
 * exposed. This struct is embedded in a larger "struct __fman_if" which
 * contains the extra bits we *don't* want exposed. */
struct __fman_if {
	struct fman_if __if;
	char node_path[PATH_MAX];
	uint64_t regs_size;
	void *dev_mem;
	struct list_head node;
};

static int dev_mem_fd = -1;
static LIST_HEAD(__ifs);

/* This is the (const) global variable that callers have read-only access to.
 * Internally, we have read-write access directly to __ifs. */
const struct list_head *fman_if_list = &__ifs;

int fman_if_init(void)
{
	int			 _errno;
	struct device_node	*dpa_node, *mac_node;
	const uint32_t		*regs_addr;
	uint64_t		phys_addr;
	const phandle		*mac_phandle;
	struct __fman_if	*__if;
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

		__if = malloc(sizeof(*__if));
		if (!__if) {
			_errno = -ENOMEM;
			goto err;
		}
		strncpy(__if->node_path, dpa_node->full_name, PATH_MAX - 1);
		__if->node_path[PATH_MAX - 1] = '\0';

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

		regs_addr = of_get_address(mac_node, 0, &__if->regs_size, NULL);
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

		__if->dev_mem = mmap(NULL, __if->regs_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				dev_mem_fd, phys_addr);
		if (unlikely(__if->dev_mem == MAP_FAILED)) {
			_errno = -ENOMEM;
			fprintf(stderr, "%s:%hu:%s(): mmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__,
				-errno, strerror(errno));
			goto err;
		}

		if (of_device_is_compatible(mac_node, "fsl,fman-1g-mac"))
			__if->__if.mac_type = fman_mac_1g;
		else if (of_device_is_compatible(mac_node, "fsl,fman-10g-mac"))
			__if->__if.mac_type = fman_mac_10g;
		else {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s: %s:0x%09llx: unknown MAC type\n",
				__FILE__, __LINE__, __func__,
				mac_node->full_name, phys_addr);
			goto err;
		}

		printf("Found %s\n", dpa_node->full_name);
		list_add(&__if->__if.node, &__ifs);
	}

	return 0;
err:
	free(__if);
	fman_if_finish();
	return _errno;
}

void fman_if_finish(void)
{
	struct __fman_if *__if, *tmpif;

	assert(dev_mem_fd != -1);

	list_for_each_entry_safe(__if, tmpif, &__ifs, __if.node) {
		int _errno;
		/* disable Rx and Tx */
		if (__if->__if.mac_type == fman_mac_1g)
			out_be32(__if->dev_mem + 0x100,
				in_be32(__if->dev_mem + 0x100) & ~(u32)0x5);
		else
			out_be32(__if->dev_mem + 8,
				in_be32(__if->dev_mem + 8) & ~(u32)3);
		/* release the mapping */
		_errno = munmap(__if->dev_mem, __if->regs_size);
		if (unlikely(_errno < 0))
			fprintf(stderr, "%s:%hu:%s(): munmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__,
				-errno, strerror(errno));
		printf("Tearing down %s\n", __if->node_path);
		list_del(&__if->__if.node);
		free(__if);
	}

	close(dev_mem_fd);
	dev_mem_fd = -1;
}

void fman_if_enable_rx(const struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(dev_mem_fd != -1);

	/* enable Rx and Tx */
	if (__if->__if.mac_type == fman_mac_1g)
		out_be32(__if->dev_mem + 0x100,
			in_be32(__if->dev_mem + 0x100) | 0x5);
	else
		out_be32(__if->dev_mem + 8,
			in_be32(__if->dev_mem + 8) | 3);
}

void fman_if_disable_rx(const struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(dev_mem_fd != -1);

	/* only disable Rx, not Tx */
	if (__if->__if.mac_type == fman_mac_1g)
		out_be32(__if->dev_mem + 0x100,
			in_be32(__if->dev_mem + 0x100) & ~(u32)0x4);
	else
		out_be32(__if->dev_mem + 8,
			in_be32(__if->dev_mem + 8) & ~(u32)2);
}
