/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
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

#include <usdpaa/fman.h>

#include <internal/of.h>

/* The exported "struct fman_if" type contains the subset of fields we want
 * exposed. This struct is embedded in a larger "struct __fman_if" which
 * contains the extra bits we *don't* want exposed. */
struct __fman_if {
	struct fman_if __if;
	char node_path[PATH_MAX];
	uint64_t regs_size;
	void *ccsr_map;
	struct list_head node;
};

static int ccsr_map_fd = -1;
static LIST_HEAD(__ifs);

/* This is the (const) global variable that callers have read-only access to.
 * Internally, we have read-write access directly to __ifs. */
const struct list_head *fman_if_list = &__ifs;

static void if_destructor(struct __fman_if *__if)
{
	struct fman_if_bpool *bp, *tmpbp;
	list_for_each_entry_safe(bp, tmpbp, &__if->__if.bpool_list, node) {
		list_del(&bp->node);
		free(bp);
	}
	free(__if);
}

int fman_if_init(void)
{
	int			 _errno;
	struct device_node	*dpa_node, *mac_node, *tx_node, *pool_node;
	struct device_node	*fman_node;
	const uint32_t		*regs_addr;
	uint64_t		phys_addr;
	const phandle		*mac_phandle, *ports_phandle, *pools_phandle;
	const phandle		*tx_channel_id, *mac_addr;
	const phandle		*rx_phandle, *tx_phandle, *cell_idx;
	struct __fman_if	*__if;
	size_t			 lenp;
	struct fman_if_bpool	*bpool;

	/* If multiple dependencies try to initialise the Fman driver, don't
	 * panic. */
	if (ccsr_map_fd != -1)
		return 0;

	ccsr_map_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_map_fd < 0)) {
		fprintf(stderr, "%s:%hu:%s(): open(/dev/mem) = %d (%s)\n",
			__FILE__, __LINE__, __func__, -errno, strerror(errno));
		return ccsr_map_fd;
	}

	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-init") {
		if (of_device_is_available(dpa_node) == false)
			continue;

		/* Allocate an object for this network interface */
		__if = malloc(sizeof(*__if));
		if (!__if) {
			_errno = -ENOMEM;
			goto err;
		}
		INIT_LIST_HEAD(&__if->__if.bpool_list);
		strncpy(__if->node_path, dpa_node->full_name, PATH_MAX - 1);
		__if->node_path[PATH_MAX - 1] = '\0';

		/* Obtain the MAC node used by this interface */
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

		/* Map the CCSR regs for the MAC node */
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
		__if->ccsr_map = mmap(NULL, __if->regs_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				ccsr_map_fd, phys_addr);
		if (unlikely(__if->ccsr_map == MAP_FAILED)) {
			_errno = -ENOMEM;
			fprintf(stderr, "%s:%hu:%s(): mmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__,
				-errno, strerror(errno));
			goto err;
		}

		/* Get the index of the Fman this i/f belongs to */
		fman_node = of_get_parent(mac_node);
		if (!fman_node) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_parent(%s)\n",
				__FILE__, __LINE__, __func__, mac_node->name);
			goto err;
		}
		cell_idx = of_get_property(fman_node, "cell-index", &lenp);
		if (!cell_idx) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, "
				"cell-index) failed\n", __FILE__, __LINE__,
				__func__, fman_node->full_name);
			goto err;
		}
		assert(lenp == sizeof(*cell_idx));
		__if->__if.fman_idx = *cell_idx;

		/* Is the MAC node 1G or 10G? */
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

		/* Extract the index of the MAC */
		cell_idx = of_get_property(mac_node, "cell-index", &lenp);
		if (!cell_idx) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, "
				"cell-index) failed\n", __FILE__, __LINE__,
				__func__, mac_node->full_name);
			goto err;
		}
		assert(lenp == sizeof(*cell_idx));
		__if->__if.mac_idx = *cell_idx;

		/* Extract the MAC address */
		mac_addr = of_get_property(mac_node, "local-mac-address",
					&lenp);
		if (!mac_addr) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s: %s:0x%09llx: unknown MAC "
				"address\n", __FILE__, __LINE__, __func__,
				mac_node->full_name, phys_addr);
			goto err;
		}
		/* TODO: assert(lenp == ??!!) */
		memcpy(&__if->__if.mac_addr, mac_addr, ETH_ALEN);

		/* Extract the Tx port (it's the second of the two port handles)
		 * and get its channel ID */
		ports_phandle = of_get_property(mac_node, "fsl,port-handles",
						&lenp);
		if (!ports_phandle) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, "
				"fsl,port-handles) failed\n",
				__FILE__, __LINE__, __func__, mac_node->full_name);
			goto err;
		}
		assert(lenp == (2 * sizeof(phandle)));
		tx_node = of_find_node_by_phandle(ports_phandle[1]);
		if (!tx_node) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_find_node_by_phandle("
				"fsl,port-handles) failed\n",
				__FILE__, __LINE__, __func__);
			goto err;
		}
		tx_channel_id = of_get_property(tx_node, "fsl,qman-channel-id",
						&lenp);
		assert(lenp == sizeof(*tx_channel_id));
		__if->__if.tx_channel_id = *tx_channel_id;

		/* Extract the Rx/Tx FQIDs. (Note, the device representation is
		 * silly, there are "counts" that must always be 1.) */
		rx_phandle = of_get_property(dpa_node,
				"fsl,qman-frame-queues-rx", &lenp);
		if (!rx_phandle) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, "
				"fsl,qman-frame-queues-rx) failed\n",
				__FILE__, __LINE__, __func__, dpa_node->full_name);
			goto err;
		}
		assert(lenp == (4 * sizeof(phandle)));
		assert((rx_phandle[1] == 1) && (rx_phandle[3] == 1));
		__if->__if.fqid_rx_err = rx_phandle[0];
		tx_phandle = of_get_property(dpa_node,
				"fsl,qman-frame-queues-tx", &lenp);
		if (!tx_phandle) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, "
				"fsl,qman-frame-queues-tx) failed\n",
				__FILE__, __LINE__, __func__, dpa_node->full_name);
			goto err;
		}
		assert(lenp == (4 * sizeof(phandle)));
		assert((tx_phandle[1] == 1) && (tx_phandle[3] == 1));
		__if->__if.fqid_tx_err = tx_phandle[0];
		__if->__if.fqid_tx_confirm = tx_phandle[2];

		/* Obtain the buffer pool nodes used by this interface */
		pools_phandle = of_get_property(dpa_node,
					"fsl,bman-buffer-pools", &lenp);
		if (!pools_phandle) {
			_errno = -EINVAL;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, "
				"fsl,bman-buffer-pools) failed\n",
				__FILE__, __LINE__, __func__, dpa_node->full_name);
			goto err;
		}
		/* For each pool, parse the corresponding node and add a pool
		 * object to the interface's "bpool_list" */
		assert(lenp && !(lenp % sizeof(phandle)));
		while (lenp) {
			size_t proplen;
			const phandle *prop;
			/* Allocate an object for the pool */
			bpool = malloc(sizeof(*bpool));
			if (!bpool) {
				_errno = -ENOMEM;
				goto err;
			}
			/* Find the pool node */
			pool_node = of_find_node_by_phandle(*pools_phandle);
			if (!pool_node) {
				free(bpool);
				_errno = -ENXIO;
				fprintf(stderr, "%s:%hu:%s(): "
					"of_find_node_by_phandle(fsl,"
					"bman-buffer-pools) failed\n",
					__FILE__, __LINE__, __func__);
				goto err;
			}
			/* Extract the BPID property */
			prop = of_get_property(pool_node, "fsl,bpid", &proplen);
			if (!prop) {
				free(bpool);
				_errno = -EINVAL;
				fprintf(stderr, "%s:%hu:%s(): of_get_property("
					"%s, fsl,bpid) failed\n",
					__FILE__, __LINE__, __func__,
					pool_node->full_name);
				goto err;
			}
			assert(proplen == sizeof(*prop));
			bpool->bpid = *prop;
			/* Extract the cfg property (count/size/addr) */
			prop = of_get_property(pool_node, "fsl,bpool-cfg",
						&proplen);
			if (!prop) {
				/* It's OK for there to be no bpool-cfg */
				bpool->count = bpool->size = bpool->addr = 0;
			} else {
				assert(proplen == (6 * sizeof(*prop)));
				bpool->count = ((uint64_t)prop[0] << 32) |
						prop[1];
				bpool->size = ((uint64_t)prop[2] << 32) |
						prop[3];
				bpool->addr = ((uint64_t)prop[4] << 32) |
						prop[5];
			}
			/* Parsing of the pool is complete, add it to the
			 * interface list. */
			list_add_tail(&bpool->node, &__if->__if.bpool_list);
			lenp -= sizeof(phandle);
			pools_phandle++;
		}
		/* Parsing of the network interface is complete, add it to the
		 * list. */
		printf("Found %s\n", dpa_node->full_name);
		list_add_tail(&__if->__if.node, &__ifs);
	}

	return 0;
err:
	if_destructor(__if);
	fman_if_finish();
	return _errno;
}

void fman_if_finish(void)
{
	struct __fman_if *__if, *tmpif;

	assert(ccsr_map_fd != -1);

	list_for_each_entry_safe(__if, tmpif, &__ifs, __if.node) {
		int _errno;
		/* disable Rx and Tx */
		if (__if->__if.mac_type == fman_mac_1g)
			out_be32(__if->ccsr_map + 0x100,
				in_be32(__if->ccsr_map + 0x100) & ~(u32)0x5);
		else
			out_be32(__if->ccsr_map + 8,
				in_be32(__if->ccsr_map + 8) & ~(u32)3);
		/* release the mapping */
		_errno = munmap(__if->ccsr_map, __if->regs_size);
		if (unlikely(_errno < 0))
			fprintf(stderr, "%s:%hu:%s(): munmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__,
				-errno, strerror(errno));
		printf("Tearing down %s\n", __if->node_path);
		list_del(&__if->__if.node);
		free(__if);
	}

	close(ccsr_map_fd);
	ccsr_map_fd = -1;
}

void fman_if_enable_rx(const struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* enable Rx and Tx */
	if (__if->__if.mac_type == fman_mac_1g)
		out_be32(__if->ccsr_map + 0x100,
			in_be32(__if->ccsr_map + 0x100) | 0x5);
	else
		out_be32(__if->ccsr_map + 8,
			in_be32(__if->ccsr_map + 8) | 3);
}

void fman_if_disable_rx(const struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* only disable Rx, not Tx */
	if (__if->__if.mac_type == fman_mac_1g)
		out_be32(__if->ccsr_map + 0x100,
			in_be32(__if->ccsr_map + 0x100) & ~(u32)0x4);
	else
		out_be32(__if->ccsr_map + 8,
			in_be32(__if->ccsr_map + 8) & ~(u32)2);
}
