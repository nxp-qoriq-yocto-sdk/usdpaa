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

/* This header declares the driver interface we implement */
#include <usdpaa/fman.h>

/* This header declares things about Fman hardware itself (the format of status
 * words and an inline implementation of CRC64). We include it only in order to
 * instantiate the one global variable it depends on. */
#include <fsl_fman.h>

#include <internal/of.h>

/* Instantiate the global variable that the inline CRC64 implementation (in
 * <fsl_fman.h>) depends on. */
DECLARE_FMAN_CRC64_TABLE();

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

	if (__if->__if.mac_type == fman_offline)
		goto cleanup;

	list_for_each_entry_safe(bp, tmpbp, &__if->__if.bpool_list, node) {
		list_del(&bp->node);
		free(bp);
	}
cleanup:
	free(__if);
}

/* These constructs shrink the size of fman_[if_]init() considerably */
#define my_log(err, fmt, args...) \
	fprintf(stderr, "ERR: %s:%hu:%s()\n%s: " fmt, \
		__FILE__, __LINE__, __func__, strerror(err), ##args)
#define my_err(cond, rc, fmt, args...) \
	if (unlikely(cond)) { \
		_errno = (rc); \
		my_log(_errno, fmt, ##args); \
		goto err; \
	}

static int fman_if_init(const struct device_node *dpa_node, int is_offline)
{
	const char *rprop = is_offline ? "fsl,qman-frame-queues-oh" :
					 "fsl,qman-frame-queues-rx";
	const char *mprop = is_offline ? "fsl,fman-oh-port" :
					 "fsl,fman-mac";
	uint64_t phys_addr;
	struct __fman_if *__if;
	struct fman_if_bpool *bpool;
	const phandle *mac_phandle, *ports_phandle, *pools_phandle;
	const phandle *tx_channel_id, *mac_addr, *cell_idx;
	const phandle *rx_phandle, *tx_phandle;
	const struct device_node *mac_node, *tx_node, *pool_node, *fman_node;
	const uint32_t *regs_addr;
	const char *mname, *fname;
	const char *dname = dpa_node->full_name;
	size_t lenp;
	int _errno;

	if (of_device_is_available(dpa_node) == false)
		return 0;

	/* Allocate an object for this network interface */
	__if = malloc(sizeof(*__if));
	my_err(!__if, -ENOMEM, "malloc(%d)\n", sizeof(*__if));
	INIT_LIST_HEAD(&__if->__if.bpool_list);
	strncpy(__if->node_path, dpa_node->full_name, PATH_MAX - 1);
	__if->node_path[PATH_MAX - 1] = '\0';

	/* Obtain the MAC node used by this interface */
	mac_phandle = of_get_property(dpa_node, mprop, &lenp);
	my_err(!mac_phandle, -EINVAL, "%s: no %s\n", dname, mprop);
	assert(lenp == sizeof(phandle));
	mac_node = of_find_node_by_phandle(*mac_phandle);
	my_err(!mac_node, -ENXIO, "%s: bad 'fsl,fman-mac\n", dname);
	mname = mac_node->full_name;

	/* Map the CCSR regs for the MAC node */
	if (!is_offline) {
		regs_addr = of_get_address(mac_node, 0, &__if->regs_size, NULL);
		my_err(!regs_addr, -EINVAL, "of_get_address(%s)\n", mname);
		phys_addr = of_translate_address(mac_node, regs_addr);
		my_err(!phys_addr, -EINVAL, "of_translate_address(%s, %p)\n",
			mname, regs_addr);
		__if->ccsr_map = mmap(NULL, __if->regs_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				ccsr_map_fd, phys_addr);
		my_err(__if->ccsr_map == MAP_FAILED, -errno,
			"mmap(0x%"PRIx64")\n", phys_addr);
	}

	/* Get the index of the Fman this i/f belongs to */
	fman_node = of_get_parent(mac_node);
	my_err(!fman_node, -ENXIO, "of_get_parent(%s)\n", mname);
	fname = fman_node->full_name;
	cell_idx = of_get_property(fman_node, "cell-index", &lenp);
	my_err(!cell_idx, -ENXIO, "%s: no cell-index)\n", fname);
	assert(lenp == sizeof(*cell_idx));
	__if->__if.fman_idx = *cell_idx;

	/* Is the MAC node 1G or 10G? */
	if (is_offline)
		__if->__if.mac_type = fman_offline;
	else if (of_device_is_compatible(mac_node, "fsl,fman-1g-mac"))
		__if->__if.mac_type = fman_mac_1g;
	else if (of_device_is_compatible(mac_node, "fsl,fman-10g-mac"))
		__if->__if.mac_type = fman_mac_10g;
	else
		my_err(1, -EINVAL, "%s: unknown MAC type\n", mname);

	/* Extract the index of the MAC */
	cell_idx = of_get_property(mac_node, "cell-index", &lenp);
	my_err(!cell_idx, -ENXIO, "%s: no cell-index\n", mname);
	assert(lenp == sizeof(*cell_idx));
	__if->__if.mac_idx = *cell_idx;

	if (!is_offline) {
		/* Extract the MAC address */
		mac_addr = of_get_property(mac_node, "local-mac-address",
					&lenp);
		my_err(!mac_addr, -EINVAL, "%s: no local-mac-address\n",
			mname);
		memcpy(&__if->__if.mac_addr, mac_addr, ETH_ALEN);
	
		/* Extract the Tx port (it's the second of the two port handles)
		 * and get its channel ID */
		ports_phandle = of_get_property(mac_node, "fsl,port-handles",
						&lenp);
		my_err(!ports_phandle, -EINVAL, "%s: no fsl,port-handles\n",
			mname);
		assert(lenp == (2 * sizeof(phandle)));
		tx_node = of_find_node_by_phandle(ports_phandle[1]);
		my_err(!tx_node, -ENXIO, "%s: bad fsl,port-handle[1]\n", mname);
		/* Extract the channel ID (from tx-port-handle) */
		tx_channel_id = of_get_property(tx_node, "fsl,qman-channel-id",
						&lenp);
		my_err(!tx_channel_id, -EINVAL, "%s: no fsl-qman-channel-id\n",
			tx_node->full_name);
	} else {
		/* Extract the channel ID (from mac) */
		tx_channel_id = of_get_property(mac_node, "fsl,qman-channel-id",
						&lenp);
		my_err(!tx_channel_id, -EINVAL, "%s: no fsl-qman-channel-id\n",
			mac_node->full_name);
	}
	assert(lenp == sizeof(*tx_channel_id));
	__if->__if.tx_channel_id = *tx_channel_id;

	/* Extract the Rx FQIDs. (Note, the device representation is silly,
	 * there are "counts" that must always be 1.) */
	rx_phandle = of_get_property(dpa_node, rprop, &lenp);
	my_err(!rx_phandle, -EINVAL, "%s: no fsl,qman-frame-queues-rx\n",
		dname);
	assert(lenp == (4 * sizeof(phandle)));
	assert((rx_phandle[1] == 1) && (rx_phandle[3] == 1));
	__if->__if.fqid_rx_err = rx_phandle[0];

	/* No special Tx FQs for offline interfaces, nor hard-coded pools */
	if (is_offline)
		goto ok;

	/* Extract the Tx FQIDs */
	tx_phandle = of_get_property(dpa_node,
			"fsl,qman-frame-queues-tx", &lenp);
	my_err(!tx_phandle, -EINVAL, "%s: no fsl,qman-frame-queues-tx\n",
		dname);
	assert(lenp == (4 * sizeof(phandle)));
	assert((tx_phandle[1] == 1) && (tx_phandle[3] == 1));
	__if->__if.fqid_tx_err = tx_phandle[0];
	__if->__if.fqid_tx_confirm = tx_phandle[2];

	/* Obtain the buffer pool nodes used by this interface */
	pools_phandle = of_get_property(dpa_node, "fsl,bman-buffer-pools",
					&lenp);
	my_err(!pools_phandle, -EINVAL, "%s: no fsl,bman-buffer-pools\n",
		dname);
	/* For each pool, parse the corresponding node and add a pool object to
	 * the interface's "bpool_list" */
	assert(lenp && !(lenp % sizeof(phandle)));
	while (lenp) {
		size_t proplen;
		const phandle *prop;
		const char *pname;
		/* Allocate an object for the pool */
		bpool = malloc(sizeof(*bpool));
		my_err(!bpool, -ENOMEM, "malloc(%d)\n", sizeof(*bpool));
		/* Find the pool node */
		pool_node = of_find_node_by_phandle(*pools_phandle);
		my_err(!pool_node, -ENXIO, "%s: bad fsl,bman-buffer-pools\n",
			dname);
		pname = pool_node->full_name;
		/* Extract the BPID property */
		prop = of_get_property(pool_node, "fsl,bpid", &proplen);
		my_err(!prop, -EINVAL, "%s: no fsl,bpid\n", pname);
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
		/* Parsing of the pool is complete, add it to the interface
		 * list. */
		list_add_tail(&bpool->node, &__if->__if.bpool_list);
		lenp -= sizeof(phandle);
		pools_phandle++;
	}

ok:
	/* Parsing of the network interface is complete, add it to the list. */
	printf("Found %s, Tx Channel = %x, FMAN = %x, Port ID = %x\n",
		dname, __if->__if.tx_channel_id, __if->__if.fman_idx,
		__if->__if.mac_idx);
	list_add_tail(&__if->__if.node, &__ifs);
	return 0;
err:
	if_destructor(__if);
	return _errno;
}

int fman_init(void)
{
	const struct device_node *dpa_node;
	int _errno;

	/* If multiple dependencies try to initialise the Fman driver, don't
	 * panic. */
	if (ccsr_map_fd != -1)
		return 0;

	ccsr_map_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_map_fd < 0)) {
		my_log(-errno, "open(/dev/mem)\n");
		return ccsr_map_fd;
	}

	/* Parse offline ports first, so they initialise first. That way,
	 * initialisation of regular ports can "choose" an offline port to
	 * association with. */
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-oh") {
		_errno = fman_if_init(dpa_node, 1);
		my_err(_errno, _errno, "if_init(%s)\n", dpa_node->full_name);
	}
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-init") {
		_errno = fman_if_init(dpa_node, 0);
		my_err(_errno, _errno, "if_init(%s)\n", dpa_node->full_name);
	}
	return 0;
err:
	fman_finish();
	return _errno;
}

void fman_finish(void)
{
	struct __fman_if *__if, *tmpif;

	assert(ccsr_map_fd != -1);

	list_for_each_entry_safe(__if, tmpif, &__ifs, __if.node) {
		int _errno;

		/* No need to enable Offline port */
		if (__if->__if.mac_type == fman_offline)
			continue;

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

	/* No need to enable Offline port */
	if (__if->__if.mac_type == fman_offline)
		return;

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

	/* No need to disable Offline port */
	if (__if->__if.mac_type == fman_offline)
		return;

	/* only disable Rx, not Tx */
	if (__if->__if.mac_type == fman_mac_1g)
		out_be32(__if->ccsr_map + 0x100,
			in_be32(__if->ccsr_map + 0x100) & ~(u32)0x4);
	else
		out_be32(__if->ccsr_map + 8,
			in_be32(__if->ccsr_map + 8) & ~(u32)2);
}
