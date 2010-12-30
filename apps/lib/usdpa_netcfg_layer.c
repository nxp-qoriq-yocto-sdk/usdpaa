/* Copyright (c) 2010 Freescale Semiconductor, Inc.
 * All rights reserved.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <compat.h>
#include <of.h>
#include "usdpa_netcfg_layer.h"

/* This data structure contaings all configurations information
 * related to usages of DPA devices.
 * */
struct usdpa_netcfg_info *usdpa_netcfg;

void dump_usdpa_netcfg(struct usdpa_netcfg_info *cfg_ptr)
{
	uint32_t port_id, bpool_id;
	struct fm_eth_port_cfg *p_cfg;
	struct fm_ethport_fq *pfq;
	struct bm_bpool_info *p_bpool;

	printf("..........   FMAN PORT Configuration  ..........\n");
	for (port_id = 0; port_id < cfg_ptr->num_ethports; port_id++) {
		p_cfg = &cfg_ptr->port_cfg[port_id];
		pfq = &p_cfg->fq;
		printf("pcd start = %x , count = %x\n",
			pfq->pcd.start, pfq->pcd.count);
		printf("dfault start = %x , count = %x\n",
			pfq->rx_def.start, pfq->rx_def.count);
		printf("rx error start = %x , count = %x\n",
			pfq->rx_err.start, pfq->rx_err.count);
		printf("tx error start = %x , count = %x\n",
			pfq->tx_err.start, pfq->tx_err.count);
		printf("tx confirm start = %x , count = %x\n",
			pfq->tx_confirm.start, pfq->tx_confirm.count);
		printf("tx start = %x , count = %x\n",
			pfq->tx.start, pfq->tx.count);

		printf("MAC address" MAC_FMT, NMAC_STR(p_cfg->fm_mac_addr));

		printf(" Rx channel id =  %x\n", p_cfg->qm_rx_channel_id);
		printf(" Tx channel id =  %x\n", p_cfg->qm_tx_channel_id);
		for (bpool_id = 0; bpool_id < p_cfg->bm_num_of_bpool;
							bpool_id++) {
			p_bpool = &p_cfg->bpool[bpool_id];
			printf("bpid = %x\n", p_bpool->bpid);
			printf("addr = %llx\n", p_bpool->addr);
			printf("size = %x\n", p_bpool->size);
			printf("count = %x\n", p_bpool->count);
		}
	}
}

static struct device_node *fman_port_mac_node(struct device_node *node)
{
	struct device_node *mac_node;
	const phandle *mac_phandle;
	uint32_t len;

	mac_phandle = of_get_property(node, "fsl,fman-mac", &len);
	if (unlikely(mac_phandle == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
			"fsl,fman-mac failed\n", __FILE__,
			__LINE__, __func__, node->full_name);
		return NULL;
	}

	mac_node = of_find_node_by_phandle(*mac_phandle);
	if (unlikely(mac_node == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): "
			"of_find_node_by_phandle(fsl,fman-mac)"
			"failed\n", __FILE__, __LINE__, __func__);
		return NULL;
	}

	return mac_node;
}

static int fman_mac_fm_index(struct device_node *mac_node, uint32_t *fman)
{
	struct device_node *pnode;
	uint32_t *cell_index, len;

	if (unlikely(mac_node == NULL))
		return -EINVAL;

	pnode = of_get_parent(mac_node);
	if (unlikely(pnode == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): of_get_parent(%s, not found\n",
				__FILE__, __LINE__, __func__, mac_node->name);
		return -ENXIO;
	}

	cell_index = of_get_property(pnode, "cell-index", &len);
	if (unlikely(cell_index == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, cell-index"
				" failed\n", __FILE__, __LINE__, __func__,
				pnode->full_name);
		return -ENXIO;
	}

	*fman = *cell_index;
	return 0;
}

static int fman_mac_port_type(struct device_node *mac_node, uint32_t *port_type)
{
	uint32_t p_type = 0;

	if (unlikely(mac_node == NULL))
		return -EINVAL;

	if (likely(of_device_is_compatible(mac_node,
				"fsl,p4080-fman-1g-mac"))) {
		p_type = 1;
	} else if (likely(of_device_is_compatible(mac_node,
				"fsl,p4080-fman-10g-mac"))) {
		p_type = 10;
	} else {
		return -ENXIO;
	}

	*port_type = p_type;
	return 0;
}

static int fman_mac_port_idx(struct device_node *mac_node, uint32_t *port_num)
{
	uint32_t *cell_index, len;

	cell_index = of_get_property(mac_node, "cell-index", &len);
	if (unlikely(cell_index == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): of_get_property(%s, cell-index"
				" failed\n", __FILE__, __LINE__, __func__,
				mac_node->full_name);
		return -ENXIO;
	}

	*port_num = *cell_index;
	return 0;
}

static inline uint8_t fman_num_enabled_macports(void)
{
	uint8_t count = 0;
	struct device_node *dpa_node;

	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-init") {
		if (of_device_is_available(dpa_node) == false)
			continue;

		count++;
	}
	return count;
}

static int dt_parse_eth_info(void)
{
	size_t lenp, len;
	struct fmc_netcfg_fqs xmlcfg;
	struct device_node *dpa_node, *mac_node, *port_node;
	struct device_node *channel_node, *bpool_node;
	uint32_t *rx_frame_queue, *tx_frame_queue;
	const phandle *channel_phandle;
	const phandle *port_phandle, *bpool_phandle;
	uint8_t *mac_addr;
	uint32_t *port_addr, *channel_addr, *bpool_addr;
	int _errno = 0;
	struct fm_eth_port_cfg *p_cfg;
	uint32_t bpid, count = 0;
	uint64_t data;
	uint32_t fman_num, port_type, port_index;
	struct bm_bpool_info bp_info[MAX_BPOOL_PER_PORT];
	uint8_t num_ports, curr = 0;
	size_t size;

	/* Number of MAC ports */
	num_ports = fman_num_enabled_macports();
	size = sizeof(*usdpa_netcfg) +
		(num_ports * sizeof(struct fm_eth_port_cfg));

	/* Allocate space for all enabled mac ports */
	usdpa_netcfg = calloc(size, 1);
	if (unlikely(usdpa_netcfg == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): calloc failed\n",
			__FILE__, __LINE__, __func__);
		return -ENOMEM;
	}

	usdpa_netcfg->num_ethports = num_ports;

	/* Read for all enabled MAC ports */
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-init") {
		if (of_device_is_available(dpa_node) == false)
			continue;

		printf("Found %s...\n", dpa_node->full_name);

		mac_node = fman_port_mac_node(dpa_node);

		_errno = fman_mac_fm_index(mac_node, &fman_num);
		if (unlikely(_errno))
			goto error;

		_errno = fman_mac_port_type(mac_node, &port_type);
		if (unlikely(_errno))
			goto error;

		_errno = fman_mac_port_idx(mac_node, &port_index);
		if (unlikely(_errno))
			goto error;

		p_cfg = &usdpa_netcfg->port_cfg[curr++];

		rx_frame_queue = of_get_property(dpa_node,
					"fsl,qman-frame-queues-rx", &lenp);
		if (unlikely(rx_frame_queue == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"fsl,qman-frame-queues-rx failed\n", __FILE__,
				__LINE__, __func__, dpa_node->full_name);
			goto error;
		}

		/* Rx default Frame Queues are not picked up from device tree.
		 * Rx default is taken from the FMC config file.
		 * */
		p_cfg->fq.rx_err.start = rx_frame_queue[0];
		p_cfg->fq.rx_err.count = rx_frame_queue[1];

		_errno = fmc_netcfg_get_info(fman_num, port_type,
					port_index, &xmlcfg);
		if (unlikely(_errno)) {
			fprintf(stderr, "%s:%hu:%s(): Error in parsing FMC"
				"config file\n", __FILE__, __LINE__, __func__);
			goto error;
		}

		p_cfg->fq.pcd.start = xmlcfg.pcd.start;
		p_cfg->fq.pcd.count = xmlcfg.pcd.count;
		/* RX default FQs are overwritten here */
		p_cfg->fq.rx_def.start = xmlcfg.rxdef.start;
		p_cfg->fq.rx_def.count = xmlcfg.rxdef.count;

		tx_frame_queue = of_get_property(dpa_node,
					"fsl,qman-frame-queues-tx", &lenp);
		if (unlikely(tx_frame_queue == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"fsl,qman-frame-queues-tx failed\n", __FILE__,
				__LINE__, __func__, dpa_node->full_name);
			goto error;
		}

		p_cfg->fq.tx_err.start = tx_frame_queue[0];
		p_cfg->fq.tx_err.count = tx_frame_queue[1];
		p_cfg->fq.tx_confirm.start = tx_frame_queue[2];
		p_cfg->fq.tx_confirm.count = tx_frame_queue[3];

		mac_addr = (uint8_t *)of_get_property(mac_node,
					"local-mac-address", &lenp);
		if (unlikely(mac_addr == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"local-mac-address failed\n", __FILE__,
				__LINE__, __func__, mac_node->full_name);
			goto error;
		}

		memcpy(&(p_cfg->fm_mac_addr[0]), mac_addr, 6);

		port_phandle = of_get_property(mac_node,
					"fsl,port-handles", &lenp);
		if (unlikely(port_phandle == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"fsl,port-handles failed\n", __FILE__,
				__LINE__, __func__, mac_node->full_name);
			goto error;
		}

		port_node = of_find_node_by_phandle(port_phandle[1]);
		if (unlikely(port_node == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_find_node_by_phandle(fsl,port-handles)"
				"failed\n", __FILE__, __LINE__, __func__);
			goto error;
		}

		port_addr = of_get_property(port_node,
					"fsl,qman-channel-id", &lenp);
		if (unlikely(port_addr == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"fsl,qman-channel-id failed\n", __FILE__,
				__LINE__, __func__, port_node->full_name);
			goto error;
		}

		p_cfg->qm_tx_channel_id = *port_addr;

		channel_phandle = of_get_property(dpa_node,
					"fsl,qman-channel", &lenp);
		if (unlikely(channel_phandle == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"fsl,qman-channel failed\n", __FILE__,
				__LINE__, __func__, dpa_node->full_name);
			goto error;
		}

		channel_node = of_find_node_by_phandle(*channel_phandle);
		if (unlikely(channel_node == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): "
				"of_find_node_by_phandle(fsl,qman-channel)"
				"failed\n", __FILE__, __LINE__, __func__);
			goto error;
		}

		channel_addr = of_get_property(channel_node,
					"fsl,qman-channel-id", &lenp);
		if (unlikely(channel_addr == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"fsl,qman-channel-id failed\n", __FILE__,
				__LINE__, __func__, channel_node->full_name);
			goto error;
		}

		p_cfg->qm_rx_channel_id = *channel_addr;

		bpool_phandle = of_get_property(dpa_node,
					"fsl,bman-buffer-pools", &lenp);
		if (unlikely(bpool_phandle == NULL)) {
			_errno = -ENXIO;
			fprintf(stderr, "%s:%hu:%s(): of_get_property(%s,"
				"fsl,bman-buffer-pools failed\n", __FILE__,
				__LINE__, __func__, dpa_node->full_name);
			goto error;
		}

		count = 0;
		while (lenp) {
			bpool_node = of_find_node_by_phandle(*bpool_phandle++);
			if (unlikely(bpool_node == NULL)) {
				_errno = -ENXIO;
				fprintf(stderr, "%s:%hu:%s(): "
					"of_find_node_by_phandle("
					"fsl,bman-buffer-pools) failed\n",
					__FILE__, __LINE__, __func__);
				goto error;
			}

			bpool_addr = of_get_property(bpool_node,
							"fsl,bpid", &len);
			if (unlikely(bpool_addr == NULL)) {
				_errno = -ENXIO;
				fprintf(stderr, "%s:%hu:%s(): "
					"of_get_property(fsl,bpid) failed\n",
					__FILE__, __LINE__, __func__);
				goto error;
			}

			bpid = *bpool_addr;

			bpool_addr = of_get_property(bpool_node,
						"fsl,bpool-cfg", &len);
			if (unlikely(bpool_addr == NULL)) {
				_errno = -ENXIO;
				fprintf(stderr, "%s:%hu:%s(): "
					"of_get_property(fsl,bpool-cfg)"
					"failed\n",
					__FILE__, __LINE__, __func__);
				goto error;
			}

			/* buffer pool id */
			bp_info[count].bpid = bpid;

			/* number of buffers */
			data = *bpool_addr++;
			data = (data << 32) | *bpool_addr++;
			bp_info[count].count = data;

			/* size of buffer */
			data = *bpool_addr++;
			data = (data << 32) | *bpool_addr++;
			bp_info[count].size = data;

			/* buffer address */
			data = *bpool_addr++;
			data = (data << 32) | *bpool_addr++;
			bp_info[count].addr = data;

			count++;

			lenp -= sizeof(uint32_t);
		}

		p_cfg->bm_num_of_bpool = count;
		p_cfg->bpool = (struct bm_bpool_info *)malloc(
			sizeof(struct bm_bpool_info) * p_cfg->bm_num_of_bpool);

		if (unlikely(p_cfg->bpool == NULL)) {
			fprintf(stderr, "%s:%hu:%s(): malloc failed\n",
				__FILE__, __LINE__, __func__);
			_errno = -ENOMEM;
			goto error;
		}

		for (count = 0; count < p_cfg->bm_num_of_bpool; count++) {
			p_cfg->bpool[count].bpid = bp_info[count].bpid;
			p_cfg->bpool[count].count = bp_info[count].count;
			p_cfg->bpool[count].size = bp_info[count].size;
			p_cfg->bpool[count].addr = bp_info[count].addr;
		}
	}

	return 0;
error:
	for (count = 0; count < num_ports; count++)
		free(usdpa_netcfg->port_cfg[count].bpool);

	free(usdpa_netcfg);

	return _errno;
}

struct usdpa_netcfg_info *usdpa_netcfg_acquire(char *pcd_file, char *cfg_file)
{
	int _errno;

	/* Initialise the XML parser */
	_errno = fmc_netcfg_parser_init(pcd_file, cfg_file);
	if (unlikely(_errno)) {
		fprintf(stderr, "%s:%hu:%s(): xml parser init failed "
			"(ERRNO = %d)\n", __FILE__, __LINE__, __func__, _errno);
		return NULL;
	}

	/* Parse device tree */
	_errno = dt_parse_eth_info();
	if (unlikely(_errno)) {
		fprintf(stderr, "%s:%hu:%s(): Device Tree parsing failed "
			"(ERRNO = %d)\n", __FILE__, __LINE__, __func__, _errno);
		return NULL;
	}

	return usdpa_netcfg;
}

void usdpa_netcfg_release(struct usdpa_netcfg_info *cfg_ptr)
{
	uint32_t port_id;

	for (port_id = 0; port_id < cfg_ptr->num_ethports; port_id++)
		free(cfg_ptr->port_cfg[port_id].bpool);

	free(cfg_ptr);
}
