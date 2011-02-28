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

#include <usdpaa/usdpa_netcfg.h>
#include "fmc_netcfg_parser.h"

#include <inttypes.h>

#define MAX_BPOOL_PER_PORT	8

/* FIXME: Hardcoded values should be replaced.
 */
#define QM_POOL_CHANNELS	{qm_channel_pool4, qm_channel_pool5, \
				qm_channel_pool6, qm_channel_pool7}
#define QM_CGRIDS		{10, 11, 12, 13}

static const uint8_t qm_pool_channels[] = QM_POOL_CHANNELS;
static const uint8_t qm_cgrid[] = QM_CGRIDS;

/* This data structure contaings all configurations information
 * related to usages of DPA devices.
 * */
struct usdpa_netcfg_info *usdpa_netcfg;

void dump_usdpa_netcfg(struct usdpa_netcfg_info *cfg_ptr)
{
	int i;

	printf("..........  USDPAA Configuration  ..........\n\n");

	/* CGRs */
	printf("Available CGRS: %d\n", cfg_ptr->num_cgrids);
	printf("	{");
	for (i = 0; i < cfg_ptr->num_cgrids; i++)
		printf("%s%d", i ? "," : "", cfg_ptr->cgrids[i]);
	printf("}\n\n");

	/* Pool channels */
	printf("Available pool channels: %d\n", cfg_ptr->num_pool_channels);
	printf("	{");
	for (i = 0; i < cfg_ptr->num_pool_channels; i++)
		printf("%s%d", i ? "," : "", cfg_ptr->pool_channels[i]);
	printf("}\n\n");

	/* Network interfaces */
	printf("Network interfaces: %d\n", cfg_ptr->num_ethports);
	for (i = 0; i < cfg_ptr->num_ethports; i++) {
		struct fman_if_bpool *bpool;
		struct fm_eth_port_cfg *p_cfg = &cfg_ptr->port_cfg[i];
		struct fman_if *__if = p_cfg->fman_if;
		printf("\n+ Fman %d, MAC %d (%s);\n",
			__if->fman_idx, __if->mac_idx,
			__if->mac_type == fman_mac_1g ? "1G" : "10G");
		printf("	  mac_addr: " ETH_MAC_PRINTF_FMT "\n",
			ETH_MAC_PRINTF_ARGS(&__if->mac_addr));
		printf("     tx_channel_id: 0x%02x\n", __if->tx_channel_id);
		printf("      fqid_rx_hash: (PCD: start 0x%x, count %d)\n",
			p_cfg->pcd.start, p_cfg->pcd.count);
		printf("       fqid_rx_def: 0x%x\n", p_cfg->rx_def);
		printf("       fqid_rx_err: 0x%x\n", __if->fqid_rx_err);
		printf("       fqid_tx_err: 0x%x\n", __if->fqid_tx_err);
		printf("   fqid_tx_confirm: 0x%x\n", __if->fqid_tx_confirm);
		fman_if_for_each_bpool(bpool, __if)
			printf("       buffer pool: (bpid=%d, count=%"PRId64
			       "size=%"PRId64", addr=0x%"PRIx64")\n",
			       bpool->bpid, bpool->count, bpool->size,
			       bpool->addr);
	}
}

static int qm_init_cgr_values(struct usdpa_netcfg_info *cfgptr)
{
	uint32_t *ptr;
	int i;

	cfgptr->num_cgrids = ARRAY_SIZE(qm_cgrid);
	cfgptr->cgrids	= malloc(sizeof(*(cfgptr->cgrids)) * cfgptr->num_cgrids);
	if (unlikely(cfgptr->cgrids == NULL))
		return -ENOMEM;

	ptr = cfgptr->cgrids;
	for (i = 0; i < cfgptr->num_cgrids; i++)
		cfgptr->cgrids[i] = qm_cgrid[i];

	return 0;
}

static int qm_init_pool_channel_values(struct usdpa_netcfg_info *cfgptr)
{
	uint32_t *ptr;
	int i;

	cfgptr->num_pool_channels = ARRAY_SIZE(qm_pool_channels);
	cfgptr->pool_channels = malloc(sizeof(*cfgptr->pool_channels) *
						cfgptr->num_pool_channels);
	if (unlikely(cfgptr->pool_channels == NULL))
		return -ENOMEM;

	ptr = cfgptr->pool_channels;
	for (i = 0; i < cfgptr->num_pool_channels; i++)
		cfgptr->pool_channels[i] = qm_pool_channels[i];

	return 0;
}

struct usdpa_netcfg_info *usdpa_netcfg_acquire(const char *pcd_file,
					const char *cfg_file)
{
	struct fman_if *__if;
	int _errno, idx;
	uint8_t num_ports = 0;
	size_t size;

	/* Extract dpa configuration from fman driver and FMC configuration */

	/* Initialise the XML parser */
	_errno = fmc_netcfg_parser_init(pcd_file, cfg_file);
	if (unlikely(_errno)) {
		fprintf(stderr, "%s:%hu:%s(): xml parser init failed "
			"(ERRNO = %d)\n", __FILE__, __LINE__, __func__, _errno);
		return NULL;
	}

	/* Initialise the Fman driver */
	_errno = fman_if_init();
	if (_errno) {
		fprintf(stderr, "%s:%hu:%s(): fman driver init failed "
			"(ERRNO = %d)\n", __FILE__, __LINE__, __func__, _errno);
		return NULL;
	}

	/* Number of MAC ports */
	list_for_each_entry(__if, fman_if_list, node)
		num_ports++;

	/* Allocate space for all enabled mac ports */
	size = sizeof(*usdpa_netcfg) +
		(num_ports * sizeof(struct fm_eth_port_cfg));
	usdpa_netcfg = calloc(size, 1);
	if (unlikely(usdpa_netcfg == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): calloc failed\n",
			__FILE__, __LINE__, __func__);
		goto error;
	}

	usdpa_netcfg->num_ethports = num_ports;

	/* Fill in configuration info for all ports */
	idx = 0;
	list_for_each_entry(__if, fman_if_list, node) {
		struct fmc_netcfg_fqs xmlcfg;
		struct fm_eth_port_cfg *cfg = &usdpa_netcfg->port_cfg[idx];
		/* Hook in the fman driver interface */
		cfg->fman_if = __if;
		/* Extract FMC configuration */
		_errno = fmc_netcfg_get_info(__if->fman_idx,
			__if->mac_type == fman_mac_1g ? 1 : 10,
			__if->mac_idx, &xmlcfg);
		if (_errno) {
			fprintf(stderr, "%s:%hu:%s(): fmc_netcfg_get_info()\n",
				__FILE__, __LINE__, __func__);
			goto error;
		}
		cfg->pcd.start = xmlcfg.pcd.start;
		cfg->pcd.count = xmlcfg.pcd.count;
		cfg->rx_def = xmlcfg.rxdef;
		idx++;
	}
	/* Fill in other global configuration */
	qm_init_cgr_values(usdpa_netcfg);
	qm_init_pool_channel_values(usdpa_netcfg);

	return usdpa_netcfg;

error:
	fmc_netcfg_parser_exit();
	return NULL;
}

void usdpa_netcfg_release(struct usdpa_netcfg_info *cfg_ptr)
{
	fmc_netcfg_parser_exit();
	free(cfg_ptr->pool_channels);
	free(cfg_ptr->cgrids);
	free(cfg_ptr);
}
