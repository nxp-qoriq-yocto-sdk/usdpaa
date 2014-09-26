/* Copyright (c) 2014 Freescale Semiconductor, Inc.
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
#include <usdpaa/compat.h>
#include "fm_port_ext.h"
#include "fm_pcd_ext.h"
#include "dpaa_capwap_domain_ext.h"
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <error.h>
#include <linux/dma_mem.h>

#include "dpaa_capwap_ioctl.h"
#include "app_config.h"

#define ETH_HDR_SIZE                    14
#define IPv4_HDR_SIZE                   20

#define FRAG_REASSEM_ENABLE
#define CAPWAP_MTU			1396
#define CAPWAP_FRAG_BPID		8

struct fman_dev{
	t_Handle h_dev;
	t_Handle h_pcd_dev;
};

static struct fman_dev fms[INTG_MAX_NUM_OF_FM];

extern int init_rx_fq(u32 fqid);

/*
 * ported from fmc_exec_engine_start
 */
static int get_fm_handle(uint8_t fm_index)
{
	t_FmPcdParams fm_pcd_params = { 0 };

	/* Open FMan device */
	fms[fm_index].h_dev = FM_Open(fm_index);

	if (!fms[fm_index].h_dev) {
		fprintf(stderr, "Open Fman device error\n");
		return -1;
	}

	/* Open FMan device */
	fm_pcd_params.h_Fm = fms[fm_index].h_dev;
	fms[fm_index].h_pcd_dev = FM_PCD_Open(&fm_pcd_params);

	if (!fms[fm_index].h_pcd_dev) {
		fprintf(stderr, "Open Fman PCD error\n");
		return -1;
	}

	return 0;
}

static e_FmPortType get_port_type(const char *type)
{
	if (strcmp(type, "1G") == 0)
		return e_FM_PORT_TYPE_RX;
	else if (strcmp(type, "10G") == 0)
		return e_FM_PORT_TYPE_RX_10G;
	else if (strcmp(type, "OFFLINE") == 0)
		return e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
	else if (strcmp(type, "TX_1G") == 0)
		return e_FM_PORT_TYPE_TX;
	else if (strcmp(type, "TX_10G") == 0)
		return e_FM_PORT_TYPE_TX_10G;
	else
		return e_FM_PORT_TYPE_DUMMY;
}

static int get_port_handle(struct capwap_port *port)
{
	const uint8_t lu_n[11] = {255, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1};
	const char *lu_t[11] =  {"ERR", "1G", "1G", "1G", "1G", "1G", "1G", "1G", "1G", "10G", "10G"};
	t_FmPortParams fm_port_param = { 0 };

	fm_port_param.h_Fm = fms[port->interface->fman_idx].h_dev;
	if (port->type == e_FM_PORT_TYPE_OH_OFFLINE_PARSING) {
		fm_port_param.portId = port->interface->mac_idx;
		fm_port_param.portType = port->type;
	} else {
		fm_port_param.portId = lu_n[port->interface->mac_idx];
		fm_port_param.portType = get_port_type(lu_t[port->interface->mac_idx]);
	}

	port->handle = FM_PORT_Open(&fm_port_param);

	if (!port->handle) {
		fprintf(stderr, "FM port open error\n");
		return -1;
	}

	return 0;
}

static t_Error set_inbound_op_pcd(struct capwap_port * app_port,
		uint32_t *schemes_count, u32 fqid_base)
{
	t_FmPcdKgSchemeParams scheme;
	t_FmPcdNetEnvParams net_env_param;
	t_FmPortPcdParams pcd_param;
	t_FmPortPcdKgParams kg_param;
	t_FmPortPcdCcParams cc_param;
	t_FmPortPcdPrsParams prs_param;
	t_FmPcdManipParams manip_param;
	t_FmPcdCcNodeParams cc_node_param;
	t_FmPcdCcTreeParams cc_tree_param;
	t_Handle h_pcd_dev = fms[app_port->interface->fman_idx].h_pcd_dev;
	t_Handle port_dev = app_port->handle;
	uint8_t num_of_schemes = 1;
	t_Error err;
	int i = 0;

	/* Network Environment initialization */
	memset(&net_env_param, 0, sizeof(t_FmPcdNetEnvParams));
	net_env_param.numOfDistinctionUnits = 2;
	net_env_param.units[0].hdrs[0].hdr = HEADER_TYPE_IPv4;
	net_env_param.units[0].hdrs[1].hdr = HEADER_TYPE_IPv6;
	net_env_param.units[1].hdrs[0].hdr = HEADER_TYPE_CAPWAP;
	net_env_param.units[1].hdrs[0].opt.capwapOpt = CAPWAP_FRAG_1;
	app_port->fm_pcd_info.h_NetEnv =
		FM_PCD_NetEnvCharacteristicsSet(h_pcd_dev, &net_env_param);
	if (!app_port->fm_pcd_info.h_NetEnv) {
		fprintf(stderr, "FM_PCD_NetEnvCharacteristicsSet error\n");
		return -1;
	}

	/* Manips */
#ifdef FRAG_REASSEM_ENABLE
	memset(&manip_param, 0, sizeof(t_FmPcdManipParams));
	manip_param.type = e_FM_PCD_MANIP_REASSEM;
	manip_param.u.reassem.hdr = HEADER_TYPE_CAPWAP;
	manip_param.u.reassem.u.capwapReassem.dataMemId = 0;
	manip_param.u.reassem.u.capwapReassem.dataLiodnOffset = 0;
	manip_param.u.reassem.u.capwapReassem.maxNumFramesInProcess = 128;
	manip_param.u.reassem.u.capwapReassem.timeOutMode =
		e_FM_PCD_MANIP_TIME_OUT_BETWEEN_FRAMES;
	manip_param.u.reassem.u.capwapReassem.fqidForTimeOutFrames = 0;
	manip_param.u.reassem.u.capwapReassem.
		timeoutThresholdForReassmProcess = 1000000;
	manip_param.u.reassem.u.capwapReassem.numOfFramesPerHashEntry =
		e_FM_PCD_MANIP_EIGHT_WAYS_HASH;
	manip_param.u.reassem.u.capwapReassem.relativeSchemeId =
		*schemes_count;
	manip_param.u.reassem.u.capwapReassem.maxReassembledFrameLength = 0;
	app_port->fm_pcd_info.h_Manips[1] =
		FM_PCD_ManipNodeSet(h_pcd_dev, &manip_param);
	if(!app_port->fm_pcd_info.h_Manips[1]) {
		fprintf(stderr, "FM_PCD_ManipNodeSet failed\n");
		return -1;
	}
	app_port->fm_pcd_info.h_ManipsOrder[app_port->fm_pcd_info.numOfManips++]
		= app_port->fm_pcd_info.h_Manips[1];
	*schemes_count += 1;
#endif /* FRAG_REASSEM_ENABLE */

	memset(&manip_param, 0, sizeof(t_FmPcdManipParams));
	manip_param.type = e_FM_PCD_MANIP_HDR;
	manip_param.u.hdr.dontParseAfterManip = TRUE;
	manip_param.u.hdr.rmv = TRUE;
	manip_param.u.hdr.rmvParams.type = e_FM_PCD_MANIP_RMV_BY_HDR;
	manip_param.u.hdr.rmvParams.u.byHdr.type =
		e_FM_PCD_MANIP_RMV_BY_HDR_CAPWAP;
	app_port->fm_pcd_info.h_Manips[0] =
		FM_PCD_ManipNodeSet(h_pcd_dev, &manip_param);
	if (!app_port->fm_pcd_info.h_Manips[0]) {
		fprintf(stderr, "FM_PCD_ManipNodeSet failed\n");
		return -1;
	}
	app_port->fm_pcd_info.h_ManipsOrder[app_port->fm_pcd_info.numOfManips++]
		= app_port->fm_pcd_info.h_Manips[0];

	/* CC initialization */
	memset(&cc_node_param, 0, sizeof(t_FmPcdCcNodeParams));
	cc_node_param.extractCcParams.type  = e_FM_PCD_EXTRACT_NON_HDR;
	cc_node_param.extractCcParams.extractNonHdr.src =
		e_FM_PCD_EXTRACT_FROM_FLOW_ID;
	cc_node_param.extractCcParams.extractNonHdr.action =
		e_FM_PCD_ACTION_INDEXED_LOOKUP;
	cc_node_param.extractCcParams.extractNonHdr.offset = 0;
	cc_node_param.extractCcParams.extractNonHdr.size = 2;

	cc_node_param.keysParams.numOfKeys = 4;
	cc_node_param.extractCcParams.extractNonHdr.icIndxMask =
		(uint16_t)((cc_node_param.keysParams.numOfKeys - 1) << 4);
	cc_node_param.keysParams.keySize = 2;
	cc_node_param.keysParams.maxNumOfKeys =
		cc_node_param.keysParams.numOfKeys;
	cc_node_param.keysParams.statisticsMode =
		e_FM_PCD_CC_STATS_MODE_BYTE_AND_FRAME;

	for (i = 0; i < cc_node_param.keysParams.numOfKeys; i++) {
		cc_node_param.keysParams.keyParams[i].ccNextEngineParams.
			nextEngine = e_FM_PCD_DONE;
		cc_node_param.keysParams.keyParams[i].ccNextEngineParams.
			params.enqueueParams.action = e_FM_PCD_ENQ_FRAME;
		cc_node_param.keysParams.keyParams[i].ccNextEngineParams.
			params.enqueueParams.overrideFqid = TRUE;
		cc_node_param.keysParams.keyParams[i].ccNextEngineParams.
			params.enqueueParams.newFqid = fqid_base + i;
		cc_node_param.keysParams.keyParams[i].ccNextEngineParams.
			statisticsEn = TRUE;
		cc_node_param.keysParams.keyParams[i].ccNextEngineParams.
			h_Manip = app_port->fm_pcd_info.h_Manips[0];
	}
	app_port->fm_pcd_info.h_CcNodes[0] =
		FM_PCD_MatchTableSet(h_pcd_dev, &cc_node_param);
	if (!app_port->fm_pcd_info.h_CcNodes[0]) {
		fprintf(stderr, "FM_PCD_MatchTableSet failed\n");
		return -1;
	}
	app_port->fm_pcd_info.
		h_CcNodesOrder[app_port->fm_pcd_info.numOfCcNodes++] =
		app_port->fm_pcd_info.h_CcNodes[0];

	/* define a tree with 1 group of size 1 only, all traffic goes to this node */
	memset(&cc_tree_param, 0, sizeof(t_FmPcdCcTreeParams));
	cc_tree_param.numOfGrps = 1;
	cc_tree_param.h_NetEnv = app_port->fm_pcd_info.h_NetEnv;
	cc_tree_param.ccGrpParams[0].numOfDistinctionUnits =  0;
	cc_tree_param.ccGrpParams[0].nextEnginePerEntriesInGrp[0].nextEngine =
		e_FM_PCD_CC;
	cc_tree_param.ccGrpParams[0].nextEnginePerEntriesInGrp[0].params.
		ccParams.h_CcNode = app_port->fm_pcd_info.h_CcNodes[0];

	/* Build tree */
	app_port->fm_pcd_info.h_CcTree =
		FM_PCD_CcRootBuild(h_pcd_dev, &cc_tree_param);
	if (!app_port->fm_pcd_info.h_CcTree) {
		fprintf(stderr, "FM_PCD_CcRootBuild failed\n");
		return -1;
	}

	/* Scheme initialization */
	memset(&scheme, 0, sizeof(t_FmPcdKgSchemeParams));
	scheme.netEnvParams.h_NetEnv = app_port->fm_pcd_info.h_NetEnv;
	scheme.id.relativeSchemeId = (uint8_t)(*schemes_count + i);
	scheme.schemeCounter.update = TRUE;
	scheme.baseFqid = fqid_base;
	scheme.nextEngine = e_FM_PCD_CC;
	scheme.kgNextEngineParams.cc.h_CcTree = app_port->fm_pcd_info.h_CcTree;
	scheme.kgNextEngineParams.cc.grpId = 0;
	app_port->fm_pcd_info.h_Schemes[0] =
		FM_PCD_KgSchemeSet(h_pcd_dev, &scheme);
	if (!app_port->fm_pcd_info.h_Schemes[0]) {
		fprintf(stderr, "FM_PCD_KgSchemeSet failed");
		return -1;
	}
	*schemes_count += 1;

	/* bind port to PCD properties */
	/* initialize PCD parameters */
	memset(&pcd_param, 0, sizeof(t_FmPortPcdParams));
	pcd_param.h_NetEnv = app_port->fm_pcd_info.h_NetEnv;
	pcd_param.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC;
	pcd_param.p_PrsParams = &prs_param;
	pcd_param.p_KgParams = &kg_param;
	pcd_param.p_CcParams = &cc_param;

#ifdef FRAG_REASSEM_ENABLE
	pcd_param.h_CapwapReassemblyManip = app_port->fm_pcd_info.h_Manips[1];
#endif /* FRAG_REASSEM_ENABLE */

	/* initialize parser port parameters */
	memset(&prs_param, 0, sizeof(t_FmPortPcdPrsParams));
	prs_param.parsingOffset = 0;
	prs_param.firstPrsHdr = HEADER_TYPE_CAPWAP;

	/* initialize Keygen port parameters */
	memset(&kg_param, 0, sizeof(t_FmPortPcdKgParams));
	kg_param.numOfSchemes = num_of_schemes;
	for (i = 0; i < num_of_schemes; i++)
		kg_param.h_Schemes[i] = app_port->fm_pcd_info.h_Schemes[i];

	/* initialize coarse classification parameters */
	memset(&cc_param, 0, sizeof(t_FmPortPcdCcParams));
	cc_param.h_CcTree = app_port->fm_pcd_info.h_CcTree;

	app_port->fm_pcd_info.pcdSet = TRUE;

	FM_PORT_Disable(port_dev);
	err = FM_PORT_SetPCD(port_dev, &pcd_param);
	FM_PORT_Enable(port_dev);

	return err;
}

static t_Error set_capwap_eth_rx_pcd (struct capwap_port * app_port,
		uint32_t *schemes_count, u32 fqid_base, u32 non_capwap_fqid)
{
	t_FmPcdKgSchemeParams scheme;
	t_FmPcdNetEnvParams net_env_param;
	t_FmPortPcdParams pcd_param;
	t_FmPcdCcTreeParams cc_tree_param;
	t_FmPcdCcNodeParams cc_node_param;
	t_FmPortPcdCcParams cc_param;
	t_FmPortPcdPrsParams prs_param;
	t_FmPortPcdKgParams kg_param;
	uint8_t i, k, next_extraction;
	uint8_t num_of_schemes = 2;
	t_Error err = E_OK;
	t_Handle h_pcd_dev = fms[app_port->interface->fman_idx].h_pcd_dev;
	t_Handle h_PortDev = app_port->handle;

	app_port->fm_pcd_info.rxPcdQsBase = fqid_base;

	/* Network Environment initialization */
	memset(&net_env_param, 0, sizeof(t_FmPcdNetEnvParams));
	net_env_param.numOfDistinctionUnits = 2;
	net_env_param.units[0].hdrs[0].hdr = HEADER_TYPE_IPv6;
	net_env_param.units[0].hdrs[1].hdr = HEADER_TYPE_IPv4;
	net_env_param.units[1].hdrs[0].hdr = HEADER_TYPE_UDP;
	net_env_param.units[1].hdrs[1].hdr = HEADER_TYPE_UDP_LITE;
	app_port->fm_pcd_info.h_NetEnv =
		FM_PCD_NetEnvCharacteristicsSet(h_pcd_dev, &net_env_param);
	if(!app_port->fm_pcd_info.h_NetEnv) {
		fprintf(stderr, "FM_PCD_NetEnvCharacteristicsSet error\n");
		return -1;
	}

	/* Table & Tree */
	memset(&cc_node_param, 0, sizeof(t_FmPcdCcNodeParams));
	cc_node_param.extractCcParams.type  = e_FM_PCD_EXTRACT_NON_HDR;
	cc_node_param.extractCcParams.extractNonHdr.src =
		e_FM_PCD_EXTRACT_FROM_KEY;
	cc_node_param.extractCcParams.extractNonHdr.action =
		e_FM_PCD_ACTION_EXACT_MATCH;
	cc_node_param.extractCcParams.extractNonHdr.offset = 0;
	/* (4+2+1, SIP+SPORT+CAPWAP_TYPE);*/
	cc_node_param.extractCcParams.extractNonHdr.size = 7;

	cc_node_param.keysParams.numOfKeys = 0;
	cc_node_param.keysParams.keySize =
		cc_node_param.extractCcParams.extractNonHdr.size;
	cc_node_param.keysParams.statisticsMode = e_FM_PCD_CC_STATS_MODE_NONE;

	cc_node_param.keysParams.ccNextEngineParamsForMiss.nextEngine =
		e_FM_PCD_DONE;
	cc_node_param.keysParams.ccNextEngineParamsForMiss.params.
		enqueueParams.overrideFqid = TRUE;
	cc_node_param.keysParams.ccNextEngineParamsForMiss.params.
		enqueueParams.newFqid = non_capwap_fqid;
	cc_node_param.keysParams.ccNextEngineParamsForMiss.statisticsEn = TRUE;
	app_port->fm_pcd_info.h_CcNodes[0] =
		FM_PCD_MatchTableSet(h_pcd_dev, &cc_node_param);
	if(!app_port->fm_pcd_info.h_CcNodes[0]) {
		fprintf(stderr, "FM_PCD_ManipNodeSet failed\n");
		return -1;
	}

	memset(&cc_tree_param, 0, sizeof(t_FmPcdCcTreeParams));
	cc_tree_param.numOfGrps = 1;
	cc_tree_param.h_NetEnv = app_port->fm_pcd_info.h_NetEnv;
	cc_tree_param.ccGrpParams[0].numOfDistinctionUnits =  0;
	cc_tree_param.ccGrpParams[0].nextEnginePerEntriesInGrp[0].nextEngine =
		e_FM_PCD_CC;
	cc_tree_param.ccGrpParams[0].nextEnginePerEntriesInGrp[0].params.
		ccParams.h_CcNode = app_port->fm_pcd_info.h_CcNodes[0];

	/* Build tree */
	app_port->fm_pcd_info.h_CcTree =
		FM_PCD_CcRootBuild(h_pcd_dev, &cc_tree_param);
	if(!app_port->fm_pcd_info.h_CcTree) {
		fprintf(stderr, "FM_PCD_CcRootBuild failed\n");
		return -1;
	}

	/* Scheme initialization */
	for(i = 0; i < num_of_schemes; i++) {
		memset(&scheme, 0, sizeof(t_FmPcdKgSchemeParams));
		scheme.netEnvParams.h_NetEnv = app_port->fm_pcd_info.h_NetEnv;
		scheme.id.relativeSchemeId = (uint8_t)(*schemes_count+i);
		scheme.schemeCounter.update = TRUE;
		next_extraction = 0;
		switch(i) {
		case(0): /* IP+UDP */
			scheme.baseFqid = app_port->fm_pcd_info.rxPcdQsBase;
			scheme.netEnvParams.numOfDistinctionUnits = 2;
			scheme.netEnvParams.unitIds[0] = 0; /* (IPv4/IPv6) */
			scheme.netEnvParams.unitIds[1] = 1; /* (UDP/UDP_LITE) */
			scheme.nextEngine = e_FM_PCD_CC;
			scheme.kgNextEngineParams.cc.h_CcTree =
				app_port->fm_pcd_info.h_CcTree;
			scheme.kgNextEngineParams.cc.grpId = 0;
			scheme.useHash = TRUE;
			scheme.keyExtractAndHashParams.
				hashDistributionNumOfFqids = 1;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].type =
				e_FM_PCD_EXTRACT_BY_HDR;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].extractByHdr.hdr =
				HEADER_TYPE_IPv4;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].extractByHdr.type
				= e_FM_PCD_EXTRACT_FULL_FIELD;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction++].extractByHdr.
				extractByHdrType.fullField.ipv4 =
				NET_HEADER_FIELD_IPv4_SRC_IP;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].type =
				e_FM_PCD_EXTRACT_BY_HDR;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].extractByHdr.hdr =
				HEADER_TYPE_UDP;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].extractByHdr.type
				= e_FM_PCD_EXTRACT_FULL_FIELD;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction++].extractByHdr.
				extractByHdrType.fullField.udp =
				NET_HEADER_FIELD_UDP_PORT_SRC;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].type =
				e_FM_PCD_EXTRACT_BY_HDR;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].extractByHdr.hdr =
				HEADER_TYPE_UDP;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].extractByHdr.type
				= e_FM_PCD_EXTRACT_FROM_HDR;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction].extractByHdr.
				extractByHdrType.fromHdr.offset = 8;
			scheme.keyExtractAndHashParams.
				extractArray[next_extraction++].extractByHdr.
				extractByHdrType.fromHdr.size = 1;
			break;
		case (1): /* Garbage collector */
			scheme.nextEngine = e_FM_PCD_DONE;
			scheme.baseFqid = non_capwap_fqid;
			scheme.kgNextEngineParams.doneAction =
				e_FM_PCD_ENQ_FRAME;
			break;
		}
		scheme.keyExtractAndHashParams.numOfUsedExtracts =
			next_extraction;
		scheme.keyExtractAndHashParams.privateDflt0 = 0x01020304;
		scheme.keyExtractAndHashParams.privateDflt1 = 0x11121314;
		scheme.keyExtractAndHashParams.numOfUsedDflts =
			FM_PCD_KG_NUM_OF_DEFAULT_GROUPS;
		for(k = 0; k < FM_PCD_KG_NUM_OF_DEFAULT_GROUPS; k++) {
			scheme.keyExtractAndHashParams.dflts[k].type =
				(e_FmPcdKgKnownFieldsDfltTypes)k; /* all types */
			scheme.keyExtractAndHashParams.dflts[k].dfltSelect =
				e_FM_PCD_KG_DFLT_GBL_0;
		}
		app_port->fm_pcd_info.h_Schemes[i] =
			FM_PCD_KgSchemeSet(h_pcd_dev, &scheme);
		if (!app_port->fm_pcd_info.h_Schemes[i]) {
			fprintf(stderr, "FM_PCD_KgSchemeSet failed");
			return -1;
		}
	}
	*schemes_count += num_of_schemes;

	/* bind port to PCD properties */
	/* initialize PCD parameters */
	memset(&pcd_param, 0, sizeof(t_FmPortPcdParams));
	pcd_param.h_NetEnv = app_port->fm_pcd_info.h_NetEnv;
	pcd_param.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC;
	pcd_param.p_PrsParams = &prs_param;
	pcd_param.p_KgParams = &kg_param;
	pcd_param.p_CcParams = &cc_param;

	/* initialize parser port parameters */
	memset(&prs_param, 0, sizeof(t_FmPortPcdPrsParams));
	prs_param.parsingOffset = 0;
	prs_param.firstPrsHdr = HEADER_TYPE_ETH;

	/* initialize Keygen port parameters */
	memset(&kg_param, 0, sizeof(t_FmPortPcdKgParams));
	kg_param.numOfSchemes = num_of_schemes;
	for (i = 0; i < num_of_schemes; i++)
		kg_param.h_Schemes[i] = app_port->fm_pcd_info.h_Schemes[i];

	/* initialize coarse classification parameters */
	memset(&cc_param, 0, sizeof(t_FmPortPcdCcParams));
	cc_param.h_CcTree = app_port->fm_pcd_info.h_CcTree;

	FM_PORT_Disable(h_PortDev);
	err = FM_PORT_SetPCD(h_PortDev, &pcd_param);
	FM_PORT_Enable(h_PortDev);

	return err;
}

static int init_all_pcds(void)
{
	int ret;
	uint32_t current_schemes[INTG_MAX_NUM_OF_FM];
	struct dpaa_capwap_domain_fqs fqs;

	printf("Setting PCDs\n");
	ret = get_fm_handle(app_conf.fm);
	if (ret)
		goto err;
	ret = get_port_handle(&app_conf.ob_op);
	if (ret)
		goto err;
	ret = get_port_handle(&app_conf.capwap_eth);
	if (ret)
		goto err;
	ret = get_port_handle(&app_conf.ib_op);
	if (ret)
		goto err;

	/* FM_PCD_SetAdvancedOffloadSupport must be set before FM_PCD_Enable */
        ret = FM_PCD_SetAdvancedOffloadSupport(fms[app_conf.fm].h_pcd_dev);
        if (ret != E_OK) {
		fprintf(stderr, "Set Advanced Offload Support failed:0x%x\n",
				ret);
		goto err;
	}

	ret = FM_PCD_Enable(fms[app_conf.fm].h_pcd_dev);
        if (ret != E_OK) {
		fprintf(stderr, "FM_PCD_Enable failed:0x%x\n", ret);
		goto err;
	}

        ret = FM_PCD_KgSetAdditionalDataAfterParsing(fms[app_conf.fm].h_pcd_dev,
			16);
        if (ret != E_OK) {
		fprintf(stderr, "FM_PCD_KgSetAdditionalDataAfterParsing failed:0x%x",
				ret);
		goto err;
	}

	ret = ioctl(app_conf.capwap_domain_dev_fd,
			DPA_CAPWAP_IOC_DOMAIN_GET_FQIDS, &fqs);
	if (ret < 0) {
		printf("capwap domain add in tunnel failed\n");
		goto err;
	}

	memset(current_schemes, 0, sizeof(current_schemes));
	ret = set_inbound_op_pcd(&app_conf.ib_op, &current_schemes[app_conf.fm],
			fqs.inbound_core_rx_fqs.fqid_base);
	if (ret) {
		fprintf(stderr, "Setting PCD for post dec port failed\n");
		goto err;
	}


	ret = set_capwap_eth_rx_pcd(&app_conf.capwap_eth,
			&current_schemes[app_conf.fm],
			fqs.inbound_eth_rx_fqs.fqid_base,
			app_conf.capwap_eth.interface->fqid_rx_def);
	if (ret) {
		fprintf(stderr, "Setting PCD for CAPWAP Frame Rx port failed\n");
		goto err;
	}
	return 0;
err:
	return ret;
}

static void *add_new_tunnel(void *h_Domain,
                             bool is_inbound,
			     struct tunnel_info *p_tunnel,
			     bool is_control,
			     bool is_dtls)
{
	t_FmPcdCcNextEngineParams cc_next_engine_param = {0};
	struct iphdr ipv4_header;
	struct ether_header ether_header;
	struct udphdr udp_hdr;
	int ret;
	uint8_t capwapHdr[] = {
		0x00,0x18,0x43,0x10,
		0x00,0x01,0x00,0x00,
		0x08,0xfc,0x6e,0x64 };
	uint8_t	iv[16] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0xef, 0xfe, 0xef, 0xfe,
		0x55, 0x66, 0x77, 0x88 };

	if (is_inbound) { /* inbound tunnel */
		struct dpaa_capwap_domain_tunnel_in_params tunnel_params;
		memset(&tunnel_params, 0, sizeof(tunnel_params));

		tunnel_params.sip.u.ipv4_addr = p_tunnel->src_ip;
		tunnel_params.dip.u.ipv4_addr = p_tunnel->dest_ip;
		if (is_control) {
			tunnel_params.src_port = 0x147e;
			tunnel_params.dst_port = 0x147e;
		} else {
			tunnel_params.src_port = 0x147f;
			tunnel_params.dst_port = 0x147f;
		}

		tunnel_params.is_control = is_control;
		if (is_dtls) {
			tunnel_params.dtls = TRUE;
			tunnel_params.dtls_params.type = 0x17;
			tunnel_params.dtls_params.arw = e_DTLS_ARS_0;
			tunnel_params.dtls_params.epoch = 0xEEEE;
			tunnel_params.dtls_params.seq_num =
				0x0000999988888888LL;
			tunnel_params.dtls_params.wbIv = TRUE;
			memcpy(tunnel_params.dtls_params.p_Iv, iv, 16);
			tunnel_params.dtls_params.alg_type =
				p_tunnel->cipherdata->algtype;
			tunnel_params.dtls_params.auth_key =
				p_tunnel->authdata->key;
			tunnel_params.dtls_params.auth_key_len =
				p_tunnel->authdata->keylen * 8;
			tunnel_params.dtls_params.cipher_key =
				p_tunnel->cipherdata->key;
			tunnel_params.dtls_params.cipher_key_len =
				p_tunnel->cipherdata->keylen * 8;
		}

		tunnel_params.capwap_domain_id = h_Domain;
		tunnel_params.tunnel_id = NULL;
		ret = ioctl(app_conf.capwap_domain_dev_fd,
				DPA_CAPWAP_IOC_DOMAIN_ADD_IN_TUNNEL,
				&tunnel_params);
		if (ret < 0) {
			printf("capwap domain add in tunnel failed\n");
			return NULL;
		}

		return tunnel_params.tunnel_id;
	} else { /* outbound tunnel */
		struct dpaa_capwap_domain_tunnel_out_params tunnel_params;

		memset(&tunnel_params, 0, sizeof(tunnel_params));
		cc_next_engine_param.nextEngine = e_FM_PCD_DONE;
		cc_next_engine_param.params.enqueueParams.action =
			e_FM_PCD_ENQ_FRAME;
		cc_next_engine_param.params.enqueueParams.overrideFqid = FALSE;

		memset(&ether_header, 0, sizeof(ether_header));
		ether_header.ether_type = 0x800;
		memcpy(ether_header.ether_dhost, p_tunnel->dest_mac, 6);
		memcpy(ether_header.ether_shost, p_tunnel->src_mac, 6);

		memset(&ipv4_header, 0, sizeof(ipv4_header));
		ipv4_header.version = 4;
		ipv4_header.ihl = 5;
		ipv4_header.ttl = IPDEFTTL;
		ipv4_header.tot_len = 0;
		ipv4_header.saddr = p_tunnel->src_ip;
		ipv4_header.daddr = p_tunnel->dest_ip;
		ipv4_header.protocol = 0x11;

		memset(&udp_hdr, 0, sizeof(udp_hdr));
		if (is_control) {
			udp_hdr.source = 0x147e;
			udp_hdr.dest = 0x147e;
		} else {
			udp_hdr.source = 0x147f;
			udp_hdr.dest = 0x147f;
		}
#ifdef FRAG_REASSEM_ENABLE
		tunnel_params.size_for_fragment = CAPWAP_MTU;
		tunnel_params.frag_bp_enable = TRUE;
		tunnel_params.frag_bp_id = CAPWAP_FRAG_BPID;
#endif
		tunnel_params.p_NextEngineParams = &cc_next_engine_param;
		tunnel_params.eth_header_size = ETH_HDR_SIZE;
		tunnel_params.p_ether_header = (uint8_t *)&ether_header;
		tunnel_params.ip_header_size = IPv4_HDR_SIZE;
		tunnel_params.p_ip_header = (uint8_t *)&ipv4_header;
		tunnel_params.last_pid_offset = 9;
		tunnel_params.initial_id = 1;
		tunnel_params.udp_or_lite = FALSE;
		tunnel_params.p_udp_header = (uint8_t *)&udp_hdr;
		tunnel_params.capwap_header_size = sizeof(capwapHdr);
		tunnel_params.p_capwap_header = capwapHdr;
		tunnel_params.is_control = is_control;

		if (is_dtls) {
			tunnel_params.dtls = TRUE;
			tunnel_params.dtls_params.type = 0x17;
			tunnel_params.dtls_params.version = 0xFEFF;
			tunnel_params.dtls_params.epoch = 0xEEEE;
			tunnel_params.dtls_params.seq_num =
				0x0000999988888888LL;
			tunnel_params.dtls_params.wbIv = TRUE;
			memcpy(tunnel_params.dtls_params.p_Iv, iv, 16);
			tunnel_params.dtls_params.alg_type =
				p_tunnel->cipherdata->algtype;
			tunnel_params.dtls_params.auth_key =
				p_tunnel->authdata->key;
			tunnel_params.dtls_params.auth_key_len =
				p_tunnel->authdata->keylen * 8;
			tunnel_params.dtls_params.cipher_key =
				p_tunnel->cipherdata->key;
			tunnel_params.dtls_params.cipher_key_len =
				p_tunnel->cipherdata->keylen * 8;
		}

		tunnel_params.capwap_domain_id = h_Domain;
		tunnel_params.tunnel_id = NULL;
		ret = ioctl(app_conf.capwap_domain_dev_fd,
				DPA_CAPWAP_IOC_DOMAIN_ADD_OUT_TUNNEL,
				&tunnel_params);
		if (ret < 0) {
			printf("capwap domain add out tunnel failed\n");
			return NULL;
		}

		return tunnel_params.tunnel_id;
	}
}

extern struct qman_fq *get_def_fq(struct capwap_port *port);

static int init_domain(uint8_t  max_num_of_tunnels)
{
	struct dpaa_capwap_domain_params capwap_domain_params;
	void *capwap_domain;
	void *in_ctrl_dtls_tunnel, *in_ctrl_non_dtls_tunnel;
	void *in_data_dtls_tunnel, *in_data_non_dtls_tunnel;
	void *out_ctrl_dtls_tunnel, *out_ctrl_non_dtls_tunnel;
	void *out_data_dtls_tunnel, *out_data_non_dtls_tunnel;
	struct capwap_domain_kernel_rx_ctl rx_ctl;
	struct qman_fq *fq;
	uint64_t context_a = 0;
	uint32_t context_b = 0;
	uint16_t channel;
	int ret;

	memset(&capwap_domain_params, 0,
			sizeof(struct dpaa_capwap_domain_params));
	capwap_domain_params.h_fm_pcd =
		(void *)((struct t_Device *)fms[app_conf.fm].h_pcd_dev)->fd;

	capwap_domain_params.inbound_pre_params.h_Table =
		app_conf.capwap_eth.fm_pcd_info.h_CcNodes[0];
	capwap_domain_params.inbound_pre_params.key_fields =
		DPAA_CAPWAP_DOMAIN_KEY_FIELD_SIP |
		DPAA_CAPWAP_DOMAIN_KEY_FIELD_SPORT |
		DPAA_CAPWAP_DOMAIN_KEY_FIELD_PREAMBLE;

	capwap_domain_params.outbound_op.port_handle =
		(void *)((struct t_Device *)app_conf.ob_op.handle)->fd;
	capwap_domain_params.outbound_op.fm_id =
		app_conf.ob_op.interface->fman_idx;
	capwap_domain_params.outbound_op.port_id =
		app_conf.ob_op.interface->mac_idx;

	capwap_domain_params.inbound_op.fm_id =
		app_conf.ib_op.interface->fman_idx;
	capwap_domain_params.inbound_op.port_id =
		app_conf.ib_op.interface->mac_idx;

	capwap_domain_params.max_num_of_tunnels = max_num_of_tunnels;
	capwap_domain_params.id = NULL;

	ret = ioctl(app_conf.capwap_domain_dev_fd, DPA_CAPWAP_IOC_DOMAIN_INIT,
			&capwap_domain_params);
	if (ret < 0) {
		fprintf(stderr,"capwap domain init failed:0x%x\n", ret);
		return ret;
	}

	capwap_domain = capwap_domain_params.id;

	/* OutBound */
	out_ctrl_dtls_tunnel = add_new_tunnel(capwap_domain, FALSE,
			app_conf.tunnel_list[0], TRUE, TRUE);
	out_data_dtls_tunnel = add_new_tunnel(capwap_domain, FALSE,
			app_conf.tunnel_list[0], FALSE, TRUE);
	out_ctrl_non_dtls_tunnel = add_new_tunnel(capwap_domain, FALSE,
			app_conf.tunnel_list[0], TRUE, FALSE);
	out_data_non_dtls_tunnel = add_new_tunnel(capwap_domain, FALSE,
			app_conf.tunnel_list[0], FALSE, FALSE);
	/* InBound */
	in_ctrl_dtls_tunnel = add_new_tunnel(capwap_domain, TRUE,
			app_conf.tunnel_list[0], TRUE, TRUE);
	in_data_dtls_tunnel = add_new_tunnel(capwap_domain, TRUE,
			app_conf.tunnel_list[0], FALSE, TRUE);
	in_ctrl_non_dtls_tunnel = add_new_tunnel(capwap_domain, TRUE,
			app_conf.tunnel_list[0], TRUE, FALSE);
	in_data_non_dtls_tunnel = add_new_tunnel(capwap_domain, TRUE,
			app_conf.tunnel_list[0], FALSE, FALSE);
#if 0
	/* Test Remove and re-add tunnel function */
	printf("remove tunnel %p\n", out_ctrl_dtls_tunnel);
	ret = ioctl(app_conf.capwap_domain_dev_fd,
			DPA_CAPWAP_IOC_DOMAIN_REMOVE_TUNNEL,
			&out_ctrl_dtls_tunnel);
	if (ret < 0) {
		printf("capwap domain remove tunnel failed\n");
		return ret;
	}
	ret = ioctl(app_conf.capwap_domain_dev_fd,
			DPA_CAPWAP_IOC_DOMAIN_REMOVE_TUNNEL,
			&in_ctrl_dtls_tunnel);
	if (ret < 0) {
		printf("capwap domain remove tunnel failed\n");
		return ret;
	}
	out_ctrl_dtls_tunnel = add_new_tunnel(capwap_domain, FALSE,
			app_conf.tunnel_list[1], TRUE, TRUE);
	in_ctrl_dtls_tunnel = add_new_tunnel(capwap_domain, TRUE,
			app_conf.tunnel_list[1], TRUE, TRUE);
#endif
#if 0
	/* Test control kernel rx function */
	if (app_conf.mode != 2) {
		rx_ctl.is_control = true;
		rx_ctl.is_dtls = true;
		rx_ctl.on = false;
		rx_ctl.capwap_domain_id = capwap_domain;
		ret = ioctl(app_conf.capwap_domain_dev_fd,
				DPA_CAPWAP_IOC_DOMAIN_KERNAL_RX_CTL, &rx_ctl);
		if (ret < 0) {
			printf("capwap domain disable kernel rx failed\n");
			return ret;
		}
		printf("disabled fqid is 0x%x\n", rx_ctl.fqid);

		ret = init_rx_fq(rx_ctl.fqid);
		if (ret) {
			printf("re-init rx fq failed in user-spcae:0x%x\n",
					rx_ctl.fqid);
			return ret;
		}
	}
#endif
	/* Non-CAPWAP Ethernet Port 1<-->capwap control-dtls tunnel */
	if (app_conf.mode == 2 && app_conf.non_capwap_eth1.interface) {
		fman_if_disable_rx(app_conf.non_capwap_eth1.interface);
		memset(&rx_ctl, 0, sizeof(struct capwap_domain_kernel_rx_ctl));
		rx_ctl.is_control = true;
		rx_ctl.is_dtls = true;
		rx_ctl.on = false;
		rx_ctl.capwap_domain_id = capwap_domain;
		ret = ioctl(app_conf.capwap_domain_dev_fd,
				DPA_CAPWAP_IOC_DOMAIN_KERNAL_RX_CTL, &rx_ctl);
		if (ret < 0) {
			printf("capwap domain disable kernel rx failed\n");
			return ret;
		}
		printf("disabled fqid is 0x%x\n", rx_ctl.fqid);
		/* CAPWAP Tunnel --> Non-CAPWAP Ethernet port */
		fq = __dma_mem_memalign(L1_CACHE_BYTES, sizeof(struct qman_fq));
		if (unlikely(NULL == fq)) {
			fprintf(stderr, "error: dma_mem_memalign failed\n");
			return -ENOMEM;
		}
		memset(fq, 0, sizeof(struct qman_fq));
		fq->fqid = rx_ctl.fqid;
		channel = app_conf.non_capwap_eth1.interface->tx_channel_id;
		context_a = (((uint64_t) 0x80000000 | fman_dealloc_bufs_mask_hi)
				<< 32) | fman_dealloc_bufs_mask_lo;
		context_b = 0;
		capwap_fq_tx_init(fq, channel, context_a, context_b);
		/* Non-CAPWAP Ethernet port --> CAPWAP Tunnel*/
		fq = get_def_fq(&app_conf.non_capwap_eth1);
		teardown_fq(fq);
		fq->fqid = app_conf.non_capwap_eth1.interface->fqid_rx_def;
		channel = app_conf.ob_op.interface->tx_channel_id;
		context_a = (u64)1 << 63;
		/* a1v */
		context_a |= (u64)1 << 61;
		/* flowid for a1, Lower flow for OP*/
		context_a |= (u64)0 << (32 + 4);
		context_b = 0;
		capwap_fq_tx_init(fq, channel, context_a, context_b);

		fman_if_enable_rx(app_conf.non_capwap_eth1.interface);
	}
	/* Non-CAPWAP Ethernet Port 2<-->capwap data-dtls tunnel */
	if (app_conf.mode == 2 && app_conf.non_capwap_eth2.interface) {
		fman_if_disable_rx(app_conf.non_capwap_eth2.interface);
		memset(&rx_ctl, 0, sizeof(struct capwap_domain_kernel_rx_ctl));
		rx_ctl.is_control = false;
		rx_ctl.is_dtls = true;
		rx_ctl.on = false;
		rx_ctl.capwap_domain_id = capwap_domain;
		ret = ioctl(app_conf.capwap_domain_dev_fd,
				DPA_CAPWAP_IOC_DOMAIN_KERNAL_RX_CTL, &rx_ctl);
		if (ret < 0) {
			printf("capwap domain disable kernel rx failed\n");
			return ret;
		}
		printf("disabled fqid is 0x%x\n", rx_ctl.fqid);
		/* CAPWAP Tunnel --> Non-CAPWAP Ethernet port */
		fq = __dma_mem_memalign(L1_CACHE_BYTES, sizeof(struct qman_fq));
		if (unlikely(NULL == fq)) {
			fprintf(stderr, "error: dma_mem_memalign failed\n");
			return -ENOMEM;
		}
		memset(fq, 0, sizeof(struct qman_fq));
		fq->fqid = rx_ctl.fqid;
		channel = app_conf.non_capwap_eth2.interface->tx_channel_id;
		context_a = (((uint64_t) 0x80000000 | fman_dealloc_bufs_mask_hi)
				<< 32) | fman_dealloc_bufs_mask_lo;
		context_b = 0;
		capwap_fq_tx_init(fq, channel, context_a, context_b);
		/* Non-CAPWAP Ethernet port --> CAPWAP Tunnel*/
		fq = get_def_fq(&app_conf.non_capwap_eth2);
		teardown_fq(fq);
		fq->fqid = app_conf.non_capwap_eth2.interface->fqid_rx_def;
		channel = app_conf.ob_op.interface->tx_channel_id;
		context_a = (u64)1 << 63;
		/* a1v */
		context_a |= (u64)1 << 61;
		/* flowid for a1, Lower flow for OP*/
		context_a |= (u64)1 << (32 + 4);
		context_b = 0;
		capwap_fq_tx_init(fq, channel, context_a, context_b);

		fman_if_enable_rx(app_conf.non_capwap_eth2.interface);
	}
	return 0;
}

int capwap_usecase(void)
{
	int ret = 0;

	app_conf.capwap_domain_dev_fd = open("/dev/fsl-capwap", O_RDWR);
	if (app_conf.capwap_domain_dev_fd < 0) {
	    printf("open capwap device failed\n");
	    return -EBUSY;
	}

	ret = init_all_pcds();
	if (ret)
		return ret;

	ret = init_domain(4);

	return 0;
}
