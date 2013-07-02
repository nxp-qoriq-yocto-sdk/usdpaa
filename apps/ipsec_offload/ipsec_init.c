/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
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

#include <ppac.h>
#include "ppam_if.h"
#include <ppac_interface.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/fsl_qman.h>
#include "usdpaa/fsl_dpa_classifier.h"
#include "usdpaa/fsl_dpa_ipsec.h"
#include "fm_ext.h"
#include "fm_pcd_ext.h"
#include "ncsw_ext.h"
#include <unistd.h>
#include <stdbool.h>
#include "fmc.h"

#include "app_config.h"
#include "app_common.h"

#define SETS 0
#define WAYS 1
#define IN_SA_PCD_HASH_OFF	0
#if defined P4080
#define NUM_SETS        2
#define NUM_WAYS        8
#elif defined B4860
#define NUM_SETS        8
#define NUM_WAYS        8
#elif defined B4420
#define NUM_SETS	8
#define NUM_WAYS	8
#else
#define NUM_SETS	2
#define NUM_WAYS	8
#endif


/* define the number of entries (ways * sets) for each inbound sa type */
static int num_entries[DPA_IPSEC_MAX_SA_TYPE][2] = {
		[DPA_IPSEC_SA_IPV4][SETS] = NUM_SETS,
		[DPA_IPSEC_SA_IPV4][WAYS] = NUM_WAYS,
		[DPA_IPSEC_SA_IPV4_NATT][SETS] = NUM_SETS,
		[DPA_IPSEC_SA_IPV4_NATT][WAYS] = NUM_WAYS,
		[DPA_IPSEC_SA_IPV6][SETS] = NUM_SETS,
		[DPA_IPSEC_SA_IPV6][WAYS] = NUM_WAYS,
};
#define IPSEC_START_IN_FLOW_ID  0

/* These values must be set according to xml pcd file */
#define IPSEC_OUT_POL_CC_NODE_KEYS { \
		16, /* Number of keys for DPA_IPSEC_PROTO_TCP_IPV4 CC Node */ \
		16, /* Number of keys for DPA_IPSEC_PROTO_TCP_IPV6 CC Node */ \
		16, /* Number of keys for DPA_IPSEC_PROTO_UDP_IPV4 CC Node */ \
		16, /* Number of keys for DPA_IPSEC_PROTO_UDP_IPV6 CC Node */ \
		16, /* Number of keys for DPA_IPSEC_PROTO_ICMP_IPV4 CC Node */ \
		16, /* Number of keys for DPA_IPSEC_PROTO_ICMP_IPV6 CC Node */ \
		16, /* Number of keys for DPA_IPSEC_PROTO_SCTP_IPV4 CC Node */ \
		16, /* Number of keys for DPA_IPSEC_PROTO_SCTP_IPV6 CC Node */ \
		NUM_SETS * NUM_WAYS, \
		/* Number of keys for DPA_IPSEC_PROTO_ANY_IPV4 CC Node */ \
		NUM_SETS * NUM_WAYS, \
		/* Number of keys for DPA_IPSEC_PROTO_ANY_IPV6 CC Node */ \
};

#define IPSEC_PRE_DEC_TBL_KEY_SIZE \
	{ \
		/* IPV4 SA */ \
		(DPA_OFFLD_IPv4_ADDR_LEN_BYTES + \
		 IP_PROTO_FIELD_LEN + \
		 ESP_SPI_FIELD_LEN), \
		 /* IPV4 SA w/ NATT*/ \
		(DPA_OFFLD_IPv4_ADDR_LEN_BYTES + \
		 IP_PROTO_FIELD_LEN + \
		 2 * PORT_FIELD_LEN + \
		 ESP_SPI_FIELD_LEN), \
		 /* IPV6 SA */ \
		(DPA_OFFLD_IPv6_ADDR_LEN_BYTES + \
		 IP_PROTO_FIELD_LEN + \
		 ESP_SPI_FIELD_LEN) \
	}

#define IPSEC_OUT_PRE_ENC_TBL_KEY_SIZE \
	{ \
		 0,	\
		 0,	\
		 0,	\
		 0,	\
		 0,	\
		 0,	\
		 0,	\
		 0,	\
		 (2 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + \
		 IP_PROTO_FIELD_LEN + \
		 2 * PORT_FIELD_LEN), \
		(2 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + \
		 IP_PROTO_FIELD_LEN + \
		 2 * PORT_FIELD_LEN) \
	}

#define IPSEC_OUT_POL_KEY_FIELDS	(DPA_IPSEC_KEY_FIELD_SIP |	\
					 DPA_IPSEC_KEY_FIELD_DIP |	\
					 DPA_IPSEC_KEY_FIELD_PROTO |	\
					 DPA_IPSEC_KEY_FIELD_SPORT |	\
					 DPA_IPSEC_KEY_FIELD_DPORT)


int manip_desc[OUT_TCPUDP_POL_NUM];
static int out_pol_cc_node_keys[] = IPSEC_OUT_POL_CC_NODE_KEYS;
static int ipsec_initialized;
static struct dpa_ipsec_params ipsec_params;
static int inb_key_size[] = IPSEC_PRE_DEC_TBL_KEY_SIZE;
static int outb_key_size[] = IPSEC_OUT_PRE_ENC_TBL_KEY_SIZE;

int ipsec_offload_init(int *dpa_ipsec_id)
{
	int i, cls_td;
	struct dpa_cls_tbl_params cls_tbl_params;
	int err;
	t_FmPcdParams pcd_params;
	struct fman_if *fif;

	err = dpa_classif_lib_init();
	if (err < 0) {
		fprintf(stderr, "dpa_classif_lib_init failed, err %d\n", err);
		goto out;
	}
	err = dpa_ipsec_lib_init();
	if (err < 0) {
		fprintf(stderr, "dpa_ipsec_lib_init failed, err %d\n", err);
		dpa_classif_lib_exit();
		goto out;
	}

	memset(manip_desc, DPA_OFFLD_DESC_NONE, sizeof(manip_desc));
	memset(&ipsec_params, 0, sizeof(ipsec_params));
	memset(&pcd_params, 0, sizeof(pcd_params));

	/* number of entries in flow_id_cc classifcation PCD xml node */
	ipsec_params.max_sa_pairs = app_conf.max_sa;
	ipsec_params.fm_pcd = pcd_dev;
	ipsec_params.ipf_bpid = app_conf.ipf_bpid;
	ipsec_params.qm_sec_ch = qm_channel_caam;

	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++) {
		/* INB/DL pre SEC classifier */
		memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
		cls_tbl_params.cc_node = cc_in_rx[i];
		cls_tbl_params.type = DPA_CLS_TBL_HASH;
		cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
		cls_tbl_params.hash_params.hash_offs = IN_SA_PCD_HASH_OFF;
		cls_tbl_params.hash_params.max_ways = num_entries[i][WAYS];
		cls_tbl_params.hash_params.num_sets = num_entries[i][SETS];
		cls_tbl_params.hash_params.key_size = inb_key_size[i];

		err = dpa_classif_table_create(&cls_tbl_params, &cls_td);
		if (err < 0) {
			fprintf(stderr, "Error creating inbound SA "
				"classif table (%d), err %d\n", i, err);
			goto out_libs;
		}

		ipsec_params.pre_sec_in_params.dpa_cls_td[i] = cls_td;
	}

	/* INB/DL  post SEC params */
	ipsec_params.post_sec_in_params.data_off = SEC_DATA_OFF_BURST;
	ipsec_params.post_sec_in_params.base_flow_id = IPSEC_START_IN_FLOW_ID;
	ipsec_params.post_sec_in_params.use_ipv6_pol = false;
	fif = get_fif(app_conf.fm, app_conf.ib_oh, fman_offline);
	if (!fif) {
		fprintf(stderr, "Could not get inbound offline port"
			" for retrieving Qm channel, err %d\n", err);
		goto out_inb_post_sec;
	}
	ipsec_params.post_sec_in_params.qm_tx_ch = fif->tx_channel_id;

	memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
	cls_tbl_params.cc_node = cc_flow_id;
	cls_tbl_params.type = DPA_CLS_TBL_INDEXED;
	cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
	cls_tbl_params.indexed_params.entries_cnt = ipsec_params.max_sa_pairs;
	err = dpa_classif_table_create(&cls_tbl_params, &cls_td);
	if (err < 0) {
		fprintf(stderr,
			"INB post SEC dpa_classif_table_create failed,"
			"err %d\n", err);
		goto out_inb_post_sec;
	}

	/* INB policy verification */
	ipsec_params.post_sec_in_params.dpa_cls_td = cls_td;
	ipsec_params.post_sec_in_params.do_pol_check = app_conf.inb_pol_check;
	if (app_conf.inb_pol_check)
		ipsec_params.post_sec_in_params.key_fields =
						DPA_IPSEC_KEY_FIELD_DPORT;
	/* OUTB/UL post SEC params */
	ipsec_params.post_sec_out_params.data_off = SEC_DATA_OFF_BURST;
	fif = get_fif(app_conf.fm, app_conf.ob_oh_post, fman_offline);
	if (!fif) {
		fprintf(stderr, "Could not get outbound offline port"
			" for retrieving Qm channel, err %d\n", err);
		goto out_inb_post_sec;
	}
	ipsec_params.post_sec_out_params.qm_tx_ch = fif->tx_channel_id;

	/* OUTB/UL pre SEC params */
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++) {
		if (cc_out_pre_enc[i] != NULL) {
			memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
			cls_tbl_params.cc_node = cc_out_pre_enc[i];
			cls_tbl_params.type = DPA_CLS_TBL_EXACT_MATCH;
			cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
			cls_tbl_params.exact_match_params.entries_cnt =
					out_pol_cc_node_keys[i];
			cls_tbl_params.exact_match_params.key_size =
							outb_key_size[i];
			err = dpa_classif_table_create(&cls_tbl_params,
							&cls_td);
			if (err < 0) {
				fprintf(stderr, "Error creating outbound "
					"classif table (%d),err %d\n", i, err);
				goto out_outb_pre_sec;
			}

			ipsec_params.pre_sec_out_params.
				table[i].dpa_cls_td = cls_td;
			ipsec_params.pre_sec_out_params.
				table[i].key_fields = IPSEC_OUT_POL_KEY_FIELDS;

		} else
			ipsec_params.pre_sec_out_params.table[i].dpa_cls_td =
							DPA_OFFLD_DESC_NONE;
	}

	err = dpa_ipsec_init(&ipsec_params, dpa_ipsec_id);
	if (err < 0) {
		fprintf(stderr, "dpa_ipsec_init failed\n");
		goto out_outb_pre_sec;
	}

	ipsec_initialized = true;
	return 0;

out_outb_pre_sec:
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++)
		if (ipsec_params.pre_sec_out_params.table[i].dpa_cls_td !=
							DPA_OFFLD_DESC_NONE)
			dpa_classif_table_free(ipsec_params.
					pre_sec_out_params.table[i].dpa_cls_td);
out_inb_post_sec:
	if (ipsec_params.post_sec_in_params.dpa_cls_td !=
							DPA_OFFLD_DESC_NONE)
		dpa_classif_table_free(ipsec_params.
						post_sec_in_params.dpa_cls_td);

	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++)
		if (ipsec_params.pre_sec_in_params.dpa_cls_td[i] !=
			DPA_OFFLD_DESC_NONE)
			dpa_classif_table_free(ipsec_params.pre_sec_in_params.
						dpa_cls_td[i]);
out_libs:
	dpa_ipsec_lib_exit();
	dpa_classif_lib_exit();
out:
	return err;
}

int ipsec_offload_cleanup(int dpa_ipsec_id)
{
	int i, ret;
	if (!ipsec_initialized)
		return 0;

	ret = dpa_ipsec_free(dpa_ipsec_id);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: error freeing dpa ipsec instance %d\n",
			__func__, __LINE__, dpa_ipsec_id);
		return ret;
	}

	for (i = 0; i < OUT_TCPUDP_POL_NUM; i++)
		if (manip_desc[i] != DPA_OFFLD_DESC_NONE)
			dpa_classif_free_hm(manip_desc[i]);

	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++)
		dpa_classif_table_free(ipsec_params.pre_sec_in_params.
				dpa_cls_td[i]);


	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++)
		if (ipsec_params.pre_sec_out_params.table[i].dpa_cls_td !=
							DPA_OFFLD_DESC_NONE)
			dpa_classif_table_free(ipsec_params.
					pre_sec_out_params.table[i].dpa_cls_td);
	return 0;
}