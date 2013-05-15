/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
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

#include "fmc.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <error.h>
#include <assert.h>
#include <usdpaa/compat.h>
#include <usdpaa/fsl_dpa_classifier.h>
#include <usdpaa/fsl_dpa_stats.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/dma_mem.h>
#include <ppac.h>

#include "ppam_if.h"
#include "dpa_classif_demo.h"


#define IPv4_OFFSET				14
#define IPv4_SA_OFFSET				26
#define IPv4_DA_OFFSET				30
#define IPv4_CKSUM_OFFSET			24
#define ETYPE_OFFSET				12
#define APP_TABLE_KEY_SIZE_IPv4			9
#define CLS_MBR_SIZE				2

#define ENABLE_PROMISC


static int		ppac_cli_next_stage(int argc, char *argv[]);

static int		ppam_cli_parse(int		key,
				char			*arg,
				struct argp_state	*state);

static u16		ipv4_cksum(const struct iphdr *iphdr);


static struct dpa_classif_connection	conn[APP_NUM_OF_ENTRIES] = {
	/* Lookup Key (IPSA, IPDA, IPPROTO)		     Frame    Entry */
	/*						     Queue Id	Id  */
	{{ 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x0a, 0x0a, 6 },	 6020,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x0a, 0x0a, 17 }, 6021,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x0a, 0x0b, 6 },	 6022,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x0a, 0x0b, 17 }, 6023,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x0a, 0x0a, 6 },	 6024,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x0a, 0x0a, 17 }, 6025,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x0a, 0x0b, 6 },	 6026,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x0a, 0x0b, 17 }, 6027,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x03, 0xc0, 0xa8, 0x0a, 0x0a, 6 },	 6028,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x03, 0xc0, 0xa8, 0x0a, 0x0a, 17 }, 6029,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x03, 0xc0, 0xa8, 0x0a, 0x0b, 6 },	 6030,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x03, 0xc0, 0xa8, 0x0a, 0x0b, 17 }, 6031,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x04, 0xc0, 0xa8, 0x0a, 0x0a, 6 },	 6032,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x04, 0xc0, 0xa8, 0x0a, 0x0a, 17 }, 6033,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x04, 0xc0, 0xa8, 0x0a, 0x0b, 6 },	 6034,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x04, 0xc0, 0xa8, 0x0a, 0x0b, 17 }, 6035,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x05, 0xc0, 0xa8, 0x0a, 0x0a, 6 },	 6036,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x05, 0xc0, 0xa8, 0x0a, 0x0a, 17 }, 6037,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x05, 0xc0, 0xa8, 0x0a, 0x0b, 6 },	 6038,	0 },
	{{ 0xc0, 0xa8, 0x01, 0x05, 0xc0, 0xa8, 0x0a, 0x0b, 17 }, 6039,	0 }
};

static const uint8_t
	static_entry_key[APP_NUM_OF_STATIC_ENTRIES][APP_TABLE_KEY_SIZE] = {
	{ 0xc0, 0xa8, 0x01, 0x06, 0xc0, 0xa8, 0x0a, 0x0a, 6 },
	{ 0xc0, 0xa8, 0x01, 0x06, 0xc0, 0xa8, 0x0a, 0x0a, 17 },
	{ 0xc0, 0xa8, 0x01, 0x06, 0xc0, 0xa8, 0x0a, 0x0b, 6 },
	{ 0xc0, 0xa8, 0x01, 0x06, 0xc0, 0xa8, 0x0a, 0x0b, 17 }
};

static const uint8_t new_key[APP_NUM_ENTRIES_TO_UPDATE][APP_TABLE_KEY_SIZE] = {
	{ 0xc0, 0xa8, 0x21, 0x01, 0xd2, 0xa8, 0x0a, 0x0a, 6 },
	{ 0xc0, 0xa8, 0x21, 0x01, 0xd2, 0xa8, 0x0a, 0x0a, 17 },
	{ 0xc0, 0xa8, 0x21, 0x01, 0xd2, 0xa8, 0x0a, 0x0b, 6 },
	{ 0xc0, 0xa8, 0x21, 0x01, 0xd2, 0xa8, 0x0a, 0x0b, 17 },
	{ 0xc0, 0xa8, 0x21, 0x02, 0xd2, 0xa8, 0x0a, 0x0a, 6 }
};

static const uint8_t new_static_entry_key[APP_NUM_STATIC_ENTRIES_TO_UPDATE]
							[APP_TABLE_KEY_SIZE] = {
	{ 0xc0, 0xa8, 0x01, 0x12, 0xc0, 0xa8, 0x0a, 0x0b, 6 },
	{ 0xc0, 0xa8, 0x01, 0x12, 0xc0, 0xa8, 0x0a, 0x0b, 17 }
};

struct ppam_arguments ppam_args = {
	.fm	= 1,
	.port	= 0
};

const char ppam_doc[] = "DPA Classifier use case";

static const struct argp_option argp_opts[] = {
	{"fm",		'f', "INT", 0, "FMan index"},
	{"port",	't', "INT", 0, "FMan port index"},
	{}
};

const struct argp ppam_argp = {argp_opts, ppam_cli_parse, 0, ppam_doc};

/* Register the "next_stage" PPAC CLI command */
cli_cmd(next_stage, ppac_cli_next_stage);

static int create_dpa_stats_counters(void);

static int		td				= DPA_OFFLD_DESC_NONE;
static int		fwd_hmd[APP_NUM_OF_ENTRIES]	= {
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE
};
static int		update_hmd[APP_NUM_OF_ENTRIES]	= {
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE,
	DPA_OFFLD_DESC_NONE, DPA_OFFLD_DESC_NONE
};
static int		stage;
struct fmc_model_t	cmodel;

t_Handle		pcds[2];
t_Handle		ccnodes[2];

int dpa_stats_id;
int cnt_id;
void *storage;

enum dpa_stats_op {
	dpa_stats_get_async = 0,
	dpa_stats_get_sync,
	dpa_stats_reset
};

int ppam_init(void)
{
	int				err, i;
	char				object_name[100];
	struct dpa_cls_hm_update_params	update_params;
	struct dpa_cls_hm_update_resources update_hm_res;
	struct dpa_cls_hm_fwd_params	fwd_params;
	struct dpa_cls_hm_fwd_resources fwd_hm_res;
	const char			*pcd_path;
	const char			*cfg_path;
	const char			*pdl_path;
	t_Handle			hm_fwd;
	t_Handle			hm_update_ipsa;

	pcd_path = getenv("DEF_PCD_PATH");
	if (pcd_path == NULL) {
		error(0, EINVAL, "$DEF_PCD_PATH environment variable not"
			" defined");
		return EINVAL;
	}

	cfg_path = getenv("DEF_CFG_PATH");
	if (cfg_path == NULL) {
		error(0, EINVAL, "$DEF_CFG_PATH environment variable not"
			" defined");
		return EINVAL;
	}

	pdl_path = getenv("DEF_PDL_PATH");
	if (pdl_path == NULL) {
		error(0, EINVAL, "$DEF_PDL_PATH environment variable not"
			" defined");
		return EINVAL;
	}

	printf("dpa_classifier_demo: using the following config file: %s\n",
		cfg_path);
	printf("dpa_classifier_demo: using the following PCD file: %s\n",
		pcd_path);
	printf("dpa_classifier_demo: using the following PDL file: %s\n",
		pdl_path);
	/* Parse the input XML files and create the FMC Model */
	err = fmc_compile(&cmodel,
			cfg_path,
			pcd_path,
			pdl_path,
			NULL,
			0,
			0,
			NULL);
	if (err != 0) {
		error(0, EBUSY, "Failed to create the FMC Model");
		return err;
	}

	/* Execute the obtained FMC Model */
	err = fmc_execute(&cmodel);
	if (err != 0) {
		error(0, err, "Failed to execute the FMC Model");
		return err;
	}

	printf("dpa_classifier_demo is assuming FMan:%d and port:%d\n",
		ppam_args.fm, ppam_args.port);
	/* Get the PCD Handle and the CC Node Handle */
	sprintf(object_name, "fm%d/pcd", ppam_args.fm);
	pcds[0] = fmc_get_handle(&cmodel, object_name);
	if (!pcds[0]) {
		error(0, EINVAL, "Failed to acquire the PCD handle. Are you "
			"using the correct parameters for this test and "
			"platform?");
		return -EINVAL;
	}
	sprintf(object_name, "fm%d/port/1G/%d/ccnode/fman_3_tuple_classif",
		ppam_args.fm, ppam_args.port);
	ccnodes[0] = fmc_get_handle(&cmodel, object_name);
	if (!ccnodes[0]) {
		error(0, EINVAL, "Failed to acquire the CC node handle. Are "
			"you using the correct parameters for this test and "
			"platform?");
		return -EINVAL;
	}

	/* Attempt to initialize the DPA Classifier user space library */
	err = dpa_classif_lib_init();
	if (err < 0) {
		error(0, -err, "Failed to initialize the DPA Classifier user "
			"space library");
		return -err;
	}

	printf("Header manipulations:\n");

	memset(&update_params, 0, sizeof(update_params));
	update_params.op_flags = DPA_CLS_HM_UPDATE_IPv4_UPDATE;
	update_params.update.l3.field_flags = DPA_CLS_HM_IP_UPDATE_IPSA;
	update_params.update.l3.ipsa.version = 4;

	memset(&update_hm_res, 0, sizeof(update_hm_res));

	memset(&fwd_params, 0, sizeof(fwd_params));
	fwd_params.out_if_type = DPA_CLS_HM_IF_TYPE_ETHERNET;
	fwd_params.eth.macsa[0] = 0x00;
	fwd_params.eth.macsa[1] = 0x10;
	fwd_params.eth.macsa[2] = 0x63;
	fwd_params.eth.macsa[3] = 0x88;
	fwd_params.eth.macsa[4] = 0x88;
	fwd_params.eth.macsa[5] = 0x88;
	fwd_params.eth.macda[0] = 0x00;
	fwd_params.eth.macda[1] = 0x20;
	fwd_params.eth.macda[2] = 0x63;
	fwd_params.eth.macda[3] = 0xaa;
	fwd_params.eth.macda[4] = 0xaa;
	fwd_params.eth.macda[5] = 0xaa;

	memset(&fwd_hm_res, 0, sizeof(fwd_hm_res));

	for (i = 0; i < APP_NUM_OF_ENTRIES; i++) {
		sprintf(object_name, "fm%d/hdr/fwd%d", ppam_args.fm, i+1);
		hm_fwd = fmc_get_handle(&cmodel, object_name);
		sprintf(object_name, "fm%d/hdr/update_ipsa%d", ppam_args.fm,
			i+1);
		hm_update_ipsa = fmc_get_handle(&cmodel, object_name);
		printf("	%d) Forwarding 0x%p, IPSA update 0x%p\n", i+1,
			hm_fwd, hm_update_ipsa);

		update_params.update.l3.ipsa.addr.ipv4.word = 0x11223300 + i;

		update_hm_res.update_node = hm_update_ipsa;

		err = dpa_classif_set_update_hm(&update_params,
			DPA_OFFLD_DESC_NONE, &update_hmd[i], false,
			&update_hm_res);
		if (err < 0) {
			error(0, -err, "Failed to set up \"update\" header "
				"manipulation #%d.\n", i+1);
			goto main_error;
		}

		fwd_params.eth.macsa[5] = i;
		fwd_params.eth.macda[5] = i;

		fwd_hm_res.fwd_node = hm_fwd;

		err = dpa_classif_set_fwd_hm(&fwd_params, update_hmd[i],
			&fwd_hmd[i], true, &fwd_hm_res);
		if (err < 0) {
			error(0, -err, "Failed to set up forwarding header "
				"manipulation #%d.\n", i+1);
			goto main_error;
		}
	}

	/* Create the DPA Classifier table */
	err = create_exact_match_table();
	if (err < 0)
		goto main_error;

	printf("Stage #1 is ready - Created & populated table.\n");
	printf("When ready to go to the next test stage, type "
		"\"next_stage\"\n");

	return 0;

main_error:
	clean_up();

	return -err;
}

void ppam_finish(void)
{
	clean_up();
}

void clean_up(void)
{
	int err, i;

	if (td >= 0) {
		/* Flush DPA Classifier table */
		err = dpa_classif_table_flush(td);
		if (err < 0)
			error(0, -err, "DPA Classifier table flush failed");
		else
			printf("DPA Classifier table flushed.\n");

		/* Free DPA Classifier table */
		err = dpa_classif_table_free(td);
		if (err < 0) {
			error(0, -err, "Failed to free DPA Classifier table "
				"(td=%d)", td);
		} else
			printf("INFO: DPA Classifier table resources "
				"released.\n");
	}

	/* Free header manipulation operations */
	for (i = 0; i < APP_NUM_OF_ENTRIES; i++) {
		if (update_hmd[i] != DPA_OFFLD_DESC_NONE)
			dpa_classif_free_hm(update_hmd[i]);

		if (fwd_hmd[i] != DPA_OFFLD_DESC_NONE)
			dpa_classif_free_hm(fwd_hmd[i]);
	}

	/* Release DPA Classifier library */
	dpa_classif_lib_exit();

	/* Clean-up the FMC model */
	err = fmc_clean(&cmodel);
	if (err != 0)
		error(0, EBUSY, "Failed to clean-up PCD configuration");
	else
		printf("INFO: PCD configuration successfully restored.\n");

	/* Remove the DPA Stats counter */
	if (cnt_id != DPA_OFFLD_INVALID_OBJECT_ID)
		dpa_stats_remove_counter(cnt_id);

	err = dpa_stats_free(dpa_stats_id);
	if (err < 0)
		error(0, -err, "Failed to release DPA Stats instance\n");
	else
		printf("DPA Stats instance successfully released\n");

	/* Release DPA Stats instance */
	dpa_stats_lib_exit();

	printf("DPA Stats library successfully released\n");
}

static int ppac_cli_next_stage(int argc, char *argv[])
{
	struct dpa_cls_tbl_entry_mod_params mod_params;
	struct dpa_stats_cls_member_params mbr_prm;
	struct dpa_offload_lookup_key key, newKey;
	struct dpa_cls_hm_update_params update_hm_params;
	struct dpa_cls_hm_fwd_params fwd_hm_params;
	int err, i;

	uint8_t			key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t			mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t			new_key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t			new_mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];

	printf("\nNext test stage...\n");
	switch (++stage) {
	case 1: /* Remove first APP_NUM_ENTRIES_TO_REMOVE entries */

		/* Prepare lookup key */
		key.byte = key_data;
		key.mask = mask_data;
		key.size = APP_TABLE_KEY_SIZE;
		memset(key.mask, 0xff, APP_TABLE_KEY_SIZE);

		for (i = 0; i < APP_NUM_ENTRIES_TO_REMOVE; i++) {
			memcpy(key.byte, conn[i].key, APP_TABLE_KEY_SIZE);
			err = dpa_classif_table_delete_entry_by_key(td, &key);
			if (err < 0) {
				error(0, -err, "Failed to remove "
					"entry #%d from the table (td=%d)",
					i, td);
				clean_up();
				exit(-err);
			}

			mbr_prm.type = DPA_STATS_CLS_MEMBER_SINGLE_KEY;
			mbr_prm.key.byte = NULL;
			mbr_prm.key.mask = NULL;
			mbr_prm.key.size = 0;

			/* Modify DPA Stats class counter to invalidate the
			 * corresponding lookup key */
			err = dpa_stats_modify_class_counter(
					cnt_id,
					&mbr_prm,
					i);
			if (err < 0) {
				error(0, -err, "Failed to modify DPA Stats "
						"counter: %d\n", cnt_id);
				return -err;
			}
		}

		/* Remove static entries: */
		for (i = 0; i < APP_NUM_STATIC_ENTRIES_TO_REMOVE; i++) {
			memcpy(key.byte, static_entry_key[i],
							APP_TABLE_KEY_SIZE);
			err = dpa_classif_table_delete_entry_by_key(td, &key);
			if (err < 0) {
				error(0, -err, "Failed to remove static entry "
					"#%d from the table (td=%d)", i, td);
				clean_up();
				exit(-err);
			}
		}

		/*
		 * Modify IPSA update header manipulations for the remaining
		 * entries:
		 */
		memset(&update_hm_params, 0,
				sizeof(struct dpa_cls_hm_update_params));
		update_hm_params.update.l3.ipsa.version = 4;

		for (i = APP_NUM_ENTRIES_TO_REMOVE; i < APP_NUM_OF_ENTRIES;
									i++) {
			update_hm_params.update.l3.ipsa.addr.ipv4.word =
								0xac0a0a00 + i;
			err = dpa_classif_modify_update_hm(update_hmd[i],
				&update_hm_params, DPA_CLS_HM_UPDATE_MOD_SIP);
			if (err < 0) {
				error(0, -err, "Failed to modify IPSA update "
					"header manipulation #%d\n", i+1);
				clean_up();
				exit(-err);
			}
		}

		printf("Stage #2 is ready - "
			"Removed first %d table entries. Removed first %d "
			"static table entries.\n", APP_NUM_ENTRIES_TO_REMOVE,
			APP_NUM_STATIC_ENTRIES_TO_REMOVE);
		break;
	case 2:
		/* Update last APP_NUM_ENTRIES_TO_UPDATE entries */
		newKey.byte = new_key_data;
		newKey.mask = new_mask_data;
		newKey.size = APP_TABLE_KEY_SIZE;
		memset(newKey.mask, 0xff, APP_TABLE_KEY_SIZE);

		key.byte = key_data;
		key.mask = mask_data;
		key.size = APP_TABLE_KEY_SIZE;
		memset(key.mask, 0xff, APP_TABLE_KEY_SIZE);

		memset(&mod_params, 0, sizeof(mod_params));
		mod_params.type = DPA_CLS_TBL_MODIFY_KEY;
		mod_params.key = &newKey;

		for (i = 1; i <= APP_NUM_ENTRIES_TO_UPDATE; i++) {
			memcpy(mod_params.key->byte,
				new_key[i-1],
				APP_TABLE_KEY_SIZE);
			memcpy(key.byte,
				conn[APP_NUM_OF_ENTRIES-i].key,
				APP_TABLE_KEY_SIZE);

			err = dpa_classif_table_modify_entry_by_key(
					td, &key, &mod_params);
			if (err < 0) {
				error(0, -err, "Failed to modify entry "
					"#%d from the table (td=%d)",
					(APP_NUM_OF_ENTRIES-i), td);
				clean_up();
				exit(-err);
			}

			mbr_prm.type = DPA_STATS_CLS_MEMBER_SINGLE_KEY;
			mbr_prm.key.byte = key_data;
			mbr_prm.key.mask = mask_data;
			mbr_prm.key.size = APP_TABLE_KEY_SIZE;

			memcpy(mbr_prm.key.byte,
					new_key[i-1], APP_TABLE_KEY_SIZE);
			memset(mbr_prm.key.mask, 0xff, APP_TABLE_KEY_SIZE);

			/* Modify DPA Stats class counter */
			err = dpa_stats_modify_class_counter(cnt_id,
					&mbr_prm, (APP_NUM_OF_ENTRIES-i));
			if (err < 0) {
				error(0, -err, "Failed to modify DPA Stats "
						"counter: %d\n", cnt_id);
				return -err;
			}
		}

		/* Modify the last static keys */
		for (i = 0; i < APP_NUM_STATIC_ENTRIES_TO_UPDATE; i++) {
			memcpy(mod_params.key->byte, new_static_entry_key[i],
				APP_TABLE_KEY_SIZE);
			memcpy(key.byte,
				static_entry_key[APP_NUM_STATIC_ENTRIES_TO_UPDATE + i],
				APP_TABLE_KEY_SIZE);
			err = dpa_classif_table_modify_entry_by_key(
				td, &key, &mod_params);
			if (err < 0) {
				error(0, -err, "Failed to modify static entry "
					"#%d from the table (td=%d)",
					(APP_NUM_STATIC_ENTRIES_TO_UPDATE + i),
					td);
				clean_up();
				exit(-err);
			}
		}

		/*
		 * Modify forwarding header manipulations for the remaining
		 * entries:
		 */
		memset(&fwd_hm_params, 0,
				sizeof(struct dpa_cls_hm_fwd_params));
		fwd_hm_params.eth.macsa[0] = 0x00;
		fwd_hm_params.eth.macsa[2] = 0x12;
		fwd_hm_params.eth.macsa[3] = 0x13;
		fwd_hm_params.eth.macsa[4] = 0x14;
		fwd_hm_params.eth.macsa[5] = 0x15;

		for (i = APP_NUM_ENTRIES_TO_REMOVE; i < APP_NUM_OF_ENTRIES;
									i++) {
			fwd_hm_params.eth.macsa[1] = i;
			err = dpa_classif_modify_fwd_hm(fwd_hmd[i],
				&fwd_hm_params, DPA_CLS_HM_FWD_MOD_ETH_MACSA);
			if (err < 0) {
				error(0, -err, "Failed to modify FORWARDING "
					"header manipulation #%d\n", i+1);
				clean_up();
				exit(-err);
			}
		}

		printf("Stage #3 is ready - "
			"Updated key for last %d table entries. Updated key for"
			" last %d static table entries.\n",
			APP_NUM_ENTRIES_TO_UPDATE,
			APP_NUM_STATIC_ENTRIES_TO_UPDATE);
		break;
	default: /* Last stage was reached. */
		printf("Last stage reached.\n");
		printf("Please type \"quit\" to end the test.\n");
		return 0;
	}
	printf("When ready to go to the next test stage, type "
		"\"next_stage\"\n");

	return 0;
}

static int ppam_interface_init(struct ppam_interface	*p,
			const struct fm_eth_port_cfg	*cfg,
			unsigned int			num_tx_fqs,
			uint32_t			*flags __maybe_unused)
{
	p->num_tx_fqids = num_tx_fqs;
	p->tx_fqids = malloc(p->num_tx_fqids * sizeof(*p->tx_fqids));
	if (!p->tx_fqids)
		return -ENOMEM;

#ifdef ENABLE_PROMISC
	/* Enable promiscuous mode for testing purposes */
	fman_if_promiscuous_enable(cfg->fman_if);
#endif /* ENABLE_PROMISC */

	return 0;
}

static void ppam_interface_finish(struct ppam_interface *p)
{
	free(p->tx_fqids);
}

static void ppam_interface_tx_fqid(struct ppam_interface	*p,
				unsigned			idx,
				uint32_t			fqid)
{
	p->tx_fqids[idx] = fqid;
}

static int ppam_rx_error_init(struct ppam_rx_error	*p,
			struct ppam_interface		*_if,
			struct qm_fqd_stashing		*stash_opts)
{
	return 0;
}

static void ppam_rx_error_finish(struct ppam_rx_error	*p,
				struct ppam_interface	*_if)
{
}

static inline void ppam_rx_error_cb(struct ppam_rx_error	*p,
				struct ppam_interface		*_if,
				const struct qm_dqrr_entry	*dqrr)
{
	const struct qm_fd	*fd = &dqrr->fd;
	char			*buf;
	uint16_t		*etype;

	buf = (char *)__dma_mem_ptov(qm_fd_addr(&dqrr->fd));
	etype = (uint16_t *) &buf[ETYPE_OFFSET];

	printf("RX ERROR: FQID=%d, frame EType=0x%04x, size=%d bytes\n",
		dqrr->fqid, *etype, fd->length20);

	ppac_drop_frame(fd);
}

static int ppam_rx_default_init(struct ppam_rx_default	*p,
				struct ppam_interface	*_if,
				unsigned int idx,
				struct qm_fqd_stashing	*stash_opts)
{
	return 0;
}

static void ppam_rx_default_finish(struct ppam_rx_default	*p,
				struct ppam_interface		*_if)
{
}

static inline void ppam_rx_default_cb(struct ppam_rx_default	*p,
				struct ppam_interface		*_if,
				const struct qm_dqrr_entry	*dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	char			*p_Buf;
	uint16_t		*etype;

	p_Buf = (char *)__dma_mem_ptov(qm_fd_addr(&dqrr->fd)) + fd->offset;
	etype = (uint16_t *) &p_Buf[ETYPE_OFFSET];

	printf("RX DEFAULT: FQID=%d, frame EType=0x%04x, size=%d bytes\n",
		dqrr->fqid, *etype, fd->length20);

	ppac_drop_frame(fd);
}

static int ppam_tx_error_init(struct ppam_tx_error	*p,
			struct ppam_interface		*_if,
			struct qm_fqd_stashing		*stash_opts)
{
	return 0;
}

static void ppam_tx_error_finish(struct ppam_tx_error	*p,
				struct ppam_interface	*_if)
{
}

static inline void ppam_tx_error_cb(struct ppam_tx_error	*p,
				struct ppam_interface		*_if,
				const struct qm_dqrr_entry	*dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	char			*p_Buf;
	uint16_t		*etype;

	p_Buf = (char *)__dma_mem_ptov(qm_fd_addr(&dqrr->fd));
	etype = (uint16_t *) &p_Buf[ETYPE_OFFSET];

	printf("TX ERROR: FQID=%d, frame EType=0x%04x, size=%d bytes\n",
		dqrr->fqid, *etype, fd->length20);

	ppac_drop_frame(fd);
}

static int ppam_tx_confirm_init(struct ppam_tx_confirm	*p,
				struct ppam_interface	*_if,
				struct qm_fqd_stashing	*stash_opts)
{
	return 0;
}

static void ppam_tx_confirm_finish(struct ppam_tx_confirm	*p,
				struct ppam_interface		*_if)
{
}

static inline void ppam_tx_confirm_cb(struct ppam_tx_confirm	*p,
				struct ppam_interface		*_if,
				const struct qm_dqrr_entry	*dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_rx_hash_init(struct ppam_rx_hash	*p,
			struct ppam_interface		*_if,
			unsigned			idx,
			struct qm_fqd_stashing		*stash_opts)
{
	p->tx_fqid = _if->tx_fqids[idx % _if->num_tx_fqids];
	TRACE("Mapping Rx FQ %p:%d --> Tx FQID %d\n", p, idx, p->tx_fqid);
	return 0;
}

static void ppam_rx_hash_finish(struct ppam_rx_hash	*p,
				struct ppam_interface	*_if,
				unsigned		idx)
{
}

static inline void ppam_rx_hash_cb(struct ppam_rx_hash		*p,
				   const struct qm_dqrr_entry	*dqrr)
{
	char			*p_Buf;
	const struct qm_fd	*fd = &dqrr->fd;
	struct qm_fd		local_fd;

	printf("RX | IPv4 frame | FQID=%d | size=%d bytes\n",
		dqrr->fqid, fd->length20);

	p_Buf = (char *)__dma_mem_ptov(qm_fd_addr(fd)) + fd->offset;

	printf("  MACDA: %02x-%02x-%02x-%02x-%02x-%02x "
		"MACSA: %02x-%02x-%02x-%02x-%02x-%02x\n", p_Buf[0], p_Buf[1],
		p_Buf[2], p_Buf[3], p_Buf[4], p_Buf[5], p_Buf[6], p_Buf[7],
		p_Buf[8], p_Buf[9], p_Buf[10], p_Buf[11]);
	printf("  IPSA: %d.%d.%d.%d (hex %02x.%02x.%02x.%02x) IPDA: "
		"%d.%d.%d.%d (hex %02x.%02x.%02x.%02x)\n",
		p_Buf[IPv4_SA_OFFSET], p_Buf[IPv4_SA_OFFSET + 1],
		p_Buf[IPv4_SA_OFFSET + 2], p_Buf[IPv4_SA_OFFSET + 3],
		p_Buf[IPv4_SA_OFFSET], p_Buf[IPv4_SA_OFFSET + 1],
		p_Buf[IPv4_SA_OFFSET + 2], p_Buf[IPv4_SA_OFFSET + 3],
		p_Buf[IPv4_SA_OFFSET + 4], p_Buf[IPv4_SA_OFFSET + 5],
		p_Buf[IPv4_SA_OFFSET + 6], p_Buf[IPv4_SA_OFFSET + 7],
		p_Buf[IPv4_SA_OFFSET + 4], p_Buf[IPv4_SA_OFFSET + 5],
		p_Buf[IPv4_SA_OFFSET + 6], p_Buf[IPv4_SA_OFFSET + 7]);

	/* Send frame to tx */
	if (p->tx_fqid) {
		u16 *fqid = (u16*)&p_Buf[IPv4_DA_OFFSET + 2];
		u16 *cksum = (u16*)&p_Buf[IPv4_CKSUM_OFFSET];

		local_fd = *fd;

		/*
		 * Update the IPDA by encoding the frame queue id in the last 2
		 * bytes.
		 */
		p_Buf[IPv4_DA_OFFSET + 1] = 0x78;
		*fqid = (u16)dqrr->fqid;

		/* Recompute header checksum: */
		*cksum = 0;
		*cksum = ipv4_cksum((struct iphdr*) &p_Buf[IPv4_OFFSET]);

#ifdef ENABLE_PROMISC
		/* Remove Ethernet CRC */
		local_fd.length20 -= 4;
#endif /* ENABLE_PROMISC */

		ppac_send_frame(p->tx_fqid, &local_fd);
		return;
	}

	/* Drop the frame */
	ppac_drop_frame(fd);
}

static int ppam_cli_parse(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'f':
		ppam_args.fm = atoi(arg);
		if ((ppam_args.fm < 0) || (ppam_args.fm > 1)) {
			error(0, EINVAL, "FMan Id must be zero or 1");
			return -EINVAL;
		}
		break;
	case 't':
		ppam_args.port = atoi(arg);
		if ((ppam_args.port < 0) || (ppam_args.port > 5)) {
			error(0, EINVAL,
				"FMan port Id must be in the range 0-5");
			return -EINVAL;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int create_exact_match_table(void)
{
	struct dpa_cls_tbl_params	table_params;
	int				err = 0;

	/* Create an Exact Match table */
	memset(&table_params, 0, sizeof(table_params));
	table_params.type	= DPA_CLS_TBL_EXACT_MATCH;
	table_params.cc_node	= ccnodes[0];
	table_params.entry_mgmt	= DPA_CLS_TBL_MANAGE_BY_KEY;
	table_params.prefilled_entries = APP_NUM_OF_STATIC_ENTRIES;

	table_params.exact_match_params.key_size = 9;
	table_params.exact_match_params.entries_cnt = 24;

	err = dpa_classif_table_create(&table_params, &td);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Classifier table");
		return err;
	}
	printf("\nSuccessfully CREATED DPA Classifier "
			"Exact Match table (td=%d).\n", td);

	err = create_dpa_stats_counters();
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counters");
		return err;
	}

	err = populate_table(td);

	return err;
}

int populate_table(int tbl_desc)
{
	int				i, err;
	struct dpa_offload_lookup_key	key;
	struct dpa_cls_tbl_action	action;
	struct dpa_stats_cls_member_params params;

	uint8_t			key_data[DPA_OFFLD_MAXENTRYKEYSIZE];
	uint8_t			mask_data[DPA_OFFLD_MAXENTRYKEYSIZE];

	/* Prepare action */
	memset(&action, 0, sizeof(action));
	action.type = DPA_CLS_TBL_ACTION_ENQ;
	action.enable_statistics = true;

	/* Prepare lookup key */
	key.byte = key_data;
	key.mask = mask_data;
	key.size = APP_TABLE_KEY_SIZE;
	memset(key.mask, 0xff, APP_TABLE_KEY_SIZE);

	for (i = 0; i < APP_NUM_OF_ENTRIES; i++) {

		/* Update lookup key */
		memcpy(key.byte, conn[i].key, APP_TABLE_KEY_SIZE);

		/* Update action */
		action.enq_params.new_fqid = conn[i].fqid;
		action.enq_params.override_fqid = TRUE;
		action.enq_params.hmd = fwd_hmd[i];

		err = dpa_classif_table_insert_entry(tbl_desc,
				&key, &action, 0, NULL);
		if (err < 0) {
			error(0, -err, "Failed to insert entry #%d in "
				"the DPA Classifier table (td=%d)",
				i, tbl_desc);
			return err;
		}

		params.type = DPA_STATS_CLS_MEMBER_SINGLE_KEY;
		params.key.byte = key_data;
		params.key.mask = mask_data;
		params.key.size = APP_TABLE_KEY_SIZE;

		/* Update lookup key */
		memcpy(key.byte, conn[i].key, APP_TABLE_KEY_SIZE);
		memset(key.mask, 0xff, APP_TABLE_KEY_SIZE);

		/* Modify DPA Stats class counter */
		err = dpa_stats_modify_class_counter(cnt_id,
				&params, i);
		if (err < 0) {
			error(0, -err, "Failed to remove DPA Stats counter\n");
			return -err;
		}
	}
	printf("Successfully populated "
			"DPA Classifier table (%d entries)\n", i);

	return 0;
}

static int create_dpa_stats_counters(void)
{
	struct dpa_stats_params stats_params;
	struct dpa_stats_cls_cnt_params cls_params;
	int err = 0;
	uint32_t i = 0;

	/* Attempt to initialize the DPA Stats user space library */
	err = dpa_stats_lib_init();
	if (err < 0) {
		error(0, -err, "Failed to initialize the"
				" DPA Stats user space library");
		return -err;
	}

	printf("DPA Stats library successfully initialized\n");

	stats_params.max_counters = 1;
	stats_params.storage_area_len = 1000;

	stats_params.storage_area = malloc(stats_params.storage_area_len);
	if (!stats_params.storage_area) {
		printf("cannot allocate storage area\n");
		return -1;
	}

	/* Save storage area pointer */
	storage = stats_params.storage_area;

	err = dpa_stats_init(&stats_params, &dpa_stats_id);
	if (err < 0) {
		error(0, -err, "Failed to initialize DPA Stats instance\n");
		return err;
	}
	printf("\nSuccessfully Initialized DPA Stats "
			"instance: %d\n", dpa_stats_id);

	/* Create Classifier Table class counter */
	cls_params.type = DPA_STATS_CNT_CLASSIF_TBL;
	cls_params.class_members = APP_NUM_OF_ENTRIES;
	cls_params.classif_tbl_params.td = td;
	cls_params.classif_tbl_params.cnt_sel = DPA_STATS_CNT_CLASSIF_BYTES |
						DPA_STATS_CNT_CLASSIF_PACKETS;
	cls_params.classif_tbl_params.key_type = DPA_STATS_CLASSIF_SINGLE_KEY;

	/* Allocate memory for keys array */
	cls_params.classif_tbl_params.keys = malloc(
			cls_params.class_members *
			sizeof(struct dpa_offload_lookup_key));
	if (!cls_params.classif_tbl_params.keys) {
		error(0, -err, "Failed to allocate memory for keys\n");
		return -1;
	}

	/* No lookup key is configured in the class */
	for (i = 0; i < cls_params.class_members; i++) {
		memset(&cls_params.classif_tbl_params.keys[i],
				0, sizeof(struct dpa_offload_lookup_key));
	}

	err = dpa_stats_create_class_counter(dpa_stats_id,
			&cls_params, &cnt_id);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counter\n");
		return err;
	}
	printf("Successfully created DPA Stats counter: %d\n", cnt_id);

	return 0;
}

static void print_dpa_stats_cnts(void)
{
	uint32_t *stg = (uint32_t *)storage;
	uint32_t i = 0;

	printf("\nKEY:: BYTES FRAMES\n");
	for (i = 0; i < 10; i++)
		printf("%d %7d %5d\n",
			i, *(stg + i*CLS_MBR_SIZE), *(stg + i*CLS_MBR_SIZE+1));

	for (i = 10; i < APP_NUM_OF_ENTRIES; i++)
		printf("%d, %5d %5d\n",
			i, *(stg + i*CLS_MBR_SIZE), *(stg + i*CLS_MBR_SIZE+1));
}

void request_done_cb(int dpa_id,
		unsigned int storage_area_offset, unsigned int cnts_written,
		int bytes_written)
{
	printf("storage_area_offset = %d\n", storage_area_offset);
	printf("cnts_written = %d\n", cnts_written);
	printf("bytes_written = %d\n", bytes_written);
	print_dpa_stats_cnts();
}

static int get_cnts_statistics(enum dpa_stats_op op)
{
	struct dpa_stats_cnt_request_params req_params;
	int cnts_len = 0, err = 0;

	req_params.cnts_ids = &cnt_id;
	req_params.cnts_ids_len = 1;
	req_params.reset_cnts = FALSE;
	req_params.storage_area_offset = 0;

	cnts_len = 0;

	switch (op) {
	case dpa_stats_get_sync:
		err = dpa_stats_get_counters(req_params, &cnts_len, NULL);
		if (err < 0) {
			error(0, -err, "Failed to create DPA Stats request\n");
			return err;
		}
		printf("\nSuccessfully created DPA Stats request\n");
		print_dpa_stats_cnts();
		break;
	case dpa_stats_reset:
		err = dpa_stats_reset_counters(&cnt_id, 1);
		if (err < 0) {
			error(0, -err, "Failed to reset DPA Stats counters\n");
			return err;
		}
		printf("\nSuccessfully reset DPA Stats counters\n");
		break;
	case dpa_stats_get_async:
		err = dpa_stats_get_counters(req_params,
				&cnts_len, &request_done_cb);
		if (err < 0) {
			error(0, -err, "Failed to create DPA Stats request\n");
			return err;
		}
		printf("\nSuccessfully created DPA Stats request\n");
		break;
	default:
		printf("Invalid operation\n");
		break;
	}

	return 0;
}

static u16 ipv4_cksum(const struct iphdr *iphdr)
{
	int cksum = 0;
	int i;
	u16 *w = (u16*) iphdr;

	for (i = 0; i < (iphdr->ihl * 2); i++) {
		cksum += w[i];
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (u16) ((~cksum) & 0xffff);
}

static int ppac_cli_dpa_stats_cmd(int argc, char *argv[])
{
	if (!strcmp(argv[0], "get_stats"))
		get_cnts_statistics(dpa_stats_get_async);
	else if (!strcmp(argv[0], "get_stats_sync"))
		get_cnts_statistics(dpa_stats_get_sync);
	else if (!strcmp(argv[0], "reset_stats"))
		get_cnts_statistics(dpa_stats_reset);

	return 0;
}

cli_cmd(get_stats, ppac_cli_dpa_stats_cmd);
cli_cmd(get_stats_sync, ppac_cli_dpa_stats_cmd);
cli_cmd(reset_stats, ppac_cli_dpa_stats_cmd);

/* Inline the PPAC machinery */
#include <ppac.c>
