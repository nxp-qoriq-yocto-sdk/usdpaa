/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
met:
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
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _FRA_CFG_PARSER_H
#define _FRA_CFG_PARSER_H

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_rman.h>
#include <internal/compat.h>

extern const char default_fra_cfg_path[];

#define MAX_NUM_OF_RX_CHAN 4

enum dist_type {
	DIST_TYPE_RX,
	DIST_TYPE_TX,
	DIST_TYPE_FWD
};

struct dist_rx_cfg {
	uint8_t port;
	uint8_t port_mask;
	uint16_t sid;
	uint16_t sid_mask;
	int fqid;
	enum RMAN_FQ_MODE fq_mode;
	int fq_count;
	uint8_t wq;
	uint8_t chan_count;
	enum qm_channel channel[MAX_NUM_OF_RX_CHAN];
	struct rio_tran	*tran;
};

struct dist_tx_cfg {
	uint8_t port;
	uint8_t fq_count;
	uint8_t wq;
	uint16_t did;
	int fqid;
	struct rio_tran	*tran;
};

struct dist_fwd_cfg {
	uint8_t	fman_num;	/* 0 => FMAN0, 1 => FMAN1 and so on */
	uint8_t	port_type;	/* 1 => "1G" or 10 => "10G" ,so on*/
	uint8_t port_num;	/* 0 onwards */
};

struct dist_cfg {
	struct dist_cfg *next;
	char name[32];
	uint8_t type;
	uint8_t number;
	union {
		struct dist_rx_cfg dist_rx_cfg;
		struct dist_tx_cfg dist_tx_cfg;
		struct dist_fwd_cfg dist_fwd_cfg;
	};
};

struct dist_order_cfg {
	struct list_head node;
	struct dist_cfg *dist_cfg;
};

struct fra_policy_cfg {
	struct list_head dist_order_cfg_list;
	struct rman_cfg rman_cfg;
};

extern const char *DIST_TYPE_STR[];
extern const char *FQ_MODE_STR[];
extern const char *MD_CREATE_MODE_STR[];
extern const char *RIO_TYPE_TO_STR[];

extern struct fra_policy_cfg *fra_policy_cfg;

int fra_parse_cfgfile(const char *cfg_file);
void fra_cfg_parser_exit(void);

#endif /*_FRA_CFG_PARSER_H*/
