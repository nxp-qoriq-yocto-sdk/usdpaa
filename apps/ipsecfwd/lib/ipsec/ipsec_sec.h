/*
 * Copyright (C) 2011 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LIB_IPSEC_SEC_H
#define LIB_IPSEC_SEC_H

#include <stdint.h>
#include <rcu_lock.h>
#include <compiler.h>
#include "ip/ip.h"
#include "ipsec/ipsec.h"
#include "ip/ip_common.h"
#include "net/annotations.h"
#include <fsl_sec/pdb.h>
#include "ip/ip_appconf.h"


/* BPID for use by SEC in case simple FD mode is used */
extern u32 sec_bpid;
extern bool simple_fd_mode;

struct preheader_t {
	union {
		uint32_t word;
		struct {
			unsigned int rsls:1;
			unsigned int rsvd1_15:15;
			unsigned int rsvd16_24:9;
			unsigned int idlen:7;
		} field;
	} __PACKED hi;

	union {
		uint32_t word;
		struct {
			unsigned int rsvd32_33:2;
			unsigned int fsgt:1;
			unsigned int lng:1;
			unsigned int offset:2;
			unsigned int abs:1;
			unsigned int add_buf:1;
			uint8_t pool_id;
			uint16_t pool_buffer_size;
		} field;
	} __PACKED lo;
} __PACKED;

struct init_descriptor_header_t {
	union {
		uint32_t word;
		struct {
			unsigned int ctype:5;
			unsigned int rsvd5_6:2;
			unsigned int dnr:1;
			unsigned int one:1;
			unsigned int rsvd9:1;
			unsigned int start_idx:6;
			unsigned int zro:1;
			unsigned int rsvd17_18:2;
			unsigned int sc:1;
			unsigned int propogate_dnr:1;
			unsigned int rsvd21:1;
			unsigned int share:2;
			unsigned int rsvd24_25:2;
			unsigned int desc_len:6;
		} field;
	} __PACKED command;
} __PACKED;


struct ipsec_encap_descriptor_t {
	struct preheader_t prehdr;
	struct init_descriptor_header_t deschdr;
	struct ipsec_encap_pdb pdb;
	struct iphdr iphdr;
	/* DCL library will fill following info */
	uint32_t reserved1; /**< For Storing Jump Command */
	uint32_t reserved2[12]; /**<Max Space for storing auth Key */
	uint32_t reserved3[7]; /**<Max Space for storing enc Key */
	uint32_t reserved4; /**< For operation Command */
} __PACKED;

struct ipsec_decap_descriptor_t {
	struct preheader_t prehdr;
	struct init_descriptor_header_t deschdr;
	struct ipsec_decap_pdb pdb;
	/* DCL library will fill following info */
	uint32_t reserved1; /**< For Storing Jump Command */
	uint32_t reserved2[12]; /**<Max Space for storing auth Key */
	uint32_t reserved3[7]; /**<Max Space for storing dec Key */
	uint32_t reserved4; /**< For operation Command */
} __PACKED;

void
*create_encapsulation_sec_descriptor(struct ipsec_tunnel_t *sa, struct iphdr
				     *outer_ip_header, uint8_t next_header,
				     struct app_ctrl_sa_algo *ealg,
				     struct app_ctrl_sa_algo *aalg);

void
*create_decapsulation_sec_descriptor(struct ipsec_tunnel_t *sa,
				     struct app_ctrl_sa_algo *ealg,
				     struct app_ctrl_sa_algo *aalg);

extern int32_t init_sec_fqs(struct ipsec_tunnel_t *entry,
			       bool mode, void *ctxtA,
			       uint32_t tunnel_id);

#endif /* ifndef LIB_IPSEC_SEC_H */
