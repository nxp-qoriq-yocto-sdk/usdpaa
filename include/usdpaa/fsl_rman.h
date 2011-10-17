/* Copyright (c) 2011 Freescale Semiconductor, Inc.
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

#ifndef _FSL_RMAN_H
#define _FSL_RMAN_H

#include <limits.h>

#define RMAN_MAX_NUM_OF_CHANNELS 2

enum RIO_TYPE {
	RIO_TYPE0 = 0,
	RIO_TYPE1,
	RIO_TYPE2,
	RIO_TYPE3,
	RIO_TYPE4,
	RIO_TYPE5,
	RIO_TYPE6,
	RIO_TYPE7,
	RIO_TYPE8,
	RIO_TYPE9,
	RIO_TYPE10,
	RIO_TYPE11,
	RIO_TYPE_NUM,
	RIO_TYPE_DSTR = RIO_TYPE9,
	RIO_TYPE_DBELL = RIO_TYPE10,
	RIO_TYPE_MBOX = RIO_TYPE11
};

enum RIO_MBOX_NUM {
	RIO_MBOX_A,
	RIO_MBOX_B,
	RIO_MBOX_C,
	RIO_MBOX_D
};

enum RMAN_FQ_MODE {
	DIRECT,
	ALGORITHMIC
};

struct rio_tran {
	struct list_head node;
	char name[PATH_MAX];
	uint8_t type;
	uint8_t flowlvl;
	uint8_t flowlvl_mask;
	union {
		struct mbox_attr {
			uint8_t mbox;
			uint8_t mbox_mask;
			uint8_t ltr;
			uint8_t ltr_mask;
			uint8_t msglen;
			uint8_t msglen_mask;
		} mbox;

		struct dstr_attr {
			uint16_t streamid;
			uint16_t streamid_mask;
			uint8_t cos;
			uint8_t cos_mask;
		} dstr;
	};
};

struct ibcu_cfg {
	uint8_t		ibcu;
	uint8_t		port;
	uint8_t		port_mask;
	uint16_t	sid;
	uint16_t	sid_mask;
	uint16_t	did;
	uint16_t	did_mask;
	int		fqid;
	uint8_t		bpid;
	uint8_t		sgbpid;
	uint32_t	msgsize;
	uint32_t	sgsize;
	uint32_t	data_offset;
	enum RMAN_FQ_MODE	fq_mode;
	struct rio_tran	*tran;
};

struct rman_cfg {
	uint8_t fq_bits[RIO_TYPE_NUM];
	uint8_t bpid[RIO_TYPE_NUM];
	uint8_t rx_channel_id;
	uint8_t md_create;
	uint8_t sgbpid;
};

struct rman_dev;

/**
 * rman_get_channel_id - get the default transmission channel id
 * @rmdev: RMan device info
 * @index: RMan channel index
 *
 * RMan device has two channels, each channel is assigned to QMan channel.
 * This function returns the corresponding QMan channel id.
 */
int rman_get_channel_id(const struct rman_dev *rmdev, int index);
/************************* ibcu handler ***************************/
/**
 * rman_release_ibcu - release the ibcu resource
 * @rmdev: RMan device info
 * @fqid: Frame queue id
 *
 * Each running IBCU has been specified an unique fqid, This function will
 * disable the corresponding ibcu resource
 */
void rman_release_ibcu(struct rman_dev *rmdev, int fqid);
/**
 * rman_request_ibcu - request the ibcu resource
 * @rmdev: RMan device info
 * @fqid: Frame queue id
 *
 * If the fqid has been binded to a ibcu resource, just returns the
 * corresponding ibcu index, if not returns the first idle ibcu index.
 * If no idle ibcu it returns -EINVAL
 */
int rman_request_ibcu(struct rman_dev *rmdev, int fqid);
/**
 * rman_get_ibcu - get the ibcu index
 * @rmdev: RMan device info
 * @fqid: Frame queue id
 *
 * If the fqid has been binded to a ibcu resource, just returns the
 * corresponding ibcu index, otherwise returns -EINVAL.
 */
int rman_get_ibcu(const struct rman_dev *rmdev, int fqid);
/**
 * rman_enable_ibcu - enable the ibcu
 * @rmdev: RMan device info
 * @cfg: ibcu configuration
 *
 * This function enable the ibcu according ibcu configuration.
 * Returns %0 on success or %-EINVAL on failure.
 */
int rman_enable_ibcu(struct rman_dev *rmdev, const struct ibcu_cfg *cfg);

/************************* init function ***************************/
/**
 * rman_dev_init - initialize the RMan device
 * @cfg: RMan device configuration
 *
 * This function firstly opens RMan uio file, then maps the RMan register space,
 * finally configures RMan according to rman configuration
 * Returns the pointer of rman_dev on success or %NULL on failure.
 */
struct rman_dev *rman_dev_init(const struct rman_cfg *cfg);
/**
 * rman_dev_finish - release the RMan resource
 * @rmdev: RMan device info
 *
 * Releases All the RMan resource.
 */
void rman_dev_finish(struct rman_dev *rmdev);

#endif /*_ FSL_RMAN_H */
