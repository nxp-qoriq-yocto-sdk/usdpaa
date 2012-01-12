/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions aremet:
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

#ifndef _RMAN_IF_H
#define _RMAN_IF_H

#include <usdpaa/fsl_bman.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_rman.h>
#include "fra_bpool.h"

struct tx_opt;

#define SUPPORT_MULTIE_SESSION

#define RM_FD_SIZE		0x20
#define RM_DATA_OFFSET		0x40
#define FD_TYPE_OFFSET		28
#define FD_SET_TYPE(fd, type)	(((fd)->cmd) = (type) << FD_TYPE_OFFSET)
#define FD_GET_FTYPE(fd)	((((fd)->status) >> FD_TYPE_OFFSET) & 0xf)
#define FD_GET_STATUS(fd)	(((fd)->status) & 0x07ffffff)

struct rman_inb_md {
	/* word0 */
	uint8_t ftype:4; /* rio type */
	uint8_t __reserved0:4;
	uint8_t __reserved1[3];
	/* word1 */
	uint32_t __reserved2;
	/* word2 */
	uint32_t __reserved3;
	/* word3 */
	uint16_t sid;
	uint16_t src;
	/* word4 */
	uint8_t __reserved4:3;
	uint8_t flowlvl:3;
	uint8_t __reserved5:2;
	uint8_t sint:4;
	uint8_t __reserved6:4;
	uint16_t other_attr;
	/* word5 */
	uint16_t did;
	uint16_t dest;
	/* word6 */
	uint32_t __reserved7;
	/* word7 */
	uint32_t count;
};

struct rman_outb_md {
	/* word0 */
	uint8_t ftype:4; /* Descriptor type select */
	uint8_t br:1; /* Buffer release enable */
	uint8_t so:1; /* Strict ordering */
	uint8_t cs:1; /* Completion status */
	uint8_t es:1; /* Error status */
	uint8_t __reserved0[2];
	union {
		uint8_t retry; /* Retry error threshold */
		uint8_t hop_count; /* Hop count in RapidIO port-write packet*/
	} __packed;
	/* word1 */
	uint32_t address;
	/* word2 */
	uint32_t __reserved1:8;
	uint32_t status_fqid:24;
	/* word3 */
	uint16_t did;
	uint16_t dest;
	/* word4 */
	uint8_t __reserved2:3;
	uint8_t flowlvl:3;
	uint8_t __reserved3:2;
	uint8_t tint:4;
	uint8_t __reserved4:4;
	uint16_t other_attr;
	/* word5 */
	uint32_t message_group;
	/* word6 */
	uint32_t message_list;
	/* word7 */
	uint32_t count;
};

enum msg_flag {
	USING_BMB,
	USING_FD
};

struct msg_buf {
	union {
		struct rman_outb_md omd;
		struct rman_inb_md imd;
	};
	enum msg_flag flag;
	union {
		struct qm_fd *fd;
		struct bm_buffer bmb;
	};
	uint32_t len;
	void *data;
};

uint32_t msg_max_size(enum RIO_TYPE type);
struct msg_buf *msg_alloc(enum RIO_TYPE type);
struct msg_buf *fd_to_msg(struct qm_fd *fd);

static inline void  msg_free(struct msg_buf *msg)
{
	if (msg->flag == USING_FD)
		bpool_fd_free(msg->fd);
	else
		bpool_buffer_free(&msg->bmb);
}

static inline uint8_t msg_get_type(const struct msg_buf *msg)
{
	return msg->imd.ftype;
}

static inline int msg_get_len(const struct msg_buf *msg)
{
	return msg->len;
}

static inline uint16_t msg_get_sid(const struct msg_buf *msg)
{
	return msg->imd.sid;
}

static inline uint16_t msg_get_did(const struct msg_buf *msg)
{
	return msg->imd.did;
}

static inline void dbell_set_data(struct msg_buf *msg, uint16_t data)
{
	*(uint16_t *)msg->data = data;
	msg->len = 2;
}

static inline uint16_t dbell_get_data(const struct msg_buf *msg)
{
	return *(uint16_t *)msg->data;
}

static inline uint8_t mbox_get_mbox(const struct msg_buf *msg)
{
	return msg->imd.src & 3;
}

static inline uint8_t mbox_get_ltr(const struct msg_buf *msg)
{
	return (msg->imd.src >> 6) & 3;
}

static inline int mbox_get_size(const struct msg_buf *msg)
{
	return msg->imd.count & 0xffff;
}

static inline uint16_t dstr_get_streamid(const struct msg_buf *msg)
{
	return msg->imd.src;
}

static inline uint16_t dstr_get_cos(const struct msg_buf *msg)
{
	return msg->imd.other_attr & 0xff;
}

static inline int dstr_get_size(const struct msg_buf *msg)
{
	return msg->imd.count & 0xffffff;
}

/**
 * This function returns the status of SRIO port.
 * If the port has been connected returns 1,
 * otherwise returns 0.
 */
int rman_get_port_status(int port_number);

/* If create frame queue directly this function returns 1,
 * Otherwise, this function  returns the number of receive frame queue
 * calculated according to transaction configuration
 */
int rman_get_rxfq_count(enum RMAN_FQ_MODE fq_mode, const struct rio_tran *tran);

/* This function searches the ibcu which is binded to the specified fqid.
 * and returns this ibcu index. If does not find, returns -EINVAL.
 */
int fqid_to_ibcu(int fqid);

/* Initializes the receiving frame queue */
int rman_rxfq_init(struct qman_fq *fq, int fqid, uint8_t wq,
		   enum qm_channel channel);
/* Binds the specified fqid to a ibcu resource, and enables the ibcu filter
 * starts the receiving frame queue.
 */
int rman_rxfq_start(int fqid, int fq_mode, uint8_t port, uint8_t port_mask,
		    uint16_t sid, uint16_t sid_mask, struct rio_tran *tran);
/* Disables the ibcu filter corresponding to the specified fqid
 * closes the receiving frame queue.
 */
int rman_rxfq_finish(int fqid);

/* Initializes the transmission status frame queue */
int rman_stfq_init(struct qman_fq *fq, int fqid, uint8_t wq,
		   enum qm_channel channel);

/* Initializes the transmission frame queue */
int rman_txfq_init(struct qman_fq *fq, int fqid, uint8_t wq, uint8_t rmchan);

/* Releases the frame queue */
void rman_fq_free(struct qman_fq *fq);

/* Sends the message stored in msg, using the std_md RMan frame descriptor,
 * via the frame queue specified by opt.
 */
int rman_send_msg(struct rman_outb_md *std_md, struct tx_opt *opt,
		  struct msg_buf *msg);
/* Sends the message described by fd, using the std_md RMan frame descriptor,
 * via the frame queue specified by opt.
 */
int rman_send_fd(struct rman_outb_md *std_md, struct tx_opt *opt,
		 struct qm_fd *fd);

/* Initializes RMan interface according to RMan configuration */
int rman_if_init(struct rman_cfg *cfg);

/* Releases RMan interface resource */
void rman_if_finish(void);

#endif	/* _RMAN_IF_H */
