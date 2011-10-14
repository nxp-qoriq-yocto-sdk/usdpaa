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

#ifndef FSL_SRIO_H
#define FSL_SRIO_H

#define	SRIO_OB_WIN_NUM		9	/* SRIO outbound window number */
#define	SRIO_IB_WIN_NUM		5	/* SRIO inbound window number */

enum srio_lawbar_size {
	LAWAR_SIZE_BASE = 0xa,
	LAWAR_SIZE_4,
	LAWAR_SIZE_8K,
	LAWAR_SIZE_16K,
	LAWAR_SIZE_32K,
	LAWAR_SIZE_64K,
	LAWAR_SIZE_128K,
	LAWAR_SIZE_256K,
	LAWAR_SIZE_512K,
	LAWAR_SIZE_1M,
	LAWAR_SIZE_2M,
	LAWAR_SIZE_4M,
	LAWAR_SIZE_8M,
	LAWAR_SIZE_16M,
	LAWAR_SIZE_32M,
	LAWAR_SIZE_64M,
	LAWAR_SIZE_128M,
	LAWAR_SIZE_256M,
	LAWAR_SIZE_512M,
	LAWAR_SIZE_1G,
	LAWAR_SIZE_2G
};

struct srio_port_info {
	uint64_t range_start;
	uint64_t range_size;
};

struct srio_dev;

int fsl_srio_uio_init(struct srio_dev **srio);
int fsl_srio_uio_finish(struct srio_dev *sriodev);
int fsl_srio_connection(struct srio_dev *sriodev, uint8_t port_id);
int fsl_srio_set_attr(struct srio_dev *sriodev,
		      uint8_t port_id, int32_t win_id, uint32_t win_attr);
int fsl_srio_set_obwin(struct srio_dev *sriodev, uint8_t port_id,
		       uint8_t win_id, uint64_t ob_win_phys,
		       uint64_t ob_win_sys, size_t win_size);
int fsl_srio_set_ibwin(struct srio_dev *sriodev, uint8_t port_id,
		      uint8_t win_id, uint64_t ib_win_phys, uint64_t ib_win_sys,
		      size_t win_size);
int fsl_srio_clr_bus_err(struct srio_dev *sriodev);
int fsl_srio_port_connected(struct srio_dev *sriodev);
int fsl_srio_get_port_num(struct srio_dev *sriodev);
int fsl_srio_get_port_info(struct srio_dev *sriodev, uint8_t port_id,
			   struct srio_port_info *port);
#endif
