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

#include <internal/of.h>
#include <usdpaa/of.h>
#include <error.h>
#include "srio_driver.h"

static int srio_uio_fd = -1;

/* This function maps the SRIO registers and windows */
int fsl_srio_uio_init(struct srio_dev **srio)
{
	int ret;
	struct srio_dev *sriodev;
	size_t lenp;
	const struct device_node *dt_node;
	const uint32_t *port_num;

	if (srio_uio_fd >= 0)
		return -EBUSY;

	sriodev = malloc(sizeof(*sriodev));
	if (!sriodev)
		return -errno;
	memset(sriodev, 0, sizeof(*sriodev));
	*srio = sriodev;

	dt_node = of_find_compatible_node(NULL, NULL, "fsl,rapidio-delta");
	if (!dt_node) {
		ret = -ENODEV;
		error(0, -ret, "%s(): compatible", __func__);
		goto err_of_compatible;
	}

	port_num = (typeof(port_num))of_get_property(dt_node, "fsl,port-num",
						     &lenp);
	if (!port_num) {
		error(0, ENODEV, "%s(): property port-num", __func__);
		fprintf(stderr, "Using default port number\n");
		sriodev->port_num = SRIO_PORT_DEFAULT_NUM;
	} else
		sriodev->port_num = *port_num;

	srio_uio_fd = open("/dev/srio-uio", O_RDWR);
	if (srio_uio_fd < 0) {
		ret = -errno;
		error(0, -ret, "%s(): /dev/srio-uio", __func__);
		goto err_of_compatible;
	}

	sriodev->rio_regs = mmap(NULL, SRIO_UIO_MEM_SIZE, PROT_READ | PROT_WRITE,
				 MAP_SHARED, srio_uio_fd, 0);
	if (sriodev->rio_regs == MAP_FAILED) {
		ret = -errno;
		error(0, -ret, "%s(): RIO regs", __func__);
		goto err_reg_map;
	}

	sriodev->mem_win = mmap(NULL, SRIO_UIO_WIN_SIZE, PROT_READ | PROT_WRITE,
				MAP_SHARED, srio_uio_fd, 4096);
	if (sriodev->mem_win == MAP_FAILED) {
		ret = -errno;
		error(0, -ret, "%s(): RIO window", __func__);
		goto err_mem_map;
	}

	return 0;

err_mem_map:
	munmap(sriodev->rio_regs, SRIO_UIO_MEM_SIZE);
err_reg_map:
	if (srio_uio_fd >= 0) {
		close(srio_uio_fd);
		srio_uio_fd = -1;
	}
err_of_compatible:
	free(sriodev);

	return ret;
}

/* This function releases the srio related resource */
int fsl_srio_uio_finish(struct srio_dev *sriodev)
{
	if (!sriodev)
		return -EINVAL;

	if (sriodev->rio_regs)
		munmap(sriodev->rio_regs, SRIO_UIO_MEM_SIZE);
	if (sriodev->mem_win)
		munmap(sriodev->mem_win, SRIO_UIO_WIN_SIZE);

	free(sriodev);

	if (srio_uio_fd >= 0)
		close(srio_uio_fd);

	return 0;
}

/* This function does the srio port connection check */
int fsl_srio_connection(struct srio_dev *sriodev, uint8_t port_id)
{
	uint32_t ccsr;
	struct rio_regs *rio_regs;
	struct rio_mport *port;

	if (!sriodev || (port_id > sriodev->port_num))
		return -EINVAL;

	port = &sriodev->port[port_id];
	rio_regs = sriodev->rio_regs;
	ccsr = in_be32(&rio_regs->lp_serial.port[port_id].ccsr);

	/* Checking the port training status */
	if (in_be32(&rio_regs->lp_serial.port[port_id].escsr) & 1) {
		fprintf(stderr, "Port is not ready. "
			"Try to restart connection...\n");
		if (ccsr & RIO_CCSR_PT) {
			/* Disable ports */
			out_be32(&rio_regs->lp_serial.port[port_id].ccsr, 0);
			/* Set 1x lane */
			out_be32(&rio_regs->lp_serial.port[port_id].ccsr,
				 in_be32(&rio_regs->lp_serial.port[port_id].ccsr)
				 | RIO_CCSR_PW0_1X);
			/* Enable ports */
			out_be32(&rio_regs->lp_serial.port[port_id].ccsr,
				 in_be32(&rio_regs->lp_serial.port[port_id].ccsr)
				 | RIO_CCSR_OPE_IPE_EN);
		}
		msleep(100);
		if (in_be32(&rio_regs->lp_serial.port[port_id].escsr) & 1) {
			error(0, EIO, "%s()", __func__);
			return -EIO;
		}
		fprintf(stderr, "Port restart success!\n");
	}

	port->enable = 1;
	/* Accept all port package */
	out_be32(&rio_regs->impl.port[port_id].accr, RIO_ISR_AACR_AA);

	return 0;
}

/*
 * This function checks the srio port connection status, and returns
 * the status flag.
 */
int fsl_srio_port_connected(struct srio_dev *sriodev)
{
	uint32_t port_flag = 0; /* bit0 - port1; bit1 - port2 ... */
	uint32_t i;

	if (!sriodev)
		return -EINVAL;

	for (i = 0; i < sriodev->port_num; i++)
		if (sriodev->port[0].enable)
			port_flag |= 0x01  << i++;

	return port_flag;
}

/* This function sets the outbound window protocol type attributes */
int fsl_srio_set_attr(struct srio_dev *sriodev, uint8_t port_id,
		      uint8_t win_id, uint32_t win_attr)
{
	struct rio_atmu *atmu;

	if (!sriodev || port_id > sriodev->port_num || win_id > SRIO_OB_WIN_NUM)
		return -EINVAL;

	atmu = &sriodev->rio_regs->atmu;

	out_be32(&atmu->port[port_id].outbw[win_id].rowar,
		 (in_be32(&atmu->port[port_id].outbw[win_id].rowar)
		  & ~RIO_ROWAR_WR_MASK) | win_attr);

	return 0;
}

/* This function initializes the outbound window all parameters */
int fsl_srio_set_obwin(struct srio_dev *sriodev, uint8_t port_id,
		       uint8_t win_id, dma_addr_t ob_win_phys, size_t win_size)
{
	struct rio_atmu *atmu;

	if (!sriodev || port_id > sriodev->port_num || win_id > SRIO_OB_WIN_NUM)
		return -EINVAL;

	atmu = &sriodev->rio_regs->atmu;
	out_be32(&atmu->port[port_id].outbw[win_id].rowbar,
		 ob_win_phys >> 12);
	out_be32(&atmu->port[port_id].outbw[win_id].rowtar,
		 SRIO_SYS_ADDR >> 12);
	out_be32(&atmu->port[port_id].outbw[win_id].rowtear, 0);
	out_be32(&atmu->port[port_id].outbw[win_id].rowar,
		 ROWAR_EN_WIN | win_size);

	return 0;
}

/* This function initializes the inbound window all parameters */
int fsl_srio_set_ibwin(struct srio_dev *sriodev, uint8_t port_id,
		       uint8_t win_id, dma_addr_t ib_win_phys,
		       size_t win_size)
{
	struct rio_atmu *atmu;

	if (!sriodev || port_id > sriodev->port_num || win_id > SRIO_IB_WIN_NUM)
		return -EINVAL;

	atmu = &sriodev->rio_regs->atmu;

	out_be32(&atmu->port[port_id].inbw[win_id].riwbar, SRIO_SYS_ADDR >> 12);
	out_be32(&atmu->port[port_id].inbw[win_id].riwtar, ib_win_phys >> 12);
	out_be32(&atmu->port[port_id].inbw[win_id].riwar, RIWAR_MEM | win_size);

	return 0;
}

/* This function clears the srio error */
int fsl_srio_clr_bus_err(struct srio_dev *sriodev)
{
	int i;

	if (!sriodev)
		return -EINVAL;

	for (i = 0; i < sriodev->port_num; i++)
		out_be32(&sriodev->rio_regs->lp_serial.port[i].escsr, ~0);

	return 0;
}
