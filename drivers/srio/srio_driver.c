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

static int __fsl_srio_get_port_num(struct srio_dev *srio_dev,
				 const struct device_node *srio_node)
{
	const struct device_node *child;
	int i = 0;

	for_each_child_node(srio_node, child)
		i++;

	return i;
}

static int fsl_srio_port_init(struct srio_dev *srio_dev,
			      const struct device_node *node, uint32_t id)
{
	const struct device_node *srio_node;
	struct srio_port *srio_port;
	const uint32_t *dt_range, *cell_index;
	uint64_t law_start, law_size;
	uint32_t paw, aw, sw;
	char port_uio_name[PATH_MAX];
	int ret;

	srio_node = node;
	cell_index = of_get_property(srio_node, "cell-index", NULL);
	if (!cell_index) {
		ret = -ENODEV;
		error(0, -ret, "%s(): of_get_property cell-index", __func__);
		return ret;
	}

	dt_range = of_get_property(srio_node, "ranges", NULL);
	if (!dt_range) {
		ret = -ENODEV;
		error(0, -ret, "%s(): of_get_property ranges", __func__);
		return ret;
	}

	aw = of_n_addr_cells(srio_node);
	sw = of_n_size_cells(srio_node);
	paw = of_n_addr_cells(srio_node);
	law_start = of_read_number(dt_range + aw, paw);
	law_size = of_read_number(dt_range + aw + paw, sw);

	srio_port = &srio_dev->port[id];
	srio_port->port_id = *cell_index;
	srio_port->win_range.start = law_start;
	srio_port->win_range.size = law_size;

	snprintf(port_uio_name, PATH_MAX - 1, "/dev/srio-uio-port%d",
			srio_port->port_id);

	srio_port->port_fd = open(port_uio_name, O_RDWR);
	if (srio_port->port_fd  < 0) {
		ret = -errno;
		error(0, -ret, "%s(): Srio uio port", __func__);
		return ret;
	}

	srio_port->mem_win = mmap(NULL, srio_port->win_range.size,
				  PROT_READ | PROT_WRITE, MAP_SHARED,
				  srio_port->port_fd, 0);
	if (srio_port->mem_win == MAP_FAILED) {
		ret = -errno;
		error(0, -ret, "%s(): Srio window", __func__);
		goto err_mem_map;
	}

	return 0;

err_mem_map:
	close(srio_port->port_fd);

	return ret;
}

/* This function maps the SRIO registers and windows */
int fsl_srio_uio_init(struct srio_dev **srio)
{
	int ret;
	struct srio_dev *sriodev;
	const struct device_node *srio_node, *child;
	const uint32_t *regs_addr_ptr;
	uint64_t  regs_addr;
	int i;

	sriodev = (struct srio_dev *)malloc(sizeof(struct srio_dev));
	if (!sriodev)
		return -errno;
	memset(sriodev, 0, sizeof(struct srio_dev));
	*srio = sriodev;

	srio_node = of_find_compatible_node(NULL, NULL, "fsl,srio");
	if (!srio_node) {
		ret = -ENODEV;
		error(0, -ret, "%s(): compatible", __func__);
		goto err_of_compatible;
	}

	regs_addr_ptr = of_get_address(srio_node, 0, &sriodev->regs_size, NULL);
	if (!regs_addr_ptr) {
		ret = -ENODEV;
		error(0, -ret, "%s(): of_get_address", __func__);
		goto err_of_compatible;
	}

	regs_addr = of_translate_address(srio_node, regs_addr_ptr);
	if (!regs_addr) {
		ret = -ENODEV;
		error(0, -ret, "%s(): of_translate_address", __func__);
		goto err_of_compatible;
	}

	sriodev->port_num = __fsl_srio_get_port_num(sriodev, srio_node);
	if (sriodev->port_num == 0) {
		ret = -ENODEV;
		error(0, -ret, "%s(): Srio port", __func__);
		goto err_of_compatible;

	}

	sriodev->reg_fd = open("/dev/srio-uio-regs", O_RDWR);
	if (sriodev->reg_fd < 0) {
		ret = -errno;
		error(0, -ret, "%s(): Srio uio regs", __func__);
		goto err_of_compatible;
	}

	sriodev->rio_regs = mmap(NULL, sriodev->regs_size,
				 PROT_READ | PROT_WRITE, MAP_SHARED,
				 sriodev->reg_fd, 0);
	if (sriodev->rio_regs == MAP_FAILED) {
		ret = -errno;
		error(0, -ret, "%s(): Srio regs", __func__);
		goto err_reg_map;
	}

	sriodev->port = malloc(sizeof(struct srio_port) * sriodev->port_num);
	if (!sriodev->port) {
		ret = -errno;
		error(0, -ret, "%s(): Port memory", __func__);
		goto err_port_malloc;
	}
	memset(sriodev->port, 0, sizeof(struct srio_port) * sriodev->port_num);

	i = 0;
	for_each_child_node(srio_node, child) {
		ret = fsl_srio_port_init(sriodev, child, i);
		if (ret < 0)
			goto err_port_malloc;
		i++;
	}

	return 0;

err_port_malloc:
	munmap(sriodev->rio_regs, sriodev->regs_size);
err_reg_map:
	close(sriodev->reg_fd);
err_of_compatible:
	free(sriodev);
	*srio = NULL;

	return ret;
}

/* This function releases the srio related resource */
int fsl_srio_uio_finish(struct srio_dev *sriodev)
{
	int i;

	if (!sriodev)
		return -EINVAL;

	for (i = 0; i < sriodev->port_num; i++) {
		munmap(sriodev->port[i].mem_win,
		       sriodev->port[i].win_range.size);
		close(sriodev->port[i].port_fd);
	}

	if (sriodev->reg_fd) {
		munmap(sriodev->rio_regs, sriodev->regs_size);
		close(sriodev->reg_fd);
		free(sriodev->port);
		free(sriodev);
	}

	return 0;
}

/* This function does the srio port connection check */
int fsl_srio_connection(struct srio_dev *sriodev, uint8_t port_id)
{
	uint32_t ccsr;
	struct rio_regs *rio_regs;
	struct srio_port *port;

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
		if (sriodev->port[i].enable)
			port_flag |= 0x01  << i;

	return port_flag;
}

/*
 * This function return the total port number of rapidio.
 */
int fsl_srio_get_port_num(struct srio_dev *sriodev)
{
	return (int)sriodev->port_num;
}

/* This function copies the srio port info to user */
int fsl_srio_get_port_info(struct srio_dev *sriodev, uint8_t port_id,
			   struct srio_port_info *port)
{
	uint32_t i;

	if (!port)
		return -EINVAL;

	for (i = 0; i < sriodev->port_num; i++) {
		if (sriodev->port[i].port_id == port_id)
			break;
	}

	if (i == sriodev->port_num)
		return -ENODEV;

	port->range.start = sriodev->port[i].win_range.start;
	port->range.size = sriodev->port[i].win_range.size;

	return 0;
}

/* This function sets the outbound window protocol type attributes */
int fsl_srio_set_attr(struct srio_dev *sriodev, uint8_t port_id,
		      uint8_t win_id, uint32_t win_attr)
{
	struct rio_atmu *atmu;

	if (!sriodev || win_id > SRIO_OB_WIN_NUM)
		return -EINVAL;

	atmu = &sriodev->rio_regs->atmu;

	out_be32(&atmu->port[port_id].outbw[win_id].rowar,
		 (in_be32(&atmu->port[port_id].outbw[win_id].rowar)
		  & ~RIO_ROWAR_WR_MASK) | win_attr);

	return 0;
}

/* This function initializes the outbound window all parameters */
int fsl_srio_set_obwin(struct srio_dev *sriodev, uint8_t port_id,
		       uint8_t win_id, uint64_t ob_win_phys,
		       uint64_t ob_win_sys, size_t win_size)
{
	struct rio_atmu *atmu;

	if (!sriodev || win_id > SRIO_OB_WIN_NUM)
		return -EINVAL;

	atmu = &sriodev->rio_regs->atmu;
	out_be32(&atmu->port[port_id].outbw[win_id].rowbar,
		 ob_win_phys >> 12);
	out_be32(&atmu->port[port_id].outbw[win_id].rowtar,
		 ob_win_sys >> 12);
	out_be32(&atmu->port[port_id].outbw[win_id].rowtear, 0);
	out_be32(&atmu->port[port_id].outbw[win_id].rowar,
		 ROWAR_EN_WIN | win_size);

	return 0;
}

/* This function initializes the inbound window all parameters */
int fsl_srio_set_ibwin(struct srio_dev *sriodev, uint8_t port_id,
		       uint8_t win_id, uint64_t ib_win_phys,
		       uint64_t ib_win_sys, size_t win_size)
{
	struct rio_atmu *atmu;

	if (!sriodev || win_id > SRIO_IB_WIN_NUM)
		return -EINVAL;

	atmu = &sriodev->rio_regs->atmu;

	out_be32(&atmu->port[port_id].inbw[win_id].riwbar, ib_win_sys >> 12);
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
