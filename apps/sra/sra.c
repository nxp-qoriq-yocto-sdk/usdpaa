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

#include <internal/compat.h>
#include <usdpaa/of.h>
#include <usdpaa/dma_mem.h>
#include <usdpaa/fsl_dma.h>
#include <usdpaa/fsl_srio.h>
#include <error.h>
#include <atb_clock.h>

#define SRIO_WIN_BASE_PHYS1	0xc20000000ull	/* port1 outbound win base */
#define SRIO_WIN_BASE_PHYS2	0xc30000000ull	/* port2 outbound win base */
#define SRIO_WIN_SIZE		0x800000
#define SRIO_PORT_NUM		2
#define SRIO_WIN_ATTR_NRW	(0x4 << 12 | 0x4 << 16)
#define SRIO_INPUT_CMD_NUM	5
#define SRIO_CMD_NUM		3
#define SRIO_CMD_MIN_NUM	2
#define SRIO_TEST_DATA_NUM	21
#define SRIO_ATTR_FLUSH		(0x1 << 12)
#define SRIO_ATTR_SWRITE	(0x3 << 12)
#define SRIO_ATTR_NWRITE	(0x4 << 12)
#define SRIO_ATTR_NWRITE_R	(0x5 << 12)
#define SRIO_ATTR_MAINTW	(0x7 << 12)
#define SRIO_ATTR_IO_READ_HOME	(0x2 << 16)
#define SRIO_ATTR_NREAD		(0x4 << 16)
#define SRIO_ATTR_MAINTR	(0x7 << 16)
#define SRIO_ATTR_ATOMIC_INC	(0xc << 16)
#define SRIO_ATTR_ATOMIC_DEC	(0xd << 16)
#define SRIO_ATTR_ATOMIC_SET	(0xe << 16)
#define SRIO_ATTR_ATOMIC_CLR	(0xf << 16)

#define DMA_POOL_ALGIN_SIZE	0x2000000
#define SRIO_POOL_PORT_OFFSET	0x2000000
#define SRIO_POOL_SECT_SIZE	0x800000
#define SRIO_POOL_SECT_NUM	8
#define SRIO_POOL_PORT_SECT_NUM	4
#define SRIO_POOL_PORT_NUM	2

#define TEST_MAX_TIMES		50
#define ATTR_CMD_NUM		5
#define OP_CMD_NUM		5

struct srio_pool_org {
	uint8_t write_recv_data[1024*1024*8];	/* space mapped to
						   other port win */
	uint8_t read_recv_data[1024*1024*8];	/* port read data space */
	uint8_t write_data_prep[1024*1024*8];	/* port DMA write data
						   prepare space*/
	uint8_t res[1024*1024*8];
};

struct srio_port_pool {
	struct srio_pool_org *phys;
	struct srio_pool_org *virt;
};

enum srio_io_op {
	SRIO_DIR_WRITE,
	SRIO_DIR_READ,
	SRIO_DIR_SET_MEM,
	SRIO_DIR_PRI_MEM,
};

struct dma_pool {
	dma_addr_t dma_phys_base;
	void *dma_virt_base;
};

static const uint32_t srio_test_win_attrv[] = {3 << 12, 4 << 12, 5 << 12, 4 << 16, 0};
static const char * const srio_test_win_attrc[] = {"SWRITE", "NWRITE",
						   "NWRITE_R", "NREAD", "DMA"};
static const char * const cmd_name[] = {"-attr", "-op", "-test"};
static const char * const attr_param[][7] = { {"port1", "port2"},
					      {"flush", "swrite", "nwrite", "nwrite_r", "maintw"},
					      {"io_read_home", "nread", "maintr", "atomic_inc",
					       "atomic_dec", "atomic_set", "atomic_clr"} };
static const char * const op_param[][4] = { {"port1", "port2"},
					    {"w", "r", "s", "p"} };
static const char * const sector_name[] = {"map space", "read data space",
					   "write preparing space", "reserved"};

enum srio_cmd {
	SRIO_ATTR,
	SRIO_OP,
	SRIO_TEST
};

struct cmd_port_param {
	uint32_t win_attr;
	uint8_t op_type;
	size_t op_len;

};

struct cmd_param_type {
	uint8_t curr_cmd;
	uint8_t curr_port_id;
	struct cmd_port_param port[SRIO_PORT_NUM];
	uint8_t test_type;
	uint8_t test_bwc;
};

enum srio_write_type {
	FLUSH,
	SWRITE,
	NWRITE,
	NWRITE_R,
	MAINTW,
};

enum srio_read_type {
	IO_READ_HOME,
	NREAD,
	MAINTR,
	ATOMIC_INC,
	ATOMIC_DEC,
	ATOMIC_SET,
	ATOMIC_CLR,
};

struct cmd_param_type cmd_param;

static int par_to_srio_attr(uint8_t write_attr, uint8_t read_attr,
			    uint32_t *win_attr)
{
	if (!win_attr)
		return -EINVAL;

	switch (write_attr) {
	case FLUSH:
		*win_attr |= SRIO_ATTR_FLUSH;
		break;
	case SWRITE:
		*win_attr |= SRIO_ATTR_SWRITE;
		break;
	case NWRITE:
		*win_attr |= SRIO_ATTR_NWRITE;
		break;
	case NWRITE_R:
		*win_attr |= SRIO_ATTR_NWRITE_R;
		break;
	case MAINTW:
		*win_attr |= SRIO_ATTR_MAINTW;
	}

	switch (read_attr) {
	case IO_READ_HOME:
		*win_attr |= SRIO_ATTR_IO_READ_HOME;
		break;
	case NREAD:
		*win_attr |= SRIO_ATTR_NREAD;
		break;
	case MAINTR:
		*win_attr |= SRIO_ATTR_MAINTR;
		break;
	case ATOMIC_INC:
		*win_attr |= SRIO_ATTR_ATOMIC_INC;
		break;
	case ATOMIC_DEC:
		*win_attr |= SRIO_ATTR_ATOMIC_DEC;
		break;
	case ATOMIC_SET:
		*win_attr |= SRIO_ATTR_ATOMIC_SET;
		break;
	case ATOMIC_CLR:
		*win_attr |= SRIO_ATTR_ATOMIC_CLR;
	}

	return 0;
}

static int attr_param_trans(int32_t cmd_num, char **cmd_in)
{
	int i;
	uint8_t port;
	uint8_t read_attr, write_attr;
	uint32_t win_attr = 0;

	if (cmd_num != ATTR_CMD_NUM)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(attr_param[0]) && attr_param[0][i]; i++)
		if (!strcmp(cmd_in[2], attr_param[0][i]))
			break;

	if (i == ARRAY_SIZE(attr_param[0]) || !attr_param[0][i])
		return -EINVAL;

	port = i;

	for (i = 0; i < ARRAY_SIZE(attr_param[1]) && attr_param[1][i]; i++)
		if (!strcmp(cmd_in[3], attr_param[1][i]))
			break;

	if (i == ARRAY_SIZE(attr_param[1]) || !attr_param[1][i])
		return -EINVAL;

	write_attr = i;

	for (i = 0; i < ARRAY_SIZE(attr_param[2]) && attr_param[2][i]; i++)
		if (!strcmp(cmd_in[4], attr_param[2][i]))
			break;

	if (i == ARRAY_SIZE(attr_param[2]) || !attr_param[2][i])
		return -EINVAL;

	read_attr = i;

	par_to_srio_attr(write_attr, read_attr, &win_attr);
	cmd_param.curr_port_id = port;
	cmd_param.port[port].win_attr = win_attr;

	return 0;
}

static int op_param_trans(int32_t cmd_num, char **cmd_in)
{
	int32_t i;
	uint8_t port_id;

	if (cmd_num != OP_CMD_NUM)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(op_param[0]) && op_param[0][i]; i++)
		if (!strcmp(cmd_in[2], op_param[0][i]))
			break;

	if (i == ARRAY_SIZE(op_param[0]) || !op_param[0][i])
		return -EINVAL;

	port_id = i;

	for (i = 0; i < ARRAY_SIZE(op_param[1]) && op_param[1][i]; i++)
		if (!strcmp(cmd_in[3], op_param[1][i]))
			break;

	if (i == ARRAY_SIZE(op_param[1]) || !op_param[1][i])
		return -EINVAL;

	cmd_param.curr_port_id = port_id;
	cmd_param.port[port_id].op_type = i;
	cmd_param.port[port_id].op_len = strtoul(cmd_in[4], NULL, 0);
	if (cmd_param.port[port_id].op_len > SRIO_WIN_SIZE)
		return -EINVAL;

	return 0;
}

static int cmd_translate(int32_t cmd_num, char **cmd_in)
{
	int i, err = 0;

	if (cmd_num < SRIO_CMD_MIN_NUM)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(cmd_name) && cmd_name[i]; i++)
		if (!strcmp(cmd_in[1], cmd_name[i]))
			break;

	if (i == ARRAY_SIZE(cmd_name) || !cmd_name[i])
		return -EINVAL;

	cmd_param.curr_cmd = i;

	switch (i) {
	case SRIO_ATTR:
		err = attr_param_trans(cmd_num, cmd_in);
		break;
	case SRIO_OP:
		err = op_param_trans(cmd_num, cmd_in);
		break;
	case SRIO_TEST:
		break;
	}

	return err;
}

static int op_implement(struct srio_dev *sriodev, struct dma_dev *dmadev,
			struct srio_port_pool  *port_pool)
{
	uint8_t port_id = cmd_param.curr_port_id;
	int i, j, k, err;
	const char *pri;

	switch (cmd_param.port[port_id].op_type) {
	case SRIO_DIR_WRITE:
		fsl_dma_direct_start(dmadev, port_id, 0,
				     (dma_addr_t)(uintptr_t)
				     port_pool[port_id].phys->write_data_prep,
				     (port_id == 0) ?
				     SRIO_WIN_BASE_PHYS1 : SRIO_WIN_BASE_PHYS2,
				     cmd_param.port[port_id].op_len);
		break;
	case SRIO_DIR_READ:
		fsl_dma_direct_start(dmadev, port_id, 0,
				     (port_id == 0) ?
				     SRIO_WIN_BASE_PHYS1 : SRIO_WIN_BASE_PHYS2,
				     (dma_addr_t)(uintptr_t)
				     port_pool[port_id].phys->read_recv_data,
				     cmd_param.port[port_id].op_len);
		break;
	case SRIO_DIR_SET_MEM:
		for (i = 0; i < SRIO_POOL_PORT_NUM; i++) {
			memset(&port_pool[i].virt->write_recv_data,
			       i * SRIO_POOL_PORT_SECT_NUM,
			       SRIO_POOL_SECT_SIZE);
			memset(&port_pool[i].virt->read_recv_data,
			       i * SRIO_POOL_PORT_SECT_NUM + 1,
			       SRIO_POOL_SECT_SIZE);
			memset(&port_pool[i].virt->write_data_prep,
			       i * SRIO_POOL_PORT_SECT_NUM + 2,
			       SRIO_POOL_SECT_SIZE);
			memset(&port_pool[i].virt->res,
			       i * SRIO_POOL_PORT_SECT_NUM + 3,
			       SRIO_POOL_SECT_SIZE);
		}
		break;
	case SRIO_DIR_PRI_MEM:
		for (j = 0; j < SRIO_POOL_PORT_NUM; j++)
			for (k = 0; k < SRIO_POOL_PORT_SECT_NUM; k++) {
				printf("port%d %s\n", j + 1, sector_name[k]);
				pri = (typeof(pri))port_pool[j].virt +
					SRIO_POOL_SECT_SIZE * k;
				for (i = 0; i < 20; i += 4)
					printf("%x\t%x\t%x\t%x\n",
					       *(pri + i), *(pri + i + 1),
					       *(pri + i + 2), *(pri + i + 3));
			}
	}

	err = fsl_dma_wait(dmadev, port_id, 0);
	if (err < 0) {
		fsl_srio_clr_bus_err(sriodev);
		return err;
	}

	return 0;
}

static int attr_implement(struct srio_dev *sriodev,
			  struct srio_port_pool	 *port_pool)
{
	uint8_t port_id = cmd_param.curr_port_id;

	fsl_srio_set_obwin(sriodev, port_id, 1,
			   (port_id == 0) ? SRIO_WIN_BASE_PHYS1 : SRIO_WIN_BASE_PHYS2,
			   LAWAR_SIZE_8M);
	fsl_srio_set_ibwin(sriodev, port_id, 1,
			   (dma_addr_t)(uintptr_t)port_pool[port_id].phys->write_recv_data,
			   LAWAR_SIZE_8M);
	fsl_srio_set_attr(sriodev, port_id, 1,
			  cmd_param.port[port_id].win_attr);

	return 0;
}

static int srio_perf_test(struct srio_dev *sriodev, struct dma_dev *dmadev,
			  struct srio_port_pool	 *port_pool)
{
	int i, j, k, h, err;
	dma_addr_t src_phys, dest_phys;
	struct atb_clock *atb_clock;
	uint64_t atb_multiplier = 0;

	atb_clock = malloc(sizeof(*atb_clock));
	if (!atb_clock)
		return -errno;
	atb_multiplier = atb_get_multiplier();

	for (i = 0; i < SRIO_PORT_NUM; i++)
		if (fsl_srio_port_connected(sriodev) & (0x1 << i)) {
			fsl_srio_set_obwin(sriodev, i, 1, (i == 0) ?
					   SRIO_WIN_BASE_PHYS1 : SRIO_WIN_BASE_PHYS2,
					   LAWAR_SIZE_8M);
			fsl_srio_set_ibwin(sriodev, i, 1, (dma_addr_t)(uintptr_t)
					   port_pool[i].phys->write_recv_data,
					   LAWAR_SIZE_8M);
		}

	for (h = 0; h < DMA_BWC_NUM; h++) {
		if (h < DMA_BWC_NUM - 1)
			/* BWC is from 1 to 1024 */
			printf("\n----------BWC is %d byte-----------\n",
			       (1 << h));
		else {
			h = DMA_BWC_DIS;
			printf("\n----------BWC is Disabled----------\n");
		}

		fsl_dma_chan_bwc(dmadev, 0, 0, h);

		for (i = 0; i < ARRAY_SIZE(srio_test_win_attrv); i++) {
			printf("\nSRIO %s Test for %d times\n",
			       srio_test_win_attrc[i], TEST_MAX_TIMES);
			if (i < ARRAY_SIZE(srio_test_win_attrv) - 1)
				fsl_srio_set_attr(sriodev, 0, 1,
						  srio_test_win_attrv[i]);

			if (i < ARRAY_SIZE(srio_test_win_attrv) - 2) {
				src_phys = (dma_addr_t)(uintptr_t)
					port_pool[0].phys->write_data_prep;
				dest_phys = SRIO_WIN_BASE_PHYS1;
			} else if (i == ARRAY_SIZE(srio_test_win_attrv) - 2) {
				src_phys = SRIO_WIN_BASE_PHYS1;
				dest_phys = (dma_addr_t)(uintptr_t)
					port_pool[0].phys->read_recv_data;
			} else {
				src_phys = (dma_addr_t)(uintptr_t)
					port_pool[0].phys;
				dest_phys = (dma_addr_t)(uintptr_t)
					port_pool[1].phys;
			}

			/* SRIO test data is from 4 bytes to 1M bytes*/
			for (j = 2; j < SRIO_TEST_DATA_NUM; j++) {
				atb_clock_init(atb_clock);
				atb_clock_reset(atb_clock);
				for (k = 0; k < TEST_MAX_TIMES; k++) {
					atb_clock_start(atb_clock);
					fsl_dma_direct_start(dmadev, 0, 0,
							     src_phys, dest_phys,
							     (1 << j));

					err = fsl_dma_wait(dmadev, 0, 0);
					if (err < 0) {
						error(0, -err,
						      "SRIO transmission failed");
						fsl_srio_clr_bus_err(sriodev);
						return err;
					}
					atb_clock_stop(atb_clock);
				}
				printf("length(byte): %-15u time(us): %-15f"
				       "avg Gb/s: %-15f max Gb/s: %-15f\n", (1 << j),
				       atb_to_seconds(atb_clock_total(atb_clock),
						      atb_multiplier) / TEST_MAX_TIMES
				       * ATB_MHZ,
				       (1 << j) * 8 * TEST_MAX_TIMES /
				       (atb_to_seconds(atb_clock_total(atb_clock),
						       atb_multiplier) * 1000000000.0),
				       (1 << j) * 8 /
				       (atb_to_seconds(atb_clock_min(atb_clock),
						       atb_multiplier) * 1000000000.0));
				atb_clock_finish(atb_clock);
			}
		}
	}

	return 0;
}

static int cmd_implement(struct srio_dev *sriodev, struct dma_dev *dmadev,
			 struct srio_port_pool	*port_pool)
{
	switch (cmd_param.curr_cmd) {
	case SRIO_ATTR:
		attr_implement(sriodev, port_pool);
		break;
	case SRIO_OP:
		op_implement(sriodev, dmadev, port_pool);
		break;
	case SRIO_TEST:
		srio_perf_test(sriodev, dmadev, port_pool);
	}

	return 0;
}

/* Init DMA pool */
static int dma_usmem_init(struct dma_pool *pool)
{
	int err;

	err = dma_mem_setup();
	if (err < 0) {
		error(0, -err, "%s(): dma_mem_setup()", __func__);
		return err;
	}
	pool->dma_phys_base = dma_mem_bpool_base();
	pool->dma_virt_base = dma_mem_ptov(pool->dma_phys_base);

	return 0;
}

static int dma_pool_init(struct dma_pool **pool)
{
	struct dma_pool *dma_pool;
	int err;

	dma_pool = malloc(sizeof(*dma_pool));
	if (!dma_pool) {
		error(0, errno, "%s(): DMA pool", __func__);
		return -errno;
	}
	memset(dma_pool, 0, sizeof(*dma_pool));
	*pool = dma_pool;

	err = dma_usmem_init(dma_pool);
	if (err < 0) {
		error(0, -err, "%s(): DMA pool", __func__);
		free(dma_pool);
		return err;
	}

	return 0;
}

static void dma_pool_finish(struct dma_pool *pool)
{
	free(pool);
}

static void cmd_format_print(void)
{
	printf("-----------------SRIO APP CMD FORMAT-----------------\n");
	printf("\nsra -attr [port_id] [write_attr] [read_attr]\n");
	printf("\tset SRIO port window attribute\n");
	printf("\t[port_id]	: port1/port2\n");
	printf("\t[write_attr]	: swrite/nwrite/nwrite_r\n");
	printf("\t[read_attr]	: nread/atomic_inc/atomic_dec"
	       "/atomic_set/atomic_clr\n");
	printf("\nsra -op [port_id] [operation] [data_len]\n");
	printf("\t[port_id]	: port1/port2\n");
	printf("\t[operation]	: w[rite]/r[ead]/s[et]/p[rint]\n");
	printf("\t[data_len]	: shoule be less than 8M\n");
	printf("\tdata_len should be 1/2/4 for ATOMIC operation\n");
	printf("\nsra -test\n");
	printf("\tdo SRIO test and print performance result\n");
	printf("---------------------Example-------------------------\n");
	printf("@ set port1 window attribute @\n");
	printf("sra -attr port1 nwrite nread\n");
	printf("@ write 1M data via port1 @\n");
	printf("sra -op port1 w 0x100000\n");
	printf("@ read 1M data via port1 @\n");
	printf("sra -op port1 r 0x100000\n");
	printf("@ do SRIO performance test @\n");
	printf("sra -test\n");
	printf("-----------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
	struct srio_dev *sriodev;
	struct dma_dev *dmadev;
	struct dma_pool *dmapool = NULL;
	int i, err;
	struct srio_port_pool portpool[SRIO_POOL_PORT_NUM];

	memset(&cmd_param, 0, sizeof(cmd_param));
	err = cmd_translate(argc, argv);
	if (err < 0) {
		cmd_format_print();
		return err;
	}

	of_init();
	err = fsl_srio_uio_init(&sriodev);
	if (err < 0)
		error(EXIT_FAILURE, -err, "%s(): srio_uio_init()", __func__);

	for (i = 0; i < SRIO_PORT_NUM; i++)
		fsl_srio_connection(sriodev, i);

	err = fsl_srio_port_connected(sriodev);
	if (err < 0) {
		error(0, -err, "%s(): fsl_srio_connection()", __func__);
		goto err_srio_conneced;
	}

	dma_pool_init(&dmapool);

	err = fsl_dma_uio_init(&dmadev);
	if (err < 0) {
		error(0, -err, "%s(): fsl_dma_uio_init()", __func__);
		goto err_srio_conneced;

	}

	for (i = 0; i < ARRAY_SIZE(portpool); i++) {
		portpool[i].phys = (typeof(portpool[i].phys))(uintptr_t)
			(dmapool->dma_phys_base + i * SRIO_POOL_PORT_OFFSET);
		portpool[i].virt = (typeof(portpool[i].virt))
			(dmapool->dma_virt_base + i * SRIO_POOL_PORT_OFFSET);
	}

	for (i = 0; i < 2; i++)
		fsl_dma_chan_basic_direct_init(dmadev, i, 0);

	cmd_implement(sriodev, dmadev, portpool);

	fsl_dma_uio_finish(dmadev);
	dma_pool_finish(dmapool);
	fsl_srio_uio_finish(sriodev);

	of_finish();
	return EXIT_SUCCESS;

err_srio_conneced:
	fsl_srio_uio_finish(sriodev);
	of_finish();

	return err;
}