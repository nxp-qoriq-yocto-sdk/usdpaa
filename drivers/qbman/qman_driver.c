/* Copyright (c) 2008-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include <usdpaa/fsl_usd.h>
#include "qman_private.h"

/* Global variable containing revision id (even on non-control plane systems
 * where CCSR isn't available). FIXME: hard-coded. */
u16 qman_ip_rev = QMAN_REV20;

struct qman_fqid_ranges {
	unsigned int num_ranges;
	const struct qman_fqid_range {
		u32 start;
		u32 num;
	} *ranges;
};

static const struct qman_fqid_range fqid_range[] =
	{ {FSL_FQID_RANGE_START, FSL_FQID_RANGE_LENGTH} };
static const struct qman_fqid_ranges fqid_allocator = {
	.num_ranges = 1,
	.ranges = fqid_range
};


/*****************/
/* Portal driver */
/*****************/

#define PORTAL_MAX	10

static __thread int fd = -1;
static __thread const struct qbman_uio_irq *irq;

#ifdef CONFIG_FSL_QMAN_NULL_FQ_DEMUX
/* Handlers for NULL portal callbacks (ie. where the contextB field, normally
 * pointing to the corresponding FQ object, is NULL). */
static enum qman_cb_dqrr_result null_cb_dqrr(struct qman_portal *qm,
					__UNUSED struct qman_fq *fq,
					__UNUSED const struct qm_dqrr_entry *dqrr)
{
	pr_warning("Ignoring unowned DQRR frame on portal %p.\n", qm);
	return qman_cb_dqrr_consume;
}
static void null_cb_mr(struct qman_portal *qm, __UNUSED struct qman_fq *fq,
			const struct qm_mr_entry *msg)
{
	pr_warning("Ignoring unowned MR msg on portal %p, verb 0x%02x.\n",
			qm, msg->verb);
}
static const struct qman_fq_cb null_cb = {
	.dqrr = null_cb_dqrr,
	.ern = null_cb_mr,
	.dc_ern = null_cb_mr,
	.fqs = null_cb_mr
};
#endif

static int __init fsl_qman_portal_init(int cpu, int recovery_mode)
{
	const struct device_node *dt_node;
	const u32 *channel, *cell_index;
	const phandle *ph;
	struct qm_portal_config *pcfg;
	size_t lenp;
	u32 flags = 0;
	int ret = 0;
	char name[20]; /* Big enough for "/dev/qman-uio-xx" */

	if (fd >= 0) {
		pr_err("%s: on already-initialised thread\n", __func__);
		return -EBUSY;
	}
	pcfg = malloc(sizeof(*pcfg));
	if (!pcfg) {
		perror("can't allocate portal config");
		ret = -ENOMEM;
		goto end;
	}
	/* Loop the portal nodes looking for a matching cpu, and for each such
	 * match, use the cell-index to determine the UIO device name and try
	 * opening it. */
	for_each_compatible_node(dt_node, NULL, "fsl,qman-portal") {
		int cpu_idx;
		ph = of_get_property(dt_node, "cpu-handle", &lenp);
		if (!ph)
			continue;
		if (lenp != sizeof(phandle)) {
			pr_err("Malformed property %s:cpu-handle\n",
				dt_node->full_name);
			continue;
		}
		cpu_idx = check_cpu_phandle(*ph);
		if (cpu_idx != cpu)
			continue;
		cell_index = of_get_property(dt_node, "cell-index", &lenp);
		if (!cell_index || (lenp != sizeof(*cell_index))) {
			pr_err("Malformed property %s:cell-index\n",
				dt_node->full_name);
			continue;
		}
		sprintf(name, "/dev/qman-uio-%x", *cell_index);
		fd = open(name, O_RDWR);
		if (fd >= 0)
			break;
	}
	if (fd < 0) {
		ret = -ENODEV;
		goto end;
	}
	/* Parse the portal's channel */
	channel = of_get_property(dt_node, "fsl,qman-channel-id", &lenp);
	if (!channel || (lenp != sizeof(*channel))) {
		pr_err("Malformed property %s:fsl,qman-channel-id\n",
			dt_node->full_name);
		ret = -EIO;
		goto end;
	}
	pcfg->public_cfg.channel = *channel;
	/* Parse the portal's pool-channel mask */
	pcfg->public_cfg.pools = 0;
	ph = of_get_property(dt_node, "fsl,qman-pool-channels", &lenp);
	if (!ph || (lenp % sizeof(phandle))) {
		pr_err("Malformed property %s:fsl,qman-pool-channels\n",
			dt_node->full_name);
		ret = -EIO;
		goto end;
	}
	for (; lenp > 0; ph++, lenp -= sizeof(phandle)) {
		size_t tmp_lenp;
		const struct device_node *pool = of_find_node_by_phandle(*ph);
		if (!pool)
			continue;
		cell_index = of_get_property(pool, "cell-index", &tmp_lenp);
		if (!cell_index || (tmp_lenp != sizeof(*cell_index))) {
			pr_err("Malformed property %s:cell-index\n",
				pool->full_name);
			continue;
		}
		pcfg->public_cfg.pools |= QM_SDQCR_CHANNELS_POOL(*cell_index);
	}
	/* Make the portal's cache-[enabled|inhibited] regions */
	pcfg->addr.addr_ce = mmap(NULL, 16*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	pcfg->addr.addr_ci = mmap(NULL, 4*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4*1024);
	if ((pcfg->addr.addr_ce == MAP_FAILED) ||
			(pcfg->addr.addr_ci == MAP_FAILED)) {
		pr_err("Qman mmap()s failed with %p:%p\n",
			pcfg->addr.addr_ce, pcfg->addr.addr_ci);
		perror("mmap of CENA or CINH failed");
		ret = -ENODEV;
		goto end;
	}
	pcfg->public_cfg.cpu = cpu;
	pcfg->public_cfg.irq = fd;
	pcfg->has_hv_dma = 1;
	pcfg->node = NULL;

	if (pcfg->public_cfg.cpu == -1)
		goto end;

	if (pcfg->has_hv_dma)
		flags = QMAN_PORTAL_FLAG_RSTASH | QMAN_PORTAL_FLAG_DSTASH;
	ret = qman_create_affine_portal(pcfg, flags, NULL,
#ifdef CONFIG_FSL_QMAN_NULL_FQ_DEMUX
			 	&null_cb,
#else
				NULL,
#endif
				0, recovery_mode);
	if (ret) {
		pr_err("Qman portal initialisation failed (%d), ret=%d\n",
			pcfg->public_cfg.cpu, ret);
		goto end;
	}
#ifdef CONFIG_FSL_DPA_HAVE_IRQ
	/* qman_create_affine_portal() will have called request_irq(), which in
	 * USDPAA-speak, means we have to retrieve the handler here. */
	irq = qbman_get_irq_handler(fd);
	if (!irq)
		pr_warning("Qman portal interrupt handling is disabled (%d)\n",
			pcfg->public_cfg.cpu);
#endif

end:
	if (ret) {
		if (fd >= 0) {
			close(fd);
			fd = -1;
		}
		if (pcfg)
			free(pcfg);
	}
	return ret;
}

static int fsl_qman_portal_finish(void)
{
	struct qm_portal_config *cfg;
	int ret;

	if (!qman_have_affine_portal())
		return -ENODEV;
	cfg = qman_destroy_affine_portal();
	ret = munmap(cfg->addr.addr_ce, 16*1024);
	if (ret) {
		perror("munmap() of Qman ADDR_CE failed");
		goto end;
	}
	ret = munmap(cfg->addr.addr_ci, 4*1024);
	if (ret) {
		perror("munmap() of Qman ADDR_CI failed");
		goto end;
	}
end:
	if (ret)
		pr_err("Qman portal cleanup failed (%d), ret=%d\n",
			cfg->public_cfg.cpu, ret);
	free(cfg);
	close(fd);
	fd = -1;
	return ret;
}

static int fsl_fqid_range_init(int recovery_mode,
				const struct qman_fqid_ranges *fqids)
{
	u32 fqid, range;
	for (range = 0; range < fqids->num_ranges; range++) {
		for (fqid = fqids->ranges[range].start;
				fqid < (fqids->ranges[range].start +
					fqids->ranges[range].num);
				fqid++) {
			if (recovery_mode) {
				int ret = qman_recovery_cleanup_fq(fqid);
				if (ret) {
					pr_err("Failed to recover FQID %d\n",
						fqid);
					return ret;
				}
			}
		}
		qman_release_fqid_range(fqids->ranges[range].start,
					fqids->ranges[range].num);
		pr_info("Qman: FQID allocator includes range %d:%d%s\n",
			fqids->ranges[range].start, fqids->ranges[range].num,
			recovery_mode ? " (recovered)" : "");
	}
	return 0;
}

int qman_thread_init(int cpu, int recovery_mode)
{
	return fsl_qman_portal_init(cpu, recovery_mode);
}

int qman_thread_finish(void)
{
	return fsl_qman_portal_finish();
}

int qman_thread_fd(void)
{
	return fd;
}

void qman_thread_irq(void)
{
	const struct qm_portal_config *cfg = qman_get_affine_portal_config();
	if (!irq)
		return;
	irq->isr(fd, irq->arg);
	/* Now we need to uninhibit interrupts. This is the only code outside
	 * the regular portal driver that manipulates any portal register, so
	 * rather than breaking that encapsulation I am simply hard-coding the
	 * offset to the inhibit register here. */
	out_be32(cfg->addr.addr_ci + 0xe0c, 0);
}

int qman_global_init(int recovery_mode)
{
	static int done = 0;
	if (done)
		return -EBUSY;
	return fsl_fqid_range_init(recovery_mode, &fqid_allocator);
}
