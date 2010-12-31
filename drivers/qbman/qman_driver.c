/* Copyright (c) 2008-2010 Freescale Semiconductor, Inc.
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

#include "qman_private.h"

/* Global variable containing revision id (even on non-control plane systems
 * where CCSR isn't available). FIXME: hard-coded. */
u16 qman_ip_rev = QMAN_REV2;

/*****************/
/* Portal driver */
/*****************/

#define PORTAL_MAX	10

static __thread int fd;

static struct qm_portal_config configs[PORTAL_MAX];
static u8 num_portals;

static struct qm_portal_config *__qm_portal_add(
					const struct qm_portal_config *config)
{
	struct qm_portal_config *ret;
	BUG_ON((num_portals + 1) > PORTAL_MAX);
	ret = &configs[num_portals];
	*ret = *config;
	ret->index = num_portals++;
	return ret;
}

u8 qm_portal_num(void)
{
	return num_portals;
}

const struct qm_portal_config *qm_portal_config(u8 idx)
{
	if (unlikely(idx >= num_portals))
		return NULL;

	return &configs[idx];
}

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
	struct qm_portal_config cfg, *pconfig;
	char name[8], *path;

	snprintf(name, 7, "QMAN%d", cpu);
	path = getenv(name);
	if (!path) {
		pr_err("Qman cpu %d needs %s set\n", cpu, name);
		return -ENODEV;
	}
	fd = open(path, O_RDWR);
	if (fd < 0) {
		perror("can't open Qman portal UIO device");
		return -ENODEV;
	}
	cfg.addr.addr_ce = mmap(QMAN_CENA(cpu), 16*1024, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED, fd, 0);
	cfg.addr.addr_ci = mmap(QMAN_CINH(cpu), 4*1024, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 4*1024);
	if ((cfg.addr.addr_ce == MAP_FAILED) ||
			(cfg.addr.addr_ci == MAP_FAILED)) {
		pr_err("Qman mmap()s failed with %p:%p\n",
			cfg.addr.addr_ce, cfg.addr.addr_ci);
		perror("mmap of CENA or CINH failed");
		close(fd);
		return -ENODEV;
	}
	cfg.public_cfg.cpu = cpu;
	cfg.public_cfg.irq = -1;
	cfg.public_cfg.channel = qm_channel_swportal0 + (cpu ? cpu : 8);
	cfg.public_cfg.pools = QM_SDQCR_CHANNELS_POOL_MASK;
	cfg.has_hv_dma = 1;
	cfg.index = -1;
	cfg.node = NULL;
	pconfig = __qm_portal_add(&cfg);
	if (!pconfig) {
		close(fd);
		return -ENOMEM;
	}
	pr_info("Qman portal at %p:%p (%d:%d,v%04x)\n", cfg.addr.addr_ce,
		cfg.addr.addr_ci, cfg.public_cfg.cpu, cfg.public_cfg.channel,
		qman_ip_rev);
	if (cfg.public_cfg.cpu == -1)
		return 0;
	if (!qman_have_affine_portal()) {
		u32 flags = 0;
		u32 irq_sources = 0;
		if (cfg.has_hv_dma)
			flags = QMAN_PORTAL_FLAG_RSTASH |
				QMAN_PORTAL_FLAG_DSTASH;
#ifdef CONFIG_FSL_DPA_PIRQ_SLOW
		irq_sources = QM_PIRQ_EQCI | QM_PIRQ_EQRI | QM_PIRQ_MRI |
				QM_PIRQ_CSCI;
#endif
#ifdef CONFIG_FSL_QMAN_PIRQ_FAST
		irq_sources |= QM_PIRQ_DQRI;
#endif
		if (qman_create_affine_portal(pconfig, flags, NULL,
#ifdef CONFIG_FSL_QMAN_NULL_FQ_DEMUX
			 	&null_cb,
#else
				NULL,
#endif
				irq_sources,
				recovery_mode))
			pr_err("Qman portal auto-initialisation failed\n");
		else
			pr_info("Qman portal %d auto-initialised\n",
				cfg.public_cfg.cpu);
	}
	return 0;
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
	/* Load the core-affine portal */
	int ret = fsl_qman_portal_init(cpu, recovery_mode);
	if (ret) {
		pr_err("Qman portal failed initialisation (%d), ret=%d\n",
			cpu, ret);
		return ret;
	}
	return 0;
}

void qman_thread_finish(void)
{
	if (!qman_have_affine_portal())
		qman_destroy_affine_portal();
}

int qman_setup_allocator(int recovery_mode,
			const struct qman_fqid_ranges *fqids)
{
	return fsl_fqid_range_init(recovery_mode, fqids);
}
