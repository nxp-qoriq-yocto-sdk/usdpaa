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

#include "qman_private.h"

/* Global variable containing revision id (even on non-control plane systems
 * where CCSR isn't available). FIXME: hard-coded. */
u16 qman_ip_rev = QMAN_REV2;

/*****************/
/* Portal driver */
/*****************/

#define PORTAL_MAX	10

static __thread int fd = -1;

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
	u32 flags = 0;
	u32 irq_sources = 0;
	int ret = 0, suffix = 0;
	char name[20]; /* Big enough for "/dev/qman-uio-99:99" */

	if (fd >= 0) {
		pr_err("%s: on already-initialised thread\n", __func__);
		return -EBUSY;
	}
	/* Loop the possible portal devices for the required cpu until we
	 * succeed or fail with something other than -EBUSY=="in use". */
	do {
		int numchars;
		if (!suffix)
			numchars = snprintf(name, 19, "/dev/qman-uio-%d", cpu);
		else
			numchars = snprintf(name, 19, "/dev/qman-uio-%d:%d",
				cpu, suffix);
		name[numchars] = '\0';
		fd = open(name, O_RDWR);
		suffix++;
	} while (fd == -EBUSY);
	if (fd < 0) {
		perror("no available Qman portal device");
		ret = -ENODEV;
		goto end;
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
		ret = -ENODEV;
		goto end;
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
		ret = -ENOMEM;
		goto end;
	}
	if (cfg.public_cfg.cpu == -1)
		goto end;

	if (cfg.has_hv_dma)
		flags = QMAN_PORTAL_FLAG_RSTASH | QMAN_PORTAL_FLAG_DSTASH;
#ifdef CONFIG_FSL_DPA_PIRQ_SLOW
	irq_sources = QM_PIRQ_EQCI | QM_PIRQ_EQRI | QM_PIRQ_MRI | QM_PIRQ_CSCI;
#endif
#ifdef CONFIG_FSL_QMAN_PIRQ_FAST
	irq_sources |= QM_PIRQ_DQRI;
#endif
	ret = qman_create_affine_portal(pconfig, flags, NULL,
#ifdef CONFIG_FSL_QMAN_NULL_FQ_DEMUX
			 	&null_cb,
#else
				NULL,
#endif
				irq_sources, recovery_mode);
	if (ret)
		pr_err("Qman portal initialisation failed (%d), ret=%d\n",
			cfg.public_cfg.cpu, ret);
	else
		pr_info("Qman portal initialised at %p:%p (%d:%d,v%04x)\n",
			cfg.addr.addr_ce, cfg.addr.addr_ci, cfg.public_cfg.cpu,
			cfg.public_cfg.channel, qman_ip_rev);
end:
	if (ret) {
		if (fd >= 0) {
			close(fd);
			fd = -1;
		}
	}
	return ret;
}

static int fsl_qman_portal_finish(void)
{
	int ret;
	const struct qm_portal_config *cfg = qman_get_affine_portal_config();
	if (!cfg)
		return -ENODEV;
	qman_destroy_affine_portal();
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
	close(fd);
	if (ret)
		pr_err("Qman portal cleanup failed (%d), ret=%d\n",
			cfg->public_cfg.cpu, ret);
	else
		pr_info("Qman portal cleanup (%d) at %p:%p (%d)\n",
			cfg->public_cfg.cpu, cfg->addr.addr_ce,
			cfg->addr.addr_ci, fd);
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

int qman_setup_allocator(int recovery_mode,
			const struct qman_fqid_ranges *fqids)
{
	return fsl_fqid_range_init(recovery_mode, fqids);
}
