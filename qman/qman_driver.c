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
u16 qman_ip_rev = QMAN_REV1;

/*****************/
/* Portal driver */
/*****************/

static __thread struct qm_portal portal;
static __thread int fd;
DEFINE_PER_CPU(struct qman_portal *, qman_affine_portal);

u8 qm_portal_num(void)
{
	return 1;
}
EXPORT_SYMBOL(qm_portal_num);

struct qm_portal *qm_portal_get(u8 idx)
{
	if (unlikely(idx >= 1))
		return NULL;

	return &portal;
}
EXPORT_SYMBOL(qm_portal_get);

const struct qm_portal_config *qm_portal_config(const struct qm_portal *portal)
{
	return &portal->config;
}
EXPORT_SYMBOL(qm_portal_config);

static struct qm_portal *__qm_portal_add(const struct qm_addr *addr,
				const struct qm_portal_config *config)
{
	struct qm_portal *ret = &portal;
	ret->addr = *addr;
	ret->config = *config;
	ret->config.bound = 0;
#ifdef CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1
	ret->bugs = (void *)get_zeroed_page(GFP_KERNEL);
	if (!ret->bugs) {
		pr_err("Can't get zeroed page for 'bugs'\n");
		return NULL;
	}
#endif
	return ret;
}

int __qm_portal_bind(struct qm_portal *portal, u8 iface)
{
	int ret = -EBUSY;
	if (!(portal->config.bound & iface)) {
		portal->config.bound |= iface;
		ret = 0;
	}
	return ret;
}

void __qm_portal_unbind(struct qm_portal *portal, u8 iface)
{
	QM_ASSERT(portal->config.bound & iface);
	portal->config.bound &= ~iface;
}

/* Handlers for NULL portal callbacks (ie. where the contextB field, normally
 * pointing to the corresponding FQ object, is NULL). */
static enum qman_cb_dqrr_result null_cb_dqrr(struct qman_portal *qm,
					struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr)
{
	pr_warning("Ignoring unowned DQRR frame on portal %p.\n", qm);
	return qman_cb_dqrr_consume;
}
static void null_cb_mr(struct qman_portal *qm, struct qman_fq *fq,
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

static int __init fsl_qman_portal_init(int cpu)
{
	struct qm_portal_config cfg = {
		.cpu = cpu,
		.irq = -1,
		/* FIXME: hard-coded */
		.channel = qm_channel_swportal8 + cpu,
		/* FIXME: hard-coded */
		.pools = QM_SDQCR_CHANNELS_POOL_MASK,
		/* FIXME: hard-coded */
		.has_hv_dma = 1
	};
	struct qm_addr addr;
	struct qm_portal *portal;
	struct qman_portal *affine_portal;
	char name[8], *path;

	/* FIXME: hard-coded */
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
	addr.addr_ce = mmap(NULL, 16*1024, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (addr.addr_ce == MAP_FAILED)
		perror("mmap of CENA failed");
	addr.addr_ci = mmap(NULL, 4*1024, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 4*1024);
	if (addr.addr_ci == MAP_FAILED)
		perror("mmap of CINH failed");
	portal = __qm_portal_add(&addr, &cfg);
	if (!portal)
		return -ENOMEM;
	pr_info("Qman portal at %p:%p (%d:%d,v%04x)\n", addr.addr_ce,
		addr.addr_ci, cfg.cpu, cfg.channel, qman_ip_rev);
#ifndef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO
	if (cfg.cpu == -1)
		return 0;
	affine_portal = per_cpu(qman_affine_portal, cfg.cpu);
	if (!affine_portal) {
		u32 flags = 0;
		if (cfg.has_hv_dma)
			flags = QMAN_PORTAL_FLAG_RSTASH |
				QMAN_PORTAL_FLAG_DSTASH;
		affine_portal = qman_create_portal(portal, flags, NULL,
						&null_cb);
		if (!affine_portal) {
			pr_err("Qman portal auto-initialisation failed\n");
			return 0;
		}
#if 0
		/* default: enable all (available) pool channels */
		qman_static_dequeue_add_ex(affine_portal, ~0);
#endif
		pr_info("Qman portal %d auto-initialised\n", cfg.cpu);
		per_cpu(qman_affine_portal, cfg.cpu) = affine_portal;
	}
#endif
	return 0;
}

/***************/
/* Driver load */
/***************/

int qman_thread_init(int cpu)
{
	/* Load the core-affine portal */
	int ret = (get_cpu_var(qman_affine_portal) != NULL);
	put_cpu_var(qman_affine_portal);
	if (ret) {
		pr_err("Qman portal already initialised (%d)\n", cpu);
		return -EBUSY;
	}
	ret = fsl_qman_portal_init(cpu);
	if (ret) {
		pr_err("Qman portal failed initialisation (%d), ret=%d\n",
			cpu, ret);
		return ret;
	}
	pr_info("Qman portal initialised (%d)\n", cpu);
	if (__fqalloc_init())
		pr_err("Qman FQ allocator failed to initialise, continuing\n");
	return 0;
}

