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
 * where CCSR isn't available) */
u16 qman_ip_rev;

/*****************/
/* Portal driver */
/*****************/

#define PORTAL_MAX	10
#define POOL_MAX	16

/* NB: we waste an entry because idx==0 isn't valid (pool-channels have hardware
 * indexing from 1..15, as is reflected in the way SDQCR is encoded). However
 * this scheme lets us use cell-index rather than searching. */
struct __pool_channel {
	struct qm_pool_channel cfg;
	phandle ph;
};
static struct __pool_channel pools[POOL_MAX];
static u32 pools_mask;

static struct qm_portal portals[PORTAL_MAX];
static u8 num_portals;
#ifndef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO
static u8 num_affine_portals;
#endif
static DEFINE_SPINLOCK(bind_lock);
DEFINE_PER_CPU(struct qman_portal *, qman_affine_portal);

static int __qm_pool_add(u32 idx, enum qm_channel channel, phandle ph)
{
	struct __pool_channel *c = &pools[idx];
	BUG_ON(!idx || (idx >= POOL_MAX));
	BUG_ON((channel < qm_channel_pool1) || (channel > qm_channel_pool15));
	if (c->ph)
		return -EBUSY;
	c->cfg.pool = QM_SDQCR_CHANNELS_POOL(idx);
	c->cfg.channel = channel;
	c->cfg.portals = 0;
	c->ph = ph;
	pools_mask |= c->cfg.pool;
	return 0;
}

static int __qm_link(struct qm_portal *portal, phandle pool_ph)
{
	int idx = 0;
	struct __pool_channel *pool = &pools[0];
	while ((idx < POOL_MAX) && (pool->ph != pool_ph)) {
		idx++;
		pool++;
	}
	if (idx == POOL_MAX)
		return -EINVAL;
	/* Link the pool to the portal */
	pool->cfg.portals |= (1 << portal->index);
	/* Link the portal to the pool */
	portal->config.pools |= pool->cfg.pool;
	return 0;
}

static struct qm_portal *__qm_portal_add(const struct qm_addr *addr,
				const struct qm_portal_config *config)
{
	struct qm_portal *ret;
	BUG_ON((num_portals + 1) > PORTAL_MAX);
	ret = &portals[num_portals];
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
	ret->index = num_portals++;
	return ret;
}

int __qm_portal_bind(struct qm_portal *portal, u8 iface)
{
	int ret = -EBUSY;
	spin_lock(&bind_lock);
	if (!(portal->config.bound & iface)) {
		portal->config.bound |= iface;
		ret = 0;
	}
	spin_unlock(&bind_lock);
	return ret;
}

void __qm_portal_unbind(struct qm_portal *portal, u8 iface)
{
	spin_lock(&bind_lock);
	QM_ASSERT(portal->config.bound & iface);
	portal->config.bound &= ~iface;
	spin_unlock(&bind_lock);
}

u8 qm_portal_num(void)
{
	return num_portals;
}
EXPORT_SYMBOL(qm_portal_num);

struct qm_portal *qm_portal_get(u8 idx)
{
	if (unlikely(idx >= num_portals))
		return NULL;

	return &portals[idx];
}
EXPORT_SYMBOL(qm_portal_get);

const struct qm_portal_config *qm_portal_config(const struct qm_portal *portal)
{
	return &portal->config;
}
EXPORT_SYMBOL(qm_portal_config);

u32 qm_pools(void)
{
	return pools_mask;
}
EXPORT_SYMBOL(qm_pools);

const struct qm_pool_channel *qm_pool_channel(u32 mask)
{
	u32 idx = 0, m = 1;
	struct __pool_channel *c = &pools[0];
	while ((idx < POOL_MAX) && !(mask & m)) {
		idx++;
		m <<= 1;
		c++;
	}
	if (idx == POOL_MAX)
		return NULL;
	return &c->cfg;
}
EXPORT_SYMBOL(qm_pool_channel);

static int __init fsl_qman_pool_channel_init(struct device_node *node)
{
	phandle *ph;
	int ret;
	u32 *channel, *index = (u32 *)of_get_property(node, "cell-index", &ret);
	if (!index || (ret != 4) || !*index || (*index > 15)) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"cell-index");
		return -ENODEV;
	}
	channel = (u32 *)of_get_property(node, "fsl,qman-channel-id", &ret);
	if (!channel || (ret != 4)) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"fsl,qman-channel-id");
		return -ENODEV;
	}
	if (*channel != (*index + qm_channel_pool1 - 1))
		pr_err("Warning: node %s has mismatched %s and %s\n",
			node->full_name, "cell-index", "fsl,qman-channel-id");
	ph = (phandle *)of_get_property(node, "linux,phandle", &ret);
	if (!ph || (ret != sizeof(phandle))) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"linux,phandle");
		return -ENODEV;
	}
	ret = __qm_pool_add(*index, *channel, *ph);
	if (ret)
		pr_err("Failed to register pool channel %s\n", node->full_name);
	return ret;
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

static int __init fsl_qman_portal_init(struct device_node *node)
{
	struct resource res[2];
	struct qm_portal_config cfg;
	struct qm_addr addr;
	struct qm_portal *portal;
	const u32 *index, *channel;
	const phandle *ph;
#ifndef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO
	struct qman_portal *affine_portal;
#endif
	int irq, ret, numpools;
	u16 ip_rev = 0;

	if (of_device_is_compatible(node, "fsl,qman-portal-1.1"))
		ip_rev = QMAN_REV2;
	else if (of_device_is_compatible(node, "fsl,qman-portal-1.0"))
		ip_rev = QMAN_REV1;
	if (!qman_ip_rev) {
		if (ip_rev)
			qman_ip_rev = ip_rev;
		else {
			pr_warning("unknown Qman version, presuming rev1\n");
			qman_ip_rev = QMAN_REV1;
		}
	} else if (ip_rev && (qman_ip_rev != ip_rev))
		pr_warning("Revision=0x%04x, but portal '%s' has 0x%04x\n",
			qman_ip_rev, node->full_name, ip_rev);
	ret = of_address_to_resource(node, 0, &res[0]);
	if (ret) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"reg::CE");
		return ret;
	}
	ret = of_address_to_resource(node, 1, &res[1]);
	if (ret) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"reg::CI");
		return ret;
	}
	index = of_get_property(node, "cell-index", &ret);
	if (!index || (ret != 4)) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"cell-index");
		return -ENODEV;
	}
	channel = of_get_property(node, "fsl,qman-channel-id", &ret);
	if (!channel || (ret != 4)) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"fsl,qman-channel-id");
		return -ENODEV;
	}
	if (*channel != (*index + qm_channel_swportal0))
		pr_err("Warning: node %s has mismatched %s and %s\n",
			node->full_name, "cell-index", "fsl,qman-channel-id");
	cfg.channel = *channel;
	cfg.cpu = -1;
	ph = of_get_property(node, "cpu-handle", &ret);
	if (ph && (ret != sizeof(phandle))) {
		pr_err("Malformed %s property '%s'\n", node->full_name,
			"cpu-handle");
		return -ENODEV;
	}
	if (ph) {
		const u32 *cpu_val;
		struct device_node *cpu_node = of_find_node_by_phandle(*ph);
		if (!cpu_node) {
			pr_err("Bad %s property 'cpu-handle'\n",
				cpu_node->full_name);
			goto bad_cpu_ph;
		}
		cpu_val = of_get_property(cpu_node, "reg", &ret);
		if (!cpu_val || (ret != sizeof(*cpu_val))) {
			pr_err("Can't get %s property 'reg'\n",
				cpu_node->full_name);
			ret = -ENODEV;
		} else {
			int cpu;
			ret = -ENODEV;
			for_each_present_cpu(cpu) {
				if (*cpu_val == get_hard_smp_processor_id(cpu)) {
					ret = 0;
					break;
				}
			}
			if (ret)
				pr_err("Invalid cpu index %d in %s\n", *cpu_val,
					cpu_node->full_name);
			else
				cfg.cpu = cpu;
		}
		of_node_put(cpu_node);
	}
bad_cpu_ph:
	ph = of_get_property(node, "fsl,qman-pool-channels", &ret);
	if (ph && (ret % sizeof(phandle))) {
		pr_err("Malformed %s property '%s'\n", node->full_name,
			"fsl,qman-pool-channels");
		return -ENODEV;
	}
	numpools = ph ? (ret / sizeof(phandle)) : 0;
	irq = irq_of_parse_and_map(node, 0);
	if (irq == NO_IRQ) {
		pr_err("Can't get %s property '%s'\n", node->full_name,
			"interrupts");
		return -ENODEV;
	}
	cfg.irq = irq;
	if (of_get_property(node, "fsl,hv-dma-handle", &ret))
		cfg.has_hv_dma = 1;
	else
		cfg.has_hv_dma = 0;
	addr.addr_ce = ioremap_flags(res[0].start,
				res[0].end - res[0].start + 1, 0);
	addr.addr_ci = ioremap_flags(res[1].start,
				res[1].end - res[1].start + 1,
				_PAGE_GUARDED | _PAGE_NO_CACHE);
	cfg.pools = 0;
	cfg.bound = 0;
	portal = __qm_portal_add(&addr, &cfg);
	if (!portal) {
		iounmap(addr.addr_ce);
		iounmap(addr.addr_ci);
		irq_dispose_mapping(cfg.irq);
		return -ENOMEM;
	}
	pr_info("Qman portal at %p:%p (%d:%d,v%04x)\n", addr.addr_ce,
		addr.addr_ci, cfg.cpu, cfg.channel, qman_ip_rev);
	while (numpools--) {
		int tmp = __qm_link(portal, *(ph++));
		if (tmp)
			panic("Unrecoverable error linking pool channels");
	}
	/* If the portal is affine to a cpu and that cpu has no default affine
	 * portal, auto-initialise this one for the job. */
#ifndef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO
	if (cfg.cpu == -1)
		return 0;
	affine_portal = per_cpu(qman_affine_portal, cfg.cpu);
	if (!affine_portal) {
		u32 flags = 0;
		if (cfg.has_hv_dma)
			flags = QMAN_PORTAL_FLAG_RSTASH |
				QMAN_PORTAL_FLAG_DSTASH;
		/* TODO: cgrs ?? */
		affine_portal = qman_create_portal(portal, flags, NULL,
						&null_cb);
		if (!affine_portal) {
			pr_err("Qman portal auto-initialisation failed\n");
			return 0;
		}
		/* default: enable all (available) pool channels */
		qman_static_dequeue_add_ex(affine_portal, ~0);
		pr_info("Qman portal %d auto-initialised\n", cfg.cpu);
		per_cpu(qman_affine_portal, cfg.cpu) = affine_portal;
		num_affine_portals++;
	}
#endif
	return 0;
}

/***************/
/* Driver load */
/***************/

static __init int qman_init(void)
{
	struct device_node *dn;
	int ret;
	for_each_compatible_node(dn, NULL, "fsl,qman-pool-channel") {
		ret = fsl_qman_pool_channel_init(dn);
		if (ret)
			return ret;
	}
	for_each_compatible_node(dn, NULL, "fsl,qman-portal") {
		ret = fsl_qman_portal_init(dn);
		if (ret)
			return ret;
	}
#ifndef CONFIG_FSL_QMAN_PORTAL_DISABLEAUTO
	if (num_affine_portals == num_online_cpus()) {
		u32 cgid;
		for (cgid = 0; cgid < 256; cgid++)
			if (qman_init_cgr(cgid))
				pr_err("CGR init failed on CGID %d\n",
					cgid);
	} else {
		pr_err("Not all cpus have an affine Qman portal\n");
		pr_err("Expect Qman-dependent drivers to crash!\n");
	}
#endif
#ifdef CONFIG_FSL_QMAN_FQALLOCATOR
	ret = __fqalloc_init();
	if (ret)
		return ret;
#endif
	pr_info("Qman driver initialised\n");
	return 0;
}
subsys_initcall(qman_init);
