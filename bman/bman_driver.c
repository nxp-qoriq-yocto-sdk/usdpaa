/* Copyright (c) 2008, 2009 Freescale Semiconductor, Inc.
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

#include "bman_private.h"

/*****************/
/* Portal driver */
/*****************/

#define PORTAL_MAX	10
#define POOL_MAX	64

static struct bm_portal portals[PORTAL_MAX];
static u8 num_portals;
#ifndef CONFIG_FSL_BMAN_PORTAL_DISABLEAUTO
static u8 num_affine_portals;
#endif
static DEFINE_SPINLOCK(bind_lock);
DEFINE_PER_CPU(struct bman_portal *, bman_affine_portal);

/* The bman_depletion type is a bitfield representation of the 64 BPIDs as
 * booleans. We're not using it here to represent depletion state though, it's
 * to represent reservations. */
static struct bman_depletion pools;
static u8 num_pools;

static struct bm_portal *__bm_portal_add(const struct bm_addr *addr,
				const struct bm_portal_config *config)
{
	struct bm_portal *ret;
	BUG_ON((num_portals + 1) > PORTAL_MAX);
	ret = &portals[num_portals++];
	ret->addr = *addr;
	ret->config = *config;
	ret->config.bound = 0;
	return ret;
}

static int __bm_pool_add(u32 bpid, u32 *cfg, int triplets)
{
	u64 total = 0;
	BUG_ON((bpid + 1) > POOL_MAX);
	if (bman_depletion_get(&pools, bpid)) {
		pr_err("Duplicate pool for bpid %d\n", bpid);
		return -EBUSY;
	}
	while (triplets--) {
		struct bman_pool_params params = {
			.bpid = bpid,
			.flags = BMAN_POOL_FLAG_ONLY_RELEASE
		};
		u64 c = ((u64)cfg[0] << 32) | cfg[1];
		u64 d = ((u64)cfg[2] << 32) | cfg[3];
		u64 b = ((u64)cfg[4] << 32) | cfg[5];
		struct bman_pool *pobj = bman_new_pool(&params);
		if (!pobj)
			return -ENOMEM;
		while (c) {
			struct bm_buffer bufs[8];
			int ret, num_bufs = 0;
			do {
				BUG_ON(b > 0xffffffffffffull);
				bufs[num_bufs].bpid = bpid;
				bufs[num_bufs].hi = (b >> 32);
				bufs[num_bufs++].lo = b & 0xffffffff;
				b += d;
			} while (--c && (num_bufs < 8));
			ret = bman_release(pobj, bufs, num_bufs,
					BMAN_RELEASE_FLAG_WAIT);
			if (ret)
				panic("Seeding reserved buffer pool failed\n");
			total += num_bufs;
		}
		bman_free_pool(pobj);
		cfg += 6;
	}
	bman_depletion_set(&pools, bpid);
	num_pools++;
	if (total)
		pr_info("Bman: reserved bpid %d, seeded %lld items\n", bpid,
			total);
	else
		pr_info("Bman: reserved bpid %d\n", bpid);
	return 0;
}

int __bm_portal_bind(struct bm_portal *portal, u8 iface)
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

void __bm_portal_unbind(struct bm_portal *portal, u8 iface)
{
	spin_lock(&bind_lock);
	BM_ASSERT(portal->config.bound & iface);
	portal->config.bound &= ~iface;
	spin_unlock(&bind_lock);
}

u8 bm_portal_num(void)
{
	return num_portals;
}
EXPORT_SYMBOL(bm_portal_num);

struct bm_portal *bm_portal_get(u8 idx)
{
	if (unlikely(idx >= num_portals))
		return NULL;

	return &portals[idx];
}
EXPORT_SYMBOL(bm_portal_get);

const struct bm_portal_config *bm_portal_config(const struct bm_portal *portal)
{
	return &portal->config;
}
EXPORT_SYMBOL(bm_portal_config);

int bm_pool_new(u32 *bpid)
{
	int ret = 0, b = 64;
	spin_lock(&bind_lock);
	if (num_pools > 63)
		ret = -ENOMEM;
	else {
		while (b-- && bman_depletion_get(&pools, b))
			;
		BUG_ON(b < 0);
		bman_depletion_set(&pools, b);
		*bpid = b;
		num_pools++;
	}
	spin_unlock(&bind_lock);
	return ret;
}
EXPORT_SYMBOL(bm_pool_new);

void bm_pool_free(u32 bpid)
{
	spin_lock(&bind_lock);
	BUG_ON(bpid > 63);
	BUG_ON(!bman_depletion_get(&pools, bpid));
	bman_depletion_unset(&pools, bpid);
	num_pools--;
	spin_unlock(&bind_lock);
}
EXPORT_SYMBOL(bm_pool_free);

static int __init fsl_bman_portal_init(struct device_node *node)
{
	struct resource res[2];
	struct bm_portal_config cfg;
	struct bm_addr addr;
	struct bm_portal *portal;
	const phandle *cpu_ph = NULL;
#ifndef CONFIG_FSL_BMAN_PORTAL_DISABLEAUTO
	struct bman_portal *affine_portal;
#endif
	int irq, ret;

	ret = of_address_to_resource(node, 0, &res[0]);
	if (ret) {
		pr_err("Can't get %s property 'reg::CE'\n", node->full_name);
		return ret;
	}
	ret = of_address_to_resource(node, 1, &res[1]);
	if (ret) {
		pr_err("Can't get %s property 'reg::CI'\n", node->full_name);
		return ret;
	}
	irq = irq_of_parse_and_map(node, 0);
	if (irq == NO_IRQ) {
		pr_err("Can't get %s property 'interrupts'\n", node->full_name);
		return -ENODEV;
	}
	addr.addr_ce = ioremap_flags(res[0].start,
				res[0].end - res[0].start + 1, 0);
	addr.addr_ci = ioremap_flags(res[1].start,
				res[1].end - res[1].start + 1,
				_PAGE_GUARDED | _PAGE_NO_CACHE);
	cfg.irq = irq;
	cfg.cpu = -1;
	cpu_ph = of_get_property(node, "cpu-handle", &ret);
	if (cpu_ph && (ret == sizeof(phandle))) {
		const u32 *cpu_val;
		struct device_node *cpu_node = of_find_node_by_phandle(*cpu_ph);
		if (!cpu_node) {
			pr_err("Bad %s property 'cpu-handle'\n",
				cpu_node->full_name);
			goto bad_cpu_ph;
		}
		cpu_val = of_get_property(cpu_node, "reg", &ret);
		if (!cpu_val || (ret != sizeof(*cpu_val)))
			pr_err("Can't get %s property 'reg'\n",
				cpu_node->full_name);
		else {
			int cpu;
			bool invalid = true;

			for_each_present_cpu(cpu)
				if (*cpu_val == get_hard_smp_processor_id(cpu)) {
					invalid = false;
					break;
				}

			if (invalid)
				pr_err("Invalid cpu index %d in %s\n", *cpu_val,
					cpu_node->full_name);
			else
				cfg.cpu = cpu;
		}
		of_node_put(cpu_node);
	}
bad_cpu_ph:
	bman_depletion_fill(&cfg.mask);
	cfg.bound = 0;
	pr_info("Bman portal at %p:%p (%d)\n", addr.addr_ce, addr.addr_ci,
		cfg.cpu);
	portal = __bm_portal_add(&addr, &cfg);
	/* If the portal is affine to a cpu and that cpu has no default affine
	 * portal, auto-initialise this one for the job. */
#ifndef CONFIG_FSL_BMAN_PORTAL_DISABLEAUTO
	if (cfg.cpu == -1)
		return 0;
	affine_portal = per_cpu(bman_affine_portal, cfg.cpu);
	if (!affine_portal) {
		affine_portal = bman_create_portal(portal, &cfg.mask);
		if (!affine_portal)
			pr_err("Bman portal auto-initialisation failed\n");
		else {
			pr_info("Bman portal %d auto-initialised\n", cfg.cpu);
			per_cpu(bman_affine_portal, cfg.cpu) = affine_portal;
			num_affine_portals++;
		}
	}
#endif
	return 0;
}

static int __init fsl_bpool_init(struct device_node *node)
{
	int ret;
	u32 *cfg, *thresh;
	u32 *bpid = (u32 *)of_get_property(node, "fsl,bpid", &ret);
	if (!bpid || (ret!= 4)) {
		pr_err("Can't get %s property 'fsl,bpid'\n", node->full_name);
		return -ENODEV;
	}
	thresh = (u32 *)of_get_property(node, "fsl,bpool-thresholds", &ret);
	if (thresh) {
		if (ret != 16) {
			pr_err("Invalid %s property '%s'\n",
				node->full_name, "fsl,bpool-thresholds");
			return -ENODEV;
		}
#ifndef CONFIG_FSL_BMAN_CONFIG
		pr_err("Ignoring %s property '%s', no CCSR support\n",
			node->full_name, "fsl,bpool-thresholds");
#endif
	}
	cfg = (u32 *)of_get_property(node, "fsl,bpool-cfg", &ret);
	if (cfg && (!ret || (ret % 24))) {
		pr_err("Invalid %s property '%s'\n", node->full_name,
			"fsl,bpool-cfg");
		return -ENODEV;
	}
#ifdef CONFIG_FSL_BMAN_CONFIG
	if (cfg)
		ret = __bm_pool_add(*bpid, cfg, ret / 24);
	else
		ret = __bm_pool_add(*bpid, NULL, 0);
	if (ret) {
		pr_err("Can't reserve bpid %d from node %s\n", *bpid,
			node->full_name);
		return ret;
	}
	if (thresh) {
		ret = bm_pool_set(*bpid, thresh);
		if (ret)
			pr_err("No CCSR node for %s property '%s'\n",
				node->full_name, "fsl,bpool-thresholds");
	}
#endif
	return ret;
}

static __init int bman_init(void)
{
	struct device_node *dn;
	if (!bman_have_ccsr()) {
		/* If there's no CCSR, our bpid allocator is empty */
		bman_depletion_fill(&pools);
		num_pools = 64;
	}
	for_each_compatible_node(dn, NULL, "fsl,bman-portal") {
		int ret = fsl_bman_portal_init(dn);
		if (ret)
			return ret;
	}
#ifndef CONFIG_FSL_BMAN_PORTAL_DISABLEAUTO
	if (num_affine_portals == num_online_cpus()) {
		for_each_compatible_node(dn, NULL, "fsl,bpool") {
			int ret = fsl_bpool_init(dn);
			if (ret)
				return ret;
		}
	} else {
		pr_err("Not all cpus have an affine Bman portal\n");
		pr_err("Ignoring buffer pools\n");
		pr_err("Expect Bman-dependent drivers to crash!\n");
	}
#endif
	return 0;
	pr_info("Bman driver initialised\n");
}
subsys_initcall(bman_init);
