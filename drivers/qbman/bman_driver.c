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

static __thread int fd;

static struct bm_portal_config configs[PORTAL_MAX];
static u8 num_portals;

static struct bman_depletion pools = BMAN_DEPLETION_FULL;
static u8 num_pools = 64;
static DEFINE_SPINLOCK(pools_lock);

static struct bm_portal_config *__bm_portal_add(
					const struct bm_portal_config *config)
{
	struct bm_portal_config *ret;
	BUG_ON((num_portals + 1) > PORTAL_MAX);
	ret = &configs[num_portals++];
	*ret = *config;
	return ret;
}

u8 bm_portal_num(void)
{
	return num_portals;
}

const struct bm_portal_config *bm_portal_config(u8 idx)
{
	if (unlikely(idx >= num_portals))
		return NULL;

	return &configs[idx];
}

int bm_pool_new(u32 *bpid)
{
	int ret = 0, b = 64;
	spin_lock(&pools_lock);
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
	spin_unlock(&pools_lock);
	return ret;
}

void bm_pool_free(u32 bpid)
{
	spin_lock(&pools_lock);
	BUG_ON(bpid > 63);
	BUG_ON(!bman_depletion_get(&pools, bpid));
	bman_depletion_unset(&pools, bpid);
	num_pools--;
	spin_unlock(&pools_lock);
}

static int __init fsl_bman_portal_init(int cpu, int recovery_mode)
{
	struct bm_portal_config cfg, *pconfig;
	char name[8], *path;

	snprintf(name, 7, "BMAN%d", cpu);
	path = getenv(name);
	if (!path) {
		pr_err("Bman cpu %d needs %s set\n", cpu, name);
		return -ENODEV;
	}
	fd = open(path, O_RDWR);
	if (fd < 0) {
		perror("can't open Bman portal UIO device");
		return -ENODEV;
	}
	cfg.addr.addr_ce = mmap(BMAN_CENA(cpu), 16*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
	cfg.addr.addr_ci = mmap(BMAN_CINH(cpu), 4*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4*1024);
	if ((cfg.addr.addr_ce == MAP_FAILED) ||
			(cfg.addr.addr_ci == MAP_FAILED)) {
		pr_err("Bman mmap()s failed with %p:%p\n",
			cfg.addr.addr_ce, cfg.addr.addr_ci);
		perror("mmap of CENA or CINH failed");
		close(fd);
		return -ENODEV;
	}
	cfg.public_cfg.cpu = cpu;
	cfg.public_cfg.irq = -1;
	bman_depletion_fill(&cfg.public_cfg.mask);
	pconfig = __bm_portal_add(&cfg);
	if (!pconfig) {
		close(fd);
		return -ENOMEM;
	}
	pr_info("Bman portal at %p:%p (%d)\n", cfg.addr.addr_ce,
		cfg.addr.addr_ci, cfg.public_cfg.cpu);
	if (cfg.public_cfg.cpu == -1)
		return 0;
	if (!bman_have_affine_portal()) {
		u32 irq_sources = 0;
#ifdef CONFIG_FSL_DPA_HAVE_IRQ
		irq_sources = BM_PIRQ_RCRI | BM_PIRQ_BSCN;
#endif
		if (bman_create_affine_portal(pconfig, irq_sources,
						recovery_mode))
			pr_err("Bman portal auto-initialisation failed\n");
		else
			pr_info("Bman portal %d auto-initialised\n",
				cfg.public_cfg.cpu);
	}
	return 0;
}

static int fsl_bpool_range_init(int recovery_mode,
				const struct bman_bpid_ranges *bpids)
{
	int ret, warned = 0;
	u32 bpid, range;
	for (range = 0; range < bpids->num_ranges; range++) {
		for (bpid = bpids->ranges[range].start;
				bpid < (bpids->ranges[range].start +
					bpids->ranges[range].num);
				bpid++) {
			if (bpid > 63) {
				pr_err("BPIDs out range\n");
				return -EINVAL;
			}
			if (!bman_depletion_get(&pools, bpid)) {
				if (!warned) {
					warned = 1;
					pr_err("BPID overlap in, ignoring\n");
				}
			} else {
				if (recovery_mode) {
					ret = bman_recovery_cleanup_bpid(bpid);
					if (ret) {
						pr_err("Failed to recover BPID "
							"%d\n", bpid);
						return ret;
					}
				}
				bman_depletion_unset(&pools, bpid);
				num_pools--;
			}
		}
		pr_info("Bman: BPID allocator includes range %d:%d%s\n",
			bpids->ranges[range].start, bpids->ranges[range].num,
			recovery_mode ? " (recovered)" : "");
	}
	return 0;
}

int bman_thread_init(int cpu, int recovery_mode)
{
	/* Load the core-affine portal */
	int ret = fsl_bman_portal_init(cpu, recovery_mode);
	if (ret) {
		pr_err("Bman portal failed initialisation (%d), ret=%d\n",
			cpu, ret);
		return ret;
	}
	return 0;
}

void bman_thread_finish(void)
{
	if (!bman_have_affine_portal())
		bman_destroy_affine_portal();
}

int bman_setup_allocator(int recovery_mode,
			const struct bman_bpid_ranges *bpids)
{
	return fsl_bpool_range_init(recovery_mode, bpids);
}