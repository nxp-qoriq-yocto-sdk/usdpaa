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

static __thread struct bm_portal portal;
static __thread int fd;
DEFINE_PER_CPU(struct bman_portal *, bman_affine_portal);

u8 bm_portal_num(void)
{
	return 1;
}
EXPORT_SYMBOL(bm_portal_num);

struct bm_portal *bm_portal_get(u8 idx)
{
	if (unlikely(idx >= 1))
		return NULL;

	return &portal;
}
EXPORT_SYMBOL(bm_portal_get);

const struct bm_portal_config *bm_portal_config(const struct bm_portal *portal)
{
	return &portal->config;
}
EXPORT_SYMBOL(bm_portal_config);

static struct bm_portal *__bm_portal_add(const struct bm_addr *addr,
				const struct bm_portal_config *config)
{
	struct bm_portal *ret = &portal;
	ret->addr = *addr;
	ret->config = *config;
	ret->config.bound = 0;
	return ret;
}

int __bm_portal_bind(struct bm_portal *portal, u8 iface)
{
	int ret = -EBUSY;
	if (!(portal->config.bound & iface)) {
		portal->config.bound |= iface;
		ret = 0;
	}
	return ret;
}

void __bm_portal_unbind(struct bm_portal *portal, u8 iface)
{
	BM_ASSERT(portal->config.bound & iface);
	portal->config.bound &= ~iface;
}

static int __init fsl_bman_portal_init(int cpu)
{
	struct bm_portal_config cfg = {
		.cpu = cpu,
		.irq = -1,
		/* FIXME: hard-coded */
		.mask = BMAN_DEPLETION_FULL
	};
	struct bm_addr addr;
	struct bm_portal *portal;
	struct bman_portal *affine_portal;
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
	addr.addr_ce = mmap(BMAN_CENA(cfg.cpu), 16*1024, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED, fd, 0);
	if (addr.addr_ce == MAP_FAILED)
		perror("mmap of CENA failed");
	addr.addr_ci = mmap(BMAN_CINH(cfg.cpu), 4*1024, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 4*1024);
	if (addr.addr_ci == MAP_FAILED)
		perror("mmap of CINH failed");
	portal = __bm_portal_add(&addr, &cfg);
	if (!portal)
		return -ENOMEM;
	pr_info("Bman portal at %p:%p (%d)\n", addr.addr_ce, addr.addr_ci,
		cfg.cpu);
#ifndef CONFIG_FSL_BMAN_PORTAL_DISABLEAUTO
	if (cfg.cpu == -1)
		return 0;
	affine_portal = per_cpu(bman_affine_portal, cfg.cpu);
	if (!affine_portal) {
		affine_portal = bman_create_portal(portal, &cfg.mask);
		if (!affine_portal) {
			pr_err("Bman portal auto-initialisation failed\n");
			return 0;
		}
		pr_info("Bman portal %d auto-initialised\n", cfg.cpu);
		per_cpu(bman_affine_portal, cfg->cpu) = affine_portal;
	}
#endif
	return 0;
}

/***************/
/* Driver load */
/***************/

int bman_thread_init(int cpu)
{
	/* Load the core-affine portal */
	int ret = (get_cpu_var(bman_affine_portal) != NULL);
	put_cpu_var(bman_affine_portal);
	if (ret) {
		pr_err("Bman portal already initialised (%d)\n", cpu);
		return -EBUSY;
	}
	ret = fsl_bman_portal_init(cpu);
	if (ret) {
		pr_err("Bman portal failed initialisation (%d), ret=%d\n",
			cpu, ret);
		return ret;
	}
	pr_info("Bman portal initialised (%d)\n", cpu);
	return 0;
}
