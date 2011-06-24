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
#include "bman_private.h"

/*
 * Global variables of the max portal/pool number this bman version supported
 */
u16 bman_ip_rev;
EXPORT_SYMBOL(bman_ip_rev);
u16 bman_pool_max;
EXPORT_SYMBOL(bman_pool_max);

/*****************/
/* Portal driver */
/*****************/

static __thread int fd = -1;
static __thread const struct qbman_uio_irq *irq;

static struct bman_depletion pools;
static u8 num_pools;
static DEFINE_SPINLOCK(pools_lock);

struct bman_bpid_ranges {
	unsigned int num_ranges;
	const struct bman_bpid_range {
		u32 start;
		u32 num;
	} *ranges;
};
static const struct bman_bpid_range bpid_range[] =
	{ {FSL_BPID_RANGE_START, FSL_BPID_RANGE_LENGTH} };
static const struct bman_bpid_ranges bpid_allocator = {
	.num_ranges = 1,
	.ranges = bpid_range
};

int bm_pool_new(u32 *bpid)
{
	int ret = 0, b = bman_pool_max;
	spin_lock(&pools_lock);
	if (num_pools >= bman_pool_max)
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
	BUG_ON(bpid >= bman_pool_max);
	BUG_ON(!bman_depletion_get(&pools, bpid));
	bman_depletion_unset(&pools, bpid);
	num_pools--;
	spin_unlock(&pools_lock);
}

static int __init fsl_bman_portal_init(int cpu, int recovery_mode)
{
	const struct device_node *dt_node;
	struct bm_portal_config *pcfg;
	struct bman_portal *portal;
	int ret = 0;
	char name[20]; /* Big enough for "/dev/bman-uio-xx" */

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
	for_each_compatible_node(dt_node, NULL, "fsl,bman-portal") {
		size_t lenp;
		const u32 *cell_index;
		int cpu_idx;
		const phandle *cpu_ph = of_get_property(dt_node, "cpu-handle",
							&lenp);
		if (!cpu_ph)
			continue;
		if (lenp != sizeof(phandle)) {
			pr_err("Malformed property %s:cpu-handle\n",
				dt_node->full_name);
			continue;
		}
		cpu_idx = check_cpu_phandle(*cpu_ph);
		if (cpu_idx != cpu)
			continue;
		cell_index = of_get_property(dt_node, "cell-index", &lenp);
		if (!cell_index || (lenp != sizeof(*cell_index))) {
			pr_err("Malformed property %s:cell-index\n",
				dt_node->full_name);
			continue;
		}
		sprintf(name, "/dev/bman-uio-%x", *cell_index);
		fd = open(name, O_RDWR);
		if (fd >= 0)
			break;
	}
	if (fd < 0) {
		ret = -ENODEV;
		goto end;
	}
	pcfg->addr.addr_ce = mmap(NULL, 16*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	pcfg->addr.addr_ci = mmap(NULL, 4*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4*1024);
	if ((pcfg->addr.addr_ce == MAP_FAILED) ||
			(pcfg->addr.addr_ci == MAP_FAILED)) {
		pr_err("Bman mmap()s failed with %p:%p\n",
			pcfg->addr.addr_ce, pcfg->addr.addr_ci);
		perror("mmap of CENA or CINH failed");
		ret = -ENODEV;
		goto end;
	}
	pcfg->public_cfg.cpu = cpu;
	pcfg->public_cfg.irq = fd;
	bman_depletion_fill(&pcfg->public_cfg.mask);

	if (pcfg->public_cfg.cpu == -1)
		goto end;

	portal = bman_create_affine_portal(pcfg, 0, 0, recovery_mode);
	if (!portal) {
		pr_err("Bman portal initialisation failed (%d)\n",
			pcfg->public_cfg.cpu);
		goto end;
	}
#ifdef CONFIG_FSL_DPA_HAVE_IRQ
#endif
	/* bman_create_affine_portal() will have called request_irq(), which in
	 * USDPAA-speak, means we have to retrieve the handler here. */
	irq = qbman_get_irq_handler(fd);
	if (!irq)
		pr_warning("Bman portal interrupt handling is disabled (%d)\n",
			pcfg->public_cfg.cpu);

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

static int fsl_bman_portal_finish(void)
{
	const struct bm_portal_config *cfg;
	int ret;

	cfg = bman_destroy_affine_portal();
	ret = munmap(cfg->addr.addr_ce, 16*1024);
	if (ret) {
		perror("munmap() of Bman ADDR_CE failed");
		goto end;
	}
	ret = munmap(cfg->addr.addr_ci, 4*1024);
	if (ret) {
		perror("munmap() of Bman ADDR_CI failed");
		goto end;
	}
end:
	if (ret)
		pr_err("Bman portal cleanup failed (%d), ret=%d\n",
			cfg->public_cfg.cpu, ret);
	/* The cast is to remove the const attribute. NB, the 'cfg' pointer
	 * lives in the portal and is supposed to be read-only while it is being
	 * used. However bman_driver.c allocates it when setting up the portal
	 * and destroys it here when tearing the portal down, so that's why this
	 * is justified. */
	free((void *)cfg);
	close(fd);
	fd = -1;
	return ret;
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
			if (bpid >= bman_pool_max) {
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
	return fsl_bman_portal_init(cpu, recovery_mode);
}

int bman_thread_finish(void)
{
	return fsl_bman_portal_finish();
}

int bman_thread_fd(void)
{
	return fd;
}

void bman_thread_irq(void)
{
	const struct bman_portal_config *cfg = bman_get_portal_config();
	const struct bm_portal_config *pcfg = container_of(cfg,
			const struct bm_portal_config, public_cfg);
	if (!irq)
		return;
	irq->isr(fd, irq->arg);
	/* Now we need to uninhibit interrupts. This is the only code outside
	 * the regular portal driver that manipulates any portal register, so
	 * rather than breaking that encapsulation I am simply hard-coding the
	 * offset to the inhibit register here. */
	out_be32(pcfg->addr.addr_ci + 0xe0c, 0);
}

int bman_global_init(int recovery_mode)
{
	const struct device_node *dt_node;
	int ret;
	static int done = 0;
	if (done)
		return -EBUSY;
	dt_node = of_find_compatible_node(NULL, NULL, "fsl,bman-portal");
	if (!dt_node) {
		pr_err("No bman portals available for any CPU\n");
		return -ENODEV;
	}
	if (of_device_is_compatible(dt_node, "fsl,bman-portal-1.0")) {
		bman_ip_rev = BMAN_REV10;
		bman_pool_max = 64;
	} else if (of_device_is_compatible(dt_node, "fsl,bman-portal-2.0")) {
		bman_ip_rev = BMAN_REV20;
		bman_pool_max = 8;
	}
	if (!bman_ip_rev) {
		pr_err("Unknown bman portal version\n");
		return -ENODEV;
	}
	num_pools = bman_pool_max;
	bman_depletion_fill(&pools);
	ret = fsl_bpool_range_init(recovery_mode, &bpid_allocator);
	if (ret) {
		pr_err("Bman pool range set failed\n");
		return ret;
	}
	done = 1;
	return 0;
}
