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
#include <internal/process.h>
#include "bman_private.h"
#include <sys/ioctl.h>
/*
 * Global variables of the max portal/pool number this bman version supported
 */
u16 bman_ip_rev;
EXPORT_SYMBOL(bman_ip_rev);
u16 bman_pool_max;
EXPORT_SYMBOL(bman_pool_max);
#ifdef CONFIG_FSL_BMAN_CONFIG
void *bman_ccsr_map;
#endif

/*****************/
/* Portal driver */
/*****************/

static __thread int fd = -1;
static __thread struct bm_portal_config pcfg;
static __thread struct usdpaa_ioctl_portal_map map = {
	.type = usdpaa_portal_bman
};

static int __init fsl_bman_portal_init(uint32_t idx)
{
	cpu_set_t cpuset;
	struct bman_portal *portal;
	int loop, ret;
	struct usdpaa_ioctl_irq_map irq_map;

	/* Verify the thread's cpu-affinity */
	ret = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t),
				     &cpuset);
	if (ret) {
		error(0, ret, "pthread_getaffinity_np()");
		return ret;
	}
	pcfg.public_cfg.cpu = -1;
	for (loop = 0; loop < CPU_SETSIZE; loop++)
		if (CPU_ISSET(loop, &cpuset)) {
			if (pcfg.public_cfg.cpu != -1) {
				pr_err("Thread is not affine to 1 cpu\n");
				return -EINVAL;
			}
			pcfg.public_cfg.cpu = loop;
		}
	if (pcfg.public_cfg.cpu == -1) {
		pr_err("Bug in getaffinity handling!\n");
		return -EINVAL;
	}
	/* Allocate and map a bman portal */
	map.index = idx;
	ret = process_portal_map(&map);
	if (ret) {
		error(0, ret, "process_portal_map()");
		return ret;
	}
	/* Make the portal's cache-[enabled|inhibited] regions */
	pcfg.addr_virt[DPA_PORTAL_CE] = map.addr.cena;
	pcfg.addr_virt[DPA_PORTAL_CI] = map.addr.cinh;
	pcfg.public_cfg.is_shared = 0;
	pcfg.public_cfg.index = map.index;
	bman_depletion_fill(&pcfg.public_cfg.mask);

	fd = open("/dev/fsl-usdpaa-irq", O_RDONLY);
	if (fd == -1) {
		pr_err("BMan irq init failed\n");
		process_portal_unmap(&map.addr);
		return -EBUSY;
	}
	/* Use the IRQ FD as a unique IRQ number */
	pcfg.public_cfg.irq = fd;

	portal = bman_create_affine_portal(&pcfg);
	if (!portal) {
		pr_err("Bman portal initialisation failed (%d)\n",
			pcfg.public_cfg.cpu);
		process_portal_unmap(&map.addr);
		return -EBUSY;
	}
	/* Set the IRQ number */
	irq_map.type = usdpaa_portal_bman;
	irq_map.portal_cinh = map.addr.cinh;
	process_portal_irq_map(fd, &irq_map);
	return 0;
}

static int fsl_bman_portal_finish(void)
{
	__maybe_unused const struct bm_portal_config *cfg;
	int ret;

	process_portal_irq_unmap(fd);

	cfg = bman_destroy_affine_portal();
	BUG_ON(cfg != &pcfg);
	ret = process_portal_unmap(&map.addr);
	if (ret)
		error(0, ret, "process_portal_unmap()");
	return ret;
}

int bman_thread_init(void)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_portal_init(QBMAN_ANY_PORTAL_IDX);
}

int bman_thread_init_idx(uint32_t idx)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_bman_portal_init(idx);
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
	qbman_invoke_irq(pcfg.public_cfg.irq);
	/* Now we need to uninhibit interrupts. This is the only code outside
	 * the regular portal driver that manipulates any portal register, so
	 * rather than breaking that encapsulation I am simply hard-coding the
	 * offset to the inhibit register here. */
	out_be32(pcfg.addr_virt[DPA_PORTAL_CI] + 0xe0c, 0);
}


#ifdef CONFIG_FSL_BMAN_CONFIG
int bman_have_ccsr(void)
{
	if (bman_ccsr_map != NULL)
		return 1;
	else
		return 0;
}

int bman_init_ccsr(const struct device_node *node)
{
	static int ccsr_map_fd;
	uint64_t phys_addr;
	const uint32_t *bman_addr;
	uint64_t regs_size;

	bman_addr = of_get_address(node, 0, &regs_size, NULL);
	if (!bman_addr) {
		pr_err("of_get_address cannot return BMan address\n");
		return -EINVAL;
	}
	phys_addr = of_translate_address(node, bman_addr);
	if (!phys_addr) {
		pr_err("of_translate_address failed\n");
		return -EINVAL;
	}

	ccsr_map_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_map_fd < 0)) {
		pr_err("Can not open /dev/mem for BMan CCSR map\n");
		return ccsr_map_fd;
	}

	bman_ccsr_map = mmap(NULL, regs_size, PROT_READ|PROT_WRITE, MAP_SHARED,
				ccsr_map_fd, phys_addr);
	if (bman_ccsr_map == MAP_FAILED) {
		pr_err("Can not map BMan CCSR base\n");
		return -EINVAL;
	}

	return 0;
}
#endif

int bman_global_init(void)
{
	const struct device_node *dt_node;
	static int done = 0;
	if (done)
		return -EBUSY;
	/* Use the device-tree to determine IP revision until something better
	 * is devised. */
	dt_node = of_find_compatible_node(NULL, NULL, "fsl,bman-portal");
	if (!dt_node) {
		pr_err("No bman portals available for any CPU\n");
		return -ENODEV;
	}
	if (of_device_is_compatible(dt_node, "fsl,bman-portal-1.0") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-1.0.0")) {
		bman_ip_rev = BMAN_REV10;
		bman_pool_max = 64;
	} else if (of_device_is_compatible(dt_node, "fsl,bman-portal-2.0") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.0.8")) {
		bman_ip_rev = BMAN_REV20;
		bman_pool_max = 8;
	} else if (of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.0") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.1") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.2") ||
		of_device_is_compatible(dt_node, "fsl,bman-portal-2.1.3")) {
		bman_ip_rev = BMAN_REV21;
		bman_pool_max = 64;
	}
	if (!bman_ip_rev) {
		pr_err("Unknown bman portal version\n");
		return -ENODEV;
	}
#ifdef CONFIG_FSL_BMAN_CONFIG
	{
		const struct device_node *dn = of_find_compatible_node(NULL,
							NULL, "fsl,bman");
		if (!dn)
			pr_err("No bman device node available\n");

		if (bman_init_ccsr(dn))
			pr_err("BMan CCSR map failed.\n");
	}
#endif

	done = 1;
	return 0;
}

#ifdef CONFIG_FSL_BMAN_CONFIG
#define BMAN_POOL_CONTENT(n) (0x0600 + ((n) * 0x04))
u32 bm_pool_free_buffers(u32 bpid)
{
	return in_be32(bman_ccsr_map + BMAN_POOL_CONTENT(bpid));
}

static u32 __generate_thresh(u32 val, int roundup)
{
	u32 e = 0;      /* co-efficient, exponent */
	int oddbit = 0;
	while (val > 0xff) {
		oddbit = val & 1;
		val >>= 1;
		e++;
		if (roundup && oddbit)
			val++;
	}
	DPA_ASSERT(e < 0x10);
	return (val | (e << 8));
}

#define POOL_SWDET(n)       (0x0000 + ((n) * 0x04))
#define POOL_HWDET(n)       (0x0100 + ((n) * 0x04))
#define POOL_SWDXT(n)       (0x0200 + ((n) * 0x04))
#define POOL_HWDXT(n)       (0x0300 + ((n) * 0x04))
int bm_pool_set(u32 bpid, const u32 *thresholds)
{
	if (!bman_ccsr_map)
		return -ENODEV;
	if (bpid >= bman_pool_max)
		return -EINVAL;
	out_be32(bman_ccsr_map + POOL_SWDET(bpid),
					__generate_thresh(thresholds[0], 0));
	out_be32(bman_ccsr_map + POOL_SWDXT(bpid),
					__generate_thresh(thresholds[1], 1));
	out_be32(bman_ccsr_map + POOL_HWDET(bpid),
					__generate_thresh(thresholds[2], 0));
	out_be32(bman_ccsr_map + POOL_HWDXT(bpid),
					__generate_thresh(thresholds[3], 1));
	return 0;
}
#endif
