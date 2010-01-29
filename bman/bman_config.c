/* Copyright (c) 2009 Freescale Semiconductor, Inc.
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

#ifndef CONFIG_SMP
#include <linux/smp.h>	/* get_hard_smp_processor_id() */
#endif

#include "bman_private.h"

/* Last updated for v00.79 of the BG */

struct bman;

/* Register offsets */
#define REG_POOL_SWDET(n)	(0x0000 + ((n) * 0x04))
#define REG_POOL_HWDET(n)	(0x0100 + ((n) * 0x04))
#define REG_POOL_SWDXT(n)	(0x0200 + ((n) * 0x04))
#define REG_POOL_HWDXT(n)	(0x0300 + ((n) * 0x04))
#define REG_IP_REV_1		0x0bf8
#define REG_IP_REV_2		0x0bfc
#define REG_FBPR_BARE		0x0c00
#define REG_FBPR_BAR		0x0c04
#define REG_FBPR_AR		0x0c10
#define REG_SRCIDR		0x0d04
#define REG_LIODNR		0x0d08
#define REG_ERR_ISR		0x0e00	/* + "enum bm_isr_reg" */

/* Used by all error interrupt registers except 'inhibit' */
#define BM_EIRQ_IVCI	0x00000010	/* Invalid Command Verb */
#define BM_EIRQ_FLWI	0x00000008	/* FBPR Low Watermark */
#define BM_EIRQ_MBEI	0x00000004	/* Multi-bit ECC Error */
#define BM_EIRQ_SBEI	0x00000002	/* Single-bit ECC Error */
#define BM_EIRQ_BSCN	0x00000001	/* pool State Change Notification */

/**
 * bm_err_isr_<reg>_<verb> - Manipulate global interrupt registers
 * @v: for accessors that write values, this is the 32-bit value
 *
 * Manipulates BMAN_ERR_ISR, BMAN_ERR_IER, BMAN_ERR_ISDR, BMAN_ERR_IIR. All
 * manipulations except bm_err_isr_[un]inhibit() use 32-bit masks composed of
 * the BM_EIRQ_*** definitions. Note that "bm_err_isr_enable_write" means
 * "write the enable register" rather than "enable the write register"!
 */
#define bm_err_isr_status_read(bm)	__bm_err_isr_read(bm, bm_isr_status)
#define bm_err_isr_status_clear(bm, m)	__bm_err_isr_write(bm, bm_isr_status,m)
#define bm_err_isr_enable_read(bm)	__bm_err_isr_read(bm, bm_isr_enable)
#define bm_err_isr_enable_write(bm, v)	__bm_err_isr_write(bm, bm_isr_enable,v)
#define bm_err_isr_disable_read(bm)	__bm_err_isr_read(bm, bm_isr_disable)
#define bm_err_isr_disable_write(bm, v)	__bm_err_isr_write(bm, bm_isr_disable,v)
#define bm_err_isr_inhibit(bm)		__bm_err_isr_write(bm, bm_isr_inhibit,1)
#define bm_err_isr_uninhibit(bm)	__bm_err_isr_write(bm, bm_isr_inhibit,0)

/*
 * TODO: unimplemented registers
 *
 * BMAN_POOLk_SDCNT, BMAN_POOLk_HDCNT, BMAN_POOLk_CONTENT, BMAN_FULT,
 * BMAN_VLDPL, BMAN_ECSR, BMAN_ECIR, BMAN_EADR, BMAN_EECC, BMAN_EDATA<n>,
 * BMAN_SBET, BMAN_EINJ, BMAN_SBEC[0|1]
 */

/* Encapsulate "struct bman *" as a cast of the register space address. */

static struct bman *bm_create(void *regs)
{
	return (struct bman *)regs;
}

static inline u32 __bm_in(struct bman *bm, u32 offset)
{
	return in_be32((void *)bm + offset);
}
static inline void __bm_out(struct bman *bm, u32 offset, u32 val)
{
	out_be32((void *)bm + offset, val);
}
#define bm_in(reg)		__bm_in(bm, REG_##reg)
#define bm_out(reg, val)	__bm_out(bm, REG_##reg, val)

#if 0

static u32 __bm_err_isr_read(struct bman *bm, enum bm_isr_reg n)
{
	return __bm_in(bm, REG_ERR_ISR + (n << 2));
}

static void __bm_err_isr_write(struct bman *bm, enum bm_isr_reg n, u32 val)
{
	__bm_out(bm, REG_ERR_ISR + (n << 2), val);
}

static void bm_get_details(struct bman *bm, u8 *int_options, u8 *errata,
			u8 *conf_options)
{
	u32 v = bm_in(IP_REV_1);
	*int_options = (v >> 16) & 0xff;
	*errata = (v >> 8) & 0xff;
	*conf_options = v & 0xff;
}

static u8 bm_get_corenet_sourceid(struct bman *bm)
{
	return bm_in(SRCIDR);
}

static void bm_set_liodn(struct bman *bm, u16 liodn)
{
	bm_out(LIODNR, liodn & 0xfff);
}

#endif

static void bm_get_version(struct bman *bm, u16 *id, u8 *major, u8 *minor)
{
	u32 v = bm_in(IP_REV_1);
	*id = (v >> 16);
	*major = (v >> 8) & 0xff;
	*minor = v & 0xff;
}

static u32 __generate_thresh(u32 val, int roundup)
{
	u32 e = 0;	/* co-efficient, exponent */
	int oddbit = 0;
	while(val > 0xff) {
		oddbit = val & 1;
		val >>= 1;
		e++;
		if(roundup && oddbit)
			val++;
	}
	BM_ASSERT(e < 0x10);
	return (val | (e << 8));
}

static void bm_set_pool(struct bman *bm, u8 pool, u32 swdet, u32 swdxt,
			u32 hwdet, u32 hwdxt)
{
	BM_ASSERT(pool < 64);
	bm_out(POOL_SWDET(pool), __generate_thresh(swdet, 0));
	bm_out(POOL_SWDXT(pool), __generate_thresh(swdxt, 1));
	bm_out(POOL_HWDET(pool), __generate_thresh(hwdet, 0));
	bm_out(POOL_HWDXT(pool), __generate_thresh(hwdxt, 1));
}

static void bm_set_memory(struct bman *bm, u16 eba, u32 ba, int prio, u32 size)
{
	u32 exp = ilog2(size);
	/* choke if size isn't within range */
	BM_ASSERT((size >= 4096) && (size <= 1073741824) &&
			is_power_of_2(size));
	/* choke if '[e]ba' has lower-alignment than 'size' */
	BM_ASSERT(!(ba & (size - 1)));
	bm_out(FBPR_BARE, eba);
	bm_out(FBPR_BAR, ba);
	bm_out(FBPR_AR, (prio ? 0x40000000 : 0) | (exp - 1));
}

/*****************/
/* Config driver */
/*****************/

/* We support only one of these. */
static struct bman *bm;

/* TODO: Kconfig these? */
#define DEFAULT_FBPR_SZ	(PAGE_SIZE << 12)

/* Parse the <name> property to extract the memory location and size and
 * lmb_reserve() it. If it isn't supplied, lmb_alloc() the default size. */
static __init int parse_mem_property(struct device_node *node, const char *name,
				dma_addr_t *addr, size_t *sz, int zero)
{
	const u32 *pint;
	int ret;

	pint = of_get_property(node, name, &ret);
	if (!pint || (ret != 16)) {
		pr_info("No %s property '%s', using lmb_alloc(%08x)\n",
				node->full_name, name, *sz);
		*addr = lmb_alloc(*sz, *sz);
		if (zero)
			memset(phys_to_virt(*addr), 0, *sz);
		return 0;
	}
	pr_info("Using %s property '%s'\n", node->full_name, name);
	/* Props are 64-bit, but dma_addr_t is (currently) 32-bit */
	BUG_ON(sizeof(*addr) != 4);
	BUG_ON(pint[0] || pint[2]);
	*addr = pint[1];
	*sz = pint[3];
	/* Keep things simple, it's either all in the DRAM range or it's all
	 * outside. */
	if (*addr < lmb_end_of_DRAM()) {
		BUG_ON((u64)*addr + (u64)*sz > lmb_end_of_DRAM());
		if (lmb_reserve(*addr, *sz) < 0) {
			pr_err("Failed to reserve %s\n", name);
			return -ENOMEM;
		}
		if (zero)
			memset(phys_to_virt(*addr), 0, *sz);
	} else {
		/* map as cacheable, non-guarded */
		void *tmpp = ioremap_flags(*addr, *sz, 0);
		if (zero)
			memset(tmpp, 0, *sz);
		iounmap(tmpp);
	}
	return 0;
}

static int __init fsl_bman_init(struct device_node *node)
{
	struct resource res;
	u32 __iomem *regs;
	dma_addr_t fbpr_a;
	size_t fbpr_sz = DEFAULT_FBPR_SZ;
	int ret;
	u16 id;
	u8 major, minor;

	ret = of_address_to_resource(node, 0, &res);
	if (ret) {
		pr_err("Can't get %s property 'reg'\n",
				node->full_name);
		return ret;
	}
	ret = parse_mem_property(node, "fsl,bman-fbpr", &fbpr_a, &fbpr_sz, 0);
	BUG_ON(ret);
	/* Global configuration */
	regs = ioremap(res.start, res.end - res.start + 1);
	bm = bm_create(regs);
	BUG_ON(!bm);
	bm_get_version(bm, &id, &major, &minor);
	pr_info("Bman ver:%04x,%02x,%02x\n", id, major, minor);
	/* FBPR memory */
	bm_set_memory(bm, 0, (u32)fbpr_a, 0, fbpr_sz);
	/* TODO: add interrupt handling here, so that ISR is cleared *after*
	 * FBPR initialisation. */
	return 0;
}

int bman_have_ccsr(void)
{
	return (bm ? 1 : 0);
}

int bm_pool_set(u32 bpid, const u32 *thresholds)
{
	if (!bm)
		return -ENODEV;
	bm_set_pool(bm, bpid, thresholds[0], thresholds[1],
		thresholds[2], thresholds[3]);
	return 0;
}
EXPORT_SYMBOL(bm_pool_set);

__init void bman_init_early(void)
{
	struct device_node *dn;
	for_each_compatible_node(dn, NULL, "fsl,bman") {
		if (bm)
			pr_err("%s: only one 'fsl,bman' allowed\n",
				dn->full_name);
		else {
			int ret = fsl_bman_init(dn);
			BUG_ON(ret);
		}
	}
}

