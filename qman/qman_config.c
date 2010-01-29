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

#ifndef CONFIG_SMP
#include <linux/smp.h>	/* get_hard_smp_processor_id() */
#endif

#include "qman_private.h"

/* Last updated for v00.800 of the BG */

/* Register offsets */
#define REG_QCSP_PID_CFG(n)	(0x0000 + ((n) * 0x10))
#define REG_QCSP_IO_CFG(n)	(0x0004 + ((n) * 0x10))
#define REG_QCSP_DD_CFG(n)	(0x000c + ((n) * 0x10))
#define REG_DD_CFG		0x0200
#define REG_DCP_CFG(n)		(0x0300 + ((n) * 0x10))
#define REG_DCP_DD_CFG(n)	(0x0304 + ((n) * 0x10))
#define REG_PFDR_FPC		0x0400
#define REG_PFDR_FP_HEAD	0x0404
#define REG_PFDR_FP_TAIL	0x0408
#define REG_PFDR_FP_LWIT	0x0410
#define REG_PFDR_CFG		0x0414
#define REG_SFDR_CFG		0x0500
#define REG_WQ_CS_CFG(n)	(0x0600 + ((n) * 0x04))
#define REG_WQ_DEF_ENC_WQID	0x0630
#define REG_WQ_SC_DD_CFG(n)	(0x640 + ((n) * 0x04))
#define REG_WQ_PC_DD_CFG(n)	(0x680 + ((n) * 0x04))
#define REG_WQ_DC0_DD_CFG(n)	(0x6c0 + ((n) * 0x04))
#define REG_WQ_DC1_DD_CFG(n)	(0x700 + ((n) * 0x04))
#define REG_WQ_DCn_DD_CFG(n)	(0x6c0 + ((n) * 0x40)) /* n=2,3 */
#define REG_CM_CFG		0x0800
#define REG_MCR			0x0b00
#define REG_MCP(n)		(0x0b04 + ((n) * 0x04))
#define REG_HID_CFG		0x0bf0
#define REG_IP_REV_1		0x0bf8
#define REG_IP_REV_2		0x0bfc
#define REG_FQD_BARE		0x0c00
#define REG_PFDR_BARE		0x0c20
#define REG_offset_BAR		0x0004	/* relative to REG_[FQD|PFDR]_BARE */
#define REG_offset_AR		0x0010	/* relative to REG_[FQD|PFDR]_BARE */
#define REG_QCSP_BARE		0x0c80
#define REG_QCSP_BAR		0x0c84
#define REG_CI_SCHED_CFG	0x0d00
#define REG_SRCIDR		0x0d04
#define REG_LIODNR		0x0d08
#define REG_ERR_ISR		0x0e00	/* + "enum qm_isr_reg" */

/* Assists for QMAN_MCR */
#define MCR_INIT_PFDR		0x01000000
#define MCR_get_rslt(v)		(u8)((v) >> 24)
#define MCR_rslt_idle(r)	(!rslt || (rslt >= 0xf0))
#define MCR_rslt_ok(r)		(rslt == 0xf0)
#define MCR_rslt_eaccess(r)	(rslt == 0xf8)
#define MCR_rslt_inval(r)	(rslt == 0xff)

struct qman;

/* Follows WQ_CS_CFG0-5 */
enum qm_wq_class {
	qm_wq_portal = 0,
	qm_wq_pool = 1,
	qm_wq_fman0 = 2,
	qm_wq_fman1 = 3,
	qm_wq_caam = 4,
	qm_wq_pme = 5,
	qm_wq_first = qm_wq_portal,
	qm_wq_last = qm_wq_pme
};

/* Follows FQD_[BARE|BAR|AR] and PFDR_[BARE|BAR|AR] */
enum qm_memory {
	qm_memory_fqd,
	qm_memory_pfdr
};

/* Used by all error interrupt registers except 'inhibit' */
#define QM_EIRQ_CIDE	0x20000000	/* Corenet Initiator Data Error */
#define QM_EIRQ_CTDE	0x10000000	/* Corenet Target Data Error */
#define QM_EIRQ_CITT	0x08000000	/* Corenet Invalid Target Transaction */
#define QM_EIRQ_PLWI	0x04000000	/* PFDR Low Watermark */
#define QM_EIRQ_MBEI	0x01000000	/* Multi-bit ECC Error */
#define QM_EIRQ_SBEI	0x00800000	/* Single-bit ECC Error */
#define QM_EIRQ_ICVI	0x00010000	/* Invalid Command Verb */
#define QM_EIRQ_IDDI	0x00000800	/* Invalid Dequeue (Direct-connect) */
#define QM_EIRQ_IDFI	0x00000400	/* Invalid Dequeue FQ */
#define QM_EIRQ_IDSI	0x00000200	/* Invalid Dequeue Source */
#define QM_EIRQ_IDQI	0x00000100	/* Invalid Dequeue Queue */
#define QM_EIRQ_IEOI	0x00000008	/* Invalid Enqueue Overflow */
#define QM_EIRQ_IESI	0x00000004	/* Invalid Enqueue State */
#define QM_EIRQ_IECI	0x00000002	/* Invalid Enqueue Channel */
#define QM_EIRQ_IEQI	0x00000001	/* Invalid Enqueue Queue */

/**
 * qm_err_isr_<reg>_<verb> - Manipulate global interrupt registers
 * @v: for accessors that write values, this is the 32-bit value
 *
 * Manipulates QMAN_ERR_ISR, QMAN_ERR_IER, QMAN_ERR_ISDR, QMAN_ERR_IIR. All
 * manipulations except qm_err_isr_[un]inhibit() use 32-bit masks composed of
 * the QM_EIRQ_*** definitions. Note that "qm_err_isr_enable_write" means
 * "write the enable register" rather than "enable the write register"!
 */
#define qm_err_isr_status_read(qm)	__qm_err_isr_read(qm, qm_isr_status)
#define qm_err_isr_status_clear(qm, m)	__qm_err_isr_write(qm, qm_isr_status,m)
#define qm_err_isr_enable_read(qm)	__qm_err_isr_read(qm, qm_isr_enable)
#define qm_err_isr_enable_write(qm, v)	__qm_err_isr_write(qm, qm_isr_enable,v)
#define qm_err_isr_disable_read(qm)	__qm_err_isr_read(qm, qm_isr_disable)
#define qm_err_isr_disable_write(qm, v)	__qm_err_isr_write(qm, qm_isr_disable,v)
#define qm_err_isr_inhibit(qm)		__qm_err_isr_write(qm, qm_isr_inhibit,1)
#define qm_err_isr_uninhibit(qm)	__qm_err_isr_write(qm, qm_isr_inhibit,0)

/*
 * TODO: unimplemented registers
 *
 * Keeping a list here of Qman registers I have not yet covered;
 * QCSP_DD_IHRSR, QCSP_DD_IHRFR, QCSP_DD_HASR,
 * DCP_DD_IHRSR, DCP_DD_IHRFR, DCP_DD_HASR, CM_CFG,
 * QMAN_ECSR, QMAN_ECIR, QMAN_EADR, QMAN_EECC, QMAN_EDATA0-7,
 * QMAN_SBET, QMAN_EINJ, QMAN_SBEC0-12
 */

/* Encapsulate "struct qman *" as a cast of the register space address. */

static struct qman *qm_create(void *regs)
{
	return (struct qman *)regs;
}

static inline u32 __qm_in(struct qman *qm, u32 offset)
{
	return in_be32((void *)qm + offset);
}
static inline void __qm_out(struct qman *qm, u32 offset, u32 val)
{
	out_be32((void *)qm + offset, val);
}
#define qm_in(reg)		__qm_in(qm, REG_##reg)
#define qm_out(reg, val)	__qm_out(qm, REG_##reg, val)

#if 0

static u32 __qm_err_isr_read(struct qman *qm, enum qm_isr_reg n)
{
	return __qm_in(qm, REG_ERR_ISR + (n << 2));
}

static void __qm_err_isr_write(struct qman *qm, enum qm_isr_reg n, u32 val)
{
	__qm_out(qm, REG_ERR_ISR + (n << 2), val);
}

static void qm_set_portal(struct qman *qm, u8 swportalID,
			u16 ec_tp_cfg, u16 ecd_tp_cfg)
{
	qm_out(QCSP_DD_CFG(swportalID),
		((ec_tp_cfg & 0x1ff) << 16) | (ecd_tp_cfg & 0x1ff));
}

static void qm_set_ddebug(struct qman *qm, u8 mdd, u8 m_cfg)
{
	qm_out(DD_CFG, ((mdd & 0x3) << 4) | (m_cfg & 0xf));
}

static void qm_set_dc(struct qman *qm, enum qm_dc_portal portal, int ed, u8 sernd)
{
	QM_ASSERT(!ed || (portal == qm_dc_portal_fman0) ||
			(portal == qm_dc_portal_fman1));
	qm_out(DCP_CFG(portal), (ed ? 0x100 : 0) | (sernd & 0x1f));
}

static void qm_set_dc_ddebug(struct qman *qm, enum qm_dc_portal portal, u16 ecd_tp_cfg)
{
	qm_out(DCP_DD_CFG(portal), ecd_tp_cfg & 0x1ff);
}

static u32 qm_get_pfdr_free_pool_count(struct qman *qm)
{
	return qm_in(PFDR_FPC);
}

static void qm_get_pfdr_free_pool(struct qman *qm, u32 *head, u32 *tail)
{
	*head = qm_in(PFDR_FP_HEAD);
	*tail = qm_in(PFDR_FP_TAIL);
}

static void qm_set_default_wq(struct qman *qm, u16 wqid)
{
	qm_out(WQ_DEF_ENC_WQID, wqid);
}

static void qm_set_channel_ddebug(struct qman *qm, enum qm_channel channel,
				u16 tp_cfg)
{
	u32 offset;
	int upperhalf = 0;
	if ((channel >= qm_channel_swportal0) &&
				(channel <= qm_channel_swportal9)) {
		offset = (channel - qm_channel_swportal0);
		upperhalf = offset & 0x1;
		offset = REG_WQ_SC_DD_CFG(offset / 2);
	} else if ((channel >= qm_channel_pool1) &&
				(channel <= qm_channel_pool15)) {
		offset = (channel + 1 - qm_channel_pool1);
		upperhalf = offset & 0x1;
		offset = REG_WQ_PC_DD_CFG(offset / 2);
	} else if ((channel >= qm_channel_fman0_sp0) &&
				(channel <= qm_channel_fman0_sp11)) {
		offset = (channel - qm_channel_fman0_sp0);
		upperhalf = offset & 0x1;
		offset = REG_WQ_DC0_DD_CFG(offset / 2);
	}
	else if ((channel >= qm_channel_fman1_sp0) &&
				(channel <= qm_channel_fman1_sp11)) {
		offset = (channel - qm_channel_fman1_sp0);
		upperhalf = offset & 0x1;
		offset = REG_WQ_DC1_DD_CFG(offset / 2);
	}
	else if (channel == qm_channel_caam)
		offset = REG_WQ_DCn_DD_CFG(2);
	else if (channel == qm_channel_pme)
		offset = REG_WQ_DCn_DD_CFG(3);
	else {
		pr_crit("Illegal qm_channel type %d\n", channel);
		return;
	}
	__qm_out(qm, offset, upperhalf ? ((u32)tp_cfg << 16) : tp_cfg);
}

static void qm_get_details(struct qman *qm, u8 *int_options, u8 *errata,
			u8 *conf_options)
{
	u32 v = qm_in(IP_REV_1);
	*int_options = (v >> 16) & 0xff;
	*errata = (v >> 8) & 0xff;
	*conf_options = v & 0xff;
}

static void qm_set_corenet_bar(struct qman *qm, u16 eba, u32 ba)
{
	/* choke if 'ba' isn't properly aligned */
	QM_ASSERT(!(ba & 0x001fffff));
	qm_out(QCSP_BARE, eba);
	qm_out(QCSP_BAR, ba);
}

static u8 qm_get_corenet_sourceid(struct qman *qm)
{
	return qm_in(SRCIDR);
}

static u16 qm_get_liodn(struct qman *qm)
{
	return qm_in(LIODNR);
}

static void qm_set_congestion_config(struct qman *qm, u16 pres)
{
	qm_out(CM_CFG, pres);
}

#endif

static void qm_set_wq_scheduling(struct qman *qm, enum qm_wq_class wq_class,
			u8 cs_elev, u8 csw2, u8 csw3, u8 csw4, u8 csw5,
			u8 csw6, u8 csw7)
{
#ifdef CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1
#define csw(x) \
do { \
	if (++x == 8) \
		x = 7; \
} while (0)
	if (qman_ip_rev == QMAN_REV1) {
		csw(csw2);
		csw(csw3);
		csw(csw4);
		csw(csw5);
		csw(csw6);
		csw(csw7);
	}
#endif
	qm_out(WQ_CS_CFG(wq_class), ((cs_elev & 0xff) << 24) |
		((csw2 & 0x7) << 20) | ((csw3 & 0x7) << 16) |
		((csw4 & 0x7) << 12) | ((csw5 & 0x7) << 8) |
		((csw6 & 0x7) << 4) | (csw7 & 0x7));
}

static void qm_set_hid(struct qman *qm)
{
#ifdef CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1
	if (qman_ip_rev == QMAN_REV1)
		qm_out(HID_CFG, 3);
	else
#endif
	qm_out(HID_CFG, 0);
}

static void qm_set_corenet_initiator(struct qman *qm)
{
	qm_out(CI_SCHED_CFG,
		0x80000000 | /* write srcciv enable */
		(CONFIG_FSL_QMAN_CI_SCHED_CFG_SRCCIV << 24) |
		(CONFIG_FSL_QMAN_CI_SCHED_CFG_SRQ_W << 8) |
		(CONFIG_FSL_QMAN_CI_SCHED_CFG_RW_W << 4) |
		CONFIG_FSL_QMAN_CI_SCHED_CFG_BMAN_W);
}

static void qm_get_version(struct qman *qm, u16 *id, u8 *major, u8 *minor)
{
	u32 v = qm_in(IP_REV_1);
	*id = (v >> 16);
	*major = (v >> 8) & 0xff;
	*minor = v & 0xff;
}

static void qm_set_memory(struct qman *qm, enum qm_memory memory, u16 eba,
			u32 ba, int enable, int prio, int stash, u32 size)
{
	u32 offset = (memory == qm_memory_fqd) ? REG_FQD_BARE : REG_PFDR_BARE;
	u32 exp = ilog2(size);
	/* choke if size isn't within range */
	QM_ASSERT((size >= 4096) && (size <= 1073741824) &&
			is_power_of_2(size));
	/* choke if 'ba' has lower-alignment than 'size' */
	QM_ASSERT(!(ba & (size - 1)));
	__qm_out(qm, offset, eba);
	__qm_out(qm, offset + REG_offset_BAR, ba);
	__qm_out(qm, offset + REG_offset_AR,
		(enable ? 0x80000000 : 0) |
		(prio ? 0x40000000 : 0) |
		(stash ? 0x20000000 : 0) |
		(exp - 1));
}

static void qm_set_pfdr_threshold(struct qman *qm, u32 th, u8 k)
{
	qm_out(PFDR_FP_LWIT, th & 0xffffff);
	qm_out(PFDR_CFG, k);
}

static void qm_set_sfdr_threshold(struct qman *qm, u16 th)
{
	qm_out(SFDR_CFG, th & 0x3ff);
}

static int qm_init_pfdr(struct qman *qm, u32 pfdr_start, u32 num)
{
	u8 rslt = MCR_get_rslt(qm_in(MCR));

	QM_ASSERT(pfdr_start && !(pfdr_start & 7) && !(num & 7) && num);
	/* Make sure the command interface is 'idle' */
	if(!MCR_rslt_idle(rslt))
		panic("QMAN_MCR isn't idle");

	/* Write the MCR command params then the verb */
	qm_out(MCP(0), pfdr_start );
	/* TODO: remove this - it's a workaround for a model bug that is
	 * corrected in more recent versions. We use the workaround until
	 * everyone has upgraded. */
	qm_out(MCP(1), (pfdr_start + num - 16));
	lwsync();
	qm_out(MCR, MCR_INIT_PFDR);

	/* Poll for the result */
	do {
		rslt = MCR_get_rslt(qm_in(MCR));
	} while(!MCR_rslt_idle(rslt));
	if (MCR_rslt_ok(rslt))
		return 0;
	if (MCR_rslt_eaccess(rslt))
		return -EACCES;
	if (MCR_rslt_inval(rslt))
		return -EINVAL;
	pr_crit("Unexpected result from MCR_INIT_PFDR: %02x\n", rslt);
	return -ENOSYS;
}

/*****************/
/* Config driver */
/*****************/

/* TODO: Kconfig these? */
#define DEFAULT_FQD_SZ	(PAGE_SIZE << 9)
#define DEFAULT_PFDR_SZ	(PAGE_SIZE << 12)

/* We support only one of these */
static struct qman *qm;

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

/* TODO:
 * - there is obviously no handling of errors,
 * - the calls to qm_set_memory() pass no upper-bits, the physical addresses
 *   are cast on the assumption that they are <= 32bits. We BUG_ON() to handle
 *   this for now,
 * - the calls to qm_set_memory() hard-code the priority and CPC-stashing for
 *   both memory resources to zero.
 */
static int __init fsl_qman_init(struct device_node *node)
{
	struct resource res;
	u32 __iomem *regs;
	dma_addr_t fqd_a, pfdr_a;
	size_t fqd_sz = DEFAULT_FQD_SZ, pfdr_sz = DEFAULT_PFDR_SZ;
	int ret;
	u16 id;
	u8 major, minor;

	BUG_ON(sizeof(dma_addr_t) != sizeof(u32));
	ret = of_address_to_resource(node, 0, &res);
	if (ret) {
		pr_err("Can't get %s property '%s'\n", node->full_name, "reg");
		return ret;
	}
	ret = parse_mem_property(node, "fsl,qman-fqd", &fqd_a, &fqd_sz, 1);
	BUG_ON(ret);
	ret = parse_mem_property(node, "fsl,qman-pfdr", &pfdr_a, &pfdr_sz, 0);
	BUG_ON(ret);
	/* Global configuration */
	regs = ioremap(res.start, res.end - res.start + 1);
	qm = qm_create(regs);
	qm_get_version(qm, &id, &major, &minor);
	pr_info("Qman ver:%04x,%02x,%02x\n", id, major, minor);
	if (!qman_ip_rev)
		qman_ip_rev = ((u16)major << 8) | minor;
	/* FQD memory */
	qm_set_memory(qm, qm_memory_fqd, 0, (u32)fqd_a, 1, 0, 0, fqd_sz);
	/* PFDR memory */
	qm_set_memory(qm, qm_memory_pfdr, 0, (u32)pfdr_a, 1, 0, 0, pfdr_sz);
	qm_init_pfdr(qm, 8, pfdr_sz / 64 - 8);
	/* thresholds */
	qm_set_pfdr_threshold(qm, 32, 32);
	qm_set_sfdr_threshold(qm, 128);
	/* corenet initiator settings */
	qm_set_corenet_initiator(qm);
	/* HID settings */
	qm_set_hid(qm);
	/* Set scheduling weights to defaults */
	for (ret = qm_wq_first; ret <= qm_wq_last; ret++)
		qm_set_wq_scheduling(qm, ret, 0, 0, 0, 0, 0, 0, 0);
	/* Workaround for bug 3594: "PAMU Address translation exception during
	 * qman dqrr stashing". */
	if (sizeof(dma_addr_t) <= sizeof(u32))
		qm_out(QCSP_BARE, 0);
	/* TODO: add interrupt handling here, so that ISR is cleared *after*
	 * PFDR initialisation. */
	return 0;
}

__init void qman_init_early(void)
{
	struct device_node *dn;
	for_each_compatible_node(dn, NULL, "fsl,qman") {
		if (qm)
			pr_err("%s: only one 'fsl,qman' allowed\n",
				dn->full_name);
		else {
			int ret = fsl_qman_init(dn);
			BUG_ON(ret);
		}
	}
}

