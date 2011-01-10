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

#include "dpa_sys.h"
#include <linux/fsl_qman.h>

#if defined(CONFIG_FSL_QMAN_ADAPTIVE_EQCR_THROTTLE) && \
	!defined(CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1)
#error "_QMAN_ADAPTIVE_EQCR_THROTTLE requires _QMAN_BUG_AND_FEATURE_REV1"
#endif

struct qm_addr {
	void __iomem *addr_ce;	/* cache-enabled */
	void __iomem *addr_ci;	/* cache-inhibited */
};

/* used by CCSR and portal interrupt code */
enum qm_isr_reg {
	qm_isr_status = 0,
	qm_isr_enable = 1,
	qm_isr_disable = 2,
	qm_isr_inhibit = 3
};

struct qm_portal_config {
	struct qman_portal_config public_cfg;
	/* Mapped corenet portal regions */
	struct qm_addr addr;
	/* does this portal have PAMU assistance from hypervisor? */
	int has_hv_dma;
	/* Logical index (not cell-index) */
	int index;
	struct device_node *node;
};

/* Hooks for driver initialisation */
#ifdef CONFIG_FSL_QMAN_FQALLOCATOR
__init int fqalloc_init(int use_bman);
#endif

/* Revision info (for errata and feature handling) */
#define QMAN_REV1 0x0100
#define QMAN_REV2 0x0101
extern u16 qman_ip_rev; /* 0 if uninitialised, otherwise QMAN_REVx */

#ifdef CONFIG_FSL_QMAN_CONFIG
/* Hooks from qman_driver.c to qman_config.c */
int qman_init_error_int(struct device_node *node);
#endif

/* This struct represents a pool channel */
struct qm_pool_channel {
	/* The QM_SDQCR_CHANNELS_POOL(n) bit that corresponds to this channel */
	u32 pool;
	/* The channel id, used for initialising frame queues to target this
	 * channel. */
	enum qm_channel channel;
	/* Bitmask of portal (logical-, not cell-)indices that have dequeue
	 * access to this channel;
	 * 0x001 -> qm_portal_get(0)
	 * 0x002 -> qm_portal_get(1)
	 * 0x004 -> qm_portal_get(2)
	 * ...
	 * 0x200 -> qm_portal_get(9)
	 */
	u32 portals;
};

/* Hooks from qman_driver.c in to qman_high.c */
#define QMAN_PORTAL_FLAG_RSTASH      0x00000001 /* enable DQRR entry stashing */
#define QMAN_PORTAL_FLAG_DSTASH      0x00000002 /* enable data stashing */
int qman_have_affine_portal(void);
int qman_create_affine_portal(const struct qm_portal_config *config, u32 flags,
			const struct qman_cgrs *cgrs,
			const struct qman_fq_cb *null_cb,
			u32 irq_sources, int recovery_mode);
void qman_destroy_affine_portal(void);
void qman_recovery_exit_local(void);

/* This CGR feature is supported by h/w and required by unit-tests and the
 * debugfs hooks, so is implemented in the driver. However it allows an explicit
 * corruption of h/w fields by s/w that are usually incorruptible (because the
 * counters are usually maintained entirely within h/w). As such, we declare
 * this API internally. */
int qman_testwrite_cgr(struct qman_cgr *cgr, u64 i_bcnt,
	struct qm_mcr_cgrtestwrite *result);

/*************************************************/
/*   QMan s/w corenet portal, low-level i/face   */
/*************************************************/

/* Note: most functions are only used by the high-level interface, so are
 * inlined from qman_low.h. The stuff below is for use by other parts of the
 * driver. */

/* Obtain the number of portals available */
u8 qm_portal_num(void);

/* Obtain a portal handle and configuration information about it */
const struct qm_portal_config *qm_portal_config(u8 idx);

/* Obtain a mask of the available pool channels, expressed using
 * QM_SDQCR_CHANNELS_POOL(n). */
u32 qm_pools(void);

/* Retrieve a pool channel configuration, given a QM_SDQCR_CHANNEL_POOL(n)
 * bit-mask (the least significant bit of 'mask' is used if more than one bit is
 * set). */
const struct qm_pool_channel *qm_pool_channel(u32 mask);

/* For qm_dqrr_sdqcr_set(); Choose one SOURCE. Choose one COUNT. Choose one
 * dequeue TYPE. Choose TOKEN (8-bit).
 * If SOURCE == CHANNELS,
 *   Choose CHANNELS_DEDICATED and/or CHANNELS_POOL(n).
 *   You can choose DEDICATED_PRECEDENCE if the portal channel should have
 *   priority.
 * If SOURCE == SPECIFICWQ,
 *     Either select the work-queue ID with SPECIFICWQ_WQ(), or select the
 *     channel (SPECIFICWQ_DEDICATED or SPECIFICWQ_POOL()) and specify the
 *     work-queue priority (0-7) with SPECIFICWQ_WQ() - either way, you get the
 *     same value.
 */
#define QM_SDQCR_SOURCE_CHANNELS	0x0
#define QM_SDQCR_SOURCE_SPECIFICWQ	0x40000000
#define QM_SDQCR_COUNT_EXACT1		0x0
#define QM_SDQCR_COUNT_UPTO3		0x20000000
#define QM_SDQCR_DEDICATED_PRECEDENCE	0x10000000
#define QM_SDQCR_TYPE_MASK		0x03000000
#define QM_SDQCR_TYPE_NULL		0x0
#define QM_SDQCR_TYPE_PRIO_QOS		0x01000000
#define QM_SDQCR_TYPE_ACTIVE_QOS	0x02000000
#define QM_SDQCR_TYPE_ACTIVE		0x03000000
#define QM_SDQCR_TOKEN_MASK		0x00ff0000
#define QM_SDQCR_TOKEN_SET(v)		(((v) & 0xff) << 16)
#define QM_SDQCR_TOKEN_GET(v)		(((v) >> 16) & 0xff)
#define QM_SDQCR_CHANNELS_DEDICATED	0x00008000
#if 0 /* These are defined in the external fsl_qman.h API */
#define QM_SDQCR_CHANNELS_POOL_MASK	0x00007fff
#define QM_SDQCR_CHANNELS_POOL(n)	(0x00008000 >> (n))
#endif
#define QM_SDQCR_SPECIFICWQ_MASK	0x000000f7
#define QM_SDQCR_SPECIFICWQ_DEDICATED	0x00000000
#define QM_SDQCR_SPECIFICWQ_POOL(n)	((n) << 4)
#define QM_SDQCR_SPECIFICWQ_WQ(n)	(n)

/* For qm_dqrr_vdqcr_set(); Choose one PRECEDENCE. EXACT is optional. Use
 * NUMFRAMES(n) (6-bit) or NUMFRAMES_TILLEMPTY to fill in the frame-count. Use
 * FQID(n) to fill in the frame queue ID. */
#if 0 /* These are defined in the external fsl_qman.h API */
#define QM_VDQCR_PRECEDENCE_VDQCR	0x0
#define QM_VDQCR_PRECEDENCE_SDQCR	0x80000000
#define QM_VDQCR_EXACT			0x40000000
#define QM_VDQCR_NUMFRAMES_MASK		0x3f000000
#define QM_VDQCR_NUMFRAMES_SET(n)	(((n) & 0x3f) << 24)
#define QM_VDQCR_NUMFRAMES_GET(n)	(((n) >> 24) & 0x3f)
#define QM_VDQCR_NUMFRAMES_TILLEMPTY	QM_VDQCR_NUMFRAMES_SET(0)
#endif
#define QM_VDQCR_FQID_MASK		0x00ffffff
#define QM_VDQCR_FQID(n)		((n) & QM_VDQCR_FQID_MASK)

/* For qm_dqrr_pdqcr_set(); Choose one MODE. Choose one COUNT.
 * If MODE==SCHEDULED
 *   Choose SCHEDULED_CHANNELS or SCHEDULED_SPECIFICWQ. Choose one dequeue TYPE.
 *   If CHANNELS,
 *     Choose CHANNELS_DEDICATED and/or CHANNELS_POOL() channels.
 *     You can choose DEDICATED_PRECEDENCE if the portal channel should have
 *     priority.
 *   If SPECIFICWQ,
 *     Either select the work-queue ID with SPECIFICWQ_WQ(), or select the
 *     channel (SPECIFICWQ_DEDICATED or SPECIFICWQ_POOL()) and specify the
 *     work-queue priority (0-7) with SPECIFICWQ_WQ() - either way, you get the
 *     same value.
 * If MODE==UNSCHEDULED
 *     Choose FQID().
 */
#define QM_PDQCR_MODE_SCHEDULED		0x0
#define QM_PDQCR_MODE_UNSCHEDULED	0x80000000
#define QM_PDQCR_SCHEDULED_CHANNELS	0x0
#define QM_PDQCR_SCHEDULED_SPECIFICWQ	0x40000000
#define QM_PDQCR_COUNT_EXACT1		0x0
#define QM_PDQCR_COUNT_UPTO3		0x20000000
#define QM_PDQCR_DEDICATED_PRECEDENCE	0x10000000
#define QM_PDQCR_TYPE_MASK		0x03000000
#define QM_PDQCR_TYPE_NULL		0x0
#define QM_PDQCR_TYPE_PRIO_QOS		0x01000000
#define QM_PDQCR_TYPE_ACTIVE_QOS	0x02000000
#define QM_PDQCR_TYPE_ACTIVE		0x03000000
#define QM_PDQCR_CHANNELS_DEDICATED	0x00008000
#define QM_PDQCR_CHANNELS_POOL(n)	(0x00008000 >> (n))
#define QM_PDQCR_SPECIFICWQ_MASK	0x000000f7
#define QM_PDQCR_SPECIFICWQ_DEDICATED	0x00000000
#define QM_PDQCR_SPECIFICWQ_POOL(n)	((n) << 4)
#define QM_PDQCR_SPECIFICWQ_WQ(n)	(n)
#define QM_PDQCR_FQID(n)		((n) & 0xffffff)

/* Used by all portal interrupt registers except 'inhibit'. NB, some of these
 * definitions are exported for use by the qman_irqsource_***() APIs, so are
 * commented-out here. */
#define QM_PIRQ_DQAVAIL	0x0000ffff	/* Channels with frame availability */
#if 0
#define QM_PIRQ_CSCI	0x00100000	/* Congestion State Change */
#define QM_PIRQ_EQCI	0x00080000	/* Enqueue Command Committed */
#define QM_PIRQ_EQRI	0x00040000	/* EQCR Ring (below threshold) */
#define QM_PIRQ_DQRI	0x00020000	/* DQRR Ring (non-empty) */
#define QM_PIRQ_MRI	0x00010000	/* MR Ring (non-empty) */
/* This mask contains all the interrupt sources that need handling except DQRI,
 * ie. that if present should trigger slow-path processing. */
#define QM_PIRQ_SLOW	(QM_PIRQ_CSCI | QM_PIRQ_EQCI | QM_PIRQ_EQRI | \
			QM_PIRQ_MRI)
#endif
/* The DQAVAIL interrupt fields break down into these bits; */
#define QM_DQAVAIL_PORTAL	0x8000		/* Portal channel */
#define QM_DQAVAIL_POOL(n)	(0x8000 >> (n))	/* Pool channel, n==[1..15] */
#define QM_DQAVAIL_MASK		0xffff
/* This mask contains all the "irqsource" bits visible to API users */
#define QM_PIRQ_VISIBLE	(QM_PIRQ_SLOW | QM_PIRQ_DQRI)

/* These are qm_<reg>_<verb>(). So for example, qm_disable_write() means "write
 * the disable register" rather than "disable the ability to write". */
#define qm_isr_status_read(qm)		__qm_isr_read(qm, qm_isr_status)
#define qm_isr_status_clear(qm, m)	__qm_isr_write(qm, qm_isr_status, m)
#define qm_isr_enable_read(qm)		__qm_isr_read(qm, qm_isr_enable)
#define qm_isr_enable_write(qm, v)	__qm_isr_write(qm, qm_isr_enable, v)
#define qm_isr_disable_read(qm)		__qm_isr_read(qm, qm_isr_disable)
#define qm_isr_disable_write(qm, v)	__qm_isr_write(qm, qm_isr_disable, v)
/* TODO: unfortunate name-clash here, reword? */
#define qm_isr_inhibit(qm)		__qm_isr_write(qm, qm_isr_inhibit, 1)
#define qm_isr_uninhibit(qm)		__qm_isr_write(qm, qm_isr_inhibit, 0)
