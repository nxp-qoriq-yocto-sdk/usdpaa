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

#include "qman_sys.h"
#include <linux/fsl_qman.h>

struct qm_addr {
	void __iomem *addr_ce;	/* cache-enabled */
	void __iomem *addr_ci;	/* cache-inhibited */
};

/* EQCR state */
struct qm_eqcr {
	struct qm_eqcr_entry *ring, *cursor;
	u8 ci, available, ithresh, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	u32 busy;
	enum qm_eqcr_pmode pmode;
	enum qm_eqcr_cmode cmode;
#endif
};

/* DQRR state */
struct qm_dqrr {
	struct qm_dqrr_entry *ring, *cursor;
	u8 pi, ci, fill, ithresh, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	u8 flags;
	enum qm_dqrr_dmode dmode;
	enum qm_dqrr_pmode pmode;
	enum qm_dqrr_cmode cmode;
#endif
};
#define QM_DQRR_FLAG_RE 0x01 /* Stash ring entries */
#define QM_DQRR_FLAG_SE 0x02 /* Stash data */

/* MR state */
struct qm_mr {
	struct qm_mr_entry *ring, *cursor;
	u8 pi, ci, fill, ithresh, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	enum qm_mr_pmode pmode;
	enum qm_mr_cmode cmode;
#endif
};

/* MC state */
struct qm_mc {
	struct qm_mc_command *cr;
	struct qm_mc_result *rr;
	u8 rridx, vbit;
#ifdef CONFIG_FSL_QMAN_CHECKING
	enum {
		/* Can be _mc_start()ed */
		mc_idle,
		/* Can be _mc_commit()ed or _mc_abort()ed */
		mc_user,
		/* Can only be _mc_retry()ed */
		mc_hw
	} state;
#endif
};

/********************/
/* Portal structure */
/********************/

#ifdef CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1
/* For workarounds that require storage, this struct is overlayed on a
 * get_zeroed_page(), guaranteeing alignment and such. */
struct qm_portal_bugs {
	/* shadow MR ring, for QMAN9 workaround, 8-CL aligned */
	struct qm_mr_entry mr[QM_MR_SIZE];
	/* shadow MC result, for QMAN6 and QMAN7 workarounds, CL aligned */
	struct qm_mc_result result;
	/* boolean switch for QMAN7 workaround */
	int initfq_and_sched;
};
#endif

struct qm_portal {
	/* In the non-CONFIG_FSL_QMAN_CHECKING case, everything up to and
	 * including 'mc' fits in a cacheline (yay!). The 'config' part is
	 * setup-only, so isn't a cause for a concern. In other words, don't
	 * rearrange this structure on a whim, there be dragons ... */
	struct qm_addr addr;
	struct qm_eqcr eqcr;
	struct qm_dqrr dqrr;
	struct qm_mr mr;
	struct qm_mc mc;
	struct qm_portal_config config;
	/* Logical index (not cell-index) */
	int index;
#ifdef CONFIG_FSL_QMAN_BUG_AND_FEATURE_REV1
	struct qm_portal_bugs *bugs;
#endif
} ____cacheline_aligned;

/* EQCR/DQRR/[...] code uses this as a locked mechanism to bind/unbind to
 * qm_portal::bound. */
int __qm_portal_bind(struct qm_portal *portal, u8 iface);
void __qm_portal_unbind(struct qm_portal *portal, u8 iface);

/* Hooks for driver initialisation */
#ifdef CONFIG_FSL_QMAN_FQALLOCATOR
__init int __fqalloc_init(void);
#endif

/* Revision info (for errata and feature handling) */
#define QMAN_REV1 0x0100
#define QMAN_REV2 0x0101
extern u16 qman_ip_rev; /* 0 if uninitialised, otherwise QMAN_REVx */

/* Hooks from qman_high.c in to qman_driver.c */
extern DEFINE_PER_CPU(struct qman_portal *, qman_affine_portal);
static inline struct qman_portal *get_affine_portal(void)
{
	return get_cpu_var(qman_affine_portal);
}
static inline void put_affine_portal(void)
{
	put_cpu_var(qman_affine_portal);
}

/* Hooks from qman_driver.c in to qman_high.c */
#define QMAN_PORTAL_FLAG_RSTASH      0x00000001 /* enable DQRR entry stashing */
#define QMAN_PORTAL_FLAG_DSTASH      0x00000002 /* enable data stashing */
struct qman_portal *qman_create_portal(struct qm_portal *portal, u32 flags,
			const struct qman_cgrs *cgrs,
			const struct qman_fq_cb *null_cb);
void qman_destroy_portal(struct qman_portal *p);
void qman_static_dequeue_add_ex(struct qman_portal *p, u32 pools);

/* There are no CGR-related APIs exported so far, but due to the
 * uninitialised-data ECC issue in rev1.0 Qman, the driver needs to issue "Init
 * CGR" commands on boot-up. So we're declaring some internal-only APIs to
 * facilitate this for now. */
int qman_init_cgr(u32 cgid);

