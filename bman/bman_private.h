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

#include "bman_sys.h"
#include <linux/fsl_bman.h>

struct bm_addr {
	void __iomem *addr_ce;	/* cache-enabled */
	void __iomem *addr_ci;	/* cache-inhibited */
};

/* RCR state */
struct bm_rcr {
	struct bm_rcr_entry *ring, *cursor;
	u8 ci, available, ithresh, vbit;
#ifdef CONFIG_FSL_BMAN_CHECKING
	u32 busy;
	enum bm_rcr_pmode pmode;
	enum bm_rcr_cmode cmode;
#endif
};

/* MC state */
struct bm_mc {
	struct bm_mc_command *cr;
	struct bm_mc_result *rr;
	u8 rridx, vbit;
#ifdef CONFIG_FSL_BMAN_CHECKING
	enum {
		/* Can only be _mc_start()ed */
		mc_idle,
		/* Can only be _mc_commit()ed or _mc_abort()ed */
		mc_user,
		/* Can only be _mc_retry()ed */
		mc_hw
	} state;
#endif
};

/********************/
/* Portal structure */
/********************/

struct bm_portal {
	struct bm_addr addr;
	struct bm_rcr rcr;
	struct bm_mc mc;
	struct bm_portal_config config;
} ____cacheline_aligned;

/* RCR/MC/ISR code uses this as a locked mechanism to bind/unbind to
 * bm_portal::config::bound. */
int __bm_portal_bind(struct bm_portal *portal, u8 iface);
void __bm_portal_unbind(struct bm_portal *portal, u8 iface);

/* Hooks between qman_driver.c and qman_high.c */
extern DEFINE_PER_CPU(struct bman_portal *, bman_affine_portal);
static inline struct bman_portal *get_affine_portal(void)
{
	return get_cpu_var(bman_affine_portal);
}
static inline void put_affine_portal(void)
{
	put_cpu_var(bman_affine_portal);
}
struct bman_portal *bman_create_portal(struct bm_portal *portal,
					const struct bman_depletion *pools);
void bman_destroy_portal(struct bman_portal *p);

/* Pool logic in the portal driver, during initialisation, needs to know if
 * there's access to CCSR or not (if not, it'll cripple the pool allocator). */
#ifdef CONFIG_FSL_BMAN_CONFIG
int bman_have_ccsr(void);
#else
#define bman_have_ccsr() 0
#endif

/* Stockpile build constants. The _LOW value: when bman_acquire() is called and
 * the stockpile fill-level is <= _LOW, an acquire is attempted from h/w but it
 * might fail (if the buffer pool is depleted). So this value provides some
 * "stagger" in that the bman_acquire() function will only fail if lots of bufs
 * are requested at once or if h/w has been tested a couple of times without
 * luck. The _HIGH value: when bman_release() is called and the stockpile
 * fill-level is >= _HIGH, a release is attempted to h/w but it might fail (if
 * the release ring is full). So this value provides some "stagger" so that
 * ring-access is retried a couple of times prior to the API returning a
 * failure. The following *must* be true;
 *   BMAN_STOCKPILE_HIGH-BMAN_STOCKPILE_LOW > 8
 *     (to avoid thrashing)
 *   BMAN_STOCKPILE_SZ >= 16
 *     (as the release logic expects to either send 8 buffers to hw prior to
 *     adding the given buffers to the stockpile or add the buffers to the
 *     stockpile before sending 8 to hw, as the API must be an all-or-nothing
 *     success/fail.)
 */
#define BMAN_STOCKPILE_SZ   16u /* number of bufs in per-pool cache */
#define BMAN_STOCKPILE_LOW  2u  /* when fill is <= this, acquire from hw */
#define BMAN_STOCKPILE_HIGH 14u /* when fill is >= this, release to hw */
