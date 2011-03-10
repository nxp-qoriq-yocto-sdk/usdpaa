/**
 \file dpa_dev.c
 */
/*
 * Copyright (C) 2010-2011 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <usdpaa/compat.h>

#include "app_common.h"
#include "net/net_dev.h"
#include "net/frame_desc.h"
#include "net/annotations.h"
#include "ethernet/eth.h"
#include "dpa_dev.h"

struct net_dev_t *dpa_dev_allocate(struct net_dev_table_t *nt)
{
	uint32_t dpa_dev_pvt;

	dpa_dev_pvt = (sizeof(struct dpa_dev_t) - sizeof(struct net_dev_t));
	return net_dev_allocate(nt, dpa_dev_pvt);
}

struct net_dev_t *dpa_dev_init(struct net_dev_t *dev)
{
	int _errno;

	eth_net_dev_setup(dev);
	dev->state = NET_DEV_STATE_UNCONFIGURED;
	dev->iflink = 0;
	_errno = posix_memalign((void **)&dev->stats, L1_CACHE_BYTES, sizeof(*dev->stats));
	if (unlikely(_errno < 0))
		return NULL;

	memset(dev->stats, 0,  sizeof(*dev->stats));
	dev->xmit = &dpa_dev_xmit;
	return dev;
}

void dpa_dev_xmit(struct net_dev_t *dev, struct qm_fd *fd,
				void *ll_hdr __UNUSED)
{
	struct dpa_dev_t *dpa_dev = (struct dpa_dev_t *)dev;
#ifdef STATS_TBD
	volatile void *stat_addr = &(dev->stats->tx_frames.acc.words.lo);
	uint32_t len = get_single_fd_length(fd);
#endif
	uint32_t ret;

#ifdef STATS_TBD
	decorated_store_64_inc_acc_32(stat_addr, len);
#endif
retry:
	ret = qman_enqueue(dpa_dev->tx_fq[0], fd, 0);
	if (ret) {
		barrier();
		goto retry;
	}
#ifdef NOT_USDPAA
	if (unlikely(ret)) {
		uint64_t now, then = get_atb();
		do {
			now = get_atb();
		} while (now < (then + 1000));
		goto loop;
	}
	markpoint(17);
#endif
}
