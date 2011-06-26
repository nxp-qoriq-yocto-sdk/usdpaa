/**
 \file common.h
 \brief This file contains functions for managing the arp table
 */
/*
 * Copyright (C) 2010,2011 Freescale Semiconductor, Inc.
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

#ifndef __COMMON_H
#define __COMMON_H

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>

#include <internal/compat.h>

#include "app_common.h"

extern struct bman_pool *pool[MAX_NUM_BMAN_POOLS];
static inline void free_buff(const struct qm_fd *fd)
{
	struct bm_buffer buf;
	int ret;

	BUG_ON(fd->format != qm_fd_contig);

	bm_buffer_set64(&buf, qm_fd_addr(fd));
retry:
	ret = bman_release(pool[fd->bpid], &buf, 1, 0);
	if (ret) {
		barrier();
		goto retry;
	}
}

#endif	/* __COMMON_H */
