/**
 \file rt.c
 \brief Implements a simple, fast route cache for ip forwarding.
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

#include "common/refcount.h"
#include "net/rt.h"
#include "app_common.h"

struct rt_t *rt_create(void)
{
	int _errno;
	uint32_t entries;
	struct rt_t *rt;

	_errno = posix_memalign((void **)&rt, L1_CACHE_BYTES, sizeof(*rt));
	if (unlikely(_errno < 0))
		return NULL;
	memset(rt, 0, sizeof(*rt));
	rt->free_entries = mem_cache_create(sizeof(struct rt_dest_t),
					    RT_DEST_POOL_SIZE);
	if (!rt->free_entries) {
		free(rt);
		return NULL;
	}

	entries = mem_cache_refill(rt->free_entries, RT_DEST_POOL_SIZE);

	if (entries != RT_DEST_POOL_SIZE) {
		free(rt);
		return NULL;
	}
	lwsync();
	return rt;
}

void rt_delete(struct rt_t *rt)
{
#if 0
	uint32_t entries;

	rt->free_entries = mem_cache_create(sizeof(struct rt_dest_t),
					    RT_DEST_POOL_SIZE);
	if (!rt->free_entries)
		return NULL;

	entries = mem_cache_refill(rt->free_entries, RT_DEST_POOL_SIZE);
	if (entries != RT_DEST_POOL_SIZE)
		return NULL;
#endif
	free(rt);

	return;
}

struct rt_dest_t *rt_dest_alloc(struct rt_t *rt)
{
	struct rt_dest_t *dest;

	dest = mem_cache_alloc(rt->free_entries);
	if (likely(NULL != dest)) {
		dest->refcnt = refcount_create();
		if (dest->refcnt == NULL)
			return NULL;
	}
	return dest;
}

bool rt_dest_try_free(struct rt_t *rt, struct rt_dest_t *dest)
{
	bool retval;

	if (refcount_try_await_zero(dest->refcnt)) {
		refcount_destroy(dest->refcnt);
		mem_cache_free(rt->free_entries, dest);
		retval = true;
	} else {
		retval = false;
	}

	return retval;
}

void rt_dest_free(struct rt_t *rt, struct rt_dest_t *dest)
{
	bool done;

	do {
		done = rt_dest_try_free(rt, dest);
	} while (done == false);
}
