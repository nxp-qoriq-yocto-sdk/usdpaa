/**
 \file ll_cache.h
 \brief This file contains Cache related data structures
 */
/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc.
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
#ifndef _LIB_NET_LL_CACHE_H
#define _LIB_NET_LL_CACHE_H   1

#include "common/common.h"
#include "net/net.h"

/**
 \brief Link Layer Cache Structure
 */
struct ll_cache_t {
	uint32_t ll_hdr_len;			/**< Header length */
	uint32_t ll_addr_len;			/**< L2 layer address size */
	uint8_t ll_data[LL_MAX_ALIGNED_HEADER];	/**< L2 Header */
};

#define ETH_LL_HDR_LEN 14

/**
 \brief Allocates the Cache Structure
 \return Pointer to the allocated buffer or NULL if allocation failed
 */
struct ll_cache_t *ll_cache_create(void);

void *__real_memcpy(void *dest, const void *src, size_t n);
/**
 \brief Updates the Cache structure with the Header Data
 \param[inout] ll_hdr Pointer to the Header
 \param[in] llc Pointer to the Link layer Cache Structure
 \return none
 */
static inline void ll_cache_output(void *ll_hdr, struct ll_cache_t *llc)
{
	memcpy(ll_hdr, llc->ll_data, ETH_LL_HDR_LEN);
}
#endif /* _LIB_NET_LL_CACHE_H */
