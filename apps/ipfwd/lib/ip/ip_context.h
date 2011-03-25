/**
 \file ip_context.h
 \brief This file contains the IP Context data structure specific to application
 */
/*
 * Copyright (C) 2010 - 2011 Freescale Semiconductor, Inc.
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
#ifndef __LIB_IP_IP_CONTEXT_H
#define __LIB_IP_IP_CONTEXT_H

#include "net/context.h"

/**
 \brief IP Context
 \details Contains Structure pointers to the information used by TCP/ IP
 applications for processing of Frame
 */
struct ip_context_t {
	struct fq_context_t fq_ctxt;	/**< Frame Queue context tructure*/
	struct ip_statistics_t *stats;	/**< Pointer to the statistics related to IP Fwd Application*/
	struct ip_hooks_t *hooks;	/**< Pointer to the Hook Table*/
	struct ip_protos_t *protos;	/**< Pointer to the Protocol handler table*/
	struct rc_t *rc;		/**< Pointer to the Route Cache*/
	void *user_data;		/**< Pointer to User data*/
} __attribute__((aligned(L1_CACHE_BYTES)));

#endif /* __LIB_IP_IP_CONTEXT_H */
