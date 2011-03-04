/**
 \file net_context.h
 \brief This file contains the Frame Queue context related data structure
	This context is passed in contextB of FQ during initialization
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
#ifndef _LIB_NET_CONTEXT_H_
#define _LIB_NET_CONTEXT_H_	1

#include "net_dev.h"
#include "annotations.h"

struct fq_context_t;

/**
 \brief Function pointer used for Parsing of received frame/
 confirmation of xmitted frame
 \param[in] ctxt ContextB came in Frame Descriptor
 \param[in] notes Pointer to annotations field in incoming buffer
 \param[in] data Pointer to data in buffer
 */
typedef void (*frame_handler_t) (struct fq_context_t *ctxt,
				 struct annotations_t *notes, void *data);

/**
 \brief Frame Queue Context
 \details Application specific Internal Context to initialize
 Frame Manager frame Queues with proper
 cntx_B, prepended data offset and data offset
 */
struct fq_context_t {
	frame_handler_t handler;
	/**< Function pointer used for Parsing of received
	frame/ confirmation of xmitted frame*/
	struct net_dev_t *dev;		/**< Net Device Pointer*/
};

#endif /* _LIB_NET_CONTEXT_H_ */
