/**
 \file notify.h
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
#ifndef __LIB_NET_NOTIFY_H
#define __LIB_NET_NOTIFY_H

#include <stdint.h>

/**
 \brief Prototype for Notification Callback
 \return none
 */
typedef void (*notify_fn) (uint32_t, void *);

/**
 \brief Notification Callback node
 */
struct notify_t {
	notify_fn callback;  /**< Pointer to Callback function */
	struct notify_t *next;	/**< POinter to next node in the Chain */
};

/**
 \brief List of Notification Callback nodes
 */
struct notify_chain_t {
	uint32_t lock;	/**< Lock to access the head of the List */
	struct notify_t *head;	/**< Pointer head of the List */
};

struct notify_chain_t *notify_create_chain(void);
void notify_subscribe(struct notify_chain_t *chain, notify_fn callback);
void notify_publish_event(struct notify_chain_t *chain,
			  uint32_t event, void *data);

#endif /* __LIB_NET_NOTIFY_H */
