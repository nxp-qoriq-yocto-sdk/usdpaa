/**
 \file ip_protos.c
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
#include "ip/ip_protos.h"
#include <assert.h>

struct ip_protos_t *ip_protos_create(void)
{
	struct ip_protos_t *protos;
	uint32_t i;

	protos = malloc(sizeof(*protos));
	if (protos == NULL)
		return NULL;

	for (i = 0; i < IP_PROTO_COUNT; i++) {
		protos->proto_data[i].handler = NULL;
		protos->proto_data[i].user_data = NULL;
	}
	return protos;
}

void ip_protos_set_handler(struct ip_protos_t *protos,
			   ip_proto_handler_t handler,
			   void *user_data, enum IP_PROTO proto_id)
{
	assert(protos != NULL);

	protos->proto_data[proto_id].handler = handler;
	protos->proto_data[proto_id].user_data = user_data;
}
