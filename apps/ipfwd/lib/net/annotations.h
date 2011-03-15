/**
 \file annotations.h
 \brief This file contains annotation structure added to each ingress frame
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
#ifndef LIB_COMMON_ANNOTATIONS_H
#define LIB_COMMON_ANNOTATIONS_H

#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>

#include "frame_desc.h"
#include "rt.h"

/**
 \brief Prepended Data to the Frame
 \details The structure is the Prepended Data to the Frame which is used by FMAN
*/
struct annotations_t {
	const struct qm_fd *fd;
	/**< Pointer to frame descriptor*/
	struct rt_dest_t *dest;
	/**< Pointer to the info related to Next Hop*/
	uint8_t reserved1[8];
	struct output_parse_result_t parse;	/**< Pointer to Parsed result*/
	uint64_t timestamp;			/**< TimeStamp */
	uint64_t hash_result;			/**< Hash Result */
} __PACKED;

#endif	/* LIB_COMMON_ANNOTATIONS_H */
