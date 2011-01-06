/**
 \file frame_handler.h
 \brief  Frame queue callback handlers prototypes
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

#ifndef LIB_NET_FRAME_HANDLER_H
#define LIB_NET_FRAME_HANDLER_H 1

#include "context.h"
#include "annotations.h"

/**
  \brief Attempt to parse unknown frame types into known frame types.
  This handler is designed to forward frames to parts of the system as if they
  had been correctly parsed by the Frame Manager.
  \param[in] ctxt Frame Queue Context
  \param[in] notes Pointer to the Prepended Data
  \param[in] datd Pointer to the Data of the frame received
 */
void parsing_handler(struct fq_context_t *ctxt,
		     struct annotations_t *notes, void *data);

/*!
  \brief This handler is designed to confirm xmittion of frames
 to parts of the system by the Frame Manager.
  \param[in] ctxt Frame Queue Context
  \param[in] notes Pointer to the Prepended Data
  \param[in] data Pointer to the Data
 */
void confirm_handler(struct fq_context_t *ctxt,
		     struct annotations_t *notes, void *data);

/*!
  \brief This handler is designed to notify xmittion error of
 frames to parts of the system by the Frame Manager.
  \param[in] ctxt Frame Queue Context
  \param[in] notes Pointer to the Prepended Data
  \param[in] datd Pointer to the Data
 */
void tx_error_handler(struct fq_context_t *ctxt,
		      struct annotations_t *notes, void *data);

/*!
  \brief This handler is designed to notify error while receiving of
  frames to parts of the system by the Frame Manager.
  \param[in] ctxt Frame Queue Context
  \param[in] notes Pointer to the Prepended Data
  \param[in] datd Pointer to the Data
 */
void rx_error_handler(struct fq_context_t *ctxt,
		      struct annotations_t *notes, void *data);

#endif /* ifndef LIB_NET_FRAME_HANDLER_H */
