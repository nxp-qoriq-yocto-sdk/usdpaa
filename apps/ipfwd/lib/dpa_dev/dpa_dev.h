/**
 \file dpa_dev.h
 \brief This file contains data structures, and defines related to DPA
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
#ifndef LIB_DPA_DPA_DEV_H
#define LIB_DPA_DPA_DEV_H

#include <stdint.h>
#include "net/net_dev.h"
#include "net/frame_handler.h"

/**
 \brief DPA FQ and net device configuration structure
 */
/* net_dev is 50B */
struct dpa_dev_t {
	struct net_dev_t net_dev;	/**< Net device structure*/
	struct qman_fq *tx_fq[8];		/**< FQ to send data to FMAN*/
	struct qman_fq *tx_err_fq;
	struct qman_fq *tx_confirm_fq;
	/**< FQ to receive xmitt confirmation from FMAN*/
	struct qman_fq *rx_fq[1024];		/**< FQ to receive frame from FMAN*/
	struct qman_fq *rx_err_fq;	/**< FQ to receive errors from FMAN*/
	struct qman_fq *rx_def_fq;	/**< Default FQ on which frames are received from FMan*/
};

/**
 \brief Allocates a net dev structure
 \param[in] nt Pointer to the net dev table
 \return Pointer to allocated net dev structure
 \note When we stop a device, and eventually remove it, the FQs must be
  reclaimed.  Since each FQ may contain a context which may reference the
  device, we must free and release each of the contexts in turn before
  releasing the device.
 */
struct net_dev_t *dpa_dev_allocate(struct net_dev_table_t *nt);

/**
 \brief Sets up all of the correct function pointers for a QM device, allocates FQs
	for the egress and error queues.
 \param[in] dev Pointer to the net dev structure to be initialized
 \return Pointer to the net dev structure
 */
struct net_dev_t *dpa_dev_init(struct net_dev_t *dev);

/**
 \brief Transmit Handler to a physical ethernet port
 \param[in] dev net_dev handle
 \param[in] notes Pointer to Prepended data from Frame manager
 \param[in] ll_payload Pointer to the Data in the Frame
 */
void dpa_dev_xmit(struct net_dev_t *dev, struct qm_fd *fd, void *ll_payload);

#endif /* LIB_DPA_DPA_DEV_H */
