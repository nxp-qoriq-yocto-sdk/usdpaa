/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * DPA Stats user space library implementation
 */

#include <internal/of.h>
#include <linux/fsl_dpa_stats.h>
#include <usdpaa/dma_mem.h>
#include <sys/ioctl.h>

#include "dpa_stats_ioctl.h"
#include <error.h>
#include <pthread.h>
#include <search.h>

#define DPA_STATS_DEV_FILE_NAME	  "/dev/dpa_stats"

#define NUM_EVENTS_IN_READ	5

/*
 * The device data structure is necessary so that the dpa_classifier library
 * can translate the "fmlib" handles into FM driver handles.
 */
typedef struct t_Device {
	uint32_t	id;
	int		fd;
	void		*h_UserPriv;
	uint32_t	owners;
} t_Device;

static int dpa_stats_devfd = -1;
pthread_t event_thread;

void *dpa_stats_event_thread(void *arg);

int dpa_stats_lib_init(void)
{
	int err = 0;

	if (dpa_stats_devfd >= 0) {
		error(0, EEXIST, "DPA Stats library is already initialized\n");
		return -EEXIST;
	}

	dpa_stats_devfd = open(DPA_STATS_DEV_FILE_NAME, O_RDWR);
	if (dpa_stats_devfd < 0) {
		error(0, errno, "Could not open /dev/dpa_stats\n");
		return -errno;
	}

	/* Initialize the thread for reading events: */
	err = pthread_create(&event_thread, NULL, dpa_stats_event_thread, NULL);

	return err;
}

void dpa_stats_lib_exit(void)
{
	if (dpa_stats_devfd < 0)
		return;
	close(dpa_stats_devfd);
	dpa_stats_devfd = -1;
}

int dpa_stats_init(const struct dpa_stats_params *params, int *dpa_stats_id)
{
	struct ioc_dpa_stats_params prm;
	struct dma_mem *map;

	if (!params || !dpa_stats_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	memset(&prm, 0, sizeof(prm));

	/* Check if the user-provided storage area is DMA mapped */
	map = dma_mem_findv(params->storage_area);
	if (!map) {
		prm.stg_area_mapped = false;
		prm.virt_stg_area = params->storage_area;
	} else {
		prm.stg_area_mapped = true;
		prm.phys_stg_area = dma_mem_vtop(map, params->storage_area);
	}

	prm.dpa_stats_id = 0;
	prm.max_counters = params->max_counters;
	prm.storage_area_len = params->storage_area_len;

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_INIT, prm) < 0) {
		error(0, errno, "Couldn't initialize the DPA Stats instance\n");
		return -errno;
	}

	return 0;
}

int dpa_stats_free(int dpa_stats_id)
{
	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	if (dpa_stats_id < 0) {
		error(0, EINVAL, "Invalid DPA Stats identifier\n");
		return -EINVAL;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_FREE, &dpa_stats_id) < 0) {
		error(0, errno, "Could not free the DPA Stats instance\n");
		return -errno;
	}

	return 0;
}

int dpa_stats_create_counter(int dpa_stats_id,
			     const struct dpa_stats_cnt_params *cnt_params,
			     int *dpa_stats_cnt_id)
{
	struct ioc_dpa_stats_cnt_params prm;
	struct t_Device *dev;

	if (dpa_stats_id < 0 || !cnt_params || !dpa_stats_cnt_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	memcpy(&prm.cnt_params, cnt_params, sizeof(prm.cnt_params));

	switch (cnt_params->type) {
	case DPA_STATS_CNT_CLASSIF_NODE:
		/* Translate Cc node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->classif_node_params.cc_node;
		prm.cnt_params.classif_node_params.cc_node = (void *)dev->id;
		break;
	case DPA_STATS_CNT_REASS:
		/* Translate Manip node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->reass_params.reass;
		prm.cnt_params.reass_params.reass = (void *)dev->id;
		break;
	case DPA_STATS_CNT_FRAG:
		/* Translate Manip node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->frag_params.frag;
		prm.cnt_params.frag_params.frag = (void *)dev->id;
		break;
	case DPA_STATS_CNT_POLICER:
		/* Translate Policer node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->plcr_params.plcr;
		prm.cnt_params.plcr_params.plcr = (void *)dev->id;
		break;
	default:
		break;
	}

	if (ioctl(dpa_stats_devfd, DPA_STATS_IOC_CREATE_COUNTER, &prm) < 0) {
		error(0, errno, "Could not create counter\n");
		return -errno;
	}

	if (prm.cnt_id >= 0)
		*dpa_stats_cnt_id = prm.cnt_id;

	return 0;
}

int dpa_stats_create_class_counter(int dpa_stats_id,
			      const struct dpa_stats_cls_cnt_params *cnt_params,
			      int *dpa_stats_cnt_id)
{
	struct ioc_dpa_stats_cls_cnt_params prm;
	struct t_Device *dev;
	uint32_t i = 0;

	if (dpa_stats_id < 0 || !cnt_params || !dpa_stats_cnt_id) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	memcpy(&prm.cnt_params, cnt_params, sizeof(*cnt_params));

	switch (cnt_params->type) {
	case DPA_STATS_CNT_CLASSIF_NODE:
		/* Translate Cc node handle to FMD type of handles */
		dev = (t_Device *)cnt_params->classif_node_params.cc_node;
		prm.cnt_params.classif_node_params.cc_node = (void *)dev->id;
		break;
	case DPA_STATS_CNT_REASS:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Manip node handle to FMD type of handle */
			dev = (t_Device *)cnt_params->reass_params.reass[i];
			prm.cnt_params.reass_params.reass[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_FRAG:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Manip node handle to FMD type of handle */
			dev = (t_Device *)cnt_params->frag_params.frag[i];
			prm.cnt_params.frag_params.frag[i] = (void *)dev->id;
		}
		break;
	case DPA_STATS_CNT_POLICER:
		for (i = 0; i < cnt_params->class_members; i++) {
			/* Translate Policer node handle to FMD type handles */
			dev = (t_Device *)cnt_params->plcr_params.plcr[i];
			prm.cnt_params.plcr_params.plcr[i] = (void *)dev->id;
		}
		break;
	default:
		break;
	}

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_CREATE_CLASS_COUNTER, &prm) < 0) {
		error(0, errno, "Could not create class counter\n");
		return -errno;
	}

	if (prm.cnt_id >= 0)
		*dpa_stats_cnt_id = prm.cnt_id;

	return 0;
}

int dpa_stats_modify_class_counter(int dpa_stats_cnt_id,
		const struct dpa_stats_cls_member_params *params,
		int member_index)
{
	struct ioc_dpa_stats_cls_member_params prm;

	if (dpa_stats_cnt_id < 0 || !params || member_index < 0) {
		error(0, EINVAL, "Invalid input parameters\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	prm.cnt_id = dpa_stats_cnt_id;
	prm.member_index = member_index;

	memcpy(&prm.params, params, sizeof(*params));

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_MODIFY_CLASS_COUNTER, &prm) < 0) {
		error(0, errno, "Could not modify class counter\n");
		return -errno;
	}

	return 0;
}

int dpa_stats_remove_counter(int dpa_stats_cnt_id)
{
	if (dpa_stats_cnt_id < 0) {
		error(0, EINVAL, "Invalid input parameter\n");
		return -EINVAL;
	}

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -ENODEV;
	}

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_REMOVE_COUNTER, &dpa_stats_cnt_id) < 0) {
		error(0, errno, "Could not remove this counter\n");
		return -errno;
	}

	return 0;
}

int dpa_stats_get_counters(struct dpa_stats_cnt_request_params params,
			   int *cnts_len,
			   dpa_stats_request_cb request_done)
{
	struct ioc_dpa_stats_cnt_request_params ioc_prm;

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -EAGAIN;
	}

	memcpy(&ioc_prm.req_params, &params, sizeof(params));

	ioc_prm.cnts_len = *cnts_len;
	ioc_prm.request_done = request_done;

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_GET_COUNTERS, &ioc_prm) < 0) {
		error(0, errno, "Could not create request\n");
		return -errno;
	}

	*cnts_len = ioc_prm.cnts_len;

	return 0;
}

int dpa_stats_reset_counters(int *cnts_ids, unsigned int cnts_ids_len)
{
	struct ioc_dpa_stats_cnts_reset_params ioc_prm;

	if (dpa_stats_devfd < 0) {
		error(0, ENODEV, "DPA Stats library is not initialized\n");
		return -EAGAIN;
	}

	ioc_prm.cnts_ids = cnts_ids;
	ioc_prm.cnts_ids_len = cnts_ids_len;

	if (ioctl(dpa_stats_devfd,
		  DPA_STATS_IOC_RESET_COUNTERS, &ioc_prm) < 0) {
		error(0, errno, "Could not reset counters\n");
		return -errno;
	}

	return 0;
}

void *dpa_stats_event_thread(void *arg)
{
	char buffer[NUM_EVENTS_IN_READ * sizeof(struct dpa_stats_event_params)];
	struct dpa_stats_event_params   *event_prm  = NULL;
	ssize_t bufferSize = 0;

	event_prm  = (struct dpa_stats_event_params *)buffer;

	/*
	* Read NUM_EVENTS_IN_READ from the advanced config interface.
	* This call is blocking and will put the thread to sleep if
	* there are no events available. It will return one or more
	* events if there are available.
	*/
	do {
		bufferSize = read(dpa_stats_devfd, buffer, (NUM_EVENTS_IN_READ *
				sizeof(*event_prm)));

		/* Dispatch events */
		while (bufferSize >= sizeof(struct dpa_stats_event_params)) {
			event_prm->request_done(event_prm->dpa_stats_id,
						event_prm->storage_area_offset,
						event_prm->cnts_written,
						event_prm->bytes_written);
			bufferSize -= sizeof(struct dpa_stats_event_params);
		}
	} while (1);
}
