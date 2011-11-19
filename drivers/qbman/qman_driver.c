/* Copyright (c) 2008-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include <usdpaa/fsl_usd.h>
#include "qman_private.h"

/* Global variable containing revision id (even on non-control plane systems
 * where CCSR isn't available) */
u16 qman_ip_rev;
EXPORT_SYMBOL(qman_ip_rev);

static __thread int fd = -1;
static __thread const struct qbman_uio_irq *irq;

static int __init fsl_qman_portal_init(void)
{
	cpu_set_t cpuset;
	const struct device_node *dt_node;
	const u32 *channel, *cell_index;
	struct qm_portal_config *pcfg;
	struct qman_portal *portal;
	size_t lenp;
	int loop, ret = 0;
	char name[20]; /* Big enough for "/dev/qman-uio-xx" */

	if (fd >= 0) {
		pr_err("%s: on already-initialised thread\n", __func__);
		return -EBUSY;
	}
	pcfg = malloc(sizeof(*pcfg));
	if (!pcfg) {
		perror("can't allocate portal config");
		ret = -ENOMEM;
		goto end;
	}
	ret = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t),
				     &cpuset);
	if (ret) {
		errno = ret;
		perror("pthread_getaffinity_np");
		goto end;
	}
	pcfg->public_cfg.cpu = -1;
	for (loop = 0; loop < CPU_SETSIZE; loop++)
		if (CPU_ISSET(loop, &cpuset)) {
			if (pcfg->public_cfg.cpu != -1) {
				pr_err("Thread is not affine to 1 cpu\n");
				ret = -EINVAL;
				goto end;
			}
			pcfg->public_cfg.cpu = loop;
		}
	if (pcfg->public_cfg.cpu == -1) {
		pr_err("Bug in getaffinity handling!\n");
		ret = -EINVAL;
		goto end;
	}
	/* Loop the portal nodes looking for a matching cpu, and for each such
	 * match, use the cell-index to determine the UIO device name and try
	 * opening it. */
	for_each_compatible_node(dt_node, NULL, "fsl,qman-portal") {
		cell_index = of_get_property(dt_node, "cell-index", &lenp);
		if (!cell_index || (lenp != sizeof(*cell_index))) {
			pr_err("Malformed property %s:cell-index\n",
				dt_node->full_name);
			continue;
		}
		sprintf(name, "/dev/qman-uio-%x", *cell_index);
		fd = open(name, O_RDWR);
		if (fd >= 0)
			break;
	}
	if (fd < 0) {
		ret = -ENODEV;
		goto end;
	}
	/* Parse the portal's channel */
	channel = of_get_property(dt_node, "fsl,qman-channel-id", &lenp);
	if (!channel || (lenp != sizeof(*channel))) {
		pr_err("Malformed property %s:fsl,qman-channel-id\n",
			dt_node->full_name);
		ret = -EIO;
		goto end;
	}
	pcfg->public_cfg.channel = *channel;
	pcfg->public_cfg.pools = QM_SDQCR_CHANNELS_POOL_MASK;
	/* Make the portal's cache-[enabled|inhibited] regions */
	pcfg->addr_virt[DPA_PORTAL_CE] = mmap(NULL, 16*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	pcfg->addr_virt[DPA_PORTAL_CI] = mmap(NULL, 4*1024,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4*1024);
	if ((pcfg->addr_virt[DPA_PORTAL_CE] == MAP_FAILED) ||
			(pcfg->addr_virt[DPA_PORTAL_CI] == MAP_FAILED)) {
		perror("mmap of CENA or CINH failed");
		ret = -ENODEV;
		goto end;
	}
	pcfg->public_cfg.irq = fd;
	pcfg->public_cfg.is_shared = 0;
	pcfg->node = NULL;

	if (pcfg->public_cfg.cpu == -1)
		goto end;

	portal = qman_create_affine_portal(pcfg, NULL);
	if (!portal) {
		pr_err("Qman portal initialisation failed (%d)\n",
			pcfg->public_cfg.cpu);
		goto end;
	}
	/* qman_create_affine_portal() will have called request_irq(), which in
	 * USDPAA-speak, means we have to retrieve the handler here. */
	irq = qbman_get_irq_handler(fd);
	if (!irq)
		pr_warning("Qman portal interrupt handling is disabled (%d)\n",
			pcfg->public_cfg.cpu);

end:
	if (ret) {
		if (fd >= 0) {
			close(fd);
			fd = -1;
		}
		if (pcfg)
			free(pcfg);
	}
	return ret;
}

static int fsl_qman_portal_finish(void)
{
	const struct qm_portal_config *cfg;
	int ret;

	cfg = qman_destroy_affine_portal();
	ret = munmap(cfg->addr_virt[DPA_PORTAL_CE], 16*1024);
	if (ret) {
		perror("munmap() of Qman ADDR_CE failed");
		goto end;
	}
	ret = munmap(cfg->addr_virt[DPA_PORTAL_CI], 4*1024);
	if (ret) {
		perror("munmap() of Qman ADDR_CI failed");
		goto end;
	}
end:
	if (ret)
		pr_err("Qman portal cleanup failed (%d), ret=%d\n",
			cfg->public_cfg.cpu, ret);
	/* The cast is to remove the const attribute. NB, the 'cfg' pointer
	 * lives in the portal and is supposed to be read-only while it is being
	 * used. However qman_driver.c allocates it when setting up the portal
	 * and destroys it here when tearing the portal down, so that's why this
	 * is justified. */
	free((void *)cfg);
	close(fd);
	fd = -1;
	return ret;
}

int qman_thread_init(void)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_qman_portal_init();
}

int qman_thread_finish(void)
{
	return fsl_qman_portal_finish();
}

int qman_thread_fd(void)
{
	return fd;
}

void qman_thread_irq(void)
{
	const struct qman_portal_config *cfg = qman_get_portal_config();
	const struct qm_portal_config *pcfg = container_of(cfg,
			const struct qm_portal_config, public_cfg);
	if (!irq)
		return;
	irq->isr(fd, irq->arg);
	/* Now we need to uninhibit interrupts. This is the only code outside
	 * the regular portal driver that manipulates any portal register, so
	 * rather than breaking that encapsulation I am simply hard-coding the
	 * offset to the inhibit register here. */
	out_be32(pcfg->addr_virt[DPA_PORTAL_CI] + 0xe0c, 0);
}

int qman_global_init(void)
{
	const struct device_node *dt_node;
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
	int ret;
#endif
	static int done = 0;
	if (done)
		return -EBUSY;

	dt_node = of_find_compatible_node(NULL, NULL, "fsl,qman-portal");
	if (!dt_node) {
		pr_err("No qman portals available for any CPU\n");
		return -ENODEV;
	}
	if (of_device_is_compatible(dt_node, "fsl,qman-portal-1.0"))
		qman_ip_rev = QMAN_REV10;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-1.1"))
		qman_ip_rev = QMAN_REV11;
	else if	(of_device_is_compatible(dt_node, "fsl,qman-portal-1.2"))
		qman_ip_rev = QMAN_REV12;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-2.0"))
		qman_ip_rev = QMAN_REV20;
	if (!qman_ip_rev) {
		pr_err("Unknown qman portal version\n");
		return -ENODEV;
	}
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
	ret = qman_setup_fq_lookup_table(CONFIG_FSL_QMAN_FQ_LOOKUP_MAX);
	if (ret)
		return ret;
#endif
	return 0;
}
