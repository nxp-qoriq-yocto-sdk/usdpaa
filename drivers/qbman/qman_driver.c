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
u16 qm_channel_pool1;
EXPORT_SYMBOL(qm_channnel_pool1);
u16 qm_channel_caam = QMAN_CHANNEL_CAAM;
EXPORT_SYMBOL(qman_channel_caam);
u16 qm_channel_pme = QMAN_CHANNEL_PME;
EXPORT_SYMBOL(qman_channel_pme);

/* Ccsr map address to access ccsrbased register */
void *qman_ccsr_map;
/* The qman clock frequency */
u32 qman_clk;
/* Two CEETM instances provided by QMan v3.0 */
struct qm_ceetm qman_ceetms[QMAN_CEETM_MAX];

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

static __init int fsl_ceetm_init(struct device_node *node)
{
	enum qm_dc_portal dcp_portal;
	struct qm_ceetm_sp *sp;
	struct qm_ceetm_lni *lni;
	const u32 *range;
	int i;
	size_t ret;

	/* Find LFQID range */
	range = of_get_property(node, "fsl,ceetm-lfqid-range", &ret);
	if (!range) {
		pr_err("No fsl,ceetm-lfqid-range in node %s\n",
							node->full_name);
		return -EINVAL;
	}
	if (ret != 8) {
		pr_err("fsl,ceetm-lfqid-range is not a 2-cell range in node"
						" %s\n", node->full_name);
		return -EINVAL;
	}

	dcp_portal = (range[0] & 0x0F0000) >> 16;
	if (dcp_portal > qm_dc_portal_fman1) {
		pr_err("The DCP portal %d doesn't support CEETM\n", dcp_portal);
		return -EINVAL;
	}

	qman_ceetms[dcp_portal].idx = dcp_portal;
	INIT_LIST_HEAD(&qman_ceetms[dcp_portal].sub_portals);
	INIT_LIST_HEAD(&qman_ceetms[dcp_portal].lnis);

	/* Find Sub-portal range */
	range = of_get_property(node, "fsl,ceetm-sp-range", &ret);
	if (!range) {
		pr_err("No fsl,ceetm-sp-range in node %s\n", node->full_name);
		return -EINVAL;
	}
	if (ret != 8) {
		pr_err("fsl,ceetm-sp-range is not a 2-cell range in node %s\n",
							node->full_name);
		return -EINVAL;
	}

	for (i = 0; i < range[1]; i++) {
		sp = kmalloc(sizeof(*sp), GFP_KERNEL);
		if (!sp) {
			pr_err("Can't alloc memory for sub-portal %d\n",
								range[0] + i);
			return -ENOMEM;
		}
		sp->idx = range[0] + i;
		sp->dcp_idx = dcp_portal;
		sp->is_claimed = 0;
		list_add_tail(&sp->node, &qman_ceetms[dcp_portal].sub_portals);
		sp++;
	}
	pr_info("Qman: Reserve sub-portal %d:%d for CEETM %d\n",
					range[0], range[1], dcp_portal);
	qman_ceetms[dcp_portal].sp_range[0] = range[0];
	qman_ceetms[dcp_portal].sp_range[1] = range[1];

	/* Find LNI range */
	range = of_get_property(node, "fsl,ceetm-lni-range", &ret);
	if (!range) {
		pr_err("No fsl,ceetm-lni-range in node %s\n", node->full_name);
		return -EINVAL;
	}
	if (ret != 8) {
		pr_err("fsl,ceetm-lni-range is not a 2-cell range in node %s\n",
							node->full_name);
		return -EINVAL;
	}

	for (i = 0; i < range[1]; i++) {
		lni = kmalloc(sizeof(*lni), GFP_KERNEL);
		if (!lni) {
			pr_err("Can't alloc memory for LNI %d\n",
							range[0] + i);
			return -ENOMEM;
		}
		lni->idx = range[0] + i;
		lni->dcp_idx = dcp_portal;
		lni->is_claimed = 0;
		INIT_LIST_HEAD(&lni->channels);
		list_add_tail(&lni->node, &qman_ceetms[dcp_portal].lnis);
		lni++;
	}
	pr_info("Qman: Reserve LNI %d:%d for CEETM %d\n",
					range[0], range[1], dcp_portal);
	qman_ceetms[dcp_portal].lni_range[0] = range[0];
	qman_ceetms[dcp_portal].lni_range[1] = range[1];

	return 0;
}

int qman_global_init(void)
{
	const struct device_node *dt_node;
	int ret;
	u32 *chanid;
	static int ccsr_map_fd;
	const uint32_t *qman_addr;
	uint64_t phys_addr;
	uint64_t regs_size;
	const u32 *clk;

	static int done = 0;
	if (done)
		return -EBUSY;

	dt_node = of_find_compatible_node(NULL, NULL, "fsl,qman-portal");
	if (!dt_node) {
		pr_err("No qman portals available for any CPU\n");
		return -ENODEV;
	}
	if (of_device_is_compatible(dt_node, "fsl,qman-portal-1.0") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-1.0.0"))
		qman_ip_rev = QMAN_REV10;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-1.1") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-1.1.0"))
		qman_ip_rev = QMAN_REV11;
	else if	(of_device_is_compatible(dt_node, "fsl,qman-portal-1.2") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-1.2.0"))
		qman_ip_rev = QMAN_REV12;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-2.0") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-2.0.0"))
		qman_ip_rev = QMAN_REV20;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-3.0.0") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-3.0.1") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-3.0.2") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-3.0.3"))
		qman_ip_rev = QMAN_REV30;
	if (!qman_ip_rev) {
		pr_err("Unknown qman portal version\n");
		return -ENODEV;
	}
	if ((qman_ip_rev & 0xFF00) >= QMAN_REV30) {
		qm_channel_caam = QMAN_CHANNEL_CAAM_REV3;
		qm_channel_pme = QMAN_CHANNEL_PME_REV3;
	}

	dt_node = of_find_compatible_node(NULL, NULL, "fsl,pool-channel-range");
	if (!dt_node) {
		pr_err("No qman pool channel range available\n");
		return -ENODEV;
	}
	chanid = of_get_property(dt_node, "fsl,pool-channel-range", &ret);
	if (!chanid) {
		pr_err("Can not get pool-channel-range property\n");
		return -EINVAL;
	}
	qm_channel_pool1 = chanid[0];

	/* Parse CEETM */
	for_each_compatible_node(dt_node, NULL, "fsl,qman-ceetm") {
		ret = fsl_ceetm_init(dt_node);
		if (ret)
			return ret;
	}

	/* get ccsr base */
	dt_node = of_find_compatible_node(NULL, NULL, "fsl,qman");
	if (!dt_node) {
		pr_err("No qman device node available\n");
		return -ENODEV;
	}
	qman_addr = of_get_address(dt_node, 0, &regs_size, NULL);
	if (!qman_addr) {
		pr_err("of_get_address cannot return qman address\n");
		return -EINVAL;
	}
	phys_addr = of_translate_address(dt_node, qman_addr);
	if (!phys_addr) {
		pr_err("of_translate_address failed\n");
		return -EINVAL;
	}

	ccsr_map_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_map_fd < 0)) {
		pr_err("Can not open /dev/mem for qman ccsr map\n");
		return ccsr_map_fd;
	}

	qman_ccsr_map = mmap(NULL, regs_size, PROT_READ|PROT_WRITE, MAP_SHARED,
				ccsr_map_fd, phys_addr);
	if (qman_ccsr_map == MAP_FAILED) {
		pr_err("Can not map qman ccsr base\n");
		return -EINVAL;
	}

	clk = of_get_property(dt_node, "clock-frequency", NULL);
	if (!clk)
		pr_warning("Can't find Qman clock frequency\n");
	else
		qman_clk = *clk;

#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
	ret = qman_setup_fq_lookup_table(CONFIG_FSL_QMAN_FQ_LOOKUP_MAX);
	if (ret)
		return ret;
#endif
	return 0;
}

#define CEETM_CFG_PRES     0x904
int qman_ceetm_get_prescaler(u16 *pres)
{
	*pres = (u16)in_be32(qman_ccsr_map + CEETM_CFG_PRES);
	return 0;
}

#define CEETM_CFG_IDX      0x900
#define DCP_CFG(n)	(0x0300 + ((n) * 0x10))
#define DCP_CFG_CEETME_MASK 0xFFFF0000
#define QM_SP_ENABLE_CEETM(n) (0x80000000 >> (n))
int qman_sp_enable_ceetm_mode(enum qm_dc_portal portal, u16 sub_portal)
{
	u32 dcp_cfg;

	dcp_cfg = in_be32(qman_ccsr_map + DCP_CFG(portal));
	dcp_cfg |= QM_SP_ENABLE_CEETM(sub_portal);
	out_be32(qman_ccsr_map + DCP_CFG(portal), dcp_cfg);
	return 0;
}

int qman_sp_disable_ceetm_mode(enum qm_dc_portal portal, u16 sub_portal)
{
	u32 dcp_cfg;

	dcp_cfg = in_be32(qman_ccsr_map + DCP_CFG(portal));
	dcp_cfg &= ~(QM_SP_ENABLE_CEETM(sub_portal));
	out_be32(qman_ccsr_map + DCP_CFG(portal), dcp_cfg);
	return 0;
}

#define MISC_CFG	0x0be0
#define MISC_CFG_WPM_MASK	0x00000002
int qm_set_wpm(int wpm)
{
	u32 before;
	u32 after;

	if (!qman_ccsr_map)
		return -ENODEV;

	before = in_be32(qman_ccsr_map + MISC_CFG);
	after = (before & (~MISC_CFG_WPM_MASK)) | (wpm << 1);
	out_be32(qman_ccsr_map + MISC_CFG, after);
	return 0;
}

int qm_get_wpm(int *wpm)
{
	u32 before;

	if (!qman_ccsr_map)
		return -ENODEV;

	before = in_be32(qman_ccsr_map + MISC_CFG);
	*wpm = (before & MISC_CFG_WPM_MASK) >> 1;
	return 0;
}
