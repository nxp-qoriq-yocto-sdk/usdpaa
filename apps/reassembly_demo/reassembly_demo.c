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

#include <ppac.h>
#include "ppam_if.h"
#include <ppac_interface.h>
#include <error.h>
#include <usdpaa/fsl_dpa_stats.h>

#include <inttypes.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <linux/if_vlan.h>

#include "fmc.h"

#if defined(B4860)
#include "vsp_api.h"
#endif

#define ENABLE_PROMISC
#define NET_IF_ADMIN_PRIORITY 4

static int ppam_cli_parse(int key, char *arg, struct argp_state *state);
static int create_dpa_stats_counters(void);

static int reass_timeout_fq_init(struct qman_fq *fq, u32 fqid, u16 channel,
		qman_cb_dqrr cb);
static void reass_timeout_fq_remove(struct qman_fq *fq);
static enum qman_cb_dqrr_result cb_drop_timeout(
		struct qman_portal *qm __always_unused,
		struct qman_fq *fq __always_unused,
		const struct qm_dqrr_entry *dqrr);

/* VLAN header definition */
struct vlan_hdr {
	__u16 tci;
	__u16 type;
};

/* Override the default command prompt */
const char ppam_prompt[] = "reassembly_demo > ";

struct ppam_arguments {
	int	fm;
	int	port;
};

struct ppam_arguments ppam_args = {
	.fm	= 1,
	.port	= 0
};

const char ppam_doc[] = "Reassembly demo application";

static const struct argp_option argp_opts[] = {
	{"fm",		'f', "INT", 0, "FMan index"},
	{"port",	'o', "INT", 0, "FMan port index"},
	{}
};

const struct argp ppam_argp = {argp_opts, ppam_cli_parse, 0, ppam_doc};

struct fmc_model_t cmodel;

int dpa_stats_id;
int cnt_ids[14];
void *storage;
struct qman_fq to_reass_fq;

enum dpa_stats_op {
	dpa_stats_get_async = 0,
	dpa_stats_get_sync,
	dpa_stats_reset
};

/*
 * PPAM-overridable paths to FMan configuration files.
 */
const char ppam_pcd_path[] = __stringify(DEF_PCD_PATH);
const char ppam_cfg_path[] = __stringify(DEF_CFG_PATH);
const char ppam_pdl_path[] = __stringify(DEF_PDL_PATH);

int ppam_init(void)
{
	const char *pcd_path = ppam_pcd_path;
	const char *cfg_path = ppam_cfg_path;
	const char *pdl_path = ppam_pdl_path;
	const char *envp;
	int err = 0;
	u32 reass_fqid = 0;

	envp = getenv("DEF_PCD_PATH");
	if (envp != NULL)
		pcd_path = envp;

	envp = getenv("DEF_CFG_PATH");
	if (envp != NULL)
		cfg_path = envp;

	envp = getenv("DEF_PDL_PATH");
	if (envp != NULL)
		pdl_path = envp;

	/* Parse the input XML files and create the FMC Model */
	err = fmc_compile(&cmodel,
			cfg_path,
			pcd_path,
			pdl_path,
			NULL,
			0,
			0,
			NULL);
	if (err != 0) {
		error(0, err, "Failed to create the FMC Model\n");
		return -err;
	}

	reass_fqid =
cmodel.fman[ppam_args.fm].reasm[0].u.reassem.u.ipReassem.fqidForTimeOutFrames;

#if defined(B4860)
	/* Init vsp */
	err = vsp_init(ppam_args.fm, ppam_args.port);
	if (err != 0) {
		error(0, err, "Failed to initialize VSP\n");
		return -err;
	}
#endif

	/* Execute the obtained FMC Model */
	err = fmc_execute(&cmodel);
	if (err != 0) {
		error(0, err, "Failed to execute the FMC Model\n");
		return -err;
	}

	TRACE("PCD configuration successfully applied.\n");

	memset(&to_reass_fq, 0, sizeof(struct qman_fq));
	reass_timeout_fq_init(
		&to_reass_fq,
		reass_fqid,
		get_rxc(),
		cb_drop_timeout);

	/* Create DPA Stats counters */
	err = create_dpa_stats_counters();
	if (err != 0) {
		error(0, err, "Failed to create the DPA Stats counters\n");
		return -err;
	}

	return 0;
}

void ppam_finish()
{
	int err = 0;
	uint32_t i = 0;

	for (i = 0; i < sizeof(cnt_ids)/sizeof(cnt_ids[0]); i++) {
		err = dpa_stats_remove_counter(cnt_ids[i]);
		if (err != 0)
			error(0, err, "Failed to remove counter");
		else
			TRACE("DPA Stats counter successfully removed.\n");
	}

	err = dpa_stats_free(dpa_stats_id);
	if (err < 0)
		error(0, -err, "Failed to release DPA Stats instance\n");

	TRACE("DPA Stats instance successfully released\n");

	/* Release DPA Stats instance */
	dpa_stats_lib_exit();
	TRACE("DPA Stats library successfully released\n");

	 /* Clean-up the FMC model */
	err = fmc_clean(&cmodel);
	if (err != 0)
		error(0, err, "Failed to clean-up PCD configuration");
	else
		TRACE("PCD configuration successfully restored.\n");

	reass_timeout_fq_remove(&to_reass_fq);
#if defined(B4860)
	/* Cleanup vsp */
	err = vsp_clean();
	if (err !=  0)
		error(0, err, "Failed to cleanup VSP\n");
#endif
}

static int ppam_interface_init(struct ppam_interface *p,
			       const struct fm_eth_port_cfg *cfg,
			       unsigned int num_tx_fqs,
			       uint32_t *flags __maybe_unused)
{
	p->num_tx_fqids = num_tx_fqs;
	p->tx_fqids = malloc(p->num_tx_fqids * sizeof(*p->tx_fqids));
	if (!p->tx_fqids)
		return -ENOMEM;
#ifdef ENABLE_PROMISC
	/* Enable promiscuous mode for testing purposes */
	fman_if_promiscuous_enable(cfg->fman_if);
#endif /* ENABLE_PROMISC */
	return 0;
}
static void ppam_interface_finish(struct ppam_interface *p)
{
	free(p->tx_fqids);
}
static void ppam_interface_tx_fqid(struct ppam_interface *p, unsigned idx,
				   uint32_t fqid)
{
	p->tx_fqids[idx] = fqid;
}

static int ppam_rx_error_init(struct ppam_rx_error *p,
			      struct ppam_interface *_if,
			      struct qm_fqd_stashing *stash_opts)
{
	return 0;
}
static void ppam_rx_error_finish(struct ppam_rx_error *p,
				 struct ppam_interface *_if)
{
}
static inline void ppam_rx_error_cb(struct ppam_rx_error *p,
				    struct ppam_interface *_if,
				    const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_rx_default_init(struct ppam_rx_default *p,
				struct ppam_interface *_if,
				unsigned int idx,
				struct qm_fqd_stashing *stash_opts)
{
	return 0;
}
static void ppam_rx_default_finish(struct ppam_rx_default *p,
				   struct ppam_interface *_if)
{
}
static inline void ppam_rx_default_cb(struct ppam_rx_default *p,
				      struct ppam_interface *_if,
				      const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;

	ppac_drop_frame(fd);
}

static int ppam_tx_error_init(struct ppam_tx_error *p,
			      struct ppam_interface *_if,
			      struct qm_fqd_stashing *stash_opts)
{
	return 0;
}
static void ppam_tx_error_finish(struct ppam_tx_error *p,
				 struct ppam_interface *_if)
{
}
static inline void ppam_tx_error_cb(struct ppam_tx_error *p,
				    struct ppam_interface *_if,
				    const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_tx_confirm_init(struct ppam_tx_confirm *p,
				struct ppam_interface *_if,
				struct qm_fqd_stashing *stash_opts)
{
	return 0;
}
static void ppam_tx_confirm_finish(struct ppam_tx_confirm *p,
				   struct ppam_interface *_if)
{
}
static inline void ppam_tx_confirm_cb(struct ppam_tx_confirm *p,
				      struct ppam_interface *_if,
				      const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_rx_hash_init(struct ppam_rx_hash *p, struct ppam_interface *_if,
			     unsigned idx, struct qm_fqd_stashing *stash_opts)
{
	p->tx_fqid = _if->tx_fqids[idx % _if->num_tx_fqids];

	TRACE("Mapping Rx FQ %p:%d --> Tx FQID %d\n", p, idx, p->tx_fqid);
	return 0;
}

static void ppam_rx_hash_finish(struct ppam_rx_hash *p,
				struct ppam_interface *_if,
				unsigned idx)
{
}

/* Swap 6-byte MAC headers "efficiently" (hopefully) */
static inline void ether_header_swap(struct ether_header *prot_eth)
{
	register u32 a, b, c;
	u32 *overlay = (u32 *)prot_eth;
	a = overlay[0];
	b = overlay[1];
	c = overlay[2];
	overlay[0] = (b << 16) | (c >> 16);
	overlay[1] = (c << 16) | (a >> 16);
	overlay[2] = (a << 16) | (b >> 16);
}

static inline void ppam_rx_hash_cb(struct ppam_rx_hash *p,
				   const struct qm_dqrr_entry *dqrr)
{
	void *addr;
	void *annotations;
	struct ether_header *prot_eth;
	const struct qm_fd *fd = &dqrr->fd;
	struct qm_fd _fd;
	uint32_t tx_fqid;
	void *next_header;
	bool continue_parsing;
	uint16_t proto, len = 0;

	annotations = __dma_mem_ptov(qm_fd_addr(fd));
	TRACE("Rx: 2fwd	 fqid=%d\n", dqrr->fqid);
	switch (fd->format)	{
	case qm_fd_contig:
		TRACE("FD format = qm_fd_contig\n");
		addr = annotations + fd->offset;
		prot_eth = addr;
		break;

	case qm_fd_sg:
		TRACE("FD format = qm_fd_sg\n");
		addr = annotations + fd->offset;
		prot_eth = __dma_mem_ptov(qm_sg_entry_get64(addr)) +
				((struct qm_sg_entry *)addr)->offset;
		break;

	default:
		TRACE("FD format not supported!\n");
		BUG();
	}

	next_header = (prot_eth + 1);
	proto = prot_eth->ether_type;
	len = sizeof(struct ether_header);

	TRACE("	     phys=0x%"PRIx64", virt=%p, offset=%d, len=%d, bpid=%d\n",
	      qm_fd_addr(fd), addr, fd->offset, fd->length20, fd->bpid);
	TRACE("	     dhost="ETH_MAC_PRINTF_FMT"\n",
	      prot_eth->ether_dhost[0], prot_eth->ether_dhost[1],
	      prot_eth->ether_dhost[2], prot_eth->ether_dhost[3],
	      prot_eth->ether_dhost[4], prot_eth->ether_dhost[5]);
	TRACE("	     shost="ETH_MAC_PRINTF_FMT"\n",
	      prot_eth->ether_shost[0], prot_eth->ether_shost[1],
	      prot_eth->ether_shost[2], prot_eth->ether_shost[3],
	      prot_eth->ether_shost[4], prot_eth->ether_shost[5]);
	TRACE("	     ether_type=%04x\n", prot_eth->ether_type);
	/* Eliminate ethernet broadcasts. */
	if (prot_eth->ether_dhost[0] & 0x01)
		TRACE("	     -> dropping broadcast packet\n");
	else {
	continue_parsing = TRUE;
	while (continue_parsing) {
		switch (proto) {
		case ETHERTYPE_VLAN:
			TRACE("	       -> it's ETHERTYPE_VLAN!\n");
			{
			struct vlan_hdr *vlanhdr = (struct vlan_hdr *)
							(next_header);

			proto = vlanhdr->type;
			next_header = (void *)vlanhdr + sizeof(struct vlan_hdr);
			len = len + sizeof(struct vlan_hdr);
			}
			break;
		case ETHERTYPE_IP:
			TRACE("	       -> it's ETHERTYPE_IP!\n");
			{
			struct iphdr *iphdr = (typeof(iphdr))(next_header);
#ifdef ENABLE_TRACE
			u8 *src = (void *)&iphdr->saddr;
			u8 *dst = (void *)&iphdr->daddr;
			TRACE("		  ver=%d,ihl=%d,tos=%d,len=%d,id=%d\n",
				iphdr->version, iphdr->ihl, iphdr->tos,
				iphdr->tot_len, iphdr->id);
			TRACE("		  frag_off=%d,ttl=%d,prot=%d,"
				"csum=0x%04x\n", iphdr->frag_off, iphdr->ttl,
				iphdr->protocol, iphdr->check);
			TRACE("		  src=%d.%d.%d.%d\n",
				src[0], src[1], src[2], src[3]);
			TRACE("		  dst=%d.%d.%d.%d\n",
				dst[0], dst[1], dst[2], dst[3]);
#endif

			/* switch ethernet src/dest MAC addresses */
			ether_header_swap(prot_eth);
			TRACE("Tx: 2fwd	 fqid=%d\n", p->tx_fqid);
			TRACE("	     phys=0x%"PRIx64", offset=%d, len=%d,"
				" bpid=%d\n", qm_fd_addr(fd), fd->offset,
				fd->length20, fd->bpid);

			/* Frame received on PCD FQ range */
			if (!p->tx_fqid) {
				BUG_ON(fd->offset < sizeof(tx_fqid));
				tx_fqid = *(uint32_t *)annotations;
			} else
				tx_fqid = p->tx_fqid;
			/* IPv4 frame may contain ESP padding */
			_fd = *fd;
			_fd.length20 = len + iphdr->tot_len;

			ppac_send_frame(tx_fqid, &_fd);
			}
			continue_parsing = FALSE;
			return;

		case ETHERTYPE_IPV6:
			TRACE("	       -> it's ETHERTYPE_IPV6!\n");
			{
			struct ip6_hdr *ipv6hdr = (typeof(ipv6hdr))
							(next_header);
#ifdef ENABLE_TRACE
			TRACE("	ver=%d, priority=%d, payload_len=%d,"
				" nexthdr=%d, hop_limit=%d\n",
				((ipv6hdr->ip6_vfc & 0xf0) >> 4),
				((ipv6hdr->ip6_flow & 0x0ff00000) >> 20),
				ipv6hdr->ip6_plen,
				ipv6hdr->ip6_nxt, ipv6hdr->ip6_hops);
			TRACE(" flow_lbl=%d.%d.%d\n",
				((ipv6hdr->ip6_flow & 0x000f0000) >> 16),
				((ipv6hdr->ip6_flow & 0x0000ff00) >> 8),
				(ipv6hdr->ip6_flow & 0x000000ff));
			TRACE(" src=%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[0],
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[1],
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[2],
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[3],
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[4],
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[5],
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[6],
				ipv6hdr->ip6_src.__in6_u.__u6_addr16[7]);
			TRACE("	dst=%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[0],
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[1],
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[2],
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[3],
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[4],
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[5],
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[6],
				ipv6hdr->ip6_dst.__in6_u.__u6_addr16[7]);
#endif
			/* switch ethernet src/dest MAC addresses */
			ether_header_swap(prot_eth);
			TRACE("Tx: 2fwd	 fqid=%d\n", p->tx_fqid);
			TRACE("	     phys=0x%"PRIx64", offset=%d, len=%d, "
				"bpid=%d\n", qm_fd_addr(fd),
				fd->offset, fd->length20, fd->bpid);
			/* Frame received on Offline port PCD FQ range */
			if (!p->tx_fqid) {
				BUG_ON(fd->offset < sizeof(tx_fqid));
				tx_fqid = *(uint32_t *)annotations;
			} else
				tx_fqid = p->tx_fqid;
			/* IPv6 frame may contain ESP padding */
			_fd = *fd;
			_fd.length20 = len + sizeof(struct ip6_hdr) +
				ipv6hdr->ip6_ctlun.ip6_un1.ip6_un1_plen;
			ppac_send_frame(tx_fqid, &_fd);
			}
			continue_parsing = FALSE;
			return;

		case ETHERTYPE_ARP:
			TRACE("	       -> it's ETHERTYPE_ARP!\n");

			{
			struct ether_arp *arp = (typeof(arp))(next_header);
			TRACE("		  hrd=%d, pro=%d, hln=%d, pln=%d,"
				" op=%d\n",
				arp->arp_hrd, arp->arp_pro, arp->arp_hln,
				arp->arp_pln, arp->arp_op);
			}

			TRACE("		  -> dropping ARP packet\n");
			continue_parsing = FALSE;
			break;
		default:
			TRACE("	       -> it's UNKNOWN (!!) type 0x%04x\n",
				prot_eth->ether_type);
			TRACE("		  -> dropping unknown packet\n");
			ppac_drop_frame(fd);
			continue_parsing = FALSE;

		}
	}
	}
	ppac_drop_frame(fd);
}

static enum qman_cb_dqrr_result cb_drop_timeout(
		struct qman_portal *qm __always_unused,
		struct qman_fq *fq __always_unused,
		const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
	return qman_cb_dqrr_consume;
}

static int reass_timeout_fq_init(struct qman_fq *fq, u32 fqid,
		u16 channel,
		qman_cb_dqrr cb)
{
	struct qm_mcc_initfq opts;
	int ret;

	fq->cb.dqrr = cb;
	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);

	if (ret)
		return ret;

	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_TDTHRESH;
	qm_fqd_taildrop_set(&opts.fqd.td, 0, 1);
	opts.fqd.fq_ctrl = QM_FQCTRL_TDE;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = NET_IF_ADMIN_PRIORITY;
	return qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
}

static void reass_timeout_fq_remove(struct qman_fq *fq)
{
	u32 flags;
	int s = qman_retire_fq(fq, &flags);
	if (s == 1) {
		/* Retire is non-blocking, poll for completion */
		enum qman_fq_state state;
		do {
			qman_poll();
			qman_fq_state(fq, &state, &flags);
		} while (state != qman_fq_state_retired);
		if (flags & QMAN_FQ_STATE_NE) {
			/* FQ isn't empty, drain it */
			s = qman_volatile_dequeue(fq, 0,
					QM_VDQCR_NUMFRAMES_TILLEMPTY);
			if (s) {
				fprintf(stderr, "Fail: %s: %d\n",
						"qman_volatile_dequeue()", s);
				return;
			}
			/* Poll for completion */
			do {
				qman_poll();
				qman_fq_state(fq, &state, &flags);
			} while (flags & QMAN_FQ_STATE_VDQCR);
		}
	}
	s = qman_oos_fq(fq);
	if (s)
		fprintf(stderr, "Fail: %s: %d\n", "qman_oos_fq()", s);
	else
		qman_destroy_fq(fq, 0);
}

static int ppam_cli_parse(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'f':
		ppam_args.fm = atoi(arg);
		if ((ppam_args.fm < 0) || (ppam_args.fm > 1)) {
			error(0, EINVAL, "FMan Id must be zero or 1");
			return -EINVAL;
		}
		break;
	case 'o':
		ppam_args.port = atoi(arg);
		if ((ppam_args.port < 0) || (ppam_args.port > 5)) {
			error(0, EINVAL,
				"FMan port Id must be in the range 0-5");
			return -EINVAL;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int create_dpa_stats_counters(void)
{
	struct dpa_stats_params stats_params;
	struct dpa_stats_cnt_params cnt_params;
	struct dpa_stats_cls_cnt_params cls_cnt_params;
	void *reass, *ccNodeIpv6, *ccNodeIpv4;
	struct dpa_offload_lookup_key keys[20];
	uint32_t i = 0, cntId = 0, j = 0;
	char object_name[100];
	int err = 0;

	printf("reassembly_demo is assuming FMan:%d and port:%d\n",
		ppam_args.fm, ppam_args.port);

	/* Attempt to initialize the DPA Stats user space library */
	err = dpa_stats_lib_init();
	if (err < 0) {
		error(0, -err, "Failed to initialize the"
				" DPA Stats user space library");
		return -err;
	}

	TRACE("DPA Stats library successfully initialized\n");

	stats_params.max_counters = sizeof(cnt_ids)/sizeof(cnt_ids[0]);
	stats_params.storage_area_len = 1000;
	stats_params.storage_area = malloc(stats_params.storage_area_len);
	if (!stats_params.storage_area) {
		error(0, -err, "Failed to allocate storage area\n");
		return -err;
	}

	err = dpa_stats_init(&stats_params, &dpa_stats_id);
	if (err < 0) {
		error(0, -err, "Failed to initialize DPA Stats instance\n");
		return err;
	}
	TRACE("Successfully Initialized DPA Stats instance: %d\n",
			dpa_stats_id);

	/* Save storage area pointer */
	storage = stats_params.storage_area;

	/* Get Reassembly handle using FMC API */
	sprintf(object_name, "fm%d/reasm/reassembly", ppam_args.fm);
	/* Get Reassembly handle using FMC API */
	reass = fmc_get_handle(&cmodel, object_name);

	/* Create IP Reassembly single counter to retrieve general statistics */
	cnt_params.type = DPA_STATS_CNT_REASS;
	cnt_params.reass_params.reass = reass;
	cnt_params.reass_params.cnt_sel = DPA_STATS_CNT_REASS_GEN_ALL;

	err = dpa_stats_create_counter(dpa_stats_id,
			&cnt_params, &cnt_ids[cntId++]);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counter\n");
		return err;
	}
	TRACE("Successfully created DPA Stats counter: %d\n", cnt_ids[cntId-1]);

	/* Create IP Reassembly single counter to retrieve all IPv4 statistics*/
	cnt_params.type = DPA_STATS_CNT_REASS;
	cnt_params.reass_params.reass = reass;
	cnt_params.reass_params.cnt_sel = DPA_STATS_CNT_REASS_IPv4_ALL;

	err = dpa_stats_create_counter(dpa_stats_id,
			&cnt_params, &cnt_ids[cntId++]);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counter\n");
		return err;
	}
	TRACE("Successfully created DPA Stats counter: %d\n", cnt_ids[cntId-1]);

	/* Create IP Reassembly single counter to retrieve all IPv6 statistics*/
	cnt_params.type = DPA_STATS_CNT_REASS;
	cnt_params.reass_params.reass = reass;
	cnt_params.reass_params.cnt_sel = DPA_STATS_CNT_REASS_IPv6_ALL;

	err = dpa_stats_create_counter(dpa_stats_id,
			&cnt_params, &cnt_ids[cntId++]);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counter\n");
		return err;
	}
	TRACE("Successfully created DPA Stats counter: %d\n", cnt_ids[cntId-1]);

	/* Create Ethernet single counter to retrieve all statistics */
	cnt_params.type = DPA_STATS_CNT_ETH;
	cnt_params.eth_params.cnt_sel = DPA_STATS_CNT_ETH_ALL;
	cnt_params.eth_params.src.engine_id = ppam_args.fm;
	cnt_params.eth_params.src.eth_id =
				DPA_STATS_ETH_1G_PORT0 + ppam_args.port;

	err = dpa_stats_create_counter(dpa_stats_id,
			&cnt_params, &cnt_ids[cntId++]);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counter\n");
		return err;
	}
	TRACE("Successfully created DPA Stats counter: %d\n", cnt_ids[cntId-1]);

	/* Get Classification node used to perform IPv6 classification */
	sprintf(object_name, "fm%d/port/1G/%d/ccnode/vlan_ipv6_classif",
		ppam_args.fm, ppam_args.port);
	ccNodeIpv6 = fmc_get_handle(&cmodel, object_name);

	/* Create CcNode counters to retrieve IPv6 statistics for all keys */
	cnt_params.type = DPA_STATS_CNT_CLASSIF_NODE;
	cnt_params.classif_node_params.cc_node = ccNodeIpv6;
	cnt_params.classif_node_params.ccnode_type =
					DPA_STATS_CLASSIF_NODE_EXACT_MATCH;
	cnt_params.classif_node_params.cnt_sel = DPA_STATS_CNT_CLASSIF_PACKETS;

	for (i = 0; i < 4; i++) {
		keys[i].size = 18;

		keys[i].byte = malloc(keys[i].size);
		if (!keys[i].byte) {
			error(0, -err, "Failed to allocate memory\n");
			return -1;
		}

		keys[i].mask = malloc(keys[i].size);
		if (!keys[i].byte) {
			error(0, -err, "Failed to allocate memory\n");
			return -1;
		}
		memset(keys[i].mask, 0xFF, keys[i].size);

		*(uint64_t *)&keys[i].byte[0] = 0x00013FFE19440100;
		*(uint64_t *)&keys[i].byte[8] = 0x000A000000BC2500;
		*(uint16_t *)&keys[i].byte[16] = 0x0D0B;

		*(uint8_t *)&keys[i].byte[1] = i + 1;
		*(uint8_t *)&keys[i].byte[6] = i + 1;

		cnt_params.classif_node_params.key.byte = keys[i].byte;
		cnt_params.classif_node_params.key.mask = keys[i].mask;
		cnt_params.classif_node_params.key.size = keys[i].size;

		err = dpa_stats_create_counter(dpa_stats_id,
				&cnt_params, &cnt_ids[cntId++]);
		if (err < 0) {
			error(0, -err, "Failed to create DPA Stats counter\n");
			return err;
		}
		TRACE("Successfully created DPA Stats counter: %d\n",
				cnt_ids[cntId-1]);
	}

	/* Create CcNode class counter to retrieve IPv6 statistics */
	cls_cnt_params.type = DPA_STATS_CNT_CLASSIF_NODE;
	cls_cnt_params.class_members = 4;
	cls_cnt_params.classif_node_params.cc_node = ccNodeIpv6;
	cls_cnt_params.classif_node_params.ccnode_type =
					DPA_STATS_CLASSIF_NODE_EXACT_MATCH;
	cls_cnt_params.classif_node_params.cnt_sel =
					DPA_STATS_CNT_CLASSIF_PACKETS;

	cls_cnt_params.classif_node_params.keys = malloc(
			cls_cnt_params.class_members *
			sizeof(struct dpa_offload_lookup_key));
	if (!cls_cnt_params.classif_node_params.keys) {
		error(0, -err, "Failed to allocate memory\n");
		return -1;
	}

	for (i = 0; i < cls_cnt_params.class_members; i++) {
		cls_cnt_params.classif_node_params.keys[i].byte = keys[i].byte;
		cls_cnt_params.classif_node_params.keys[i].mask = keys[i].mask;
		cls_cnt_params.classif_node_params.keys[i].size = keys[i].size;
	}

	err = dpa_stats_create_class_counter(dpa_stats_id,
			&cls_cnt_params, &cnt_ids[cntId++]);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counter\n");
		return err;
	}
	TRACE("Successfully created DPA Stats counter: %d\n", cnt_ids[cntId-1]);

	/* Get Classification node used to perform IPv4 classification */
	sprintf(object_name, "fm%d/port/1G/%d/ccnode/vlan_ipv4_classif",
		ppam_args.fm, ppam_args.port);
	ccNodeIpv4 = fmc_get_handle(&cmodel, object_name);

	cnt_params.type = DPA_STATS_CNT_CLASSIF_NODE;
	cnt_params.classif_node_params.cc_node = ccNodeIpv4;
	cnt_params.classif_node_params.ccnode_type =
					DPA_STATS_CLASSIF_NODE_EXACT_MATCH;
	cnt_params.classif_node_params.cnt_sel = DPA_STATS_CNT_CLASSIF_PACKETS;

	for (i = 4; i < 8; i++) {
		keys[i].size = 6;

		keys[i].byte = malloc(keys[i].size);
		if (!keys[i].byte) {
			error(0, -err, "Failed to allocate memory\n");
			return -1;
		}

		keys[i].mask = malloc(keys[i].size);
		if (!keys[i].byte) {
			error(0, -err, "Failed to allocate memory\n");
			return -1;
		}
		memset(keys[i].mask, 0xFF, keys[i].size);

		*(uint32_t *)&keys[i].byte[0] = 0x0001C0A8;
		*(uint16_t *)&keys[i].byte[4] = 0x0001;

		*(uint8_t *)&keys[i].byte[1] = i-3;
		*(uint8_t *)&keys[i].byte[5] = i-3;

		cnt_params.classif_node_params.key.byte = keys[i].byte;
		cnt_params.classif_node_params.key.mask = keys[i].mask;
		cnt_params.classif_node_params.key.size = keys[i].size;

		err = dpa_stats_create_counter(dpa_stats_id,
				&cnt_params, &cnt_ids[cntId++]);
		if (err < 0) {
			error(0, -err, "Failed to create DPA Stats counter\n");
			return err;
		}
		TRACE("Successfully created DPA Stats counter: %d\n",
				cnt_ids[cntId-1]);
	}

	/* Create CcNode class counter to retrieve IPv4 statistics */
	cls_cnt_params.type = DPA_STATS_CNT_CLASSIF_NODE;
	cls_cnt_params.class_members = 4;
	cls_cnt_params.classif_node_params.cc_node = ccNodeIpv4;
	cls_cnt_params.classif_node_params.ccnode_type =
					DPA_STATS_CLASSIF_NODE_EXACT_MATCH;
	cls_cnt_params.classif_node_params.cnt_sel =
					DPA_STATS_CNT_CLASSIF_PACKETS;

	cls_cnt_params.classif_node_params.keys = malloc(
			cls_cnt_params.class_members *
			sizeof(struct dpa_offload_lookup_key));
	if (!cls_cnt_params.classif_node_params.keys) {
		error(0, -err, "Failed to allocate memory\n");
		return -1;
	}

	for (i = 0; i < cls_cnt_params.class_members; i++) {
		j = i + 4;
		cls_cnt_params.classif_node_params.keys[i].byte = keys[j].byte;
		cls_cnt_params.classif_node_params.keys[i].mask = keys[j].mask;
		cls_cnt_params.classif_node_params.keys[i].size = keys[j].size;
	}

	err = dpa_stats_create_class_counter(dpa_stats_id,
			&cls_cnt_params, &cnt_ids[cntId++]);
	if (err < 0) {
		error(0, -err, "Failed to create DPA Stats counter\n");
		return err;
	}
	TRACE("Successfully created DPA Stats counter: %d\n", cnt_ids[cntId-1]);

	return 0;
}

static void print_dpa_stats_cnts(void)
{
	uint32_t *stg = (uint32_t *)storage;

	printf("\nREASS      : TIMEOUT RFD_POOL_BUSY INT_BUFF_BUSY "
		"EXT_BUFF_BUSY SG_FRAGS DMA_SEM NCSP\n");
	printf("%18d %8d %13d %14d %11d %7d %5d\n", *(stg), *(stg + 1),
		*(stg + 2), *(stg + 3), *(stg + 4), *(stg + 5),
		*(stg + 6));

	printf("\nREASS_IPV4 : FRAMES FRAGS_VALID FRAGS_TOTAL FRAGS_MALFORMED"
			" FRAGS_DISCARDED AUTOLEARN_BUSY EXCEED_16FRAGS\n");
	printf("%18d %8d %11d %10d %15d %15d %15d\n", *(stg + 7), *(stg + 8),
		*(stg + 9), *(stg + 10), *(stg + 11), *(stg + 12), *(stg + 13));

	printf("\nREASS_IPV6 : FRAMES FRAGS_VALID FRAGS_TOTAL FRAGS_MALFORMED"
			" FRAGS_DISCARDED AUTOLEARN_BUSY EXCEED_16FRAGS\n");
	printf("%18d %8d %11d %10d %15d %15d %15d\n", *(stg + 14), *(stg + 15),
		*(stg + 16), *(stg + 17), *(stg + 18), *(stg + 19),
		*(stg + 20));

	printf("\nETH        : DROP_PKTS  BYTES  PKTS BC_PKTS MC_PKTS "
			"CRC_ALIGN_ERR UNDERSIZE_PKTS OVERSIZE_PKTS\n");
	printf("%18d %10d %4d %5d %6d %10d %14d %12d\n", *(stg + 21),
		*(stg + 22), *(stg + 23), *(stg + 24), *(stg + 25), *(stg + 26),
		*(stg + 27), *(stg + 28));

	printf("\nETH        : FRAGMENTS JABBERS 64BYTE_PKTS 65_127BYTE_PKTS "
			"128_255BYTE_PKTS 256_511BYTE_PKTS 512_1023BYTE_PKTS "
			"1024_1518BYTE_PKTS\n");
	printf("%18d %8d %10d %12d %15d %15d %15d %17d\n", *(stg + 29),
		*(stg + 30), *(stg + 31), *(stg + 32), *(stg + 33), *(stg + 34),
		*(stg + 35), *(stg + 36));

	printf("\nETH        : OUT_PKTS OUT_DROP_PKTS OUT_BYTES IN_ERRORS "
			"OUT_ERRORS IN_UNICAST_PKTS OUT_UNICAST_PKTS\n");
	printf("%18d %9d %11d %10d %11d %11d %12d\n", *(stg + 37), *(stg + 38),
		*(stg + 39), *(stg + 40), *(stg + 41), *(stg + 42),
		*(stg + 43));

	printf("\nCNT_CLASSIF: IPv6_KEY0 IPv6_KEY1 IPv6_KEY2 IPv6_KEY3\n");
	printf("%18d %9d %9d %9d\n", *(stg + 44), *(stg + 45), *(stg + 46),
		*(stg + 47));

	printf("\nCLS_CLASSIF: IPv6_KEY0 IPv6_KEY1 IPv6_KEY2 IPv6_KEY3\n");
	printf("%18d %9d %9d %9d\n", *(stg + 48), *(stg + 49), *(stg + 50),
		*(stg + 51));

	printf("\nCNT_CLASSIF: IPv4_KEY0 IPv4_KEY1 IPv4_KEY2 IPv4_KEY3\n");
	printf("%18d %9d %9d %9d\n", *(stg + 52), *(stg + 53), *(stg + 54),
		*(stg + 55));

	printf("\nCLS_CLASSIF: IPv4_KEY0 IPv4_KEY1 IPv4_KEY2 IPv4_KEY3\n");
	printf("%18d %9d %9d %9d\n", *(stg + 56), *(stg + 57), *(stg + 58),
		*(stg + 59));
}

void request_done_cb(int dpa_id,
		unsigned int storage_area_offset, unsigned int cnts_written,
		int bytes_written)
{
	printf("storage_area_offset = %d\n", storage_area_offset);
	printf("cnts_written = %d\n", cnts_written);
	printf("bytes_written = %d\n", bytes_written);

	print_dpa_stats_cnts();
}

static int get_cnts_statistics(enum dpa_stats_op op)
{
	struct dpa_stats_cnt_request_params req_params;
	int cnts_len = 0, err = 0;

	req_params.cnts_ids = cnt_ids;
	req_params.cnts_ids_len = sizeof(cnt_ids)/sizeof(cnt_ids[0]);
	req_params.reset_cnts = FALSE;
	req_params.storage_area_offset = 0;

	cnts_len = 0;

	switch (op) {
	case dpa_stats_get_sync:
		err = dpa_stats_get_counters(req_params, &cnts_len, NULL);
		if (err < 0) {
			error(0, -err, "Failed to create DPA Stats request\n");
			return err;
		}
		print_dpa_stats_cnts();
		break;
	case dpa_stats_get_async:
		err = dpa_stats_get_counters(req_params,
				&cnts_len, &request_done_cb);
		if (err < 0) {
			error(0, -err, "Failed to create DPA Stats request\n");
			return err;
		}
		printf("\nSuccessfully created DPA Stats request\n");
		break;
	case dpa_stats_reset:
		err = dpa_stats_reset_counters(cnt_ids,
				sizeof(cnt_ids)/sizeof(cnt_ids[0]));
		if (err < 0) {
			error(0, -err, "Failed to reset DPA Stats counters\n");
			return err;
		}
		printf("\nSuccessfully reset DPA Stats counters\n");
		break;
	default:
		printf("Invalid operation\n");
		break;
	}

	return 0;
}

static int ppac_cli_dpa_stats_cmd(int argc, char *argv[])
{
	if (!strcmp(argv[0], "get_stats"))
		get_cnts_statistics(dpa_stats_get_async);
	else if (!strcmp(argv[0], "get_stats_sync"))
		get_cnts_statistics(dpa_stats_get_sync);
	else if (!strcmp(argv[0], "reset_stats"))
		get_cnts_statistics(dpa_stats_reset);

	return 0;
}

cli_cmd(get_stats, ppac_cli_dpa_stats_cmd);
cli_cmd(get_stats_sync, ppac_cli_dpa_stats_cmd);
cli_cmd(reset_stats, ppac_cli_dpa_stats_cmd);

/* Inline the PPAC machinery */
#include <ppac.c>
