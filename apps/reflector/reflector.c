/* Copyright (c) 2010,2011 Freescale Semiconductor, Inc.
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

#include <net/if_arp.h>
#include <netinet/ip.h>

/* All of the following things could be placed into vtables, declared as
 * "extern", implemented elsewhere, and generally made less hacky if you want.
 *
 * For this example however we want to show how ppac.c can be used without
 * any loss of execution speed due to the code separation between PPAC and an
 * application module. Ie. we want an equivalent compilation and the same
 * execution speed as a standalone implementation that has no "ppac"-style
 * modularity. This is the most awkward way to work but yields the least
 * performance to jumps, dereferences, and other cycle-gobblers. More modular
 * and elegant things can be done, by assuming the risks of some associated
 * indirection, dereferencing, [etc].
 *
 * To achieve this, we declare the FQ handling hooks as inlines, all prior to
 * including ppac.c. The code in ppac.c implements its own FQ handlng
 * callbacks and simply assumes that it can "call" these hooks at the
 * appropriate places within those implementations (so our hooks don't need to
 * be real function entities with well-defined addresses that can be stored). If
 * these "hooks" are in fact macros or inlines, they will be expanded in-place
 * by the pre-compiler or compiler, respectively. Ie. the resulting compilation
 * requires no excess jumping back and forth between generic (ppac.c)
 * packet-handling logic and application-specific (reflector.c) code when
 * processing packets.
 */

/* structs required by ppac.c */
struct ppam_if {
	/* We simply capture Tx FQIDs as they initialise, in order to use them
	 * when Rx FQs initialise. Indeed, the FQID is the only info we're
	 * passed during Tx FQ init, which is due to the programming model;
	 * we're hooked only on receive, not transmit (it's our receive handler
	 * that *requests* transmit), and the FQ objects used for Tx are
	 * internal to ppac.c and not 1-to-1 with FQIDs. */
	unsigned int num_tx_fqids;
	uint32_t *tx_fqids;
};
struct ppam_rx_error { };
struct ppam_rx_default { };
struct ppam_tx_error { };
struct ppam_tx_confirm { };
struct ppam_rx_hash {
	/* A more general network processing application (eg. routing) would
	 * take into account the contents of the recieved frame when computing
	 * the appropriate Tx FQID. These wrapper structures around each Rx FQ
	 * would typically contain state to assist/optimise that choice of Tx
	 * FQID, as that's one of the reasons for hashing Rx traffic to multiple
	 * FQIDs - each FQID carries proportionally fewer flows than the network
	 * interface itself, and a proportionally higher likelihood of bursts
	 * from the same flow. In "reflector" though, the choice of Tx FQID is
	 * constant for each Rx FQID, and so the only "optimisation" we can do
	 * is to store tx_fqid itself! */
	uint32_t tx_fqid;
};

/* Override the default command prompt */
const char ppam_prompt[] = "reflector> ";

/* PPAM global startup/teardown
 *
 * These hooks are not performance-sensitive and so are declared as real
 * functions, called from the PPAC library code (ie. not from the inline
 * packet-handling support).
 */
int ppam_init(void)
{
	printf("Reflector starting up\n");
	return 0;
}

void ppam_finish(void)
{
	printf("Reflector stopping\n");
}

/* There is no configuration that specifies how many Tx FQs to use
 * per-interface, it's an internal choice for ppac.c and may depend on
 * optimisations, link-speeds, command-line options, etc. Also the Tx FQIDs are
 * dynamically allocated, so they're not known until ppac.c has already
 * initialised them. So firstly, the # of Tx FQs is passed in as a parameter
 * here because there's no other place where it could be meaningfully captured.
 * (NB, an interesting alternative would be to have this hook *choose* how many
 * Tx FQs to use!) Secondly, the Tx FQIDs are "notified" to us post-allocation
 * but prior to Rx initialisation. */
static int ppam_if_init(struct ppam_if *p,
			const struct fm_eth_port_cfg *cfg,
			unsigned int num_tx_fqs)
{
	p->num_tx_fqids = num_tx_fqs;
	p->tx_fqids = malloc(p->num_tx_fqids * sizeof(*p->tx_fqids));
	if (!p->tx_fqids)
		return -ENOMEM;
	return 0;
}
static void ppam_if_finish(struct ppam_if *p)
{
	free(p->tx_fqids);
}
static void ppam_if_tx_fqid(struct ppam_if *p, unsigned idx, uint32_t fqid)
{
	p->tx_fqids[idx] = fqid;
}

static int ppam_rx_error_init(struct ppam_rx_error *p, struct ppam_if *_if)
{
	return 0;
}
static void ppam_rx_error_finish(struct ppam_rx_error *p, struct ppam_if *_if)
{
}
static inline void ppam_rx_error_cb(struct ppam_rx_error *p,
				    struct ppam_if *_if,
				    const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_rx_default_init(struct ppam_rx_default *p, struct ppam_if *_if)
{
	return 0;
}
static void ppam_rx_default_finish(struct ppam_rx_default *p, struct ppam_if *_if)
{
}
static inline void ppam_rx_default_cb(struct ppam_rx_default *p,
				      struct ppam_if *_if,
				      const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_tx_error_init(struct ppam_tx_error *p,	struct ppam_if *_if)
{
	return 0;
}
static void ppam_tx_error_finish(struct ppam_tx_error *p, struct ppam_if *_if)
{
}
static inline void ppam_tx_error_cb(struct ppam_tx_error *p,
				    struct ppam_if *_if,
				    const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_tx_confirm_init(struct ppam_tx_confirm *p, struct ppam_if *_if)
{
	return 0;
}
static void ppam_tx_confirm_finish(struct ppam_tx_confirm *p, struct ppam_if *_if)
{
}
static inline void ppam_tx_confirm_cb(struct ppam_tx_confirm *p,
				      struct ppam_if *_if,
				      const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd = &dqrr->fd;
	ppac_drop_frame(fd);
}

static int ppam_rx_hash_init(struct ppam_rx_hash *p,
		      struct ppam_if *_if,
		      unsigned idx)
{
	p->tx_fqid = _if->tx_fqids[idx % _if->num_tx_fqids];
	TRACE("Mapping Rx FQ %p:%d --> Tx FQID %d\n", p, idx, p->tx_fqid);
	return 0;
}

static void ppam_rx_hash_finish(struct ppam_rx_hash *p,
			 struct ppam_if *_if,
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
	struct ether_header *prot_eth;
	const struct qm_fd *fd = &dqrr->fd;
	BUG_ON(fd->format != qm_fd_contig);
	addr = dma_mem_ptov(qm_fd_addr(fd));
	TRACE("Rx: 2fwd	 fqid=%d\n", dqrr->fqid);
	TRACE("	     phys=0x%llx, virt=%p, offset=%d, len=%d, bpid=%d\n",
		qm_fd_addr(fd), addr, fd->offset, fd->length20, fd->bpid);
	addr += fd->offset;
	prot_eth = addr;
	TRACE("	     dhost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_dhost[0], prot_eth->ether_dhost[1],
		prot_eth->ether_dhost[2], prot_eth->ether_dhost[3],
		prot_eth->ether_dhost[4], prot_eth->ether_dhost[5]);
	TRACE("	     shost=%02x:%02x:%02x:%02x:%02x:%02x\n",
		prot_eth->ether_shost[0], prot_eth->ether_shost[1],
		prot_eth->ether_shost[2], prot_eth->ether_shost[3],
		prot_eth->ether_shost[4], prot_eth->ether_shost[5]);
	TRACE("	     ether_type=%04x\n", prot_eth->ether_type);
	/* Eliminate ethernet broadcasts. */
	if (prot_eth->ether_dhost[0] & 0x01)
		TRACE("	     -> dropping broadcast packet\n");
	else
	switch (prot_eth->ether_type)
	{
	case ETH_P_IP:
		TRACE("	       -> it's ETH_P_IP!\n");
		{
		struct iphdr *iphdr = addr + 14;
		__be32 tmp;
#ifdef ENABLE_TRACE
		u8 *src = (void *)&iphdr->saddr;
		u8 *dst = (void *)&iphdr->daddr;
		TRACE("		  ver=%d,ihl=%d,tos=%d,len=%d,id=%d\n",
			iphdr->version, iphdr->ihl, iphdr->tos, iphdr->tot_len,
			iphdr->id);
		TRACE("		  frag_off=%d,ttl=%d,prot=%d,csum=0x%04x\n",
			iphdr->frag_off, iphdr->ttl, iphdr->protocol,
			iphdr->check);
		TRACE("		  src=%d.%d.%d.%d\n",
			src[0], src[1], src[2], src[3]);
		TRACE("		  dst=%d.%d.%d.%d\n",
			dst[0], dst[1], dst[2], dst[3]);
#endif
		/* switch ipv4 src/dst addresses */
		tmp = iphdr->daddr;
		iphdr->daddr = iphdr->saddr;
		iphdr->saddr = tmp;
		/* switch ethernet src/dest MAC addresses */
		ether_header_swap(prot_eth);
		TRACE("Tx: 2fwd	 fqid=%d\n", p->tx_fqid);
		TRACE("	     phys=0x%llx, offset=%d, len=%d, bpid=%d\n",
			qm_fd_addr(fd), fd->offset, fd->length20, fd->bpid);
		ppac_send_frame(p->tx_fqid, fd);
		}
		return;
	case ETH_P_ARP:
		TRACE("	       -> it's ETH_P_ARP!\n");
#ifdef ENABLE_TRACE
		{
		struct arphdr *arphdr = addr + 14;
		TRACE("		  hrd=%d, pro=%d, hln=%d, pln=%d, op=%d\n",
			arphdr->ar_hrd, arphdr->ar_pro, arphdr->ar_hln,
			arphdr->ar_pln, arphdr->ar_op);
		}
#endif
		TRACE("		  -> dropping ARP packet\n");
		break;
	default:
		TRACE("	       -> it's UNKNOWN (!!) type 0x%04x\n",
			prot_eth->ether_type);
		TRACE("		  -> dropping unknown packet\n");
	}
	ppac_drop_frame(fd);
}

#include <ppac.c>

struct ppam_arguments {
};

struct ppam_arguments ppam_args;

const char ppam_doc[] = "Packet reflector";

static const struct argp_option argp_opts[] = {
	{}
};

const struct argp ppam_argp = {argp_opts, 0, 0, ppam_doc};
