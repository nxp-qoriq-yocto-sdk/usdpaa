/**
 \file ipfwd.c
 \brief Basic IP Forwarding Application
 */
/*
 * Copyright (C) 2010,2011 Freescale Semiconductor, Inc.
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

#include "ipfwd.h"
#include "ip/ip_forward.h"
#include "ip/ip_local.h"

#include <usdpaa/fsl_usd.h>
#include <usdpaa/dma_mem.h>
#include <usdpaa/usdpaa_netcfg.h>
#include <usdpaa/fman.h>

#include <stdio.h>
#include <mqueue.h>

/**
 \brief It holds pointers to all IP-related data structures.
 */
struct ip_stack_t {
	struct ip_statistics_t *ip_stats;	/**< IPv4 Statistics */
	struct ip_hooks_t hooks;		/**< Hooks for intermediate processing */
	struct ip_protos_t *protos;		/**< Protocol Handler */
	struct neigh_table_t *arp_table;	/**< ARP Table */
	struct net_dev_table_t *nt;		/**< Netdev Table */
	struct rt_t *rt;			/**< Routing Table */
	struct rc_t *rc;			/**< Route Cache */
	struct ip_context_t *ctxt[8];		/**< There are at max 8 IFACE in one partition due to emulator*/
};

uint32_t local_node_count[IFACE_COUNT] = { 23, 23, 23, 23, 23, 23, 23, 23, 1 };
struct node_t local_nodes[LINKLOCAL_NODES];
struct node_t iface_nodes[IFACE_COUNT];
struct ip_stack_t stack;
mqd_t mq_fd_rcv, mq_fd_snd;
struct sigevent notification;
volatile uint32_t GO_FLAG;
static __thread struct thread_data_t *__my_thread_data;
__PERCPU uint32_t rx_errors;
#define MAX_THREADS 8
uint32_t recv_channel_map;

static pthread_barrier_t init_barrier;
int cpu0_only;
/* Seed buffer pools according to the configuration symbols */
const struct ipfwd_bpool_static {
	int bpid;
	unsigned int num;
	unsigned int sz;
} ipfwd_bpool_static[] = {
	{ DMA_MEM_BP1_BPID, DMA_MEM_BP1_NUM, DMA_MEM_BP1_SIZE},
	{ DMA_MEM_BP2_BPID, DMA_MEM_BP2_NUM, DMA_MEM_BP2_SIZE},
	{ DMA_MEM_BP3_BPID, DMA_MEM_BP3_NUM, DMA_MEM_BP3_SIZE},
	{ -1, 0, 0 }
};

struct bman_pool *pool[MAX_NUM_BMAN_POOLS];
int lazy_init_bpool(u8 bpid)
{
	struct bman_pool_params params = {
		.bpid	= bpid,
#ifdef BP_DEPLETION
		.flags	= BMAN_POOL_FLAG_DEPLETION,
		.cb	= bp_depletion,
		.cb_ctx	= &pool[bpid]
#endif
	};
	if (pool[bpid])
		/* this BPID is already handled */
		return 0;
	pool[bpid] = bman_new_pool(&params);
	if (!pool[bpid]) {
		fprintf(stderr, "error: bman_new_pool(%d) failed\n", bpid);
		return -ENOMEM;
	}
	return 0;
}

void ip_fq_state_chg(struct qman_portal *qm,
		     struct qman_fq *fq, const struct qm_mr_entry *msg)
{
	pr_info("%s:FQ STATE CHANGE\n", __func__);
}

static int worker_fn(struct thread_data_t *tdata)
{

	pr_info("This is the thread on cpu %d\n", tdata->cpu);

	/* Set the qman portal's SDQCR mask */
	pr_info("Frames to be recv on channel map: 0x%x\n", recv_channel_map);
	qman_static_dequeue_add(recv_channel_map);

	/* Wait till the main thread enables all the ethernet ports */
	pthread_barrier_wait(&init_barrier);

	pr_info("Going for qman poll cpu %d\n", tdata->cpu);
	while (1)
		qman_poll();

	pr_info("Leaving thread on cpu %d\n", tdata->cpu);
	pthread_exit(NULL);
}

/**
 \brief Change Interface Configuration
 \param[out] app_ctrl_route_info contains Route parameters
 \return Integer status
 */
int32_t ipfwd_conf_intf(struct app_ctrl_op_info *route_info)
{
	pr_debug("ipfwd_conf_intf: Enter\n");

	pr_debug("ipfwd_conf_intf: Bitmask = 0x%x\n",
		  route_info->ip_info.intf_conf.bitmask);

	pr_debug("ipfwd_conf_intf: Ifname = %s\n",
		  route_info->ip_info.intf_conf.ifname);
	pr_debug("ipfwd_conf_intf: IPAddr = 0x%x\n",
		  route_info->ip_info.intf_conf.ip_addr);
	pr_debug("ipfwd_conf_intf: MAC Addr = "ETH_MAC_PRINTF_FMT"\n",
		 ETH_MAC_PRINTF_ARGS(&route_info->ip_info.intf_conf.mac_addr));

	pr_debug("ipfwd_conf_intf: Exit\n");
	return 0;
}

int is_iface_ip(in_addr_t ip_addr)
{
	int i;

	for (i = 0; i < g_num_dpa_eth_ports; i++) {
		if (iface_nodes[i].ip == ip_addr)
			return 0;
	}

	return -EINVAL;
}

/**
 \brief Gets interface node corresponding to an ip address
 \param[in] ip_addr IP Address
 \return    interface node, On success
	    NULL,	    On failure
 */
struct node_t *ipfwd_get_iface_for_ip(in_addr_t ip_addr)
{
	uint32_t port;

	for (port = 0; port < g_num_dpa_eth_ports; port++) {
		if ((iface_nodes[port].ip & IN_CLASSC_NET) ==
		    (ip_addr & IN_CLASSC_NET))
			break;
	}

	if (unlikely(port == g_num_dpa_eth_ports)) {
		pr_err("%s: Exit: Failed: Not a valid IP addr\n", __FILE__);
		return NULL;
	}

	return &iface_nodes[port];
}

/**
 \brief Gets device pointer corresponding to an ip address
 \param[in] ip_addr IP Address
 */
struct net_dev_t *ipfwd_get_dev_for_ip(in_addr_t ip_addr)
{
	const struct node_t *node;
	struct net_dev_t *dev;

	node = ipfwd_get_iface_for_ip(ip_addr);
	if (unlikely(node == NULL))
		return NULL;

	for (dev = stack.nt->device_head; dev != NULL; dev = dev->next)
		if (memcmp(dev->dev_addr, &node->mac, dev->dev_addr_len) == 0)
			break;

	return dev;
}

/**
 \brief Adds a new Route Cache entry
 \param[out] app_ctrl_route_info contains Route parameters
 \return Integer status
 */
int32_t ipfwd_add_route(struct app_ctrl_op_info *route_info)
{
	struct rc_entry_t *entry;
	struct rt_dest_t *dest;
	struct net_dev_t *dev = NULL;
	in_addr_t gw_ipaddr = route_info->ip_info.gw_ipaddr;
	int _errno;

	pr_debug("ipfwd_add_route: Enter\n");

	dest = rt_dest_alloc(stack.rt);
	if (dest == NULL) {
		pr_err
		    ("Could not allocate route cache related data structure\n");
		return -1;
	}

	dest->next = NULL;
	dest->neighbor = neigh_lookup(stack.arp_table, gw_ipaddr,
				      stack.arp_table->proto_len);
	if (dest->neighbor == NULL) {
		pr_debug
		    ("%s: Could not find neighbor entry for link-local addr\n",
		     __func__);

		dev = ipfwd_get_dev_for_ip(gw_ipaddr);
		if (dev == NULL) {
			pr_err("%s: not a valid gateway for any subnet\n",
				  __func__);
			return -1;
		}

		dest->neighbor = neigh_create(stack.arp_table);
		if (unlikely(!dest->neighbor)) {
			pr_err("%s: Unable to create Neigh Entry\n", __func__);
			return -1;
		}

		if (NULL == neigh_init(stack.arp_table, dest->neighbor, dev,
				       &gw_ipaddr)) {
			pr_err("%s: Unable to init Neigh Entry\n", __func__);
			return -1;
		}

		if (false == neigh_add(stack.arp_table, dest->neighbor)) {
			pr_err("%s: Unable to add Neigh Entry\n", __func__);
			return -1;
		}
		/* MAC addr would be updated later through ARP request */

		pr_debug("%s: Created neighbor entry, IP addr = %x\n",
			  __func__, gw_ipaddr);
	}

	dest->dev = dest->neighbor->dev;
	dest->scope = ROUTE_SCOPE_GLOBAL;

	entry = rc_create_entry(stack.rc);
	if (entry == NULL) {
		pr_err("Could not allocate route cache entry\n");
		rt_dest_free(stack.rt, dest);
		return -1;
	}

	entry->saddr = route_info->ip_info.src_ipaddr;
	entry->daddr = route_info->ip_info.dst_ipaddr;
	_errno = posix_memalign((void **)&entry->stats, L1_CACHE_BYTES,
			   sizeof(struct rc_entry_statistics_t));
	if (unlikely(_errno < 0)) {
		pr_err("Unable to allocate route entry stats\n");
		return _errno;
	}
	memset(entry->stats, 0, sizeof(struct rc_entry_statistics_t));
	refcount_acquire(dest->neighbor->refcnt);

	entry->dest = dest;
	entry->last_used = mfspr(SPR_ATBL);

	if (rc_add_update_entry(stack.rc, entry) == false) {
		pr_err("Route cache entry updated\n");
		rc_free_entry(stack.rc, entry);
	}

	pr_debug("ipfwd_add_route: Exit\n");
	return 0;
}

/**
 \brief Deletes a Route Cache entry
 \param[out] app_ctrl_route_info contains Route parameters
 \return Integer status
 */
int32_t ipfwd_del_route(struct app_ctrl_op_info *route_info)
{
	struct rt_dest_t *dest;
	pr_debug("ipfwd_del_route: Enter\n");

	dest = rc_lookup(stack.rc,
			 route_info->ip_info.src_ipaddr,
			 route_info->ip_info.dst_ipaddr);
	if (dest == NULL) {
		pr_err("Could not find route cache entry to be deleted\n");
		return -1;
	}

	refcount_release(dest->neighbor->refcnt);

	if (rc_remove_entry(stack.rc,
			    route_info->ip_info.src_ipaddr,
			    route_info->ip_info.dst_ipaddr) == false) {
		pr_err("Could not delete route cache entry\n");
		return -1;
	}

	rt_dest_free(stack.rt, dest);
	pr_debug("ipfwd_del_route: Exit\n");
	return 0;
}

/**
 \brief Adds a new Arp Cache entry
 \param[out] app_ctrl_route_info contains ARP parameters
 \return Integer status
 */
int32_t ipfwd_add_arp(struct app_ctrl_op_info *route_info)
{
	in_addr_t ip_addr = route_info->ip_info.src_ipaddr;
	struct net_dev_t *dev = NULL;
	struct neigh_t *n;

#if (LOG_LEVEL > 3)
	uint8_t *ip = (typeof(ip))&ip_addr;
	pr_debug("ipfwd_add_arp: Enter\n");

	pr_debug("IP = %d.%d.%d.%d ; MAC ="ETH_MAC_PRINTF_FMT"\n",
		 ip[0], ip[1], ip[2], ip[3],
		 ETH_MAC_PRINTF_ARGS(&route_info->ip_info.mac_addr));
#endif

	n = neigh_lookup(stack.arp_table, ip_addr,
			 stack.arp_table->proto_len);

	if (n == NULL) {
		pr_debug
		    ("%s: Could not find neighbor entry for link-local addr\n",
		     __func__);

		dev = ipfwd_get_dev_for_ip(ip_addr);
		if (dev == NULL) {
			pr_debug("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}

		n = neigh_create(stack.arp_table);
		if (unlikely(!n)) {
			pr_debug("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}
		if (NULL == neigh_init(stack.arp_table, n, dev,
				       &ip_addr)) {
			pr_err("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}

		if (false == neigh_add(stack.arp_table, n)) {
			pr_err("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}
	} else {
		n->neigh_state = NEIGH_STATE_UNKNOWN;
		if (route_info->ip_info.replace_entry) {
			if (false == neigh_replace(stack.arp_table, n)) {
				pr_err("ipfwd_add_arp: Exit: Failed\n");
				return -1;
			}
		}
	}
	/* Update ARP cache entry */
	if (NULL == neigh_update(n, route_info->ip_info.mac_addr.ether_addr_octet,
				 NEIGH_STATE_PERMANENT)) {
		pr_err("ipfwd_add_arp: Exit: Failed\n");
		return -1;
	}

	pr_debug("ipfwd_add_arp: Exit\n");
	return 0;
}

/**
 \brief Deletes an Arp Cache entry
 \param[out] app_ctrl_route_info contains ARP parameters
 \return Integer status
 */
int32_t ipfwd_del_arp(struct app_ctrl_op_info *route_info)
{
	struct neigh_t *neighbor = NULL;
	pr_debug("ipfwd_del_arp: Enter\n");

	/*
	 ** Do a Neighbour LookUp for the entry to be deleted
	 */
	neighbor = neigh_lookup(stack.arp_table,
				(route_info->ip_info.src_ipaddr),
				stack.arp_table->proto_len);
	if (neighbor == NULL) {
		pr_err
		    ("Could not find neighbor entry for link-local address\n");
		return -1;
	}

	/*
	 ** Find out if anyone is using this entry
	 */
	if (*(neighbor->refcnt) != 0) {
		pr_err
		    ("Could not delete neighbor entry as it is being used\n");
		return -1;
	}

	/*
	 ** Delete the ARP Entry
	 */
	if (false == neigh_remove(stack.arp_table,
				  route_info->ip_info.
					   src_ipaddr,
				  stack.arp_table->proto_len)) {
		pr_err("Could not delete neighbor entry\n");
		return -1;
	}

	pr_debug("ipfwd_del_arp: Exit\n");
	return 0;
}

/**
 \brief Initializes Receive context for IPSEC Forwarding app
 \param[in] struct net_dev * Netdev Pointer
 \param[in] struct ip_stack_t * ipstack pointer
 \param[out] Return initialized context
 */
static inline void
initialize_contexts(struct ip_context_t *ip_ctxt, struct net_dev_t *dev,
		    struct ip_stack_t *ip_stack)
{
	ip_ctxt->fq_ctxt.handler = &ip_handler;
	ip_ctxt->fq_ctxt.dev = dev;
	ip_ctxt->stats = ip_stack->ip_stats;
	ip_ctxt->hooks = &ip_stack->hooks;
	ip_ctxt->protos = ip_stack->protos;
	ip_ctxt->rc = ip_stack->rc;
}

/**
 \brief Initializes array of network local nodes
 \details Initializes array of network local nodes and assign it mac
	and ip addresses. Local nodes initialized are nodes directly
	connected to the interfaces
 \param[in] struct node_t * a Network Node
 \param[in] uint32_t Number of nodes to be created
 */
void create_local_nodes(struct node_t *arr, const struct usdpaa_netcfg_info *cfg_ptr)
{
	uint32_t port, node, node_idx;
	uint16_t addr_hi;
	const struct fman_if *fif;

	addr_hi = ETHERNET_ADDR_MAGIC;
	for (port = 0, node_idx = 0; port < g_num_dpa_eth_ports; port++) {
		fif = cfg_ptr->port_cfg[port].fman_if;
		for (node = 0; node < local_node_count[port]; node++,
			     node_idx++) {
			memcpy(&arr[node_idx].mac, &addr_hi, sizeof(addr_hi));
			arr[node_idx].ip = 0xc0a80a02 +
				((100 * fif->fman_idx +
				  10 * ((fif->mac_type == fman_mac_1g ? 0 : 5) + fif->mac_idx))
				 << 8) + node;
			memcpy(arr[node_idx].mac.ether_addr_octet + sizeof(addr_hi),
			       &arr[node_idx].ip,
			       sizeof(arr[node_idx].ip));
		}
	}
}

/**
\brief Initializes array of network iface nodes
\details Assign mac and ip addresses to the interface nodes.
 Interface nodes corresponds to the interfaces
\param[in] struct node_t * a Network Node
\param[in] uint32_t Number of nodes to be created
*/
void create_iface_nodes(struct node_t *arr, const struct usdpaa_netcfg_info *cfg_ptr)
{
	uint32_t port, if_idx;
	const struct fman_if *fif;

	for (port = 0, if_idx = 0; port < g_num_dpa_eth_ports; port++, if_idx++) {
		fif = cfg_ptr->port_cfg[port].fman_if;
		arr[if_idx].mac = fif->mac_addr;
		arr[if_idx].ip = 0xc0a80a01 +
			((100 * fif->fman_idx +
			  10 * ((fif->mac_type == fman_mac_1g ? 0 : 5) + fif->mac_idx)) << 8);
		pr_debug("PortID = %d is FMan\ninterface node with IP Address\n"
			 "%d.%d.%d.%d and MAC Address\n"ETH_MAC_PRINTF_FMT"\n", port,
			 ((uint8_t *)&arr[if_idx].ip)[0],
			 ((uint8_t *)&arr[if_idx].ip)[1],
			 ((uint8_t *)&arr[if_idx].ip)[2],
			 ((uint8_t *)&arr[if_idx].ip)[3],
			 ETH_MAC_PRINTF_ARGS(&arr[if_idx].mac));
	}
}

/**
 \brief Device Tx Initialization
 */
void dpa_dev_tx_init(struct dpa_dev_t *dev, struct ipfwd_fq_range_t *fq_range)
{
	uint32_t fq_idx;

	if (unlikely(fq_range->fq_count == 0)) {
		pr_err("FQ Count is zero\n");
		return;
	}

	for (fq_idx = 0; fq_idx < fq_range->fq_count; fq_idx++) {
		dev->tx_fq[fq_idx] = fq_range->fq[fq_idx];
	}
}

/**
 \brief Device Rx Initialization
 */
void dpa_dev_rx_init(struct dpa_dev_t *dev, struct ipfwd_fq_range_t *fq_range,
		     struct ip_context_t *ctxt)
{
	uint32_t fq_idx;
	struct ip_fq_context_t *fq_ctxt;

	if (unlikely(fq_range->fq_count == 0)) {
		pr_err("FQ Count is zero\n");
		return;
	}

	for (fq_idx = 0; fq_idx < fq_range->fq_count; fq_idx++) {
		dev->rx_fq[fq_idx] = fq_range->fq[fq_idx];
		fq_ctxt = (struct ip_fq_context_t *)(fq_range->fq[fq_idx]);
		fq_ctxt->ip_ctxt = ctxt;
	}
}

/**
 \brief Creates netdev Device Nodes
 \param[in] struct ip_stack_t * IPFwd stack structure
 \param[in] struct node_t * Link Node
 \param[in] uint32_t Number of network devices to be created
 \param[out] return status
 */
static int32_t
create_devices(struct ip_stack_t *ip_stack, struct node_t *link_nodes)
{
	uint32_t port;
	struct net_dev_t *dev;
	struct ip_context_t *ctxt;
	int _errno;

	ip_stack->nt = net_dev_init();
	if (unlikely(!ip_stack->nt)) {
		pr_err("No memory available for neighbor table\n");
		return -ENOMEM;
	}
	for (port = 0; port < g_num_dpa_eth_ports; port++) {
		_errno = posix_memalign((void **)&ctxt, L1_CACHE_BYTES,
					sizeof(struct ip_context_t));
		if (unlikely(_errno < 0)) {
			pr_err("No Memory for IP context\n");
			return _errno;
		}
		dev = dpa_dev_allocate(ip_stack->nt);
		if (unlikely(dev == NULL)) {
			pr_err("Unable to allocate net device Structure\n");
			free(ctxt);
			return -ENOMEM;
		}

		dpa_dev_init(dev);
		dev->set_ll_address(dev, &link_nodes[port].mac);
		dev->set_mtu(dev, ETHERMTU);

		initialize_contexts(ctxt, dev, ip_stack);
		dpa_dev_rx_init((struct dpa_dev_t *)dev,
				&ipfwd_fq_range[port].pcd, ctxt);
		dpa_dev_rx_init((struct dpa_dev_t *)dev,
				&ipfwd_fq_range[port].rx_def, ctxt);
		ip_stack->ctxt[port] = ctxt;
		dpa_dev_tx_init((struct dpa_dev_t *)dev,
				&ipfwd_fq_range[port].tx);
		if (!net_dev_register(ip_stack->nt, dev)) {
			pr_err("%s: Netdev Register Failed\n", __func__);
			return -EINVAL;
		}
	}
	return 0;
}

/**
 \brief Populate static arp entries
 \param[in] struct ip_stack_t * IPFwd stack structure
 \param[in] struct node_t * Link Node
 \param[out] 0 on success, otherwise -ve value
 */
int populate_arp_cache(struct ip_stack_t *ip_stack, struct node_t *loc_nodes)
{
	uint32_t i, j, node_idx;
	struct net_dev_t *dev;
	struct node_t *node;

	dev = ip_stack->nt->device_head;
	for (j = 0, node_idx = 0; j < g_num_dpa_eth_ports; j++) {
		for (i = 0; i < local_node_count[j]; i++) {
			node = &loc_nodes[node_idx];
			if (dev == NULL) {
				dev = ip_stack->nt->device_head;
			}

			if (0 > add_arp_entry(ip_stack->arp_table, dev, node)) {
				pr_err("%s: failed to add ARP entry\n",
					  __func__);
				return -EINVAL;
			}
			node_idx++;
		}
		dev = dev->next;
	}
	return 0;
}

/**
 \brief Initialize IPSec Statistics
 \param[in] void
 \param[out] struct ip_statistics_t *
 */
struct ip_statistics_t *ipfwd_stats_init(void)
{
	int _errno;
	void *ip_stats;

	_errno = posix_memalign(&ip_stats, L1_CACHE_BYTES, sizeof(struct ip_statistics_t));
	return unlikely(_errno < 0) ? NULL : ip_stats;
}

/**
 \brief Initialize IP Stack
 \param[in] struct ip_stack_t * IPFwd Stack pointer
 \param[out] Return Status
 */
static int32_t initialize_ip_stack(struct ip_stack_t *ip_stack)
{
	int _errno;

	ip_stack->arp_table = arp_table_create();
	if (!(ip_stack->arp_table)) {
		pr_err("Failed to create ARP Table\n");
		return -1;
	}
	if (!(neigh_table_init(ip_stack->arp_table))) {
		pr_err("Failed to init ARP Table\n");
		return -1;
	}
	ip_stack->rt = rt_create();
	if (!(ip_stack->rt)) {
		pr_err("Failed in Route table initialized\n");
		return -1;
	}
	ip_stack->rc = rc_create(IP_RC_EXPIRE_JIFFIES, sizeof(in_addr_t));
	if (!(ip_stack->rc)) {
		pr_err("Failed in Route cache initialized\n");
		return -1;
	}
	_errno = ip_hooks_init(&ip_stack->hooks);
	if (unlikely(_errno < 0)) {
		pr_err("Failed in IP Stack hooks initialized\n");
		return _errno;
	}
	ip_stack->protos = ip_protos_create();
	if (!(ip_stack->protos)) {
		pr_err("IP Stack L4 Protocols initialized\n");
		return -1;
	}
	ip_stack->ip_stats = ipfwd_stats_init();
	if (!(ip_stack->ip_stats)) {
		pr_err("Unable to allocate ip stats structure for stack\n");
		return -1;
	}
	memset(ip_stack->ip_stats, 0, sizeof(struct ip_statistics_t));

	pr_debug("IP Statistics initialized\n");
	return 0;
}

/**
 \brief Message handler for message coming from Control plane
 \param[in] app_ctrl_op_info contains SA parameters
 \return NULL
*/
void process_req_from_mq(struct app_ctrl_op_info *sa_info)
{
	int32_t s32Result = 0;
	sa_info->result = IPC_CTRL_RSLT_FAILURE;

	pr_debug("process_req_from_mq: Enter\n");
	switch (sa_info->msg_type) {
	case IPC_CTRL_CMD_TYPE_ROUTE_ADD:
		s32Result = ipfwd_add_route(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ROUTE_DEL:
		s32Result = ipfwd_del_route(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ARP_ADD:
		s32Result = ipfwd_add_arp(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ARP_DEL:
		s32Result = ipfwd_del_arp(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_GO:
		s32Result = 0;
		GO_FLAG = 1;
		break;

	default:
		break;
	}

	if (s32Result == 0) {
		sa_info->result = IPC_CTRL_RSLT_SUCCESSFULL;
	} else {
		pr_err("%s: CP Request can't be handled\n", __func__);
	}

	pr_debug("process_req_from_mq: Exit\n");
	return;
}

int receive_data(mqd_t mqdes)
{
	ssize_t size;
	struct app_ctrl_op_info *ip_info = NULL;
	struct mq_attr attr;
	int _err = 0;

	ip_info = (struct app_ctrl_op_info *)malloc
			(sizeof(struct app_ctrl_op_info));
	memset(ip_info, 0, sizeof(struct app_ctrl_op_info));

	_err = mq_getattr(mqdes, &attr);
	if (unlikely(_err)) {
		pr_err("%s: %dError getting MQ attributes\n",
			 __FILE__, __LINE__);
		goto error;
	}
	size = mq_receive(mqdes, (char *)ip_info, attr.mq_msgsize, 0);
	if (unlikely(size == -1)) {
		pr_err("%s: %dRcv msgque error\n", __FILE__, __LINE__);
		goto error;
	}
	process_req_from_mq(ip_info);
	/* Sending result to application configurator tool */
	_err = mq_send(mq_fd_snd, (const char *)ip_info,
			sizeof(struct app_ctrl_op_info), 10);
	if (unlikely(_err != 0)) {
		pr_err("%s: %d Error in sending msg on MQ\n",
			__FILE__, __LINE__);
		goto error;
	}

	return 0;
error:
	free(ip_info);
	return _err;
}

void mq_handler(union sigval sval)
{
	pr_debug("mq_handler called %d\n", sval.sival_int);

	receive_data(mq_fd_rcv);
	mq_notify(mq_fd_rcv, &notification);
}

int create_mq(void)
{
	struct mq_attr attr_snd, attr_rcv;
	int _err = 0, ret;

	pr_debug("Create mq: Enter\n");
	memset(&attr_snd, 0, sizeof(attr_snd));

	/* Create message queue to send the response */
	attr_snd.mq_maxmsg = 10;
	attr_snd.mq_msgsize = 8192;
	mq_fd_snd = mq_open("/mq_snd", O_CREAT | O_WRONLY,
				(S_IRWXU | S_IRWXG | S_IRWXO), &attr_snd);
	if (mq_fd_snd == -1) {
		pr_err("%s: %dError opening SND MQ\n",
				__FILE__, __LINE__);
		_err = -errno;
		goto error;
	}

	memset(&attr_rcv, 0, sizeof(attr_rcv));

	/* Create message queue to read the message */
	attr_rcv.mq_maxmsg = 10;
	attr_rcv.mq_msgsize = 8192;
	mq_fd_rcv = mq_open("/mq_rcv", O_CREAT | O_RDONLY, (S_IRWXU | S_IRWXG | S_IRWXO), &attr_rcv);
	if (mq_fd_rcv == -1) {
		pr_err("%s: %dError opening RCV MQ\n",
				 __FILE__, __LINE__);
		_err = -errno;
		goto error;
	}

	notification.sigev_notify = SIGEV_THREAD;
	notification.sigev_notify_function = mq_handler;
	notification.sigev_value.sival_ptr = &mq_fd_rcv;
	notification.sigev_notify_attributes = NULL;
	ret =  mq_notify(mq_fd_rcv, &notification);
	if (ret) {
		pr_err("%s: %dError in mq_notify call\n",
				 __FILE__, __LINE__);
		_err = -errno;
		goto error;
	}
	pr_debug("Create mq: Exit\n");
	return 0;
error:
	if (mq_fd_snd)
		mq_close(mq_fd_snd);

	if (mq_fd_rcv)
		mq_close(mq_fd_rcv);

	return _err;
}

int global_init(struct usdpaa_netcfg_info *uscfg_info, int cpu, int first, int last)
{
	int err;
	const struct ipfwd_bpool_static *bp = ipfwd_bpool_static;
	dma_addr_t phys_addr = dma_mem_bpool_base();
	dma_addr_t phys_limit = phys_addr + dma_mem_bpool_range();
	unsigned int loop;

	pr_debug("Global initialisation: Enter\n");

	/* Initialise barrier for all the threads including main thread */
	if (!cpu0_only) {
		err = pthread_barrier_init(&init_barrier, NULL,
			last - first + 2);
		if (err != 0)
			pr_info("pthread_barrier_init failed\n");
	}
	err = bman_thread_init(cpu, 0);
	if (err) {
		fprintf(stderr, "bman_thread_init(%d) failed, ret=%d\n",
			cpu, err);
		return -1;
	}
	err = qman_thread_init(cpu, 0);
	if (err) {
		fprintf(stderr, "qman_thread_init(%d) failed, ret=%d\n",
			cpu, err);
	return -1;
	}

	/* Initialise and see any BPIDs we've been configured to set up */
	while (bp->bpid != -1) {
		struct bm_buffer bufs[8];
		unsigned int num_bufs = 0;
		u8 bpid = bp->bpid;
		err = lazy_init_bpool(bpid);
		if (err) {
			fprintf(stderr, "error: bpool (%d) init failure\n",
				bpid);
			break;
		}
		/* Drain the pool of anything already in it. */
		do {
			/* Acquire is all-or-nothing, so we drain in 8s, then in
			 * 1s for the remainder. */
			if (err != 1)
				err = bman_acquire(pool[bpid], bufs, 8, 0);
			if (err < 8)
				err = bman_acquire(pool[bpid], bufs, 1, 0);
			if (err > 0)
				num_bufs += err;
		} while (err > 0);
		if (num_bufs)
			fprintf(stderr, "warn: drained %u bufs from BPID %d\n",
				num_bufs, bpid);
		/* Fill the pool */
		for (num_bufs = 0; num_bufs < bp->num; ) {
			unsigned int rel = (bp->num - num_bufs) > 8 ? 8 :
						(bp->num - num_bufs);
			for (loop = 0; loop < rel; loop++) {
				bm_buffer_set64(&bufs[loop], phys_addr);
				phys_addr += bp->sz;
			}
			if (phys_addr > phys_limit) {
				fprintf(stderr, "error: buffer overflow\n");
				abort();
			}
			do {
				err = bman_release(pool[bpid], bufs, rel, 0);
			} while (err == -EBUSY);
			if (err)
				fprintf(stderr, "error: release failure\n");
			num_bufs += rel;
		}
		printf("Release %u bufs to BPID %d\n", num_bufs, bpid);
		bp++;
	}

	/* Initializes a soft cache of buffers */
	if (unlikely(NULL == mem_cache_init())) {
		pr_err("Cache Creation error\n");
		return -ENOMEM;
	}
	/* Initializes IP stack*/
	if (initialize_ip_stack(&stack)) {
		pr_err("Error Initializing IP Stack\n");
		return -ENOMEM;
	}
	/* Initializes ethernet interfaces */
	if (0 != init_interface(uscfg_info, &recv_channel_map,
			(struct qman_fq_cb *)&ipfwd_rx_cb,
			(struct qman_fq_cb *)&ipfwd_rx_cb_pcd,
			(struct qman_fq_cb *)&ipfwd_rx_cb_err,
			(struct qman_fq_cb *)&ipfwd_tx_cb,
			(struct qman_fq_cb *)&ipfwd_tx_cb_confirm,
			(struct qman_fq_cb *)&ipfwd_tx_cb_err,
			sizeof(struct ip_context_t *))) {
		pr_err("Unable to initialize interface\n");
		return -EINVAL;
	}
	/* Initializes array of network iface nodes */
	create_iface_nodes(iface_nodes, uscfg_info);

	/* Initializes array of network local nodes */
	create_local_nodes(local_nodes, uscfg_info);

	/* Creates netdev Device Nodes */
	if (create_devices(&stack, iface_nodes)) {
		pr_err("Unable to Create Devices\n");
		return -ENOMEM;
	}

	/* Populate static arp entries */
	populate_arp_cache(&stack, local_nodes);
	pr_info
	    ("ARP Cache Populated, Stack pointer is %p and its size = %zu\n",
	     &stack, sizeof(stack));
	pr_debug("Global initialisation: Exit\n");

	return 0;
}

struct thread_data_t *my_thread_data(void)
{
	return __my_thread_data;
}

static void *thread_wrapper(void *arg)
{
	struct thread_data_t *tdata = (struct thread_data_t *)arg;
	cpu_set_t cpuset;
	int s;

	__my_thread_data = tdata;
	/* Set this thread affine to cpu */
	CPU_ZERO(&cpuset);
	CPU_SET(tdata->cpu, &cpuset);
	s = pthread_setaffinity_np(tdata->id, sizeof(cpu_set_t), &cpuset);
	if (s != 0) {
		pr_err("pthread_setaffinity_np failed\n");
		goto end;
	}
	s = bman_thread_init(tdata->cpu, 0);
	if (s) {
		fprintf(stderr, "bman_thread_init(%d) failed, ret=%d\n",
			tdata->cpu, s);
		goto end;
	}
	s = qman_thread_init(tdata->cpu, 0);
	if (s) {
		fprintf(stderr, "qman_thread_init(%d) failed, ret=%d\n",
			tdata->cpu, s);
		goto end;
	}

	/* Invoke the application thread function */
	s = tdata->fn(tdata);
end:
	__my_thread_data = NULL;
	tdata->result = s;
	return NULL;
}

int start_threads_custom(struct thread_data_t *ctxs, int num_ctxs)
{
	int i;
	struct thread_data_t *ctx;
	/* Create the threads */
	for (i = 0, ctx = &ctxs[0]; i < num_ctxs; i++, ctx++) {
		int err;
		/* Create+start the thread */
		err = pthread_create(&ctx->id, NULL, thread_wrapper, ctx);
		if (err != 0) {
			fprintf(stderr, "error starting thread %d, %d already "
				"started\n", i, i - 1);
			return err;
		}
	}
	return 0;
}

static inline int start_threads(struct thread_data_t *ctxs, int num_ctxs,
			int first_cpu, int (*fn)(struct thread_data_t *))
{
	int loop;
	for (loop = 0; loop < num_ctxs; loop++) {
		ctxs[loop].cpu = first_cpu + loop;
		ctxs[loop].index = loop;
		ctxs[loop].fn = fn;
		ctxs[loop].total_cpus = num_ctxs;
	}
	return start_threads_custom(ctxs, num_ctxs);
}

int wait_threads(struct thread_data_t *ctxs, int num_ctxs)
{
	int i, err = 0;
	struct thread_data_t *ctx;
	/* Wait for them to join */
	for (i = 0, ctx = &ctxs[0]; i < num_ctxs; i++, ctx++) {
		int res = pthread_join(ctx->id, NULL);
		if (res != 0) {
			fprintf(stderr, "error joining thread %d\n", i);
			if (!err)
				err = res;
		}
	}
	return err;
}

int main(int argc, char *argv[])
{
	struct thread_data_t thread_data[MAX_THREADS];
	char *endptr;
	int first, last, my_cpu = 0, cpu0_poll_on = 0;
	long ncpus;
	int err, ret;
	struct usdpaa_netcfg_info *uscfg_info;

	/* Get the number of cpus */
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus == 1) {
		first = last = 0;
	} else {
		first = last = 1;
	}
	/* Parse the arguments */
	if (argc == 4) {
		first = my_toul(argv[1], &endptr, ncpus);
		if (*endptr == '\0') {
			last = first;
		} else if ((*(endptr++) == '.') && (*(endptr++) == '.') &&
				(*endptr != '\0')) {
			last = my_toul(endptr, &endptr, ncpus);
			if (last < first) {
				ret = first;
				first = last;
				last = ret;
			}
		} else {
			fprintf(stderr, "error: can't parse cpu-range '%s'\n",
				argv[1]);
			exit(EXIT_FAILURE);
		}
	} else if (argc != 4) {
		fprintf(stderr, "usage: ipfwd_app <cpu-range>" "<fmc_pcd_file> "
					"<fmc_cfgdata_file>\n");
		fprintf(stderr, "where [cpu-range] is 'n' or 'm..n'\n");
		exit(EXIT_FAILURE);
	}
	if (first == 0) {
		cpu0_poll_on = 1;
		if (first != last)
			first = first + 1;
		else
			cpu0_only = 1;
	}

	pr_info("\n** Welcome to IPFWD application! **\n");

	uscfg_info = usdpaa_netcfg_acquire(argv[2], argv[3]);
	if (uscfg_info == NULL) {
		fprintf(stderr, "error: NO Config information available\n");
		return -ENXIO;
	}

	/* - validate the config */
	if (!uscfg_info->num_ethports) {
		fprintf(stderr, "error: no network interfaces available\n");
		return -1;
	}
	if (!uscfg_info->num_pool_channels) {
		fprintf(stderr, "error: no pool channels available\n");
		return -1;
	}
	pr_info("Configuring for %d n/w interface%s and %d pool channel%s\n",
		uscfg_info->num_ethports,
		uscfg_info->num_ethports > 1 ? "s" : "",
		uscfg_info->num_pool_channels,
		uscfg_info->num_pool_channels > 1 ? "s" : "");

	err = bman_global_init(0);
	if (err) {
		fprintf(stderr, "bman_global_init() failed, ret=%d\n",
			err);
		return err;
	}
	/* Set up the fqid allocator */
	err = qman_global_init(0);
	if (err) {
		fprintf(stderr, "qman_global_init() failed, ret=%d\n",
			err);
		return err;
	}
	/* map shmem */
	err = dma_mem_setup();
	if (err) {
		pr_err("shmem setup failure\n");
		return err;
	}
	err = global_init(uscfg_info, my_cpu, first, last);
	if (err != 0) {
		pr_err("Global initialization failed\n");
		return -1;
	}

	/* Create Message queues to send and receive */
	err = create_mq();
	if (err == -1) {
		pr_err("Error in creating message queues\n");
		return -1;
	}

	if (!cpu0_only) {
		err = start_threads(thread_data, last - first + 1, first,
			 worker_fn);
		if (err != 0)
			pr_info("start_threads failed\n");
	}

	if (cpu0_poll_on) {
		pr_info("Frames to be recv on channel map: 0x%x\n",
				 recv_channel_map);
		qman_static_dequeue_add(recv_channel_map);
	}

	pr_info("Waiting for Configuration Command\n");
	/* Wait for initial IPFWD related configuration to be done */
	while (0 == GO_FLAG);

	/* Enable all the ethernet ports*/
	fman_if_enable_all_rx();

	/* Wait for other threads before start qman poll */
	if (!cpu0_only)
		pthread_barrier_wait(&init_barrier);

	/* CPU0 going for qman poll */
	if (cpu0_poll_on) {
		pr_info("Going for qman poll cpu %d\n", my_cpu);
		while (1)
			qman_poll();
	}
	/* Wait for all the threads to finish */
	if (!cpu0_only)
		wait_threads(thread_data, last - first + 1);

	usdpaa_netcfg_release(uscfg_info);
	return 0;
}
