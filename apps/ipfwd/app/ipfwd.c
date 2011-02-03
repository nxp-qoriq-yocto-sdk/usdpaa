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
#include <linux/fsl_qman.h>
#include "ip/ip_forward.h"
#include "ip/ip_local.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <errno.h>
#include <signal.h>
#include <fman.h>
#include <bigatomic.h>
#include <dma_mem.h>
#include <usdpa_netcfg.h>

uint32_t iface_subnet[IFACE_COUNT] = { 24, 29, 21, 22, 23, 25, 26, 27, 28 };
uint32_t local_node_count[IFACE_COUNT] = { 23, 23, 23, 23, 23, 23, 23, 23, 1 };
struct node_t local_nodes[LINKLOCAL_NODES];
struct node_t iface_nodes[IFACE_COUNT];
struct ip_stack_t stack;
mqd_t mq_fd_rcv, mq_fd_snd;
struct sigevent notification;
static bool infinit_fcnt;
uint32_t initial_frame_count = INITIAL_FRAME_COUNT;
volatile uint32_t GO_FLAG;
static const struct bman_bpid_range bpid_range[] = {
	{FSL_BPID_RANGE_START, FSL_BPID_RANGE_LENGTH} };
static const struct bman_bpid_ranges bpid_allocator = {
	.num_ranges = 1,
	.ranges = bpid_range
};
static const struct qman_fqid_range fqid_range[] = {
	{FSL_FQID_RANGE_START, FSL_FQID_RANGE_LENGTH} };
static const struct qman_fqid_ranges fqid_allocator = {
	.num_ranges = 1,
	.ranges = fqid_range
};
static __thread struct thread_data_t *__my_thread_data;
#define IPFWD_BPIDS		{7, 8, 9}
struct bman_pool *pool[MAX_NUM_BMAN_POOLS];
__PERCPU uint32_t rx_errors;
#define MAX_THREADS 8
uint32_t recv_channel_map;

static pthread_barrier_t init_barrier;
int cpu0_only;
void ip_fq_state_chg(struct qman_portal *qm,
		     struct qman_fq *fq, const struct qm_mr_entry *msg)
{
	APP_INFO("FQ STATE CHANGE");
}

static int worker_fn(struct thread_data_t *tdata)
{

	APP_INFO("This is the thread on cpu %d\n", tdata->cpu);

	/* Set the qman portal's SDQCR mask */
	APP_INFO("Frames to be recv on channel map: 0x%x", recv_channel_map);
	qman_static_dequeue_add(recv_channel_map);

	/* Wait till the main thread enables all the ethernet ports */
	pthread_barrier_wait(&init_barrier);

	APP_INFO("Going for qman poll cpu %d\n", tdata->cpu);
	while (1)
		qman_poll();

	APP_INFO("Leaving thread on cpu %d\n", tdata->cpu);
	pthread_exit(NULL);
}

/**
 \brief Change Interface Configuration
 \param[out] lwe_ctrl_route_info contains Route parameters
 \return Integer status
 */
int32_t ipfwd_conf_intf(struct lwe_ctrl_op_info *route_info)
{
	APP_DEBUG("ipfwd_conf_intf: Enter");

	APP_DEBUG("ipfwd_conf_intf: Bitmask = 0x%x",
		  route_info->ip_info.intf_conf.bitmask);

	APP_DEBUG("ipfwd_conf_intf: Ifname = %s",
		  route_info->ip_info.intf_conf.ifname);
	APP_DEBUG("ipfwd_conf_intf: IPAddr = 0x%x",
		  route_info->ip_info.intf_conf.ip_addr);
	APP_DEBUG("ipfwd_conf_intf: MAC Addr = %x:%x:%x:%x:%x:%x",
		  route_info->ip_info.intf_conf.mac_addr[0],
		  route_info->ip_info.intf_conf.mac_addr[1],
		  route_info->ip_info.intf_conf.mac_addr[2],
		  route_info->ip_info.intf_conf.mac_addr[3],
		  route_info->ip_info.intf_conf.mac_addr[4],
		  route_info->ip_info.intf_conf.mac_addr[5]);

	APP_DEBUG("ipfwd_conf_intf: Exit");
	return 0;
}

int is_iface_ip(uint32_t ip_addr)
{
	int i;

	for (i = 0; i < g_num_dpa_eth_ports; i++) {
		if (iface_nodes[i].ip.word == ip_addr)
			return 0;
	}

	return -EINVAL;
}

/**
 \brief Gets interface node corresponding to an ip address
 \param[in] ip_addr IP Address
 \return    interface node, On success
	    NULL, 	    On failure
 */
struct node_t *ipfwd_get_iface_for_ip(uint32_t ip_addr)
{
	uint32_t port;

	for (port = 0; port < g_num_dpa_eth_ports; port++) {
		if ((iface_nodes[port].ip.word & 0xffffff00) ==
		    (ip_addr & 0xffffff00))
			break;
	}

	if (unlikely(port == g_num_dpa_eth_ports)) {
		APP_ERROR("%s: Exit: Failed: Not a valid IP addr", __FILE__);
		return NULL;
	}

	return &iface_nodes[port];
}

/**
 \brief Gets device pointer corresponding to an ip address
 \param[in] ip_addr IP Address
 */
struct net_dev_t *ipfwd_get_dev_for_ip(unsigned int ip_addr)
{
	uint32_t port, node = 0, node_idx;
	unsigned char *mac_addr;
	struct net_dev_t *dev;

	/* Check that the arp entry creation request is for a local node */
	for (port = 0, node_idx = 0; port < g_num_dpa_eth_ports; port++) {
		for (node = 0; node < local_node_count[port];
		     node++, node_idx++) {
			if (local_nodes[node_idx].ip.word == ip_addr)
				goto _TEMP;
		}
	}

	APP_DEBUG("%s: Not a Local Node", __func__);

_TEMP:

	/*
	 ** Find out the mac address of the iface node
	 ** corresponding to the local node
	 */
	for (port = 0; port < g_num_dpa_eth_ports; port++) {
		if ((iface_nodes[port].ip.word & 0xffffff00) ==
		    (ip_addr & 0xffffff00))
			break;
	}

	if (unlikely(port == g_num_dpa_eth_ports)) {
		APP_INFO("%s: Exit: Failed: Not in any iface subnet", __func__);
		return NULL;
	}

	/*
	 ** Finding the device ptr correspnding to the iface node
	 */
	mac_addr = (unsigned char *)&(iface_nodes[port].mac);
	dev = stack.nt->device_head;
	while (dev != NULL) {
		char *dev_mac = (char *)(dev->dev_addr);

		if (memcmp(dev_mac, mac_addr, 6) == 0)
			break;

		dev = dev->next;
	}

	return dev;
}

/**
 \brief Adds a new Route Cache entry
 \param[out] lwe_ctrl_route_info contains Route parameters
 \return Integer status
 */
int32_t ipfwd_add_route(struct lwe_ctrl_op_info *route_info)
{
	struct rc_entry_t *entry;
	struct rt_dest_t *dest;
	struct net_dev_t *dev = NULL;
	unsigned int gw_ipaddr = route_info->ip_info.gw_ipaddr;

	APP_DEBUG("ipfwd_add_route: Enter");

	dest = rt_dest_alloc(stack.rt);
	if (dest == NULL) {
		APP_ERROR
		    ("Could not allocate route cache related data structure");
		return -1;
	}

	dest->next = NULL;
	dest->neighbor = neigh_lookup(stack.arp_table, gw_ipaddr,
				      stack.arp_table->proto_len);
	if (dest->neighbor == NULL) {
		APP_DEBUG
		    ("%s: Could not find neighbor entry for link-local address",
		     __func__);

		dev = ipfwd_get_dev_for_ip(gw_ipaddr);
		if (dev == NULL) {
			APP_ERROR("%s: not a valid gateway for any subnet",
				  __func__);
			return -1;
		}

		dest->neighbor = neigh_create(stack.arp_table);
		if (unlikely(!dest->neighbor)) {
			APP_ERROR("%s: Unable to create Neigh Entry", __func__);
			return -1;
		}

		if (NULL == neigh_init(stack.arp_table, dest->neighbor, dev,
				       (uint32_t *) &gw_ipaddr)) {
			APP_ERROR("%s: Unable to init Neigh Entry", __func__);
			return -1;
		}

		if (false == neigh_add(stack.arp_table, dest->neighbor)) {
			APP_ERROR("%s: Unable to add Neigh Entry", __func__);
			return -1;
		}
		/* MAC addr would be updated later through ARP request */

		APP_DEBUG("%s: Created neighbor entry, IP addr = %x",
			  __func__, gw_ipaddr);
	}

	dest->dev = dest->neighbor->dev;
	dest->scope = ROUTE_SCOPE_GLOBAL;

	entry = rc_create_entry(stack.rc);
	if (entry == NULL) {
		APP_ERROR("Could not allocate route cache entry");
		rt_dest_free(stack.rt, dest);
		return -1;
	}

	entry->saddr = route_info->ip_info.src_ipaddr;
	entry->daddr = route_info->ip_info.dst_ipaddr;
	entry->stats =
	    memalign(CACHE_LINE_SIZE,
			   sizeof(struct rc_entry_statistics_t));
	if (entry->stats == NULL) {
		APP_ERROR("Unable to allocate route entry stats");
		return -ENOMEM;
	}
	memset(entry->stats, 0, sizeof(struct rc_entry_statistics_t));
	refcount_acquire(dest->neighbor->refcnt);

	entry->dest = dest;
	entry->last_used = mfspr(SPR_ATBL);
	entry->tos = IP_TOS;

	if (rc_add_update_entry(stack.rc, entry) == false) {
		APP_ERROR("Route cache entry updated");
		rc_free_entry(stack.rc, entry);
	}

	APP_DEBUG("ipfwd_add_route: Exit");
	return 0;
}

/**
 \brief Deletes a Route Cache entry
 \param[out] lwe_ctrl_route_info contains Route parameters
 \return Integer status
 */
int32_t ipfwd_del_route(struct lwe_ctrl_op_info * route_info)
{
	struct rt_dest_t *dest;
	APP_DEBUG("ipfwd_del_route: Enter");

	dest = rc_lookup(stack.rc,
			 route_info->ip_info.src_ipaddr,
			 route_info->ip_info.dst_ipaddr,
			 (uint8_t)route_info->ip_info.tos);
	if (dest == NULL) {
		APP_ERROR("Could not find route cache entry to be deleted");
		return -1;
	}

	refcount_release(dest->neighbor->refcnt);

	if (rc_remove_entry(stack.rc,
			    route_info->ip_info.src_ipaddr,
			    route_info->ip_info.dst_ipaddr,
			    (uint8_t)route_info->ip_info.tos)
				== false) {
		APP_ERROR("Could not delete route cache entry");
		return -1;
	}

	rt_dest_free(stack.rt, dest);
	APP_DEBUG("ipfwd_del_route: Exit");
	return 0;
}

/**
 \brief Adds a new Arp Cache entry
 \param[out] lwe_ctrl_route_info contains ARP parameters
 \return Integer status
 */
int32_t ipfwd_add_arp(struct lwe_ctrl_op_info * route_info)
{
	unsigned char *c = route_info->ip_info.mac_addr;
	unsigned int ip_addr = route_info->ip_info.src_ipaddr;
	struct net_dev_t *dev = NULL;
	struct neigh_t *n;

#if (LOG_LEVEL > 3)
	unsigned char *ip = (unsigned char *)&(ip_addr);
	APP_DEBUG("ipfwd_add_arp: Enter");

	APP_DEBUG("IP = %d.%d.%d.%d ; MAC = %x:%x:%x:%x:%x:%x", ip[0],
		  ip[1], ip[2], ip[3], c[0], c[1], c[2], c[3], c[4], c[5]);
#endif

	n = neigh_lookup(stack.arp_table, ip_addr,
				stack.arp_table->proto_len);

	if (n == NULL) {
		APP_DEBUG
		    ("%s: Could not find neighbor entry for link-local address",
		     __func__);

		dev = ipfwd_get_dev_for_ip(ip_addr);
		if (dev == NULL) {
			APP_DEBUG("ipfwd_add_arp: Exit: Failed");
			return -1;
		}

		n = neigh_create(stack.arp_table);
		if (unlikely(!n)) {
			APP_DEBUG("ipfwd_add_arp: Exit: Failed");
			return -1;
		}
		if (NULL == neigh_init(stack.arp_table, n, dev,
					(uint32_t *) &ip_addr)) {
			APP_ERROR("ipfwd_add_arp: Exit: Failed");
			return -1;
		}

		if (false == neigh_add(stack.arp_table, n)) {
			APP_ERROR("ipfwd_add_arp: Exit: Failed");
			return -1;
		}
	} else {
		n->neigh_state = NEIGH_STATE_UNKNOWN;
		if (route_info->ip_info.replace_entry) {
			if (false == neigh_replace(stack.arp_table, n)) {
				APP_ERROR("ipfwd_add_arp: Exit: Failed");
				return -1;
			}
		}
	}
	/* Update ARP cache entry */
	if (NULL == neigh_update(n, c, NEIGH_STATE_PERMANENT)) {
		APP_ERROR("ipfwd_add_arp: Exit: Failed");
		return -1;
	}

	APP_DEBUG("ipfwd_add_arp: Exit");
	return 0;
}

/**
 \brief Deletes an Arp Cache entry
 \param[out] lwe_ctrl_route_info contains ARP parameters
 \return Integer status
 */
int32_t ipfwd_del_arp(struct lwe_ctrl_op_info *route_info)
{
	struct neigh_t *neighbor = NULL;
	APP_DEBUG("ipfwd_del_arp: Enter");

	/*
	 ** Do a Neighbour LookUp for the entry to be deleted
	 */
	neighbor = neigh_lookup(stack.arp_table,
				(route_info->ip_info.src_ipaddr),
				stack.arp_table->proto_len);
	if (neighbor == NULL) {
		APP_ERROR
		    ("Could not find neighbor entry for link-local address");
		return -1;
	}

	/*
	 ** Find out if anyone is using this entry
	 */
	if (*(neighbor->refcnt) != 0) {
		APP_ERROR
		    ("Could not delete neighbor entry as it is being used");
		return -1;
	}

	/*
	 ** Delete the ARP Entry
	 */
	if (false == neigh_remove(stack.arp_table,
				  route_info->ip_info.
					   src_ipaddr,
				  stack.arp_table->proto_len)) {
		APP_ERROR("Could not delete neighbor entry");
		return -1;
	}

	APP_DEBUG("ipfwd_del_arp: Exit");
	return 0;
}

/**
 \brief Update application expected frame counter for its completion
	If frame_cnt specified is 0, then application would run indefinitely
	else would come out after printing stats after certain number of pkts.
 */
static int32_t ip_edit_num_cnt(struct lwe_ctrl_op_info *cp_info)
{
	infinit_fcnt = (cp_info->ip_info.frame_cnt == 0) ?
	    true : false;

	initial_frame_count = cp_info->ip_info.frame_cnt;
	APP_INFO("Frame count changed to %d", initial_frame_count);
	if (infinit_fcnt == true)
		APP_INFO("Application is going in infinite_mode");
	else
		APP_INFO("Application is going to finite_mode");

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
	ip_ctxt->hooks = ip_stack->hooks;
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
void create_local_nodes(struct node_t *arr)
{
	uint32_t port, node, node_idx;

	for (port = 0, node_idx = 0; port < g_num_dpa_eth_ports; port++) {
		for (node = 0; node < local_node_count[port]; node++,
			node_idx++) {
			arr[node_idx].mac.ether_addr_octet[0] =
				ETHERNET_ADDR_MAGIC;
			arr[node_idx].mac.ether_addr_octet[2] =
				arr[node_idx].ip.word =
				0xc0a80002 + (iface_subnet[port] << 8) + node;
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
void create_iface_nodes(struct node_t *arr, struct usdpa_netcfg_info *cfg_ptr)
{
	uint32_t port, if_idx;
	struct fm_eth_port_cfg *p_cfg;
	const struct fman_if *fif;

	for (port = 0, if_idx = 0; port < g_num_dpa_eth_ports; port++, if_idx++) {
		p_cfg = &cfg_ptr->port_cfg[port];
		fif = p_cfg->fman_if;
		memcpy(arr[if_idx].mac.ether_addr_octet,
			fif->mac_addr.ether_addr_octet,
			ETHER_ADDR_LEN);
		arr[if_idx].ip.word = (0xc0a80001 + (iface_subnet[port] << 8));
		APP_DEBUG("PortID = %d is %s interface node with IP Address "
			 "%d.%d.%d.%d and MAC Address " MAC_FMT, port,
			 "FMAN",
			 arr[if_idx].ip.bytes[0], arr[if_idx].ip.bytes[1],
			 arr[if_idx].ip.bytes[2], arr[if_idx].ip.bytes[3],
			 NMAC_STR(arr[if_idx].mac.ether_addr_octet));
	}
}

/**
 \brief Device Tx Initialization
 */
void dpa_dev_tx_init(struct dpa_dev_t *dev, struct ipfwd_fq_range_t *fq_range)
{
	uint32_t fq_idx;

	if (unlikely(fq_range->fq_count == 0)) {
		APP_ERROR("FQ Count is zero");
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
		APP_ERROR("FQ Count is zero");
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

	ip_stack->nt = net_dev_init();
	if (unlikely(!ip_stack->nt)) {
		APP_ERROR("No memory available for neighbor table");
		return -ENOMEM;
	}
	for (port = 0; port < g_num_dpa_eth_ports; port++) {
		ctxt =
		     memalign(CACHE_LINE_SIZE, sizeof(struct ip_context_t));
		if (!ctxt) {
			APP_ERROR("No Memory for IP context");
			return -ENOMEM;
		}
		dev = dpa_dev_allocate(ip_stack->nt);
		if (unlikely(dev == NULL)) {
			APP_ERROR("Unable to allocate net device Structure");
			free(ctxt);
			return -ENOMEM;
		}

		dpa_dev_init(dev);
		dev->set_ll_address(dev, &link_nodes[port].mac);
		dev->set_mtu(dev, IFACE_MTU);

		initialize_contexts(ctxt, dev, ip_stack);
		dpa_dev_rx_init((struct dpa_dev_t *)dev,
				&ipfwd_fq_range[port].pcd, ctxt);
		dpa_dev_rx_init((struct dpa_dev_t *)dev,
				&ipfwd_fq_range[port].rx_def, ctxt);
		ip_stack->ctxt[port] = ctxt;
		dpa_dev_tx_init((struct dpa_dev_t *)dev,
				&ipfwd_fq_range[port].tx);
		if (!net_dev_register(ip_stack->nt, dev)) {
			APP_ERROR("%s: Netdev Register Failed", __func__);
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
				APP_ERROR("%s: failed to add ARP entry",
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
	return memalign(CACHE_LINE_SIZE, sizeof(struct ip_statistics_t));
}

/**
 \brief Initialize IP Stack
 \param[in] struct ip_stack_t * IPFwd Stack pointer
 \param[out] Return Status
 */
static int32_t initialize_ip_stack(struct ip_stack_t *ip_stack)
{
	ip_stack->arp_table = arp_table_create();
	if (!(ip_stack->arp_table)) {
		APP_ERROR("Failed to create ARP Table");
		return -1;
	}
	if (!(neigh_table_init(ip_stack->arp_table))) {
		APP_ERROR("Failed to init ARP Table");
		return -1;
	}
	ip_stack->rt = rt_create();
	if (!(ip_stack->rt)) {
		APP_ERROR("Failed in Route table initialized");
		return -1;
	}
	ip_stack->rc = rc_create(IP_RC_EXPIRE_JIFFIES, IP_ADDRESS_BYTES);
	if (!(ip_stack->rc)) {
		APP_ERROR("Failed in Route cache initialized");
		return -1;
	}
	ip_stack->hooks = ip_hooks_create();
	if (!(ip_stack->hooks)) {
		APP_ERROR("Failed in IP Stack hooks initialized");
		return -1;
	}
	ip_stack->protos = ip_protos_create();
	if (!(ip_stack->protos)) {
		APP_ERROR("IP Stack L4 Protocols initialized");
		return -1;
	}
	ip_stack->ip_stats = ipfwd_stats_init();
	if (!(ip_stack->ip_stats)) {
		APP_ERROR("Unable to allocate ip stats structure for stack");
		return -1;
	}
	memset(ip_stack->ip_stats, 0, sizeof(struct ip_statistics_t));

	APP_DEBUG("IP Statistics initialized\n");
	return 0;
}

/**
 \brief Message handler for message coming from Control plane
 \param[in] lwe_ctrl_op_info contains SA parameters
 \return NULL
*/
void process_req_from_mq(struct lwe_ctrl_op_info *sa_info)
{
	int32_t s32Result = 0;
	sa_info->result = LWE_CTRL_RSLT_FAILURE;

	APP_DEBUG("process_req_from_mq: Enter");
	switch (sa_info->msg_type) {
	case LWE_CTRL_CMD_TYPE_ROUTE_ADD:
		s32Result = ipfwd_add_route(sa_info);
		break;

	case LWE_CTRL_CMD_TYPE_ROUTE_DEL:
		s32Result = ipfwd_del_route(sa_info);
		break;

	case LWE_CTRL_CMD_TYPE_ARP_ADD:
		s32Result = ipfwd_add_arp(sa_info);
		break;

	case LWE_CTRL_CMD_TYPE_ARP_DEL:
		s32Result = ipfwd_del_arp(sa_info);
		break;

	case LWE_CTRL_CMD_TYPE_FRAMECNT_EDIT:
		s32Result = ip_edit_num_cnt(sa_info);
		break;

	case LWE_CTRL_CMD_TYPE_GO:
		s32Result = 0;
		GO_FLAG = 1;
		break;

	default:
		break;
	}

	if (s32Result == 0) {
		sa_info->result = LWE_CTRL_RSLT_SUCCESSFULL;
	} else {
		APP_ERROR("%s: CP Request can't be handled", __func__);
	}

	APP_DEBUG("process_req_from_mq: Exit");
	return;
}

int receive_data(mqd_t mqdes)
{
	ssize_t size;
	struct lwe_ctrl_op_info *ip_info = NULL;
	struct mq_attr attr;
	int _err = 0;

	ip_info = (struct lwe_ctrl_op_info *)malloc
			(sizeof(struct lwe_ctrl_op_info));
	memset(ip_info, 0, sizeof(struct lwe_ctrl_op_info));

	_err = mq_getattr(mqdes, &attr);
	if (unlikely(_err)) {
		APP_ERROR("%s: %dError getting MQ attributes\n",
			 __FILE__, __LINE__);
		goto error;
	}
	size = mq_receive(mqdes, (char *)ip_info, attr.mq_msgsize, 0);
	if (unlikely(size == -1)) {
		APP_ERROR("%s: %dRcv msgque error\n", __FILE__, __LINE__);
		goto error;
	}
	process_req_from_mq(ip_info);
	/* Sending result to application configurator tool */
	_err = mq_send(mq_fd_snd, (const char *)ip_info,
			sizeof(struct lwe_ctrl_op_info), 10);
	if (unlikely(_err != 0)) {
		APP_ERROR("%s: %d Error in sending msg on MQ\n",
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
	APP_DEBUG("mq_handler called %d\n", sval.sival_int);

	receive_data(mq_fd_rcv);
	mq_notify(mq_fd_rcv, &notification);
}

int create_mq(void)
{
	struct mq_attr attr_snd, attr_rcv;
	int _err = 0, ret;

	APP_DEBUG("Create mq: Enter");
	memset(&attr_snd, 0, sizeof(attr_snd));

	/* Create message queue to send the response */
	attr_snd.mq_maxmsg = 10;
	attr_snd.mq_msgsize = 8192;
	mq_fd_snd = mq_open("/mq_snd", O_CREAT | O_WRONLY,
				(S_IRWXU | S_IRWXG | S_IRWXO), &attr_snd);
	if (mq_fd_snd == -1) {
		APP_ERROR("%s: %dError opening SND MQ\n",
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
		APP_ERROR("%s: %dError opening RCV MQ\n",
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
		APP_ERROR("%s: %dError in mq_notify call\n",
				 __FILE__, __LINE__);
		_err = -errno;
		goto error;
	}
	APP_DEBUG("Create mq: Exit");
	return 0;
error:
	if (mq_fd_snd)
		mq_close(mq_fd_snd);

	if (mq_fd_rcv)
		mq_close(mq_fd_rcv);

	return _err;
}

int global_init(struct usdpa_netcfg_info *uscfg_info, int cpu, int first, int last)
{
	int err, loop;
	u8 bpids[] = IPFWD_BPIDS;

	APP_DEBUG("Global initialisation: Enter");
	/* Set up the bpid allocator */
	err = bman_setup_allocator(0, &bpid_allocator);
	if (err)
		fprintf(stderr, "Continuing despite BPID failure\n");
	/* Set up the fqid allocator */
	err = qman_setup_allocator(0, &fqid_allocator);
	if (err) {
		APP_ERROR("FQID allocator failure\n");
		return err;
	}
	/* map shmem */
	err = dma_mem_setup();
	if (err) {
		APP_ERROR("shmem setup failure\n");
		return err;
	}

	/* initialise buffer pools to release buffers*/
	for (loop = 0; loop < sizeof(bpids); loop++) {
		struct bman_pool_params params = {
			.bpid	= bpids[loop],
			.flags	= BMAN_POOL_FLAG_ONLY_RELEASE
		};
		APP_INFO("Initialising pool for bpid %d\n", bpids[loop]);
		pool[bpids[loop]] = bman_new_pool(&params);
		BUG_ON(!pool[bpids[loop]]);
	}
	/* Initialise barrier for all the threads including main thread */
	if (!cpu0_only) {
		err = pthread_barrier_init(&init_barrier, NULL,
			last - first + 2);
		if (err != 0)
			APP_INFO("pthread_barrier_init failed");
	}

	/* Initialise Bman/Qman portal */
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

	/* Initializes a soft cache of buffers */
	if (unlikely(NULL == mem_cache_init())) {
		APP_ERROR("Cache Creation error");
		return -ENOMEM;
	}
	/* Initializes IP stack*/
	if (initialize_ip_stack(&stack)) {
		APP_ERROR("Error Initializing IP Stack");
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
		APP_ERROR("Unable to initialize interface");
		return -EINVAL;
	}
	/* Initializes array of network iface nodes */
	create_iface_nodes(iface_nodes, uscfg_info);

	/* Initializes array of network local nodes */
	create_local_nodes(local_nodes);

	/* Creates netdev Device Nodes */
	if (create_devices(&stack, iface_nodes)) {
		APP_ERROR("Unable to Create Devices");
		return -ENOMEM;
	}

	/* Populate static arp entries */
	populate_arp_cache(&stack, local_nodes);
	APP_INFO
	    ("ARP Cache Populated, Stack pointer is %p and its size = %d",
	     &stack, sizeof(stack));
	APP_DEBUG("Global initialisation: Exit");

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
		APP_ERROR("pthread_setaffinity_np failed\n");
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
	struct usdpa_netcfg_info *uscfg_info;

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
			exit(-1);
		}
	} else if (argc != 4) {
		fprintf(stderr, "usage: ipfwd_app <cpu-range>" "<fmc_pcd_file> "
					"<fmc_cfgdata_file>\n");
		fprintf(stderr, "where [cpu-range] is 'n' or 'm..n'\n");
		exit(-1);
	}
	if (first == 0) {
		cpu0_poll_on = 1;
		if (first != last)
			first = first + 1;
		else
			cpu0_only = 1;
	}

	APP_INFO("\n** Welcome to IPFWD application! **");

	uscfg_info = usdpa_netcfg_acquire(argv[2], argv[3]);
	if (uscfg_info == NULL) {
		fprintf(stderr, "error: NO Config information available\n");
		return -ENXIO;
	}

	err = global_init(uscfg_info, my_cpu, first, last);
	if (err != 0) {
		APP_ERROR("Global initialization failed");
		return -1;
	}

	/* Create Message queues to send and receive */
	err = create_mq();
	if (err == -1) {
		APP_ERROR("Error in creating message queues");
		return -1;
	}

	if (!cpu0_only) {
		err = start_threads(thread_data, last - first + 1, first,
			 worker_fn);
		if (err != 0)
			APP_INFO("start_threads failed");
	}

	if (cpu0_poll_on) {
		APP_INFO("Frames to be recv on channel map: 0x%x",
				 recv_channel_map);
		qman_static_dequeue_add(recv_channel_map);
	}

	APP_INFO("Waiting for Configuration Command");
	/* Wait for initial IPFWD related configuration to be done */
	while (0 == GO_FLAG);

	/* Enable all the ethernet ports*/
	fman_if_enable_all_rx();

	/* Wait for other threads before start qman poll */
	if (!cpu0_only)
		pthread_barrier_wait(&init_barrier);

	/* CPU0 going for qman poll */
	if (cpu0_poll_on) {
		APP_INFO("Going for qman poll cpu %d\n", my_cpu);
		while (1)
			qman_poll();
	}
	/* Wait for all the threads to finish */
	if (!cpu0_only)
		wait_threads(thread_data, last - first + 1);

	usdpa_netcfg_release(uscfg_info);
	return 0;
}
