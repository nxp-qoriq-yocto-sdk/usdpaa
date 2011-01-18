/**
 \file net_dev.c
 \brief Net dev layer routines.
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
#include "net/net_dev.h"
#include "malloc.h"
#include <assert.h>

struct net_dev_table_t *net_dev_init()
{
	struct net_dev_table_t *netdev;

	netdev =  memalign(CACHE_LINE_SIZE, sizeof(struct net_dev_table_t));
	if (netdev)
		memset(netdev, 0, sizeof(*netdev));

	spin_lock_init(&(netdev->wlock));
	return netdev;
}

struct net_dev_t *net_dev_allocate(struct net_dev_table_t *table,
				   size_t priv_size)
{
	struct net_dev_t *dev;

	assert(table != NULL);
	assert(table->next_ifindex < NET_DEV_MAX_COUNT);

	dev = memalign(CACHE_LINE_SIZE, (sizeof(*dev) + priv_size));
	if (dev != NULL) {
		dev->next = NULL;
		dev->refcnt = refcount_create();
		if (unlikely(NULL == dev->refcnt)) {
			free(dev);
			return NULL;
		}
		spin_lock(&table->wlock);
		dev->ifindex = table->next_ifindex++;
		spin_unlock(&table->wlock);
		dev->state = NET_DEV_STATE_RUNNING;
		dev->reg_state = NET_DEV_REG_STATE_UNINITIALIZED;
		dev->xmit = NULL;
		dev->set_mtu = NULL;
		dev->set_ll_address = NULL;
		dev->set_header = NULL;
		dev->cache_header = NULL;
	}

	return dev;
}

bool net_dev_register(struct net_dev_table_t *table, struct net_dev_t *dev)
{
	bool retval;
	struct net_dev_t *current;
	struct net_dev_t **cur_ptr;

	assert(table != NULL);
	assert(dev != NULL);

	if (dev->reg_state == NET_DEV_REG_STATE_UNINITIALIZED) {
		spin_lock(&table->wlock);
		if (table->devices[dev->ifindex] != NULL)
			return false;
		table->devices[dev->ifindex] = dev;
		cur_ptr = &table->device_head;
		current = *cur_ptr;
		while (current != NULL) {
			cur_ptr = &current->next;
			current = *cur_ptr;
		}
		(*cur_ptr) = dev;
		dev->next = NULL;
		spin_unlock(&table->wlock);
		dev->reg_state = NET_DEV_REG_STATE_REGISTERED;
		retval = true;
	} else {
		retval = false;
	}

	return retval;
}
#ifdef STATS_TBD
void net_dev_print_stats(struct net_dev_t *dev, bool print_zero)
{
	struct net_dev_stats_t *stats;

	stats = dev->stats;
	print_stat64_pair(&stats->rx_frames, "rx_frames", print_zero);
	print_stat64_pair(&stats->tx_frames, "tx_frames", print_zero);
	print_stat64_pair(&stats->rx_errors, "rx_errors", print_zero);
	print_stat64_pair(&stats->tx_errors, "tx_errors", print_zero);
	print_stat64_pair(&stats->rx_dropped, "rx_dropped", print_zero);
	print_stat64_pair(&stats->tx_dropped, "tx_dropped", print_zero);
}
#endif
