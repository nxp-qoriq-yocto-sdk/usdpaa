/**
 \file net_dev.h
 \brief Net Device data structures and Macros
 */
/*
 * Copyright (C) 2010-2011 Freescale Semiconductor, Inc.
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
#ifndef _LIB_NET_NET_DEV_H
#define _LIB_NET_NET_DEV_H   1

#include <usdpaa/compat.h>

#include "common/refcount.h"
#include "notify.h"
#include "ll_cache.h"
#include "statistics.h"

#include <string.h>

#ifndef NET_DEV_MAX_COUNT
#define NET_DEV_MAX_COUNT		  4096
/**< Maximum Number of Net devices in the system*/
#endif

#define LL_MAX_ADDR_LEN_BYTES		6
/**< Max Address Length for L2*/
#define L3_MAX_ADDR_LEN_WORDS		1
/**< Max Address Length of L3 in Words*/
#define LL_MAX_HEADER			(14)
/**< Max Header Length for L2*/
#define LL_MAX_ALIGNED_HEADER		(16)
/**< Max Aligned Header Length for L2*/

/**
   Features:
- List of interfaces is static, and is created at initialization time.
No new interfaces may be added at run time.
- Statisics are kept per interface.
- Interface info, like the egress FQ, the control plane FQ, and the
address for the statistics is configured at initialization time, and
may not be changed at run time.
- Interface state may be manipulated in any way during run time.
- Changes to interface state are accomplished by returning a clone of the
current state to the user, allowing them to modify it, and then
atomically replacing the current state with new state, and doing an
RCU-deferred free on the replaced state.
- All entries with the exception of the state variable can be accessed
without a lock of any kind.  Access to the current state is controlled
by rcu-protected accessor functions.  Finally, statistics should be
updated via decorated storage constructs, but may be read normally.
 */

/**
 \brief Stats related to the Net Device
 */
struct net_dev_stats_t {
	struct stat64_pair_t rx_frames;		/**< Number of Received Frames*/
	struct stat64_pair_t tx_frames;		/**< Number of Transmitted Frames*/
	struct stat64_pair_t rx_errors;		/**< Number of Frames which had error while receiving*/
	struct stat64_pair_t tx_errors;		/**< Number of Frames which had error while transmitting*/
	struct stat64_pair_t rx_dropped;	/**< Number of Dropped Frames which were received*/
	struct stat64_pair_t tx_dropped;	/**< Number of Dropped Frames during transmission*/
} __attribute__((aligned(L1_CACHE_BYTES)));

/**
 \brief Net Device State
 */
enum NET_DEV_STATE {
	NET_DEV_STATE_UNCONFIGURED = 0,
	/**< Net Device State - Unconfigured*/
	NET_DEV_STATE_RUNNING
	/**< Net Device State - Running*/
};

/**
 \brief Net Device Registration State
 */
enum NET_DEV_REG_STATE {
	NET_DEV_REG_STATE_UNINITIALIZED = 0,
	/**< Net Dvice - Not registered*/
	NET_DEV_REG_STATE_REGISTERED
	/**< Net Device - Registered*/
};

/**
 \brief Events related to Device
 */
enum NET_DEV_EVENT {
	NET_DEV_EVENT_UP,			/**< Net Device Came Up*/
	NET_DEV_EVENT_DOWN,			/**< Net Device went Down*/
	NET_DEV_EVENT_CHANGEADDR
	/**< Net Device - Address Changed*/
};

/**
 \brief This represents an interface in our system.  It is a 50B structure.
*/
struct net_dev_t {
	/* Net Device Global Section: 12B */
	struct net_dev_t *next;
	/**< Pointer to Next node in the Linked List*/
	refcount_t *refcnt;
	/**< NUmber of entities accessing the Device*/
	uint16_t ifindex;		/**< Interface Index*/
	enum NET_DEV_STATE state;	/**< Net Device State*/
	enum NET_DEV_REG_STATE reg_state;
	/**< Net Device registration State*/

	/* LL Protocol Section: 28B */
	uint16_t mtu;			/**< MTU*/
	uint16_t header_len;		/**< Header Length*/
	uint16_t dev_addr_len;		/**< Address Length*/
	void (*set_mtu) (struct net_dev_t *, uint32_t new_mtu);
	/**< Function pointer for Setting the MTU */
	void (*set_ll_address) (struct net_dev_t *, void *addr);
	/**< Function to set LL address */
	void *(*set_header) (struct net_dev_t *dev, void *ll_payload,
			     void *daddr, void *saddr);
	/**< Function Pointer for filling in the Header*/
	void (*cache_header) (struct ll_cache_t *, void *ll_hdr);
	/**< Function pointer for filling in the header in the cache structure*/
	uint8_t dev_addr[LL_MAX_ADDR_LEN_BYTES];
	/**< Device address*/

	/* Driver Section: 10B */
	struct net_dev_stats_t *stats;
	/**< Device related Stats */
	void (*xmit) (struct net_dev_t *, struct qm_fd *, void *);
	/**< Function pointer for transmission of frame*/
	uint16_t iflink;

} __attribute__((aligned(L1_CACHE_BYTES)));

/**
 \brief Net Device Table
 \details Contains the set of Net devices being used in the system
*/
struct net_dev_table_t {
	spinlock_t wlock;
	/**< Write Lock for the data structure */
	struct notify_chain_t *net_dev_chain;
	uint32_t next_ifindex;
	struct net_dev_t *device_head;
	/**< Pointer to first NetDev entry */
	struct net_dev_t *devices[NET_DEV_MAX_COUNT];
	/**< Array of net devices */
} __attribute__((aligned(L1_CACHE_BYTES)));

/**
 \brief Allocates the Net Device table
 \return Pointer to the allocated Net Device Table
 */
struct net_dev_table_t *net_dev_init(void);

/**
 \brief Allocates a Net Device Structure
 \param[inout] table Pointer to the Net Device table
 \param[in] priv_size Size to be allocated along with the sizeof(net_dev_t )
 \return Pointer to the allocated Net Device Structure
 */
struct net_dev_t *net_dev_allocate(struct net_dev_table_t *table,
				   size_t priv_size);

/**
 \brief Registers the Net Device for Use by the system
 \param[inout] table Pointer to the Net Device table
 \param[in] dev Device to be registered
 \return True if Registration was Successfull else False
 */
bool net_dev_register(struct net_dev_table_t *table, struct net_dev_t *dev);

/**
 \brief Prints Stats related to a Net Device
 \param[in] dev Pointer to the Net Device
 */
void net_dev_print_stats(struct net_dev_t *dev, bool print_zero);

#endif /* _LIB_NET_NET_DEV_H */
