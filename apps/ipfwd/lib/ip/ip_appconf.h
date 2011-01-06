/**
 \file ipsec_cpdp.h
 \brief Implements a simple, fast cache for looking up IPSec tunnels.
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
#ifndef LIB_IPSEC_IPSEC_CPDP_H
#define LIB_IPSEC_IPSEC_CPDP_H

/**
 \brief	Structure for configuring an Interface
 */
struct lwe_ctrl_intf_conf {
	uint32_t ip_addr; /**< IP Address */
	uint32_t mtu; /**< MTU */
	uint32_t enable; /**< Enabling the interface */
	unsigned char mac_addr[6];  /**< MAC Address of the interface */
	char ifname[10];  /**< Interface Name */
#define LWE_CTRL_PARAM_BMASK_IFNAME		(1 << 0)
#define LWE_CTRL_PARAM_BMASK_IPADDR		(1 << 1)
#define LWE_CTRL_PARAM_BMASK_MACADDR		(1 << 2)
#define LWE_CTRL_PARAM_BMASK_MTU			(1 << 3)
#define LWE_CTRL_PARAM_BMASK_ENABLE		(1 << 4)
#define LWE_CTRL_PARAM_MAX_INTF_BIT_NO			5

#define LWE_CTRL_INTF_CONF_MDTR_PARAM_MAP (LWE_CTRL_PARAM_BMASK_IFNAME)

	uint32_t bitmask;
};

struct lwe_ctrl_ip_info {
	unsigned int src_ipaddr;			/**<Source IP Address>*/
	unsigned int dst_ipaddr;			/**<Destination IP Address>*/
	unsigned int gw_ipaddr;				/**<Gateway IP Address>*/
	unsigned int tos;				/**<Gateway IP Address>*/
	unsigned char mac_addr[6];	/**< Mac Address */
	unsigned int flow_id; /**< Flow Id */
	unsigned int frame_cnt; /**<Frame Count */
	unsigned int replace_entry;  /**< Used for overwriting an existing ARP entry */
	struct lwe_ctrl_intf_conf intf_conf; /**< Interface Configuration */
};

/**
 \brief	Structure used for communicating with USDPAA process through
posix message queue.
 */
struct lwe_ctrl_op_info {

#define LWE_CTRL_CMD_STATE_IDLE 0
#define LWE_CTRL_CMD_STATE_BUSY 1
	unsigned int state;
	/**< State of Command */

#define LWE_CTRL_CMD_TYPE_ROUTE_ADD		1
#define LWE_CTRL_CMD_TYPE_ROUTE_DEL		2
#define LWE_CTRL_CMD_TYPE_INTF_CONF_CHNG	3
#define LWE_CTRL_CMD_TYPE_ARP_ADD		4
#define LWE_CTRL_CMD_TYPE_ARP_DEL		5
#define LWE_CTRL_CMD_TYPE_FRAMECNT_EDIT		6
#define LWE_CTRL_CMD_TYPE_GO			7

	unsigned int msg_type;
	/**<Type of Request>*/

#define LWE_CTRL_RSLT_SUCCESSFULL		1
#define LWE_CTRL_RSLT_FAILURE		0
	unsigned int result;
	/**<Result - Successful, Failure>*/

	struct lwe_ctrl_ip_info ip_info;
	/**< IPfwd Info structure */
};

extern struct lwe_ctrl_op_info g_sLweCtrlSaInfo;

#endif /* ifndef LIB_IPSEC_IPSEC_CPDP_H */
