/* Copyright (c) 2011-2012 Freescale Semiconductor, Inc.
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

#include <fra_cfg_parser.h>
#include <usdpaa/fman.h>
#include <libxml/parser.h>

#define FRA_CFG_FILE_ROOT_NODE	("fra_cfg")

#define RMAN_CFG_NODE		("rman_cfg")
#define RMAN_CFG_TYPE		("type")
#define RMAN_CFG_VALUE		("value")
#define RMAN_CFG_INDEX		("index")
#define RMAN_FQ_BITS_NODE	("fqbits")
#define MD_CREATE_NODE		("md_create")
#define MD_CREATE_MODE		("mode")
#define RMAN_OSID_NODE		("osid")
#define BPID_NODE		("bpid")
#define SG_BPID_NODE		("sgbpid")

#define NETWORK_CFG_NODE	("network_cfg")
#define FMAN_PORT_NODE		("port")
#define FMAN_PORT_NAME		("name")
#define FMAN_PORT_TYPE		("type")
#define FMAN_PORT_NUM		("number")
#define FMAN_NUM		("fm")

#define TRAN_NODE		("transaction")
#define TRAN_NAME		("name")
#define TRAN_TYPE		("type")
#define TRAN_COMMON_VALUE	("value")
#define TRAN_COMMON_MASK	("mask")
#define TRAN_FLOWLVL_NODE	("flowlvl")
#define TRAN_MBOX_NODE		("mbox")
#define TRAN_LTR_NODE		("ltr")
#define TRAN_MSGLEN_NODE	("msglen")
#define TRAN_COS_NODE		("cos")
#define TRAN_STREAMID_NODE	("streamid")

#define DIST_NODE		("distribution")
#define DIST_NAME		("name")
#define DIST_TYPE		("type")
#define DIST_RIO_PORT_NODE	("rio_port")
#define DIST_RIO_PORT_MASK	("mask")
#define DIST_PORT_NUMBER	("number")
#define DIST_SID_NODE		("sid")
#define DIST_SID_VALUE		("value")
#define DIST_SID_MASK		("mask")
#define DIST_DID_NODE		("did")
#define DIST_DID_VALUE		("value")
#define DIST_FQ_NODE		("queue")
#define DIST_FQ_ID		("base")
#define DIST_FQ_MODE		("mode")
#define DIST_FQ_COUNT		("count")
#define DIST_FQ_WQ		("wq")
#define DIST_TRANREF_NODE	("transactionref")
#define DIST_TRANREF_NAME	("name")
#define DIST_FMAN_PORT_NODE	("fman_port")

#define POLICY_NODE		("policy")
#define POLICY_NAME		("name")
#define POLICY_DISTORDER_NODE	("dist_order")
#define POLICY_DISTREF_NODE	("distributionref")
#define POLICY_DISTREF_NAME	("name")

const char *RIO_TYPE_TO_STR[] = {
	[RIO_TYPE0] = "Implementation-defined",
	[RIO_TYPE1] = "reserved",
	[RIO_TYPE2] = "NREAD",
	[RIO_TYPE3] = "reserved",
	[RIO_TYPE4] = "reserved",
	[RIO_TYPE5] = "NWrite",
	[RIO_TYPE6] = "SWrite",
	[RIO_TYPE7] = "reserved",
	[RIO_TYPE8] = "Maintenance",
	[RIO_TYPE9] = "Data-streaming",
	[RIO_TYPE10] = "Doorbell",
	[RIO_TYPE11] = "Mailbox"
};

const char *DIST_TYPE_STR[] = {
	[DIST_TYPE_UNKNOWN] = "UNKNOWN",
	[DIST_TYPE_RMAN_RX] = "RMAN_RX",
	[DIST_TYPE_RMAN_TX] = "RMAN_TX",
	[DIST_TYPE_FMAN_RX] = "FMAN_RX",
	[DIST_TYPE_FMAN_TX] = "FMAN_TX",
	[DIST_TYPE_FMAN_TO_RMAN] = "FMAN_TO_RMAN",
	[DIST_TYPE_RMAN_TO_FMAN] = "RMAN_TO_FMAN"
};

const char *FQ_MODE_STR[] = {"direct", "algorithmic"};
const char *MD_CREATE_MODE_STR[] = {"yes", "no"};

LIST_HEAD(_tran_list);
struct list_head *tran_list = &_tran_list;

xmlNodePtr fra_cfg_root_node;

#define for_all_sibling_nodes(node)	\
	for (; unlikely(node != NULL); node = node->next)

static void fra_cfg_parse_error(void *ctx, xmlErrorPtr xep)
{
	error(0, 0, "%s:%hu:%s() fra_cfg_parse_error(context(%p),"
		"error pointer %p", __FILE__, __LINE__, __func__,
		ctx, xep);
}

static inline int is_node(xmlNodePtr node, xmlChar *name)
{
	return xmlStrcmp(node->name, name) ? 0 : 1;
}

static void *get_attributes(xmlNodePtr node, xmlChar *attr)
{
	char *atr = (char *)xmlGetProp(node, attr);
	if (unlikely(atr == NULL))
		error(0, 0, "%s:%hu:%s() error: "
			"(Node(%s)->Attribute (%s) not found",
			__FILE__, __LINE__, __func__,
			node->name, attr);
	return atr;
}

static enum dist_type dist_type_str_to_idx(const char *type)
{
	int idx;

	for (idx = 0; idx < ARRAY_SIZE(DIST_TYPE_STR); idx++) {
		if (!strcmp(type, DIST_TYPE_STR[idx]))
			return idx;
	}
	return DIST_TYPE_UNKNOWN;
}

static enum RIO_TYPE rio_type_str_to_idx(const char *type)
{
	int idx;

	for (idx = 0; idx < ARRAY_SIZE(RIO_TYPE_TO_STR); idx++) {
		if (!strcmp(type, RIO_TYPE_TO_STR[idx]))
			return idx;
	}
	return RIO_TYPE0;
}

static void strip_blanks(char *str)
{
	int i, j;
	int len = strlen(str);

	for (i = 0; (i < len) && (str[i] == ' '); i++)
		;

	for (j = 0; (i < len) && (str[i] != ' '); ++i, j++)
		str[j] = str[i];

	str[j] = '\0';
}

#define tran_parse_element(node, value, mask) \
	do {								\
		char *ptr;						\
		ptr = get_attributes(node, BAD_CAST TRAN_COMMON_VALUE);	\
		if (unlikely(ptr == NULL))				\
			return -EINVAL;					\
		value = strtoul(ptr, NULL, 0);				\
		ptr = get_attributes(node, BAD_CAST TRAN_COMMON_MASK);	\
		if (unlikely(ptr == NULL))				\
			return -EINVAL;					\
		mask = strtoul(ptr, NULL, 0);				\
	} while (0)

static int parse_tran(const char *tran_name, struct rio_tran *tran)
{
	uint8_t len;
	char *name;
	char *type;
	xmlNodePtr tranp;
	xmlNodePtr cur;

	cur = fra_cfg_root_node->xmlChildrenNode;
	len = strnlen(tran_name, 100);

	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST TRAN_NODE)))
			continue;
		len = strnlen(tran_name, 100);
		name = (char *)get_attributes(cur, BAD_CAST TRAN_NAME);
		if (likely(name) && !(strncmp(name, tran_name, len)))
			break;
	}
	if (!cur) {
		error(0, 0, "Transaction %s dose not exist",
			tran_name);
		return -ENXIO;
	}

	tranp = cur->xmlChildrenNode;
	snprintf(tran->name, sizeof(tran->name), tran_name);

	type = (char *)get_attributes(cur, BAD_CAST TRAN_TYPE);
	if (!type) {
		error(0, 0, "Distibution %s should has"
			" type attribute", tran_name);
		return -ENXIO;
	}
	tran->type = rio_type_str_to_idx(type);
	switch (tran->type) {
	case RIO_TYPE_DBELL:
		for_all_sibling_nodes(tranp) {
			if ((is_node(tranp, BAD_CAST TRAN_FLOWLVL_NODE))) {
				tran_parse_element(tranp, tran->flowlvl,
					tran->flowlvl_mask);
			}
		}
		break;
	case RIO_TYPE_MBOX:
		for_all_sibling_nodes(tranp) {
			if ((is_node(tranp, BAD_CAST TRAN_FLOWLVL_NODE)))
				tran_parse_element(tranp, tran->flowlvl,
						tran->flowlvl_mask);
			else if ((is_node(tranp, BAD_CAST TRAN_MBOX_NODE)))
				tran_parse_element(tranp, tran->mbox.mbox,
						tran->mbox.mbox_mask);
			else if ((is_node(tranp, BAD_CAST TRAN_LTR_NODE)))
				tran_parse_element(tranp, tran->mbox.ltr,
						tran->mbox.ltr_mask);
			else if ((is_node(tranp, BAD_CAST TRAN_MSGLEN_NODE)))
				tran_parse_element(tranp, tran->mbox.msglen,
						tran->mbox.msglen_mask);
		}
		break;
	case RIO_TYPE_DSTR:
		for_all_sibling_nodes(tranp) {
			if ((is_node(tranp, BAD_CAST TRAN_FLOWLVL_NODE)))
				tran_parse_element(tranp, tran->flowlvl,
					tran->flowlvl_mask);
			else if ((is_node(tranp, BAD_CAST TRAN_COS_NODE)))
				tran_parse_element(tranp, tran->dstr.cos,
					tran->dstr.cos_mask);
			else if ((is_node(tranp, BAD_CAST TRAN_STREAMID_NODE)))
				tran_parse_element(tranp,
					tran->dstr.streamid,
					tran->dstr.streamid_mask);
		}
		break;
	default:
		error(0, 0, "transaction %s has"
			" a invalid type %s", tran_name, type);
		return -ENXIO;
	}
	return 0;
}

static struct rio_tran *search_tran(const char *name)
{
	struct rio_tran *tran;
	list_for_each_entry(tran, tran_list, node) {
		if (!strncmp(tran->name, name, sizeof(tran->name)))
			return tran;
	}
	tran = malloc(sizeof(*tran));
	if (!tran)
		return NULL;
	memset(tran, 0, sizeof(*tran));
	if (parse_tran(name, tran)) {
		free(tran);
		return NULL;
	}
	list_add_tail(&tran->node, tran_list);
	return tran;
}

void fra_transactiones_finish(void)
{
	struct rio_tran *tran, *temp;

	list_for_each_entry_safe(tran, temp, tran_list, node) {
		list_del(&tran->node);
		free(tran);
	}
}

static int parse_dist_rman_rx(xmlNodePtr distp,
			      struct dist_rman_rx_cfg *rxcfg)
{
	char *ptr;

	for_all_sibling_nodes(distp) {
		if ((is_node(distp, BAD_CAST DIST_RIO_PORT_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_PORT_NUMBER);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			rxcfg->rio_port = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp, BAD_CAST
					     DIST_RIO_PORT_MASK);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			rxcfg->port_mask = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_SID_NODE))) {
			ptr = get_attributes(distp, BAD_CAST DIST_SID_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			rxcfg->sid = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp, BAD_CAST DIST_SID_MASK);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			rxcfg->sid_mask = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_FQ_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_FQ_ID);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			rxcfg->fqid = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp,
				BAD_CAST DIST_FQ_MODE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			if (!strcmp(ptr, FQ_MODE_STR[DIRECT]))
				rxcfg->fq_mode = DIRECT;
			else
				rxcfg->fq_mode = ALGORITHMIC;
			ptr = get_attributes(distp, BAD_CAST DIST_FQ_WQ);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			rxcfg->wq = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_TRANREF_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_TRANREF_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			strip_blanks(ptr);
			rxcfg->tran = search_tran(ptr);
		}
	}
	return 0;
}

static int parse_dist_rman_tx(xmlNodePtr distp,
			      struct dist_rman_tx_cfg *txcfg)
{
	char *ptr;
	for_all_sibling_nodes(distp) {
		if ((is_node(distp, BAD_CAST DIST_RIO_PORT_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_PORT_NUMBER);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			txcfg->rio_port = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_DID_NODE))) {
			ptr = get_attributes(distp, BAD_CAST DIST_DID_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			txcfg->did = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_FQ_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_FQ_ID);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			txcfg->fqid = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp,
				BAD_CAST DIST_FQ_COUNT);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			txcfg->fqs_num = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp,
				BAD_CAST DIST_FQ_WQ);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			txcfg->wq = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_TRANREF_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_TRANREF_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			strip_blanks(ptr);
			txcfg->tran = search_tran(ptr);
		}
	}
	return 0;
}

static int parse_dist_rman_to_fman(xmlNodePtr distp,
				   struct dist_rman_to_fman_cfg *r2fcfg)
{
	char *ptr;
	for_all_sibling_nodes(distp) {
		if ((is_node(distp, BAD_CAST DIST_RIO_PORT_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_PORT_NUMBER);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			r2fcfg->rio_port = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp, BAD_CAST
					     DIST_RIO_PORT_MASK);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			r2fcfg->port_mask = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_SID_NODE))) {
			ptr = get_attributes(distp, BAD_CAST DIST_SID_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			r2fcfg->sid = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp, BAD_CAST DIST_SID_MASK);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			r2fcfg->sid_mask = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_FQ_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_FQ_ID);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			r2fcfg->fqid = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp,
				BAD_CAST DIST_FQ_MODE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			if (!strcmp(ptr, FQ_MODE_STR[DIRECT]))
				r2fcfg->fq_mode = DIRECT;
			else
				r2fcfg->fq_mode = ALGORITHMIC;
			ptr = get_attributes(distp, BAD_CAST DIST_FQ_WQ);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			r2fcfg->wq = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_TRANREF_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_TRANREF_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			strip_blanks(ptr);
			r2fcfg->tran = search_tran(ptr);
		} else if ((is_node(distp, BAD_CAST DIST_FMAN_PORT_NODE))) {
			ptr = get_attributes(distp, BAD_CAST FMAN_PORT_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			snprintf(r2fcfg->fman_port_name,
				sizeof(r2fcfg->fman_port_name), ptr);
		}
	}
	return 0;
}

static int parse_dist_fman_rx(xmlNodePtr distp,
			      struct dist_fman_rx_cfg *rxcfg)
{
	char *ptr;
	for_all_sibling_nodes(distp) {
		if ((is_node(distp, BAD_CAST DIST_FMAN_PORT_NODE))) {
			ptr = get_attributes(distp, BAD_CAST FMAN_PORT_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			snprintf(rxcfg->fman_port_name,
				sizeof(rxcfg->fman_port_name), ptr);
		}  else if ((is_node(distp, BAD_CAST DIST_FQ_NODE))) {
			ptr = get_attributes(distp, BAD_CAST DIST_FQ_WQ);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			rxcfg->wq = strtoul(ptr, NULL, 0);
		}
	}
	return 0;
}

static int parse_dist_fman_tx(xmlNodePtr distp,
			      struct dist_fman_tx_cfg *txcfg)
{
	char *ptr;
	for_all_sibling_nodes(distp) {
		if ((is_node(distp, BAD_CAST DIST_FMAN_PORT_NODE))) {
			ptr = get_attributes(distp, BAD_CAST FMAN_PORT_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			snprintf(txcfg->fman_port_name,
				sizeof(txcfg->fman_port_name), ptr);
		}  else if ((is_node(distp, BAD_CAST DIST_FQ_NODE))) {
			ptr = get_attributes(distp, BAD_CAST DIST_FQ_COUNT);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			txcfg->fqs_num = strtoul(ptr, NULL, 0);
			ptr = get_attributes(distp, BAD_CAST DIST_FQ_WQ);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			txcfg->wq = strtoul(ptr, NULL, 0);
		}
	}
	return 0;
}

static int parse_dist_fman_to_rman(xmlNodePtr distp,
				   struct dist_fman_to_rman_cfg *f2rcfg)
{
	char *ptr;
	for_all_sibling_nodes(distp) {
		if ((is_node(distp, BAD_CAST DIST_RIO_PORT_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_PORT_NUMBER);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			f2rcfg->rio_port = strtoul(ptr, NULL, 0);
		} else if ((is_node(distp, BAD_CAST DIST_DID_NODE))) {
			ptr = get_attributes(distp, BAD_CAST DIST_DID_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			f2rcfg->did = strtoul(ptr, NULL, 0);
		}  else if ((is_node(distp, BAD_CAST DIST_TRANREF_NODE))) {
			ptr = get_attributes(distp,
				BAD_CAST DIST_TRANREF_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			strip_blanks(ptr);
			f2rcfg->tran = search_tran(ptr);
		}  else if ((is_node(distp, BAD_CAST DIST_FMAN_PORT_NODE))) {
			ptr = get_attributes(distp, BAD_CAST FMAN_PORT_NAME);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			snprintf(f2rcfg->fman_port_name,
				sizeof(f2rcfg->fman_port_name), ptr);
		}
	}
	return 0;
}

static int parse_dist(char *dist_name, struct dist_cfg *dist_cfg)
{
	char *name;
	char *type;
	int err = -ENXIO;
	xmlNodePtr distp;
	xmlNodePtr cur;

	cur = fra_cfg_root_node->xmlChildrenNode;

	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST DIST_NODE)))
			continue;
		name = (char *)get_attributes(cur, BAD_CAST DIST_NAME);
		if (likely(name) && !(strcmp(name, dist_name)))
			break;
	}
	if (!cur) {
		error(0, 0, "Distribution(%s) dose not exist",
			dist_name);
		return -ENXIO;
	}

	distp = cur->xmlChildrenNode;
	snprintf(dist_cfg->name, sizeof(dist_cfg->name), name);

	type = (char *)get_attributes(cur, BAD_CAST DIST_TYPE);
	if (!type) {
		error(0, 0, "Distribution %s should has"
			" a type attribute", dist_name);
		return -ENXIO;
	}

	dist_cfg->type = dist_type_str_to_idx(type);
	switch (dist_cfg->type) {
	case DIST_TYPE_RMAN_RX:
		err = parse_dist_rman_rx(distp, &dist_cfg->dist_rman_rx_cfg);
		break;
	case DIST_TYPE_RMAN_TX:
		err = parse_dist_rman_tx(distp, &dist_cfg->dist_rman_tx_cfg);
		break;
	case DIST_TYPE_FMAN_RX:
		err = parse_dist_fman_rx(distp, &dist_cfg->dist_fman_rx_cfg);
		break;
	case DIST_TYPE_FMAN_TX:
		err = parse_dist_fman_tx(distp, &dist_cfg->dist_fman_tx_cfg);
		break;
	case DIST_TYPE_FMAN_TO_RMAN:
		err = parse_dist_fman_to_rman(distp,
			&dist_cfg->dist_fman_to_rman_cfg);
		break;
	case DIST_TYPE_RMAN_TO_FMAN:
		err = parse_dist_rman_to_fman(distp,
			&dist_cfg->dist_rman_to_fman_cfg);
		break;
	default:
		err = -EINVAL;
		error(0, 0, "Distribution(%s) has an invalid"
			" type attribute", dist_name);
	}
	return err;
}

static void dist_order_cfg_free(struct dist_order_cfg *dist_order_cfg)
{
	struct dist_cfg *cfg;
	struct dist_cfg *temp;

	if (!dist_order_cfg)
		return;

	cfg = dist_order_cfg->dist_cfg;
	while (cfg) {
		temp = cfg;
		cfg = cfg->next;
		free(temp);
	}

	if (dist_order_cfg->node.prev && dist_order_cfg->node.next)
		list_del(&dist_order_cfg->node);
	free(dist_order_cfg);
}

void fra_cfg_release(struct fra_cfg *fra_cfg)
{
	struct dist_order_cfg  *dist_order_cfg, *temp;
	struct fra_fman_port_cfg *port, *port_temp;

	if (!fra_cfg)
		return;

	fra_transactiones_finish();

	list_for_each_entry_safe(dist_order_cfg, temp,
			&fra_cfg->dist_order_cfg_list, node) {
		dist_order_cfg_free(dist_order_cfg);
	}

	list_for_each_entry_safe(port, port_temp,
			&fra_cfg->fman_port_cfg_list, node) {
		list_del(&port->node);
		free(port);
	}

	free(fra_cfg);
}

static int parse_dist_order(xmlNodePtr cur,
			    struct list_head *dist_order_cfg_list)
{
	char *name;
	xmlNodePtr distrefp;
	struct dist_order_cfg *dist_order_cfg;
	struct dist_cfg *dist_cfg, *next_dist_cfg;
	int err = -ENXIO;

	dist_order_cfg = malloc(sizeof(struct dist_order_cfg));
	if (!dist_order_cfg)
		return -ENOMEM;
	memset(dist_order_cfg, 0, sizeof(*dist_order_cfg));

	distrefp = cur->xmlChildrenNode;
	dist_cfg = dist_order_cfg->dist_cfg;

	while (distrefp) {
		if (!is_node(distrefp, BAD_CAST POLICY_DISTREF_NODE)) {
			distrefp = distrefp->next;
			continue;
		}
		name = get_attributes(distrefp, BAD_CAST POLICY_DISTREF_NAME);
		if (unlikely(name == NULL))
			goto _err;
		strip_blanks(name);

		next_dist_cfg = malloc(sizeof(*next_dist_cfg));
		if (!next_dist_cfg) {
			error(0, 0,
				"failed to allocate dist memory");
			goto _err;
		}
		memset(next_dist_cfg, 0, sizeof(*next_dist_cfg));
		if (parse_dist(name, next_dist_cfg)) {
			error(0, 0, "Distribution(%s) has error",
				 name);
			goto _err;
		}
		if (!dist_cfg) {
			next_dist_cfg->sequence_number = 1;
			dist_order_cfg->dist_cfg = next_dist_cfg;
		} else {
			dist_cfg->next = next_dist_cfg;
			dist_cfg->next->sequence_number =
				dist_cfg->sequence_number + 1;
		}
		dist_cfg = next_dist_cfg;
		distrefp = distrefp->next;
	}
	if (!dist_order_cfg->dist_cfg) {
		err = -EINVAL;
		goto _err;
	}
	list_add_tail(&dist_order_cfg->node, dist_order_cfg_list);
	return 0;
_err:
	dist_order_cfg_free(dist_order_cfg);
	return err;
}

static int parse_rman_cfg(xmlNodePtr cur, struct rman_cfg *cfg)
{
	char *ptr;
	xmlNodePtr cfgptr;
	enum RIO_TYPE type;

	cfgptr = cur->xmlChildrenNode;
	while (cfgptr) {
		if ((is_node(cfgptr, BAD_CAST RMAN_FQ_BITS_NODE))) {
			ptr = get_attributes(cfgptr, BAD_CAST RMAN_CFG_TYPE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			type = rio_type_str_to_idx(ptr);
			ptr = get_attributes(cfgptr, BAD_CAST RMAN_CFG_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			cfg->fq_bits[type] = strtoul(ptr, NULL, 0);
		} else if ((is_node(cfgptr, BAD_CAST MD_CREATE_NODE))) {
			ptr = get_attributes(cfgptr, BAD_CAST MD_CREATE_MODE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			if (!strcmp(ptr, MD_CREATE_MODE_STR[0]))
				cfg->md_create = 0;
			else
				cfg->md_create = 1;
		} else if ((is_node(cfgptr, BAD_CAST RMAN_OSID_NODE))) {
			ptr = get_attributes(cfgptr, BAD_CAST RMAN_CFG_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			if (!strcmp(ptr, "yes"))
				cfg->osid = 1;
			else
				cfg->osid = 0;
		} else if ((is_node(cfgptr, BAD_CAST BPID_NODE))) {
			ptr = get_attributes(cfgptr, BAD_CAST RMAN_CFG_TYPE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			type = rio_type_str_to_idx(ptr);
			ptr = get_attributes(cfgptr, BAD_CAST RMAN_CFG_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			cfg->bpid[type] = strtoul(ptr, NULL, 0);
		} else if ((is_node(cfgptr, BAD_CAST SG_BPID_NODE))) {
			ptr = get_attributes(cfgptr, BAD_CAST RMAN_CFG_VALUE);
			if (unlikely(ptr == NULL))
				return -EINVAL;
			cfg->sgbpid = strtoul(ptr, NULL, 0);
		}
		cfgptr = cfgptr->next;
	}
	return 0;
}

static int parse_network_cfg(xmlNodePtr cur, struct list_head *list)
{
	char *ptr;
	xmlNodePtr cfgptr;
	struct fra_fman_port_cfg *cfg;

	cfgptr = cur->xmlChildrenNode;
	while (cfgptr) {
		if (!(is_node(cfgptr, BAD_CAST FMAN_PORT_NODE)))
			continue;
		cfg = malloc(sizeof(*cfg));
		if (!cfg)
			return -ENOMEM;
		memset(cfg, 0, sizeof(*cfg));

		ptr = get_attributes(cfgptr, BAD_CAST FMAN_PORT_NAME);
		if (unlikely(ptr == NULL))
			return -EINVAL;
		snprintf(cfg->port_name, sizeof(cfg->port_name), ptr);
		ptr = get_attributes(cfgptr, BAD_CAST FMAN_PORT_TYPE);
		if (unlikely(ptr == NULL))
			return -EINVAL;
		cfg->port_type = (strcmp(ptr, "OFFLINE") == 0) ?
				 fman_offline :
				 (strcmp(ptr, "10G") == 0) ?
				 fman_mac_10g : fman_mac_1g;
		ptr = (char *)get_attributes(cfgptr, BAD_CAST FMAN_PORT_NUM);
		if (unlikely(ptr == NULL))
			return -EINVAL;
		cfg->port_num = strtoul(ptr, NULL, 0);

		ptr = (char *)get_attributes(cfgptr, BAD_CAST FMAN_NUM);
		if (unlikely(ptr == NULL))
			return -EINVAL;
		cfg->fman_num = strtoul(ptr, NULL, 0);
		list_add_tail(&cfg->node, list);
		cfgptr = cfgptr->next;
	}
	return 0;
}

struct fra_cfg *fra_parse_cfgfile(const char *cfg_file)
{
	xmlErrorPtr xep;
	xmlNodePtr dist_order_node;
	xmlDocPtr doc;
	xmlNodePtr cur;
	struct fra_cfg *fra_cfg = NULL;
	int err;

	xmlInitParser();
	LIBXML_TEST_VERSION;
	xmlSetStructuredErrorFunc(&xep, fra_cfg_parse_error);
	xmlKeepBlanksDefault(0);

	doc = xmlParseFile(cfg_file);
	if (unlikely(doc == NULL)) {
		error(0, 0, "%s:%hu:%s() xmlParseFile(%s)",
			__FILE__, __LINE__, __func__, cfg_file);
		return NULL;
	}

	fra_cfg_root_node = xmlDocGetRootElement(doc);
	cur = fra_cfg_root_node;
	if (unlikely(cur == NULL)) {
		error(0, 0, "%s:%hu:%s() xml file(%s) empty",
			__FILE__, __LINE__, __func__, cfg_file);
		goto _err;
	}

	if (unlikely(!is_node(cur, BAD_CAST FRA_CFG_FILE_ROOT_NODE))) {
		error(0, 0, "%s:%hu:%s() xml file(%s) does not"
			"have %s node", __FILE__, __LINE__, __func__,
			cfg_file, FRA_CFG_FILE_ROOT_NODE);
		goto _err;
	}

	fra_cfg = malloc(sizeof(*fra_cfg));
	if (!fra_cfg) {
		error(0, errno, "malloc(fra_cfg memory)");
		goto _err;
	}
	memset(fra_cfg, 0, sizeof(*fra_cfg));
	INIT_LIST_HEAD(&fra_cfg->dist_order_cfg_list);
	INIT_LIST_HEAD(&fra_cfg->fman_port_cfg_list);

	cur = cur->xmlChildrenNode;
	for_all_sibling_nodes(cur) {
		if (is_node(cur, BAD_CAST RMAN_CFG_NODE)) {
			parse_rman_cfg(cur, &fra_cfg->rman_cfg);
			continue;
		}

		if (is_node(cur, BAD_CAST NETWORK_CFG_NODE)) {
			parse_network_cfg(cur,
				&fra_cfg->fman_port_cfg_list);
			continue;
		}
		if (unlikely(!is_node(cur, BAD_CAST POLICY_NODE)))
			continue;

		dist_order_node = cur->xmlChildrenNode;
		while (dist_order_node) {
			if (unlikely(!is_node(dist_order_node,
					BAD_CAST POLICY_DISTORDER_NODE))) {
				dist_order_node = dist_order_node->next;
				continue;
			}
			err = parse_dist_order(dist_order_node,
					&fra_cfg->dist_order_cfg_list);
			if (err)
				goto _err;
			dist_order_node = dist_order_node->next;
		}
	}
	return fra_cfg;
_err:
	fra_cfg_release(fra_cfg);
	xmlFreeDoc(doc);
	return NULL;
}
