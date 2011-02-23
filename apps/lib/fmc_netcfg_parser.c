/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
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

#include "fmc_netcfg_parser.h"

#define CFG_FILE_ROOT_NODE		("cfgdata")
#define CFG_NETCONFIG_NODE		("config")
#define CFG_FMAN_NODE			("engine")
#define CFG_FMAN_NA_name		("name")
#define CFG_PORT_NODE			("port")
#define CFG_PORT_NA_type		("type")
#define CFG_PORT_NA_number		("number")
#define CFG_PORT_NA_policy		("policy")

#define NPCD_FILE_ROOT_NODE		("netpcd")
#define NPCD_POLICY_NODE		("policy")
#define NPCD_POLICY_NA_name		("name")
#define NPCD_POLICY_DISTORDER_NODE	("dist_order")
#define NPCD_POLICY_DISTREF_NODE	("distributionref")
#define NPCD_POLICY_DISTREF_NA_name	("name")
#define NPCD_DIST_NODE			("distribution")
#define NPCD_DIST_NA_name		("name")
#define NPCD_DIST_FQ_NODE		("queue")
#define NPCD_DIST_FQ_NA_count		("count")
#define NPCD_DIST_FQ_NA_base		("base")

#define for_all_sibling_nodes(node)	\
	for (; unlikely(node != NULL); node = node->next)

/* Structure contains the information about the MAC interface
 * This does not have the information about the Error Frame queues
 * and Tx confirm frame queue because this information is not the in
 * FMC config (XML) file. Information about these frame queues will be
 * picked up from the Device Tree.
 * */
struct interface_info {
	uint8_t fman_num;		/* 0 => FMAN0, 1 => FMAN1 and so on */
	uint8_t port_type;		/* 1 => "1G" or 10 => "10G" ,so on*/
	uint8_t port_num;		/* 0 onwards */
	struct fmc_netcfg_fqrange pcd;	/* FIXME multiple PCD support */
	uint32_t rxdef;			/* default RX fq range */
};

/* Structure contains information about the MAC interfaces
 * */
struct fmc_netcfg_info {
	uint8_t numof_interface;
	struct interface_info interface_info[0/*numof_interface*/];
};

/* Structure contains information about the MAC interfaces specified in
 * configuration files.
 * */
struct fmc_netcfg_info *netcfg_info;
xmlNodePtr netpcd_root_node;

static void fmc_netcfg_parse_error(void *ctx, xmlErrorPtr error)
{
	fprintf(stderr, "%s:%hu:%s() fmc_netcfg_parse_error(context(%p),"
			"error pointer %p\n", __FILE__, __LINE__, __func__,
			ctx, error);
}

static inline int is_node(xmlNodePtr node, xmlChar *name)
{
	return xmlStrcmp(node->name, name) ? 0 : 1;
}

static void *get_attributes(xmlNodePtr node, xmlChar *attr)
{
	char *atr = (char *)xmlGetProp(node, attr);
	if (unlikely(atr == NULL))
		fprintf(stderr, "%s:%hu:%s() error: xmlGetProp(%s) not found\n",
				__FILE__, __LINE__, __func__,  attr);
	return atr;
}

static void strip_blanks(char *str)
{
	int i, j;
	int len = strlen(str);

	for (i = 0; (i < len) && (str[i] == ' '); i++);

	for (j = 0; (i < len) && (str[i] != ' '); ++i, j++)
		str[j] = str[i];

	str[j] = '\0';
}

static char *distribution_ref(xmlNodePtr nd)
{
	if (unlikely(!is_node(nd, BAD_CAST NPCD_POLICY_DISTREF_NODE))) {
		fprintf(stderr, "%s:%hu:%s() error: (%s) node not found\n",
			__FILE__, __LINE__, __func__, NPCD_POLICY_DISTREF_NODE);
		return NULL;
	}
	return (char *)get_attributes(nd, BAD_CAST NPCD_POLICY_DISTREF_NA_name);
}

static int pcdinfo(char *dist_name, struct fmc_netcfg_fqrange *fqr)
{
	uint8_t len;
	char *name;
	int _errno = -ENXIO;
	char *ptr;
	xmlNodePtr distp;
	xmlNodePtr cur;

	cur = netpcd_root_node->xmlChildrenNode;
	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST NPCD_DIST_NODE)))
			continue;

		len = strnlen(dist_name, 100);
		name = (char *)get_attributes(cur, BAD_CAST NPCD_DIST_NA_name);
		if (unlikely(!name) || unlikely(strncmp(name, dist_name, len)))
			continue;

		distp = cur->xmlChildrenNode;
		for_all_sibling_nodes(distp) {
			if (unlikely(!is_node(distp,
						BAD_CAST NPCD_DIST_FQ_NODE)))
				continue;

			/* Extract the number of FQs */
			ptr = get_attributes(distp,
					BAD_CAST NPCD_DIST_FQ_NA_count);
			if (unlikely(ptr == NULL)) {
				fprintf(stderr, "%s:%hu:%s() error: "
					"(Node(%s)->Attribute (%s) not found\n",
					__FILE__, __LINE__, __func__,
					distp->name, NPCD_DIST_FQ_NA_count);
				return -EINVAL;
			}

			fqr->count = strtoul(ptr, NULL, 0);

			/* Extract the starting number of FQs */
			ptr = get_attributes(distp,
					BAD_CAST NPCD_DIST_FQ_NA_base);
			if (unlikely(ptr == NULL)) {
				fprintf(stderr, "%s:%hu:%s() error: "
					"(Node(%s)->Attribute (%s) not found\n",
					__FILE__, __LINE__, __func__,
					distp->name, NPCD_DIST_FQ_NA_base);
				return -EINVAL;
			}

			fqr->start = strtoul(ptr, NULL, 0);
			_errno = 0;
			break;
		}
		break;
	}
	return _errno;
}

static int rxdefinfo(char *dist_name, uint32_t *rxdef)
{
	uint8_t len;
	char *name;
	int _errno = -ENXIO;
	char *ptr;
	xmlNodePtr distp;
	xmlNodePtr cur;

	cur = netpcd_root_node->xmlChildrenNode;
	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST NPCD_DIST_NODE)))
			continue;

		len = strnlen(dist_name, 100);
		name = (char *)get_attributes(cur, BAD_CAST NPCD_DIST_NA_name);
		if (unlikely(!name) || unlikely(strncmp(name, dist_name, len)))
			continue;

		distp = cur->xmlChildrenNode;
		for_all_sibling_nodes(distp) {
			uint32_t count;
			if (unlikely(!is_node(distp,
						BAD_CAST NPCD_DIST_FQ_NODE)))
				continue;

			/* Extract the number of FQs */
			ptr = get_attributes(distp,
					BAD_CAST NPCD_DIST_FQ_NA_count);
			if (unlikely(ptr == NULL)) {
				fprintf(stderr, "%s:%hu:%s() error: "
					"(Node(%s)->Attribute (%s) not found\n",
					__FILE__, __LINE__, __func__,
					distp->name, NPCD_DIST_FQ_NA_count);
				return -EINVAL;
			}

			count = strtoul(ptr, NULL, 0);
			if( count != 1) {
				fprintf(stderr, "%s:%hu:%s() error: "
					"(%s:%c != 1)\n",
					__FILE__, __LINE__, __func__, name,
					count);
				return -EINVAL;
			}

			/* Extract the starting number of FQs */
			ptr = get_attributes(distp,
					BAD_CAST NPCD_DIST_FQ_NA_base);
			if (unlikely(ptr == NULL)) {
				fprintf(stderr, "%s:%hu:%s() error: "
					"(Node(%s)->Attribute (%s) not found\n",
					__FILE__, __LINE__, __func__,
					distp->name, NPCD_DIST_FQ_NA_base);
				return -EINVAL;
			}

			*rxdef = strtoul(ptr, NULL, 0);
			_errno = 0;
			break;
		}
		break;
	}
	return _errno;
}

static int parse_policy(xmlNodePtr cur, struct fmc_netcfg_fqs *fqs)
{
	char *name;
	xmlNodePtr distp;
	xmlNodePtr dist_node;

	distp = cur->xmlChildrenNode;
	while (distp) {
		if (likely(is_node(distp, BAD_CAST NPCD_POLICY_DISTORDER_NODE)))
			break;
		distp = distp->next;
	}
	if (unlikely(distp == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: (Node(%s) not found\n",
			__FILE__, __LINE__, __func__,
			NPCD_POLICY_DISTORDER_NODE);
		return -ENXIO;
	}

	dist_node = distp->xmlChildrenNode;
	if (unlikely(dist_node == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: (Node(%s) have no "
			"child node\n", __FILE__, __LINE__, __func__,
			distp->name);
		return -ENXIO;
	}
	/* FIXME:  Assuming that PCD FQs will always be first entry
	 * and default FQ range will be next entry
	 */
	name = distribution_ref(dist_node);
	if (unlikely(name == NULL))
		return -ENXIO;

	if(pcdinfo(name, &fqs->pcd)) {
		fprintf(stderr, "%s:%hu:%s() error: PCD %s information not"
			" found\n", __FILE__, __LINE__, __func__, name);
		return -ENXIO;
	}

	dist_node = dist_node->next;
	if (unlikely(dist_node == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: Node RXdef not"
			" found in Node(%s)\n", __FILE__, __LINE__,
			__func__, distp->name);
		return -EINVAL;
	}

	name = distribution_ref(dist_node);
	if (unlikely(name == NULL))
		return -ENXIO;

	if (rxdefinfo(name, &fqs->rxdef)) {
		fprintf(stderr, "%s:%hu:%s() error: DEFRX %s information not"
			" found\n", __FILE__, __LINE__, __func__, name);
		return -ENXIO;
	}
	return 0;
}

static int process_pcdfile(const char *filename, char *policy_name,
				struct fmc_netcfg_fqs *fqs)
{
	xmlErrorPtr error;
	int _errno = -ENXIO;
	char *name;
	xmlDocPtr doc;
	xmlNodePtr cur;

	xmlInitParser();
	LIBXML_TEST_VERSION;
	xmlSetStructuredErrorFunc(&error, fmc_netcfg_parse_error);
	xmlKeepBlanksDefault(0);

	doc = xmlParseFile(filename);
	if (unlikely(doc == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: xmlParseFile(%s)\n",
				__FILE__, __LINE__, __func__, filename);
		return -EINVAL;
	}

	netpcd_root_node = xmlDocGetRootElement(doc);
	cur = netpcd_root_node;

	if (unlikely(cur == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) empty\n",
				__FILE__, __LINE__, __func__, filename);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	if (unlikely(!is_node(cur, BAD_CAST NPCD_FILE_ROOT_NODE))) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) is not "
			"%s\n", __FILE__, __LINE__, __func__,
			filename, NPCD_FILE_ROOT_NODE);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	cur = cur->xmlChildrenNode;
	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST NPCD_POLICY_NODE)))
			continue;

		name = (char *)get_attributes(cur,
					BAD_CAST NPCD_POLICY_NA_name);
		if (unlikely(!name) || unlikely(strcmp(name, policy_name)))
			continue;

		_errno = parse_policy(cur, fqs);
		break;
	}
	return _errno;
}

static int parse_engine(xmlNodePtr enode, const char *pcd_file)
{
	int _errno = -ENXIO;
	struct interface_info *i_info;
	struct fmc_netcfg_fqs fqs;
	char *tmp;
	static uint8_t p_curr;
	uint8_t fman, p_type, p_num;
	xmlNodePtr cur;

	if (unlikely(!is_node(enode, BAD_CAST CFG_FMAN_NODE))) {
		fprintf(stderr, "%s:%hu:%s() error: (%s) node not found"
				"in XMLFILE(%s)\n", __FILE__, __LINE__,
				__func__, CFG_FMAN_NODE, pcd_file);
		return -EINVAL;
	}
	tmp = (char *)get_attributes(enode, BAD_CAST CFG_FMAN_NA_name);
	if (unlikely(!tmp) || unlikely(strncmp(tmp, "fm", 2)) ||
				unlikely(!isdigit(tmp[2]))) {
		fprintf(stderr, "%s:%hu:%s() error: attrtibute name in %s node"
				"is neither <fm0> nor <fm1> in XMLFILE(%s)\n",
				__FILE__, __LINE__, __func__,
				CFG_FMAN_NODE, pcd_file);
		return -EINVAL;
	}

	fman = tmp[2] - '0';

	cur = enode->xmlChildrenNode;

	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST CFG_PORT_NODE)))
			continue;

		/* Get the MAC port number from PORT node attribute "number" */
		tmp = (char *)get_attributes(cur, BAD_CAST CFG_PORT_NA_number);
		if (unlikely(tmp == NULL))
			break;
		p_num = strtoul(tmp, NULL, 0);

		/* Get the MAC port type from PORT node attribute "type" */
		tmp = (char *)get_attributes(cur, BAD_CAST CFG_PORT_NA_type);
		if (unlikely(tmp == NULL))
			break;
		p_type = strtoul(tmp, NULL, 0);

		/* Get the policy applied with the MAC port from PORT node
		 attribute "policy" */
		tmp = (char *)get_attributes(cur, BAD_CAST CFG_PORT_NA_policy);
		if (unlikely(tmp == NULL))
			break;

		strip_blanks(tmp);
		_errno = process_pcdfile(pcd_file, tmp, &fqs);
		if (unlikely(_errno))
			break;

		i_info = &(netcfg_info->interface_info[p_curr]);
		p_curr++;

		i_info->fman_num = fman;
		i_info->port_num = p_num;
		i_info->port_type = p_type;
		i_info->pcd.start = fqs.pcd.start;
		i_info->pcd.count = fqs.pcd.count;
		i_info->rxdef = fqs.rxdef;
	}
	return _errno;
}

static inline uint8_t ports_in_engine_node(xmlNodePtr enode)
{
	xmlNodePtr pnode;
	uint8_t count = 0;

	pnode = enode->xmlChildrenNode;
	while (likely(pnode != NULL)) {
		if (is_node(pnode, BAD_CAST CFG_PORT_NODE))
			count++;
		pnode = pnode->next;
	}

	return count;
}

static inline uint8_t get_num_of_interface(xmlNodePtr cur)
{
	uint8_t count = 0;
	char *tmp;
	xmlNodePtr enode;

	enode = cur->xmlChildrenNode;
	for_all_sibling_nodes(enode) {
		if (unlikely(!is_node(enode, BAD_CAST CFG_FMAN_NODE)))
			continue;

		tmp = (char *)get_attributes(enode, BAD_CAST CFG_FMAN_NA_name);
		if (unlikely(!tmp) || unlikely(strncmp(tmp, "fm", 2)) ||
					unlikely(!isdigit(tmp[2])))
			continue;

		count += ports_in_engine_node(enode);
	}
	return count;
}

static int parse_cfgfile(const char *cfg_file, const char *pcd_file)
{
	xmlErrorPtr error;
	xmlNodePtr fman_node;
	xmlDocPtr doc;
	xmlNodePtr cur;
	int _errno = -ENXIO;
	uint8_t	numof_interface;

	xmlInitParser();
	LIBXML_TEST_VERSION;
	xmlSetStructuredErrorFunc(&error, fmc_netcfg_parse_error);
	xmlKeepBlanksDefault(0);

	doc = xmlParseFile(cfg_file);
	if (unlikely(doc == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: xmlParseFile(%s)\n",
				__FILE__, __LINE__, __func__, cfg_file);
		return -EINVAL;
	}

	cur = xmlDocGetRootElement(doc);
	if (unlikely(cur == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) empty\n",
				__FILE__, __LINE__, __func__, cfg_file);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	if (unlikely(!is_node(cur, BAD_CAST CFG_FILE_ROOT_NODE))) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) does not"
			"have %s node\n", __FILE__, __LINE__, __func__,
			cfg_file, CFG_FILE_ROOT_NODE);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	cur = cur->xmlChildrenNode;
	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST CFG_NETCONFIG_NODE)))
			continue;

		numof_interface = get_num_of_interface(cur);

		netcfg_info = malloc(sizeof(struct fmc_netcfg_info)
				+ (sizeof(struct interface_info)
					* numof_interface));

		netcfg_info->numof_interface = numof_interface;

		fman_node = cur->xmlChildrenNode;
		while (fman_node) {
			if (likely(is_node(fman_node, BAD_CAST CFG_FMAN_NODE)))
				_errno = parse_engine(fman_node, pcd_file);

			fman_node = fman_node->next;
		}
		/* There can not be more than one "config" node */
		break;
	}
	return _errno;
}

int fmc_netcfg_parser_init(const char *pcd_file, const char *cfg_file)
{
	int _errno;
	if (unlikely(pcd_file == NULL) || unlikely(cfg_file == NULL))
		return -EINVAL;

	_errno = parse_cfgfile(cfg_file, pcd_file);

	return _errno;
}

int fmc_netcfg_parser_exit(void)
{
	free(netcfg_info);
	return 0;
}

int fmc_netcfg_get_info(uint8_t fman, uint8_t p_type, uint8_t p_num,
				struct fmc_netcfg_fqs *cfg)
{
	struct interface_info *i_info;
	uint8_t i;

	for (i = 0; i < netcfg_info->numof_interface; i++) {
		i_info = &netcfg_info->interface_info[i];
		if (fman != i_info->fman_num || p_type != i_info->port_type ||
						p_num != i_info->port_num)
			continue;

		cfg->pcd.start = i_info->pcd.start;
		cfg->pcd.count = i_info->pcd.count;
		cfg->rxdef = i_info->rxdef;

		return 0;
	}
	return -ENXIO;
}
