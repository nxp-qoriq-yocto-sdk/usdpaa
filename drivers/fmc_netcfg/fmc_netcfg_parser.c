/* Copyright (c) 2010 Freescale Semiconductor, Inc.
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

#include <compat.h>
#include <libxml/parser.h>
#include <of.h>
#include <fmc_netcfg_parser.h>

static void fmc_netcfg_parse_error(void *ctx, xmlErrorPtr error)
{
	fprintf(stderr, "%s:%hu:%s() fmc_netcfg_parse_error(context(%p),"
			"error pointer %p\n", __FILE__, __LINE__, __func__,
			ctx, error);
}

/* Structure contains the information about the MAC interface
 * This does not have the information about the Error Frame queues
 * and Tx confirm frame queue because this information is not the in
 * FMC config (XML) file. Information about these frame queues will be
 * picked up from the Device Tree.
 * */
struct interface_info {
	uint8_t fman_num;		/* 0 => FMAN0, 1 => FMAN1 and so on */
	uint8_t port_type;		/* 1 => "1G" or 10 => "10G" */
	uint8_t port_num;		/* 0 onwards */
	struct fmc_netcfg_fqrange pcd;	/* FIXME multiple PCD support */
	struct fmc_netcfg_fqrange rxdef;/* default RX fq range */
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

#if 0
static void dump_fmc_netcfg_info(void)
{
	int i;
	struct interface_info *i_info;

	for (i = 0; i < netcfg_info->numof_interface; i++) {
		i_info = &netcfg_info->interface_info[i];
		if (!(i_info)) {
			printf("%s,%s: corrupted data structure\n",
					__FILE__, __func__);
			continue;
		}

		printf(" FMAN number = %d\n", i_info->fman_num);
		printf(" port type = %d\n ", i_info->port_type);
		printf(" Port number = %d\n", i_info->port_num);
		printf(" PCD FQ start = 0x%x\n ", i_info->pcd.start);
		printf(" PCD FQ count = %d\n ", i_info->pcd.count);
		printf(" RXDEF FQ start = 0x%x\n ", i_info->rxdef.start);
		printf(" RXDEF FQ count = %d\n ", i_info->rxdef.count);
	}
}
#endif

static void *get_attributes(xmlNodePtr node, const char *attr)
{
	char *atr = (char *)xmlGetProp(node, BAD_CAST attr);
	if (atr == NULL)
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

static char *distribution_ref(xmlNodePtr dnode)
{
	if (xmlStrcmp(dnode->name, BAD_CAST "distributionref")) {
		fprintf(stderr, "%s:%hu:%s() error: distributionref not"
				" found\n", __FILE__, __LINE__, __func__);
		return NULL;
	}
	return (char *)get_attributes(dnode, "name");
}

static int pcdinfo(char *dist_name, struct fmc_netcfg_fqrange *fqr)
{
	uint8_t len;
	char *name;
	int _errno = 0;
	char *ptr;
	xmlNodePtr distp;
	xmlNodePtr cur;

	cur = netpcd_root_node->xmlChildrenNode;
	while (cur != NULL) {
		if (xmlStrcmp(cur->name, BAD_CAST "distribution")) {
			cur = cur->next;
			continue;
		}

		len = strnlen(dist_name, 100);
		name = (char *)get_attributes(cur, "name");
		if (!name || (strncmp(name, dist_name, len))) {
			cur = cur->next;
			continue;
		}

		distp = cur->xmlChildrenNode;
		for (; distp != NULL; distp = distp->next) {
			if (xmlStrcmp(distp->name, BAD_CAST "queue"))
				continue;

			/* Extract the number of FQs */
			ptr = get_attributes(distp, "count");
			if (!ptr)
				break;

			fqr->count = strtoul(ptr, NULL, 0);

			/* Extract the starting number of FQs */
			ptr = get_attributes(distp, "base");
			if (!ptr)
				break;

			fqr->start = strtoul(ptr, NULL, 0);
			break;
		}
		break;
	}
	return _errno;
}

static int parse_policy(xmlNodePtr cur, struct fmc_netcfg_fqrange *pcd,
					struct fmc_netcfg_fqrange *rxdef)
{
	char *name;
	int _errno = 0;
	xmlNodePtr distp;
	xmlNodePtr dist_node;

	distp = cur->xmlChildrenNode;
	while (distp) {
		if (xmlStrcmp(distp->name, BAD_CAST "dist_order")) {
			distp = distp->next;
			continue;
		}
		dist_node = distp->xmlChildrenNode;
		if (dist_node != NULL) {
			/* FIXME:  Assuming that PCD FQs will
			 * always be first entry and default
			 * FQ range will be next entry
			 * */
			name = distribution_ref(dist_node);
			if (!name)
				break;

			_errno = pcdinfo(name, pcd);
			if (_errno)
				break;

			dist_node = dist_node->next;
			name = distribution_ref(dist_node);
			if (!name)
				break;

			_errno = pcdinfo(name, rxdef);
			if (_errno)
				break;
		}
		break;
	}
	return _errno;
}

static int process_pcdfile(char *filename, char *policy_name,
				struct fmc_netcfg_fqrange *pcd,
				struct fmc_netcfg_fqrange *rxdef)
{
	xmlErrorPtr error;
	int _errno = 0;
	char *name;

	xmlInitParser();
	LIBXML_TEST_VERSION;
	xmlSetStructuredErrorFunc(&error, fmc_netcfg_parse_error);
	xmlKeepBlanksDefault(0);

	xmlDocPtr doc = xmlParseFile(filename);
	if (doc == NULL) {
		fprintf(stderr, "%s:%hu:%s() error: xmlParseFile(%s)\n",
				__FILE__, __LINE__, __func__, filename);
		return -EINVAL;
	}

	netpcd_root_node = xmlDocGetRootElement(doc);
	xmlNodePtr cur = netpcd_root_node;

	if (cur == NULL) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) empty\n",
				__FILE__, __LINE__, __func__, filename);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	if (xmlStrcmp(cur->name, BAD_CAST "netpcd")) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) is not "
			"netpcd\n", __FILE__, __LINE__, __func__, filename);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if (!xmlStrcmp(cur->name, BAD_CAST "policy")) {
			name = (char *)get_attributes(cur, "name");
			if (name && !(strcmp(name, policy_name)))
				_errno = parse_policy(cur, pcd, rxdef);
		}
		cur = cur->next;
	}

	return _errno;
}

static int parse_engine(xmlNodePtr enode, char *pcd_file)
{
	int _errno = 0;
	struct interface_info *i_info;
	struct fmc_netcfg_fqrange pcd;
	struct fmc_netcfg_fqrange rxdef;
	char *tmp;
	static uint8_t p_curr;
	uint8_t fman, p_type, p_num;

	if (xmlStrcmp(enode->name, BAD_CAST "engine")) {
		fprintf(stderr, "%s:%hu:%s() error: (engine) node not found"
				"in XMLFILE(%s)\n",
				__FILE__, __LINE__, __func__, pcd_file);
		return -EINVAL;
	}
	tmp = (char *)get_attributes(enode, "name");
	if (!tmp || strncmp(tmp, "fm", 2) || !isdigit(tmp[2])) {
		fprintf(stderr, "%s:%hu:%s() error: (engine) name is neither"
				"<fm0> nor <fm1> in XMLFILE(%s)\n",
				__FILE__, __LINE__, __func__, pcd_file);
		return -EINVAL;
	}

	fman = tmp[2] - '0';

	xmlNodePtr cur = enode->xmlChildrenNode;
	while (cur != NULL) {
		if (xmlStrcmp(cur->name, BAD_CAST "port")) {
			cur = cur->next;
			continue;
		}

		tmp = (char *)get_attributes(cur, "number");
		if (!tmp) {
			cur = cur->next;
			continue;
		}

		p_num = strtoul(tmp, NULL, 0);

		tmp = (char *)get_attributes(cur, "type");
		if (!tmp) {
			cur = cur->next;
			continue;
		}
		strip_blanks(tmp);

		/* FIXME : Remove assumption of only two type of ports */
		if (!(strcmp(tmp, "10G")))
			p_type = 10;
		else
			p_type = 1;

		tmp = (char *)get_attributes(cur, "policy");
		if (!tmp) {
			cur = cur->next;
			continue;
		}
		strip_blanks(tmp);

		_errno = process_pcdfile(pcd_file, tmp, &pcd, &rxdef);
		if (_errno) {
			cur = cur->next;
			continue;
		}

		i_info = &(netcfg_info->interface_info[p_curr]);
		p_curr++;

		i_info->fman_num = fman;
		i_info->port_num = p_num;
		i_info->port_type = p_type;
		i_info->pcd.start = pcd.start;
		i_info->pcd.count = pcd.count;
		i_info->rxdef.start = rxdef.start;
		i_info->rxdef.count = rxdef.count;

		cur = cur->next;
	}
	return _errno;
}

static inline uint8_t ports_in_engine_node(xmlNodePtr enode)
{
	xmlNodePtr pnode;
	uint8_t count = 0;

	pnode = enode->xmlChildrenNode;
	while (pnode != NULL) {
		if (!xmlStrcmp(pnode->name, BAD_CAST "port"))
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
	while (enode) {
		if (!xmlStrcmp(enode->name, BAD_CAST "engine")) {
			tmp = (char *)get_attributes(enode, "name");
			if (!strcmp(tmp, "fm0") || !strcmp(tmp, "fm1"))
				count += ports_in_engine_node(enode);
		}
		enode = enode->next;
	}

	return count;
}

static int parse_cfgfile(char *cfg_file, char *pcd_file)
{
	xmlErrorPtr error;
	xmlNodePtr engineNode;
	xmlDocPtr doc;
	xmlNodePtr cur;
	int _errno = 0;
	uint8_t	numof_interface;

	xmlInitParser();
	LIBXML_TEST_VERSION;
	xmlSetStructuredErrorFunc(&error, fmc_netcfg_parse_error);
	xmlKeepBlanksDefault(0);

	doc = xmlParseFile(cfg_file);
	if (doc == NULL) {
		fprintf(stderr, "%s:%hu:%s() error: xmlParseFile(%s)\n",
				__FILE__, __LINE__, __func__, cfg_file);
		return -EINVAL;
	}

	cur = xmlDocGetRootElement(doc);
	if (cur == NULL) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) empty\n",
				__FILE__, __LINE__, __func__, cfg_file);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	if (xmlStrcmp(cur->name, BAD_CAST "cfgdata")) {
		fprintf(stderr, "%s:%hu:%s() error: xml file(%s) is not "
			"cfgdata\n", __FILE__, __LINE__, __func__, cfg_file);
		xmlFreeDoc(doc);
		return -EINVAL;
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if (xmlStrcmp(cur->name, BAD_CAST "config")) {
			cur = cur->xmlChildrenNode;
			continue;
		}

		numof_interface = get_num_of_interface(cur);

		netcfg_info = malloc(sizeof(struct fmc_netcfg_info)
				+ (sizeof(struct interface_info)
					* numof_interface));

		netcfg_info->numof_interface = numof_interface;

		engineNode = cur->xmlChildrenNode;
		while (engineNode) {
			if (!xmlStrcmp(engineNode->name, BAD_CAST "engine"))
				_errno = parse_engine(engineNode, pcd_file);

			engineNode = engineNode->next;
		}
		cur = cur->xmlChildrenNode;
	}
	return _errno;
}

int fmc_netcfg_parser_init(char *pcd_file, char *cfg_file)
{
	int _errno;
	if (pcd_file == NULL || cfg_file == NULL)
		return -EINVAL;

	_errno = parse_cfgfile(cfg_file, pcd_file);

	return _errno;
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
		cfg->rxdef.start = i_info->rxdef.start;
		cfg->rxdef.count = i_info->rxdef.count;

		return 0;
	}
	return -ENXIO;
}
