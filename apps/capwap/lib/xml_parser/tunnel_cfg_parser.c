/* Copyright (c) 2014 Freescale Semiconductor, Inc.
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

#include <flib/rta.h>

#include <libxml/parser.h>
#include <arpa/inet.h>
#include <usdpaa/compat.h>
#include "app_config.h"
#include "capwap_sec.h"

#define TUNNEL_CFG_ROOT_NODE	("tunnel_cfg")

#define TUNNEL_CFG_NODE		("tunnel")
#define TUNNEL_NAME		("name")
#define TUNNEL_CFG_IPSRC	("ipsrc")
#define TUNNEL_CFG_IPDEST	("ipdest")
#define TUNNEL_CFG_MACSRC	("macsrc")
#define TUNNEL_CFG_MACDEST	("macdest")
#define TUNNEL_CFG_VALUE	("value")
#define TUNNEL_CFG_CIPHER	("cipher")
#define TUNNEL_CFG_CIPHER_KEY_LEN	("cipher_key_len")
#define TUNNEL_CFG_CIPHER_KEY_VAL	("cipher_key_value")
#define TUNNEL_CFG_AUTH_KEY_LEN	("auth_key_len")
#define TUNNEL_CFG_AUTH_KEY_VAL	("auth_key_value")
#define TUNNEL_CFG_CIPHER_SUITE	("ciphersuite")

xmlNodePtr tunnel_cfg_root_node;

#define for_all_sibling_nodes(node)	\
	for (; unlikely(node != NULL); node = node->next)


static void tunnel_cfg_parse_error(void *ctx, xmlErrorPtr xep)
{
	error(0, 0, "%s:%hu:%s() tunnel_cfg_parse_error(context(%p),"
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

int mac_str_to_bin(char *str, uint8_t *mac)
{
    int i;
    char *s, *e;

    if ((mac == NULL) || (str == NULL))
    {
        return -1;
    }

    s = (char *) str;
    for (i = 0; i < 6; ++i)
    {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
           s = (*e) ? e + 1 : e;
    }
    return 0;
}

uint32_t dtls_alg_check(char *name)
{

	if (!strcmp(name, "CIPHER_TYPE_DTLS_DES_CBC_SHA_160"))
		return CIPHER_TYPE_DTLS_DES_CBC_SHA_160;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_DES_CBC_MD5_128"))
		return CIPHER_TYPE_DTLS_DES_CBC_MD5_128;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_3DES_CBC_MD5_128"))
		return CIPHER_TYPE_DTLS_3DES_CBC_MD5_128;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_3DES_CBC_SHA_160"))
		return CIPHER_TYPE_DTLS_3DES_CBC_SHA_160;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_3DES_CBC_SHA_384"))
		return CIPHER_TYPE_DTLS_3DES_CBC_SHA_384;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_3DES_CBC_SHA_224"))
		return CIPHER_TYPE_DTLS_3DES_CBC_SHA_224;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_3DES_CBC_SHA_512"))
		return CIPHER_TYPE_DTLS_3DES_CBC_SHA_512;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_3DES_CBC_SHA_256"))
		return CIPHER_TYPE_DTLS_3DES_CBC_SHA_256;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_256_CBC_SHA_160"))
		return CIPHER_TYPE_DTLS_AES_256_CBC_SHA_160;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_256_CBC_SHA_384"))
		return CIPHER_TYPE_DTLS_AES_256_CBC_SHA_384;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_256_CBC_SHA_224"))
		return CIPHER_TYPE_DTLS_AES_256_CBC_SHA_224;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_256_CBC_SHA_512"))
		return CIPHER_TYPE_DTLS_AES_256_CBC_SHA_512;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_256_CBC_SHA_256"))
		return CIPHER_TYPE_DTLS_AES_256_CBC_SHA_256;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_128_CBC_SHA_160"))
		return CIPHER_TYPE_DTLS_AES_128_CBC_SHA_160;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_128_CBC_SHA_384"))
		return CIPHER_TYPE_DTLS_AES_128_CBC_SHA_384;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_128_CBC_SHA_224"))
		return CIPHER_TYPE_DTLS_AES_128_CBC_SHA_224;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_128_CBC_SHA_512"))
		return CIPHER_TYPE_DTLS_AES_128_CBC_SHA_512;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_128_CBC_SHA_256"))
		return CIPHER_TYPE_DTLS_AES_128_CBC_SHA_256;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_192_CBC_SHA_160"))
		return CIPHER_TYPE_DTLS_AES_192_CBC_SHA_160;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_192_CBC_SHA_384"))
		return CIPHER_TYPE_DTLS_AES_192_CBC_SHA_384;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_192_CBC_SHA_224"))
		return CIPHER_TYPE_DTLS_AES_192_CBC_SHA_224;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_192_CBC_SHA_512"))
		return CIPHER_TYPE_DTLS_AES_192_CBC_SHA_512;
	if (!strcmp(name, "CIPHER_TYPE_DTLS_AES_192_CBC_SHA_256"))
		return CIPHER_TYPE_DTLS_AES_192_CBC_SHA_256;
	return 255;
};

uint32_t check_split_alg_n_key_len(char *name, uint16_t *key_size)
{


	if (!strcmp(name, "SPLIT_KEY_HASH_ALG_MD5_128")) {
		*key_size = 16;
		return e_SPLIT_KEY_HASH_ALG_MD5_128; /* Split-Key hashing algorithm MD5-128 */
	}
	if (!strcmp(name, "SPLIT_KEY_HASH_ALG_SHA_160")) {
		*key_size = 20;
		return e_SPLIT_KEY_HASH_ALG_SHA_160; /* Split-Key hashing algorithm SHA-160 */
	}
	if (!strcmp(name, "SPLIT_KEY_HASH_ALG_SHA_224")) {
		*key_size = 32;
		return e_SPLIT_KEY_HASH_ALG_SHA_224; /* Split-Key hashing algorithm SHA-224 */
	}
	if (!strcmp(name, "SPLIT_KEY_HASH_ALG_SHA_256")) {
		*key_size = 32;
		return e_SPLIT_KEY_HASH_ALG_SHA_256; /* Split-Key hashing algorithm SHA-256 */
	}
	if (!strcmp(name, "SPLIT_KEY_HASH_ALG_SHA_384")) {
		*key_size = 64;
		return e_SPLIT_KEY_HASH_ALG_SHA_384; /* Split-Key hashing algorithm SHA-384 */
	}
	if (!strcmp(name, "SPLIT_KEY_HASH_ALG_SHA_512")) {
		*key_size = 64;
		return e_SPLIT_KEY_HASH_ALG_SHA_512; /* Split-Key hashing algorithm SHA-512 */
	}
    return 0;
}

static int parse_tunnel(xmlNodePtr tunnel_node, struct tunnel_info *tunnel)
{
	char *name;
	xmlNodePtr tunnelp;
	char *ptr;
	struct in_addr in_addr;
	uint32_t algtype;
	uint8_t *newkey = NULL;
	uint16_t key_len;
	struct cypher_suite cypher_s;
	int i;

	if (!tunnel_node)
		return -EINVAL;

	name = get_attributes(tunnel_node, BAD_CAST TUNNEL_NAME);
	//snprintf(tunnel->name, sizeof(tunnel->name), name);

	/* Update tunnel configuration */
	tunnelp = tunnel_node->xmlChildrenNode;

	for_all_sibling_nodes(tunnelp) {
		if ((is_node(tunnelp, BAD_CAST TUNNEL_CFG_IPSRC))) {
			ptr = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_VALUE);
			if (unlikely(ptr == NULL))
				goto err;
			inet_aton(ptr, &in_addr);
			tunnel->src_ip = in_addr.s_addr;
		} else if ((is_node(tunnelp, BAD_CAST TUNNEL_CFG_IPDEST))) {
			ptr = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_VALUE);
			if (unlikely(ptr == NULL))
				goto err;
			inet_aton(ptr, &in_addr);
			tunnel->dest_ip = in_addr.s_addr;
		} else if ((is_node(tunnelp, BAD_CAST TUNNEL_CFG_MACSRC))) {
			ptr = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_VALUE);
			if (unlikely(ptr == NULL))
				goto err;
			mac_str_to_bin(ptr, tunnel->src_mac);
		} else if ((is_node(tunnelp, BAD_CAST TUNNEL_CFG_MACDEST))) {
			ptr = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_VALUE);
			if (unlikely(ptr == NULL))
				goto err;
			mac_str_to_bin(ptr, tunnel->dest_mac);
		} else if ((is_node(tunnelp, BAD_CAST TUNNEL_CFG_CIPHER))) {
			ptr = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_CIPHER_SUITE);
			if (unlikely(ptr == NULL))
				goto err;

			algtype = dtls_alg_check(ptr);
			if (algtype == 255) {
				printf("BAD Cypher Suite type for tunnel %s\n", name);
				printf("Then set Cypher Suite type for tunnel to CIPHER_TYPE_DTLS_AES_128_CBC_SHA_160\n");
				algtype = CIPHER_TYPE_DTLS_AES_128_CBC_SHA_160;
			}

			tunnel->cipherdata = malloc(sizeof(struct dtls_alg_info));
			if(!tunnel->cipherdata)
				goto err;
			tunnel->authdata = malloc(sizeof(struct dtls_alg_info));
			if(!tunnel->authdata)
				goto err;

			tunnel->cipherdata->algtype = algtype;
			cypher_s = alg_suite[algtype];
			tunnel->authdata->algtype = cypher_s.auth_type;
			tunnel->authdata->keylen = split_key_size[tunnel->authdata->algtype];
			tunnel->cipherdata->keylen = cypher_key_size[cypher_s.cypher_type];

			ptr = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_CIPHER_KEY_LEN);
			if (unlikely(ptr == NULL))
				goto err;
			key_len =strtoul(ptr, NULL, 0);
			if (tunnel->cipherdata->keylen != key_len) {
				printf("BAD Cypher key len for tunnel %s\n", name);
				goto err;
			}

			newkey = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_CIPHER_KEY_VAL);
			if (unlikely(newkey == NULL))
				goto err;
			tunnel->cipherdata->key = newkey;

			ptr = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_AUTH_KEY_LEN);
			if (unlikely(ptr == NULL))
				goto err;
			key_len = strtoul(ptr, NULL, 0);
			if (tunnel->authdata->keylen != key_len) {
				printf("BAD auth key len for tunnel %s\n", name);
				goto err;
			}

			newkey = get_attributes(tunnelp, BAD_CAST TUNNEL_CFG_AUTH_KEY_VAL);
			if (unlikely(newkey == NULL))
				goto err;
			tunnel->authdata->key = newkey;
		}
	}

	printf("new tunnel: %s\n", name);
	printf("	IP:   0x%x--->0x%x\n", tunnel->src_ip, tunnel->dest_ip);
	printf("	MAC: ");
	for(i=0; i<6; i++)
	{
		printf("%02x", tunnel->src_mac[i]);
		if(i<5)
			printf(":");
	}
	printf("--->");
	for(i=0; i<6; i++)
	{
		printf("%x", tunnel->dest_mac[i]);
		if(i<5)
			printf(":");
		else
			printf("\n");
	}

	return 0;
err:
	printf("parse error for tunnel:%s\n", name);
	free(tunnel);
	if(newkey)
		free(newkey);
	return -EINVAL;
}

int tunnel_parse_cfgfile(const char *cfg_file)
{
	xmlErrorPtr xep;
	xmlDocPtr doc;
	xmlNodePtr cur;
	struct tunnel_info *new_tunnel = NULL;
	int ret = 0;
	int i = 0;;

	xmlInitParser();
	LIBXML_TEST_VERSION;
	xmlSetStructuredErrorFunc(&xep, tunnel_cfg_parse_error);
	xmlKeepBlanksDefault(0);

	doc = xmlParseFile(cfg_file);
	if (unlikely(doc == NULL)) {
		error(0, 0, "%s:%hu:%s() xmlParseFile(%s)",
			__FILE__, __LINE__, __func__, cfg_file);
		goto _err;
	}

	tunnel_cfg_root_node = xmlDocGetRootElement(doc);
	cur = tunnel_cfg_root_node;
	if (unlikely(cur == NULL)) {
		error(0, 0, "%s:%hu:%s() xml file(%s) empty",
			__FILE__, __LINE__, __func__, cfg_file);
		goto _err;
	}

	if (unlikely(!is_node(cur, BAD_CAST TUNNEL_CFG_ROOT_NODE))) {
		error(0, 0, "%s:%hu:%s() xml file(%s) does not"
			"have %s node", __FILE__, __LINE__, __func__,
			cfg_file, TUNNEL_CFG_ROOT_NODE);
		goto _err;
	}

	/* Then update the specified configurations */
	cur = tunnel_cfg_root_node->xmlChildrenNode;
	for_all_sibling_nodes(cur) {
		if (unlikely(!is_node(cur, BAD_CAST TUNNEL_CFG_NODE)))
			continue;
		new_tunnel = malloc(sizeof(struct tunnel_info));
		memset(new_tunnel, 0, sizeof(struct tunnel_info));
		ret = parse_tunnel(cur, new_tunnel);
		if (ret) {
			error(0, 0, "parse tunnel error\n");
			goto _err;
		}
		app_conf.tunnel_list[i++] = new_tunnel;
	}

	return 0;
_err:
	xmlFreeDoc(doc);
	while ( i >= 0 )
		free(app_conf.tunnel_list[i--]);
	if(new_tunnel)
		free(new_tunnel);
	return -1;
}
