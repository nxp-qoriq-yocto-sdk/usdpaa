/* Copyright 2014 Freescale Semiconductor, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <getopt.h>

#include "fsl_capwap_br.h"
#include "fslbr.h"

#define APP_NAME "FSL-Bridge"
#define APP_VERSION "1.0"

static const struct command commands[] = {
	{ 1, "addif", fslbr_add_if_cmd, "<device>\t\tadd interface to bridge" },
	{ 1, "delif", fslbr_del_if_cmd, "<device>\t\tdelete interface from bridge" },
	{ 0, "list", fslbr_list, "show a list of interface in bridge" },
	{ 1, "encrypt", fslbr_set_encrypt, "set bridge encryption state on or off" },
};

void command_helpall(void)
{
	int i;

	for (i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
		printf("\t%-10s\t%s\n", commands[i].name, commands[i].help);
	}
}

static void help(void)
{
	printf("Usage: fslbrctl [commands]\n");
	printf("commands:\n");
	command_helpall();
};

const struct command *command_lookup(const char *cmd)
{
	int i;

	for (i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
		if (!strcmp(cmd, commands[i].name))
			return &commands[i];
	}

	return NULL;
}

int main(int argc, char *const* argv)
{
	const struct command *cmd;
	int f;
	static const struct option options[] = {
		{ .name = "help", .val = 'h' },
		{ .name = "version", .val = 'V' },
		{ 0 }
	};

	while ((f = getopt_long(argc, argv, "Vh", options, NULL)) != EOF)
		switch(f) {
		case 'h':
			help();
			return 0;
		case 'V':
			printf("%s, %s\n", APP_NAME, APP_VERSION);
			return 0;
		default:
			fprintf(stderr, "Unknown option '%c'\n", f);
			goto help;
		}

	if (argc == optind)
		goto help;

	argc -= optind;
	argv += optind;
	if ((cmd = command_lookup(*argv)) == NULL) {
		fprintf(stderr, "never heard of command [%s]\n", argv[1]);
		goto help;
	}

	if (argc < cmd->nargs + 1) {
		printf("Incorrect number of arguments for command\n");
		printf("Usage: brctl %s %s\n", cmd->name, cmd->help);
		return 1;
	}

	return cmd->func(argc, argv);

help:
	help();
	return 1;
}
