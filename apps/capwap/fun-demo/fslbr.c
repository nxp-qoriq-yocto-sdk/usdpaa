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
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "fsl_capwap_br.h"
#include <net/if.h>
#include <sys/ioctl.h>

#define fslbr_dev_file "/dev/fsl-br"

static int fslbr_fd = -1;

static int check_fd(void)
{

	if(fslbr_fd < 0)
		fslbr_fd = open(fslbr_dev_file, O_RDWR);
	return (fslbr_fd >= 0) ? 0 : -ENODEV;
}

void fslbr_close(void)
{
	close(fslbr_fd);
}

static int fslbr_add_if(int ifindex)
{
	int ret = check_fd();
	if (ret)
		return ret;
	ret = ioctl(fslbr_fd, FSLBR_IOCTL_IF_ADD, &ifindex);
	return ret;
}

int interface_up_down(const char *interface_name, bool turn_up, bool *orig_is_up)
{
	struct ifreq ifr;
	short flag;
	int s;

	if (strcmp(interface_name,"lo") == 0) {
		printf("You can't control interface lo\n");
		return 0;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = 0;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("cannot open control socket\n");
		return -1;
	}

	if (ioctl(s,SIOCGIFFLAGS,&ifr) < 0) {
		perror("ioctl");
		return -1;
	}

	if (ifr.ifr_flags & IFF_UP) {
		*orig_is_up = true;
		if (!turn_up) {
			flag = ~IFF_UP;
			ifr.ifr_flags &= flag;
			if (ioctl(s,SIOCSIFFLAGS,&ifr) < 0) {
				perror("ioctl");return -1;
			}
		}
	} else {
		*orig_is_up = false;
		if (turn_up) {
			flag = IFF_UP;
			ifr.ifr_flags |= flag;
			if (ioctl(s,SIOCSIFFLAGS,&ifr) < 0) {
				perror("ioctl");return -1;
			}
		}
	}

	return 0;
}

static int fslbr_del_if(int ifindex)
{
	int ret = check_fd();
	if (ret)
		return ret;
	ret = ioctl(fslbr_fd, FSLBR_IOCTL_IF_DEL, &ifindex);
	return ret;
}


int fslbr_add_if_cmd(int argc, char *const* argv)
{
	int ret;
	int ifindex;
	bool if_up;

	argc--;

	while (argc-- > 0) {
		const char *ifname = *++argv;
		ifindex = if_nametoindex(ifname);
		if(ifindex == 0) {
			fprintf(stderr, "interface %s does not exit!\n", ifname);
			continue;
		}

		ret = interface_up_down(ifname, false, &if_up);
		if (ret) {
			fprintf(stderr, "interface %s can't shut down!\n", ifname);
			continue;
		}

		ret = fslbr_add_if(ifindex);

		interface_up_down(ifname, true, &if_up);

		switch(ret) {
		case 0:
			continue;

		case ENODEV:
			fprintf(stderr, "Bridge isn't exist!\n");
			break;

		case EBUSY:
			fprintf(stderr,	"device %s is already a member of a bridge\n", ifname);
			break;

		default:
			fprintf(stderr, "can't add %s to bridge: %s\n",
				ifname, strerror(ret));
		}
		return 1;
	}
	return 0;
}

int fslbr_del_if_cmd(int argc, char *const* argv)
{
	int ret;
	int ifindex;
	bool if_up;

	argc--;

	while (argc-- > 0) {
		const char *ifname = *++argv;
		ifindex = if_nametoindex(ifname);
		if(ifindex == 0) {
			fprintf(stderr, "interface %s does not exit!\n", ifname);
			continue;
		}

		ret = interface_up_down(ifname, false, &if_up);
		if (ret) {
			fprintf(stderr, "interface %s can't shut down!\n", ifname);
			continue;
		}

		ret = fslbr_del_if(ifindex);

		switch(ret) {
		case 0:
			continue;

		case ENODEV:
			fprintf(stderr, "Bridge isn't exist!\n");
			break;

		case EINVAL:
			fprintf(stderr,	"device %s isn't a slave of bridge.\n", ifname);
			break;

		default:
			fprintf(stderr, "can't del %s from bridge: %s\n",
				ifname, strerror(ret));
		}
		return 1;
	}
	return 0;

}

int fslbr_list(int argc, char *const* argv)
{
	int if_list[MAX_IF_COUNT + 2];
	int i, count, status;
	char ifname[IF_NAMESIZE];

	int ret = check_fd();
	if (ret) {
		fprintf(stderr, "Bridge isn't exist!\n");
		return ret;
	}
	ret = ioctl(fslbr_fd, FSLBR_IOCTL_IF_LIST, &if_list);
	if (ret) {
		fprintf(stderr, "Can't get interface list!\n");
		return ret;
	}
	status = if_list[0];
	count = if_list[1];
	if(count < 0 || count > MAX_IF_COUNT) {
		fprintf(stderr, "Get interface count error: %d!\n", count);
		return 1;
	}
	printf("Encrypt: %s\n", status ? "on" : "off");
	printf("There are %d interfaces in the bridge: ", count);
	for(i = 0; i < count; i++)
	{
		if_indextoname(if_list[i + 2], ifname);
		printf("%s ", ifname);
	}
	printf("\n");

	return 0;
}

int fslbr_set_encrypt(int argc, char *const* argv)
{
	int ret;
	int status = -1;

	ret = check_fd();
	if (ret) {
		fprintf(stderr, "Bridge isn't exist!\n");
		return ret;
	}

	argc--;
	while (argc-- > 0) {
		const char *state = *++argv;
		if (!strcmp(state, "on"))
			status = 1;
		else if (!strcmp(state, "off"))
			status = 0;
		else {
			return 1;
			printf("incorrect state, you should set it to 'on' or 'off'");
		}
	}
	if (!status || status == 1) {
		ret = ioctl(fslbr_fd, FSLBR_IOCTL_SET_ENCRYPT, &status);
		if (ret) {
			fprintf(stderr, "set bridge encryption status error!\n");
			return ret;
		}
	}
	fslbr_list(0, NULL);
	return 0;
}
