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
#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <readline.h>  /* libedit */
#include <error.h>
#include <unistd.h>
#include <usdpaa/compat.h>
#include <getopt.h>

#define ctrl_dtls_dev_file "/dev/fsl-capwap-ctrl-dtls"
#define data_dtls_dev_file "/dev/fsl-capwap-data-dtls"
#define ctrl_n_dtls_dev_file "/dev/fsl-capwap-ctrl-n-dtls"
#define data_n_dtls_dev_file "/dev/fsl-capwap-data-n-dtls"

int fd_ctrl_dtls = -1;
int fd_ctrl_n_dtls = -1;
int fd_data_dtls = -1;
int fd_data_n_dtls = -1;

#define max(a,b) ( ((a)>(b)) ? (a):(b) )

#define MAX_FRAME_SIZE 2048
#define MIN_FRAME_SIZE 64

const char capwap_prompt[] = "capwap-tunnel> ";

struct thread_args{
	int is_silent;
	int is_reflector;
	int stats[4];
	int quit;
};

void dump_hex(uint8_t *data, uint32_t count)
{
	uint32_t i;

	for (i = 0; i < count; i++) {
		if(!(i%16))
			printf("\n%04x  ", i);
		else if(!(i%8))
			printf(" ");
		printf("%02x ", *data++);
	}
	printf("\n");
}

void rcv_thread(void *args)
{
	char rcv_packet[MAX_FRAME_SIZE];
	fd_set readset;
	int len;
	int max_fd;
	int ret;
	struct thread_args *t_args = args;

	/* listen DTLS and Non-DTLS port */
	while(!t_args->quit) {
		FD_ZERO(&readset);
		FD_SET(fd_ctrl_dtls, &readset);
		FD_SET(fd_ctrl_n_dtls, &readset);
		FD_SET(fd_data_dtls, &readset);
		FD_SET(fd_data_n_dtls, &readset);
		max_fd = max(fd_ctrl_dtls, fd_ctrl_n_dtls);
		max_fd = max(max_fd, fd_data_dtls);
		max_fd = max(max_fd, fd_data_n_dtls);
		ret = select(max_fd + 1, &readset, NULL, NULL, NULL);
		if(ret < 0) {
			printf("poll fd error\n");
			exit(1);
		}
		if(FD_ISSET(fd_ctrl_dtls, &readset) ) {
			do {
				len = read(fd_ctrl_dtls,  rcv_packet, sizeof(rcv_packet));
				if(len > 0) {
				       if (t_args->is_reflector) {
					       write(fd_ctrl_dtls, rcv_packet, len);
					       t_args->stats[0]++;
					       continue;
				       }
				       if (!t_args->is_silent)
						printf("rcv %d ctrl-dtls-packets length=%d\n", t_args->stats[0], len);
				       t_args->stats[0]++;
				}
			}while(len > 0);
		}
		if(FD_ISSET(fd_ctrl_n_dtls, &readset) ) {
			do {
				len = read(fd_ctrl_n_dtls,  rcv_packet, sizeof(rcv_packet));
				if(len > 0) {
				       if (t_args->is_reflector) {
					       write(fd_ctrl_n_dtls, rcv_packet, len);
					       t_args->stats[2]++;
					       continue;
				       }
					if (!t_args->is_silent)
						printf("rcv %d ctrl-n-dtls-packets length=%d\n", t_args->stats[2], len);
					t_args->stats[2]++;
				}
			}while(len > 0);
		}
		if(FD_ISSET(fd_data_dtls, &readset) ) {
			do {
				len = read(fd_data_dtls,  rcv_packet, sizeof(rcv_packet));
				if(len > 0) {
				       if (t_args->is_reflector) {
					       write(fd_data_dtls, rcv_packet, len);
					       t_args->stats[1]++;
					       continue;
				       }
					if (!t_args->is_silent)
						printf("rcv %d data-dtls-packets length=%d\n",  t_args->stats[1], len);
					t_args->stats[1]++;
				}
			}while(len > 0);
		}
		if(FD_ISSET(fd_data_n_dtls, &readset) ) {
			do {
				len = read(fd_data_n_dtls,  rcv_packet, sizeof(rcv_packet));
				if(len > 0 ) {
				       if (t_args->is_reflector) {
					       write(fd_data_n_dtls, rcv_packet, len);
					       t_args->stats[3]++;
					       continue;
				       }
					if (!t_args->is_silent)
						printf("rcv %d data-n-dtls-packets length=%d\n", t_args->stats[3], len);
					t_args->stats[3]++;
				}
			}while(len > 0);
		}
	}
	pthread_exit(NULL);
}
void print_help(void)
{
	printf("Available commands: send getstat q\n");
	printf("send <tunnel> <count> <length>		send packets to tunnel\n");
	printf("     <tunnel>: control-dtls-tunnel, control-n-dtls-tunnel, data-dtls-tunnel, data-n-dtls-tunnel\n");
	printf("     <count>: the integer number for the count of frames to be send\n");
	printf("     <length>: the length of frames to be sent\n");
	printf("getstat		Get the statistic number for received packets\n");
	printf("q		Quit\n");
}
void help(void)
{
	printf("Usage: fsltunnel <option>\n");
	printf("	-h	print help\n");
	printf("	-r	reflector mode, when receive a new packets from a tunnel, then send it back to this tunnel\n");
	printf("	-s	silent mode, when receive a new packets, only statistic it and don't print anyinfo\n");
}

int main(int argc, char *argv[])
{
	int ret;
	int i, cli_argc;
	pthread_t thread_id;
	int count, length;
	char *cli, **cli_argv;
	uint8_t frame[MAX_FRAME_SIZE];
	struct thread_args t_args;
	int f;
	static const struct option options[] = {
		{ .name = "help", .val = 'h' },
		{ .name = "reflector", .val = 'r' },
		{ .name = "silent", .val = 's' },
		{ 0 }
	};

	memset(&t_args, 0, sizeof(struct thread_args));
	while ((f = getopt_long(argc, argv, "hrs", options, NULL)) != EOF)
		switch(f) {
		case 'h':
			help();
			return 0;
		case 'r':
			printf("Running in reflector mode\n");
			t_args.is_reflector = 1;
			break;
		case 's':
			printf("Running in silent mode\n");
			t_args.is_silent = 1;
			break;
		default:
			fprintf(stderr, "Unknown option '%c'\n", f);
			help();
			return 1;
		}

	for (i = 0; i < MAX_FRAME_SIZE; i++)
		frame[i] = i % 256;

	fd_ctrl_dtls = open(ctrl_dtls_dev_file, O_RDWR);
	if (fd_ctrl_dtls < 0) {
		printf("open tunnel device error\n");
		return 1;
	}
	fd_ctrl_n_dtls = open(ctrl_n_dtls_dev_file, O_RDWR);
	if (fd_ctrl_n_dtls < 0) {
		printf("open tunnel device error\n");
		return 1;
	}
	fd_data_dtls = open(data_dtls_dev_file, O_RDWR);
	if (fd_data_dtls < 0) {
		printf("open tunnel device error\n");
		return 1;
	}
	fd_data_n_dtls = open(data_n_dtls_dev_file, O_RDWR);
	if (fd_data_n_dtls < 0) {
		printf("open tunnel device error\n");
		return 1;
	}
	ret = pthread_create(&thread_id,NULL,(void *)rcv_thread, (void *)&t_args);
	if (ret != 0) {
		printf("create receive thread error\n");
		return 1;
	}

	/* Run the CLI loop */
	while (1) {
		/* Get CLI input */
		cli = readline(capwap_prompt);
		if (unlikely((cli == NULL) || strncmp(cli, "q", 1) == 0))
			break;
		if (cli[0] == 0) {
			free(cli);
			continue;
		}

		cli_argv = history_tokenize(cli);
		if (unlikely(cli_argv == NULL)) {
			fprintf(stderr, "Out of memory while parsing: %s\n", cli);
			free(cli);
			continue;
		}
		for (cli_argc = 0; cli_argv[cli_argc] != NULL; cli_argc++);

		if (strcmp(cli_argv[0], "send") == 0) {
			if(cli_argc != 4) {
				printf("command error!\n");
				print_help();
				goto next_loop;
			}
			count = atoi(cli_argv[2]);
			length = atoi(cli_argv[3]);
			if (length < MIN_FRAME_SIZE || length > MAX_FRAME_SIZE) {
				printf("length max between %d-%d\n", MIN_FRAME_SIZE, MAX_FRAME_SIZE);
				goto next_loop;
			}
			if (strcmp(cli_argv[1], "control-dtls-tunnel") == 0) {
				for (i = 0; i < count; i++)
					write(fd_ctrl_dtls, frame, length);
				add_history(cli);
			} else if (strcmp(cli_argv[1], "control-n-dtls-tunnel") == 0) {
				for (i = 0; i < count; i++)
					write(fd_ctrl_n_dtls, frame, length);
				add_history(cli);
			} else if (strcmp(cli_argv[1], "data-dtls-tunnel") == 0) {
				for (i = 0; i < count; i++)
					write(fd_data_dtls, frame, length);
				add_history(cli);
			} else if (strcmp(cli_argv[1], "data-n-dtls-tunnel") == 0) {
				for (i = 0; i < count; i++)
					write(fd_data_n_dtls, frame, length);
				add_history(cli);
			} else {
				printf("Wrong tunnel name\n");
				print_help();
			}
		} else if(strcmp(cli_argv[0], "getstat") == 0) {
			printf("Rx packets: control-dtls-tunnel:	%d\n", t_args.stats[0]);
			printf("            control-n-dtls-tunnel:	%d\n", t_args.stats[2]);
			printf("            data-dtls-tunnel:		%d\n", t_args.stats[1]);
			printf("            data-n-dtls-tunnel:		%d\n", t_args.stats[3]);
			add_history(cli);
		} else
			print_help();
next_loop:
		for (cli_argc = 0; cli_argv[cli_argc] != NULL; cli_argc++)
			free(cli_argv[cli_argc]);
		free(cli_argv);
		free(cli);
	}
	t_args.quit = 1;
	pthread_cancel(thread_id);
	pthread_join(thread_id, NULL);
	close(fd_ctrl_dtls);
	close(fd_ctrl_n_dtls);
	close(fd_data_dtls);
	close(fd_data_n_dtls);
	return 0;
}
