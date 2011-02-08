/**
 \file ipc_send.c
 \brief Basic IPfwd Config Tool
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

#include "compat.h"
#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "ipc_send.h"
#include "ip/ip_appconf.h"
#include <sys/stat.h>
#include <mqueue.h>
#include <errno.h>

#ifdef DEBUG
#define APP_LOG             printf
#else
#define APP_LOG(a, ...)
#endif

unsigned int g_mndtr_param;
error_t g_parse_error;
mqd_t mq_fd_wr, mq_fd_rd;
struct sigevent notification;
volatile uint32_t response_flag;

static error_t parse_opt(int key, char *arg, struct argp_state *state);
static error_t parse_route_add_opt(int key, char *arg,
				   struct argp_state *state);
static error_t parse_arp_add_opt(int key, char *arg, struct argp_state *state);
static error_t parse_framecnt_edit_opt(int key, char *arg,
					struct argp_state *state);
static struct argp route_add_argp = {
	route_add_options, parse_route_add_opt, NULL, NULL, NULL, NULL, NULL };

static struct argp route_del_argp = {
	route_del_options, parse_route_add_opt, NULL, NULL, NULL, NULL, NULL };

static struct argp arp_add_argp = {
	arp_add_options, parse_arp_add_opt, NULL, NULL, NULL, NULL, NULL };

static struct argp arp_del_argp = {
	arp_del_options, parse_arp_add_opt, NULL, NULL, NULL, NULL, NULL };

static struct argp framecnt_argp = {
	framecnt_edit_options, parse_framecnt_edit_opt, NULL, NULL, NULL, NULL,
	NULL };

static struct argp_option options[] = {
	{"routeadd", 'B', "TYPE", 0, "adding a route", 0},
	{"routedel", 'C', "TYPE", 0, "deleting a route", 0},
	{"arpadd", 'G', "TYPE", 0, "adding a arp entry", 0},
	{"arpdel", 'H', "TYPE", 0, "deleting a arp entry", 0},
	{"framecnt", 'N', "TYPE", 0, "edit number of frames", 0},
	{"Start/ Go", 'O', "TYPE", 0,
	 "Start the processing of packets", 0},
	{0, 0, 0, 0, 0, 0}
};

/*
   The ARGP structure itself.
*/

static struct argp argp = {
	options, parse_opt, NULL, NULL, NULL, NULL, NULL };

/**
 \brief Sends data from the saInfo structure to the message queue.
 \param[in] saInfo Pointer to the structure that needs to be sent
 to the message queue
 \return none
 */
void send_to_mq(struct lwe_ctrl_op_info *saInfo)
{
	int ret;
	struct lwe_ctrl_op_info *ip_info;

	saInfo->state = LWE_CTRL_CMD_STATE_BUSY;
	ip_info = (struct lwe_ctrl_op_info *)malloc
			(sizeof(struct lwe_ctrl_op_info));
	memset(ip_info, 0, sizeof(struct lwe_ctrl_op_info));
	memcpy(ip_info, saInfo,
	       sizeof(struct lwe_ctrl_op_info));
	/* Send message to message queue */
	ret = mq_send(mq_fd_wr, (const char *)ip_info, sizeof(struct lwe_ctrl_op_info), 10);
	if (ret != 0) {
		printf("%s : Error in sending mesage on MQ\n", __FILE__);
	}
	while (response_flag == 0);
	free(ip_info);
}
/**
 \brief Processes the Route Add/ Delete Request
 \param[in] argc Number of arguments
 \param[in] argv Arguments
 \param[in] type Message Type for the CP request - Route Add or delete
 \return none
 */
void lwe_ip_add_del_command(int argc, char **argv, char *type)
{
	unsigned int i = 0;
	struct lwe_ctrl_op_info route_info;
	unsigned int mndtr_param_map[] = { LWE_CTRL_ROUTE_ADD_MDTR_PARAM_MAP,
		LWE_CTRL_ROUTE_DEL_MDTR_PARAM_MAP
	};
	struct argp *route_argp[] = { &route_add_argp, &route_del_argp };

	/*
	 ** Initializing the route info structure
	 */
	memset(&route_info, 0, sizeof(route_info));
	route_info.state = LWE_CTRL_CMD_STATE_IDLE;
	route_info.msg_type = (unsigned int)type;
	route_info.result = LWE_CTRL_RSLT_FAILURE;

	g_mndtr_param = 0;
	g_parse_error = 0;

	/* Where the magic happens */
	argp_parse(route_argp
		   [route_info.msg_type - LWE_CTRL_CMD_TYPE_ROUTE_ADD], argc,
		   argv, 0, 0, &route_info);

	if (g_parse_error != 0)
		return;

	/*
	 ** If all the mandatory parameters for the operation are present,
	 ** send the data to message queue
	 */
	if ((g_mndtr_param &
	     mndtr_param_map[route_info.msg_type -
			     LWE_CTRL_CMD_TYPE_ROUTE_ADD]) ==
	    mndtr_param_map[route_info.msg_type - LWE_CTRL_CMD_TYPE_ROUTE_ADD])
		goto copy;

	/*
	 ** Check for the mandatory parameter which is misisng
	 */
	for (i = 0; i < LWE_CTRL_PARAM_MAX_IP_BIT_NO; i++) {
		if (((mndtr_param_map
		      [route_info.msg_type -
		       LWE_CTRL_CMD_TYPE_ROUTE_ADD] & (1 << i)) != 0)
		    && ((g_mndtr_param & (1 << i)) == 0)) {
			printf
			    ("Route Entry Operation failed as mandatory parameters missing; --%s or -%c\n",
			     route_add_options[i].name,
			     route_add_options[i].key);
			return;
		}
	}			/* end of for (i = 0; i < LWE_CTRL_PARAM_MAX_B .... */

copy:
	send_to_mq(&route_info);

	return;
}

/**
 \brief Processes the ARP Add/ Delete Request
 \param[in] argc Number of arguments
 \param[in] argv Arguments
 \param[in] type Message Type for the CP request - ARP Add or delete
 \return none
 */
void lwe_arp_add_del_command(int argc, char **argv, char *type)
{
	unsigned int i = 0;
	struct lwe_ctrl_op_info route_info;
	unsigned int mndtr_param_map[] = { LWE_CTRL_ARP_ADD_MDTR_PARAM_MAP,
		LWE_CTRL_ARP_DEL_MDTR_PARAM_MAP
	};
	struct argp *route_argp[] = { &arp_add_argp, &arp_del_argp };

	APP_LOG("\r\nlwe_arp_add_del_command: Enter");
	/*
	 ** Initializing the route info structure
	 */
	memset(&route_info, 0, sizeof(route_info));
	route_info.state = LWE_CTRL_CMD_STATE_IDLE;
	route_info.msg_type = (unsigned int)type;
	route_info.result = LWE_CTRL_RSLT_FAILURE;

	g_mndtr_param = 0;

	if (route_info.msg_type == LWE_CTRL_CMD_TYPE_ARP_ADD) {
		route_info.ip_info.replace_entry = 0;
	}

	/* Where the magic happens */
	argp_parse(route_argp[route_info.msg_type - LWE_CTRL_CMD_TYPE_ARP_ADD],
		   argc, argv, 0, 0, &route_info);

	/*
	 ** If all the mandatory parameters for the operation are present,
	 ** send the data to message queue
	 */
	if ((g_mndtr_param &
	     mndtr_param_map[route_info.msg_type -
			     LWE_CTRL_CMD_TYPE_ARP_ADD]) ==
	    mndtr_param_map[route_info.msg_type - LWE_CTRL_CMD_TYPE_ARP_ADD])
		goto copy;

	/*
	 ** Check for the mandatory parameter which is misisng
	 */
	for (i = 0; i < LWE_CTRL_PARAM_ARP_MAX_BIT_NO; i++) {
		if (((mndtr_param_map
		      [route_info.msg_type -
		       LWE_CTRL_CMD_TYPE_ARP_ADD] & (1 << i)) != 0)
		    && ((g_mndtr_param & (1 << i)) == 0)) {
			printf
			    ("ARP Entry Operation failed as mandatory parameters missing; --%s or -%c\n",
			     arp_add_options[i].name, arp_add_options[i].key);
			return;
		}
	}			/* end of for (i = 0; i < LWE_CTRL_PARAM_MAX_B .... */

copy:
	send_to_mq(&route_info);

	APP_LOG("\r\nlwe_arp_add_del_command: Exit");
	return;
}

/**
 \brief Processes the Edit Frame count Request
 \param[in] argc Number of arguments
 \param[in] argv Arguments
 \param[in] type Message Type for the CP request - Edit Frame Count
 \return none
 */
void lwe_ip_edit_frame_cnt_command(int argc, char **argv, char *type)
{
	struct lwe_ctrl_op_info route_info;
	struct argp *route_argp[] = { &framecnt_argp };

	/*
	 ** Initializing the route info structure
	 */
	memset(&route_info, 0, sizeof(route_info));
	route_info.state = LWE_CTRL_CMD_STATE_IDLE;
	route_info.msg_type = (unsigned int)type;
	route_info.result = LWE_CTRL_RSLT_FAILURE;

	/* Where the magic happens */
	argp_parse(route_argp
		   [route_info.msg_type - LWE_CTRL_CMD_TYPE_FRAMECNT_EDIT], argc,
		   argv, 0, 0, &route_info);

	send_to_mq(&route_info);

	return;
}

/**
 \brief Defines actions for parsing the ipfwd command options - add/ delete;
	it is called for each option parsed
 \param[in] key For each option that is parsed, parser is called with a value of
		key from that option's key field in the option vector
 \param[in] arg If key is an option, arg is its given value.
 \param[in] state state points to a struct argp_state, containing pointer to sa_info structure
 \return 0 for success, ARGP_ERR_UNKNOWN if the value of key is not handled by this parser function
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct lwe_ctrl_op_info *sa_info = state->input;

	switch (key) {
		/* Request for Route Entry Addition */
	case 'B':
		sa_info->msg_type = LWE_CTRL_CMD_TYPE_ROUTE_ADD;
		APP_LOG
		    ("\n::FILE: %s : LINE: %d :IN PARSE_OPT::ADD OPTION SELECTED",
		     __FILE__, __LINE__);
		break;

		/* Request for route Entry Deletion */
	case 'C':
		sa_info->msg_type = LWE_CTRL_CMD_TYPE_ROUTE_DEL;
		APP_LOG
		    ("\nFILE: %s : LINE: %d :IN PARSE_OPT::DELETE OPTION SELECTED",
		     __FILE__, __LINE__);
		break;

	case 'G':
		sa_info->msg_type = LWE_CTRL_CMD_TYPE_ARP_ADD;
		APP_LOG
		    ("\nFILE: %s : LINE: %d :IN PARSE_OPT::ARP ADD OPTION SELECTED",
		     __FILE__, __LINE__);
		break;

	case 'H':
		sa_info->msg_type = LWE_CTRL_CMD_TYPE_ARP_DEL;
		APP_LOG
		    ("\nFILE: %s : LINE: %d :IN PARSE_OPT::ARP DEL OPTION SELECTED",
		     __FILE__, __LINE__);
		break;

	case 'N':
		sa_info->msg_type = LWE_CTRL_CMD_TYPE_FRAMECNT_EDIT;
		APP_LOG
		    ("\nFILE: %s : LINE: %d :IN PARSE_OPT::FRAME COUNT EDIT OPTION SELECTED",
		     __FILE__, __LINE__);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return ARGP_KEY_END;
}

/**
 \brief Defines actions for parsing the add/ delete command options;
	it is called for each option parsed
 \param[in] key For each option that is parsed, parser is called with a value of
		key from that option's key field in the option vector
 \param[in] arg If key is an option, arg is its given value.
 \param[in] state state points to a struct argp_state, containing pointer to route_info structure
 \return 0 for success, ARGP_ERR_UNKNOWN if the value of key is not handled by this parser function
	ARG_KEY_ERROR if the interface name is too long
 */
static error_t parse_route_add_opt(int key, char *arg, struct argp_state *state)
{
	struct lwe_ctrl_op_info *route_info = state->input;
	struct in_addr in_addr;

	switch (key) {

	case 's':
		inet_aton(arg, &in_addr);
		route_info->ip_info.src_ipaddr = in_addr.s_addr;
		g_mndtr_param |= LWE_CTRL_PARAM_BMASK_SRCIP;
		break;

	case 'd':
		inet_aton(arg, &in_addr);
		route_info->ip_info.dst_ipaddr = in_addr.s_addr;
		g_mndtr_param |= LWE_CTRL_PARAM_BMASK_DESTIP;
		APP_LOG("\nkey = %c; value = %s", key, arg);
		break;

	case 'g':

		inet_aton(arg, &in_addr);
		route_info->ip_info.gw_ipaddr = in_addr.s_addr;
		g_mndtr_param |= LWE_CTRL_PARAM_BMASK_GWIP;
		APP_LOG("\nkey = %c; value = %s", key, arg);
		break;

	case 't':
		/*
		 ** TBD: Not Taking TOS from user right now-
		 ** setting it as 0 in the starting -
		 ** route_info->tos = atoi(arg);
		 */
		if ((atoi(arg) < LWE_CTRL_ROUTE_TOS_MIN) ||
		    (atoi(arg) > LWE_CTRL_ROUTE_TOS_MAX)) {
			printf("Invalid Value \"%s\" for '%c'\n", arg, key);
			g_parse_error = ERANGE;
			return ERANGE;
		}

		g_mndtr_param |= LWE_CTRL_PARAM_BMASK_TOS;
		APP_LOG("\nkey = %c; value = %s", key, arg);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 \brief Defines actions for parsing the add/ delete command options;
	it is called for each option parsed
 \param[in] key For each option that is parsed, parser is called with a value of
		key from that option's key field in the option vector
 \param[in] arg If key is an option, arg is its given value.
 \param[in] state state points to a struct argp_state, containing pointer to route_info structure
 \return 0 for success, ARGP_ERR_UNKNOWN if the value of key is not handled by this parser function
 */
static error_t parse_arp_add_opt(int key, char *arg, struct argp_state *state)
{
	struct lwe_ctrl_op_info *route_info = state->input;
	struct in_addr in_addr;

	switch (key) {

	case 's':
		inet_aton(arg, &in_addr);
		route_info->ip_info.src_ipaddr = in_addr.s_addr;
		g_mndtr_param |= LWE_CTRL_PARAM_BMASK_ARP_IPADDR;
		break;

	case 'm':
		{
			char *pch;
			uint32_t l = 0;
			uint32_t i = 0;
			pch = strtok(arg, ":");
			while (pch != NULL) {
				sscanf(pch, "%x", &l);
				route_info->ip_info.mac_addr[i]
					= (uint8_t)l;
				pch = strtok(NULL, ":");
				i++;
			}
			g_mndtr_param |= LWE_CTRL_PARAM_BMASK_ARP_MACADDR;
			break;
		}

	case 'r':
		if (strcmp(arg, "true") == 0)
			route_info->ip_info.replace_entry = 1;
		else
			route_info->ip_info.replace_entry = 0;
		g_mndtr_param |= LWE_CTRL_PARAM_BMASK_ARP_REPLACE;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 \brief Defines actions for parsing the frame count edit command options;
	it is called for each option parsed
 \param[in] key For each option that is parsed, parser is called with a value of
		key from that option's key field in the option vector
 \param[in] arg If key is an option, arg is its given value.
 \param[in] state state points to a struct argp_state, containing pointer to route_info structure
 \return 0 for success, ARGP_ERR_UNKNOWN if the value of key is not handled by this parser function
 */
static error_t parse_framecnt_edit_opt(int key, char *arg,
					struct argp_state *state)
{
	struct lwe_ctrl_op_info *route_info = state->input;

	switch (key) {

	case 'n':
		route_info->ip_info.frame_cnt = atoi(arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/**
 \brief Receives data from message queue
 \param[in]message queue data structure mqd_t
 \return none
 */
int receive_from_mq(mqd_t mqdes)
{
	ssize_t size;
	struct lwe_ctrl_op_info *ip_info = NULL;
	struct mq_attr attr;
	int ret;
	unsigned int result = LWE_CTRL_RSLT_SUCCESSFULL;

	ip_info = (struct lwe_ctrl_op_info *)malloc(sizeof(struct lwe_ctrl_op_info));
	memset(ip_info, 0, sizeof(struct lwe_ctrl_op_info));
	/* Get attributes of the Receive Message queue */
	ret = mq_getattr(mqdes, &attr);
	if (ret) {
		printf("%s:Error getting attributes\n",
				__FILE__);
	}
	/* Read the message from receive queue */
	size = mq_receive(mqdes, (char *)ip_info, attr.mq_msgsize, 0);
		if (size == -1) {
			printf("%s:Rcv msgque error\n", __FILE__);
			return -1;
		}
	result = ip_info->result;
	if (ip_info->msg_type == LWE_CTRL_CMD_TYPE_ROUTE_ADD) {
		if (result == LWE_CTRL_RSLT_SUCCESSFULL) {
			printf("Route Entry Added successfully\n");

		} else {
			printf("Route Entry Addition failed\n");
		}
	} else if (ip_info->msg_type == LWE_CTRL_CMD_TYPE_ROUTE_DEL) {
		if (result == LWE_CTRL_RSLT_SUCCESSFULL) {
			printf("Route Entry Deleted successfully\n");
		} else {
			printf("Route Entry Deletion failed\n");
		}
	} else if (ip_info->msg_type == LWE_CTRL_CMD_TYPE_ARP_ADD) {
		if (result == LWE_CTRL_RSLT_SUCCESSFULL) {
			printf("ARP Entry Added successfully\n");

		} else {
			printf("ARP Entry Addition failed\n");
		}
	} else if (ip_info->msg_type == LWE_CTRL_CMD_TYPE_ARP_DEL) {
		if (result == LWE_CTRL_RSLT_SUCCESSFULL) {
			printf("ARP Entry Deleted successfully\n");
		} else {
			printf("ARP Entry Deletion failed\n");
		}
	} else if (ip_info->msg_type == LWE_CTRL_CMD_TYPE_FRAMECNT_EDIT) {
		if (result == LWE_CTRL_RSLT_SUCCESSFULL) {
			printf("Frame count edited successfully\n");
		} else {
			printf("Frame count edition failed\n");
		}
	} else if (ip_info->msg_type == LWE_CTRL_CMD_TYPE_GO) {
		if (result == LWE_CTRL_RSLT_SUCCESSFULL) {
			printf("Application Started successfully\n");
		} else {
			printf("Application failed\n");
		}
	}

	response_flag = 1;
	free(ip_info);
	return 0;
}

void mq_handler(union sigval sval)
{
	APP_LOG("mq_handler called %d\n", sval.sival_int);

	receive_from_mq(mq_fd_rd);
	mq_notify(mq_fd_rd, &notification);
}

/**
 \brief The main function. The only function call needed to process
 all command-line options and arguments nicely is argp_parse.
 \param[in] argc
 \param[in] argv
*/
int main(int argc, char **argv)
{
	struct lwe_ctrl_op_info sa_info;
	char *tmp_argv = "-O";
	struct lwe_ctrl_op_info route_info;
	int ret, tmp;

	response_flag = 0;
	/* Opens message queue to write */
	mq_fd_wr = mq_open("/mq_rcv",  O_WRONLY);
	if (mq_fd_wr == -1) {
		printf("SND mq err in opening the msgque errno\n");
		return -1;
	}

	/* Opens message queue to read */
	mq_fd_rd = mq_open("/mq_snd", O_RDONLY);
	if (mq_fd_rd == -1) {
		printf("RX mq err in opening the msgque errno\n");
		return -1;
	}

	notification.sigev_notify = SIGEV_THREAD;
	notification.sigev_notify_function = mq_handler;
	notification.sigev_value.sival_ptr = &mq_fd_rd;
	notification.sigev_notify_attributes = NULL;
	tmp = mq_notify(mq_fd_rd, &notification);
	if (tmp)
		printf("%sError in mq_notify call\n",
				 __FILE__);

	memset(&sa_info, 0, sizeof(struct lwe_ctrl_op_info));

	if (argc == 1) {
		printf("Mandatory Parameter missing\n");
		printf("Try `ipfwd_config --help' for more information\n");
		goto _close;
	}
	if (strcmp(argv[1], tmp_argv) == 0) {
		sa_info.msg_type = LWE_CTRL_CMD_TYPE_GO;
		APP_LOG
		    ("\nFILE:%s :LINE %d:IN MAIN:TYPE PROVIDED FOR GO OPT: %d",
		     __FILE__, __LINE__, sa_info.msg_type);
		/*
		** Initializing the route info structure
		*/
		memset(&route_info, 0, sizeof(route_info));
		route_info.state = LWE_CTRL_CMD_STATE_IDLE;
		route_info.msg_type = (unsigned int)sa_info.msg_type;
		route_info.result = LWE_CTRL_RSLT_FAILURE;

		send_to_mq(&route_info);
		goto _close;
	}

	/* Where the magic happens */
	argp_parse(&argp, argc, argv, 0, 0, &sa_info);

	switch (sa_info.msg_type) {
	case LWE_CTRL_CMD_TYPE_ROUTE_ADD:
		{
			APP_LOG
			    ("\nFILE: %s : LINE %d : IN MAIN : THE TYPE PROVIDED FOR ADD OPTION IS : %d",
			     __FILE__, __LINE__, sa_info.msg_type);
			lwe_ip_add_del_command(argc - 1, &argv[1],
					       (char *)sa_info.msg_type);
		}
		break;

	case LWE_CTRL_CMD_TYPE_ROUTE_DEL:
		{
			APP_LOG
			    ("\nFILE: %s : LINE %d : IN MAIN : THE TYPE PROVIDED FOR DELETE OPTION IS : %d",
			     __FILE__, __LINE__, sa_info.msg_type);
			lwe_ip_add_del_command(argc - 1, &argv[1],
					       (char *)sa_info.msg_type);
		}
		break;

	case LWE_CTRL_CMD_TYPE_ARP_ADD:
		{
			APP_LOG
			    ("\nFILE: %s : LINE %d : IN MAIN : THE TYPE PROVIDED FOR ADD OPTION IS : %d",
			     __FILE__, __LINE__, sa_info.msg_type);
			lwe_arp_add_del_command(argc - 1, &argv[1],
						(char *)sa_info.msg_type);
		}
		break;

	case LWE_CTRL_CMD_TYPE_ARP_DEL:
		{
			APP_LOG
			    ("\nFILE: %s : LINE %d : IN MAIN : THE TYPE PROVIDED FOR DELETE OPTION IS : %d",
			     __FILE__, __LINE__, sa_info.msg_type);
			lwe_arp_add_del_command(argc - 1, &argv[1],
						(char *)sa_info.msg_type);
		}
		break;

	case LWE_CTRL_CMD_TYPE_FRAMECNT_EDIT:
		{
			APP_LOG
			    ("\nFILE: %s : LINE %d : IN MAIN : THE TYPE PROVIDED FOR EDIT OPTION IS : %d",
			     __FILE__, __LINE__, sa_info.msg_type);
			lwe_ip_edit_frame_cnt_command(argc - 1, &argv[1],
						(char *)sa_info.msg_type);
		}
		break;

	default:
		APP_LOG("Invalid Option\n");
	}

_close:
	ret = mq_close(mq_fd_wr);
	if (ret) {
		printf("%s: %d error in closing MQ: errno = %d \n",
					__FILE__, __LINE__, errno);
	}
	ret = mq_close(mq_fd_rd);
	if (ret) {
		printf("%s: %d error in closing MQ: errno = %d \n",
					__FILE__, __LINE__, errno);
	}
	return 0;
}
