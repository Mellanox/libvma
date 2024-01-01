/*
 * Copyright © 2013-2024 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <pthread.h>
#include <getopt.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/wait.h>

#define NOT_IN_USE(a)		{ if (a) {}; }

void usage()
{
	printf(
"Usage: reuse_ud_test [option] <address>\n"
"\t-v\t\tShow test desription\n"
"\t-f\t\tUse fork() instead of threads\n"
"\t-h\t\tThis message\n"
);
	exit(1);
}

void describe()
{
	printf(
"Socket reuse test:\n"
" - create datagram socket\n"
" - receive msg on it\n"
" - close socket\n"
" - repeat\n"
);
	exit(1);
}

#define BIND_PORT 4242

#define MSG_HELLO 0xcafebabe
#define READ_TIMEOUT 30

struct tmsg {
	int m;
} __attribute__ ((packed));

struct sockaddr_in rem_addr;
int status = 0;
int use_fork = 0;

void *client_main(void *arg)
{
	int s;
	struct tmsg msg;
	//struct sockaddr_in addr;
	int ret;

	NOT_IN_USE(arg);

	s = socket(PF_INET, SOCK_DGRAM, 0);
	assert(s >= 0);

	if (connect(s, (struct sockaddr *)&rem_addr, sizeof(rem_addr))) {
		printf("connect failed: %m\n");
		goto out;
	}

	msg.m = MSG_HELLO;

	ret = write(s, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		printf("write failed: %m, len=%d\n", ret);
		goto out;
	}
	
	close(s);	
	return 0;
out:
	close(s);	
	status++;	
	return 0;
}


void *srv_main(void *arg)
{
	int s, ret;
	struct sockaddr_in addr;
	struct tmsg msg;
	int val = 1;
	int n;
	fd_set readfds;
	struct timeval to;

	NOT_IN_USE(arg);

	s = socket(PF_INET, SOCK_DGRAM, 0);
	assert(s >= 0);


	addr.sin_family = AF_INET;
	addr.sin_port	= htons(BIND_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;
	
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))) {
		printf("setsockopt failed: %m\n");
		goto out;
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind failed: %m\n");
		goto out;
	}

	FD_ZERO(&readfds);
	to.tv_sec = READ_TIMEOUT;
	to.tv_usec = 0;
	FD_SET(s, &readfds);

	n = select(s+1, &readfds, 0, 0, &to);
	if (n <= 0) {
		printf("select errno or timeout\n");
		goto out;
	}	

	if (!FD_ISSET(s, &readfds)) {
		printf("FD is not ready\n");
		goto out;
	}

	ret = read(s, &msg, sizeof(msg));
	if (ret < 0) {
		printf("read failed: %m\n");
		goto out;
	}

	if (ret != sizeof(msg)) {
		printf("read %d, expected %d\n", ret, (int)sizeof(msg));
		goto out;
	}

	if (msg.m != (int)MSG_HELLO) {
		printf("Bad message 0x%x\n", msg.m);
		goto out;
	}

	close(s);
	return 0;
out:
	status++;
	close(s);
	return 0;
}


int main(int argc, char **argv)
{
	int op;
	pthread_t cl_th, srv_th;
	
	while ((op = getopt(argc, argv, "hvf")) != -1) {
		switch (op) {
			case 'f':
				use_fork = 1;
				break;
			case 'v':
				describe();
				break;
			case 'h':
			default:
				usage();
		}

	}

	if (optind >= argc)
		usage();

	printf("will connect to address: %s\n", argv[optind]);
	rem_addr.sin_family = AF_INET;
	rem_addr.sin_port	= htons(BIND_PORT);
	if (!inet_aton(argv[optind], &rem_addr.sin_addr)) {
		printf("address is invalid!!!\n");
		return 1;
	}

	if (!use_fork) {
		pthread_create(&srv_th, 0, srv_main, 0);
		sleep(1);
		pthread_create(&cl_th, 0, client_main, 0);

		pthread_join(cl_th, 0);
		pthread_join(srv_th, 0);
	}
	else {
		pid_t cl_pid, srv_pid;
		int stat;

		srv_pid = fork();
		if(srv_pid == 0) {
			srv_main(0);
			exit(status);
		}
		sleep(1);
		cl_pid = fork();
		if(cl_pid == 0) {
			client_main(0);
			exit(status);
		}
		waitpid(cl_pid, &stat, 0);
		status += WEXITSTATUS(stat);
		waitpid(srv_pid, &stat, 0);
		status += WEXITSTATUS(stat);
	}

	printf("exit status: %d\n", status);
	return status;
}
