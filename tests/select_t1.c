/*
 * Copyright © 2013-2023 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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
#include <sys/time.h>
#include <signal.h>

void usage()
{
	printf(
"Usage: select_t1 [option] <address>\n"
"\t-v\t\tShow test desription\n"
"\t-h\t\tThis message\n"
);
	exit(1);
}

void describe()
{
	printf(
"Select timeout regression:\n"
" - read select on the socket and wait 10seconds. Verify that it is indeed 10seconds\n"
);
	exit(1);
}

#define BIND_PORT 4242

#define READ_TIMEOUT 10


int t1()
{
	int s;
	struct sockaddr_in addr;
	int val = 1;
	int n;
	fd_set readfds;
	struct timeval to, st,dt,et;

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

	gettimeofday(&st, 0);
	n = select(s+1, &readfds, 0, 0, &to);
	if (n < 0) {
		printf("select errno: %m\n");
		goto out;
	}	
	gettimeofday(&et, 0);
	timersub(&et, &st, &dt);
	if (abs(dt.tv_sec - READ_TIMEOUT) > 1) {
		printf("select does not honor timeout: delta: %d\n", 
			abs(dt.tv_sec - READ_TIMEOUT));
		goto out;
	}
	else {	
		printf("select timeout OK\n");
	}

	close(s);
	return 0;
out:
	close(s);
	return 1;
}

void oops()
{
	printf("Test did not complete in expected time\n");
	exit(1);	
}

int main(int argc, char **argv)
{
	int op;
	int status;
	
	while ((op = getopt(argc, argv, "hv")) != -1) {
		switch (op) {
			case 'v':
				describe();
				break;
			case 'h':
			default:
				usage();
		}

	}
	signal(SIGALRM, oops);
	alarm(2*READ_TIMEOUT);
	status = t1();

	printf("exit status: %d\n", status);
	return status;
}
