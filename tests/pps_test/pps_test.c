/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 258


/**
 * This is a  simple test, designed to measure UDP multicast send/receive rate.
 * Can be used in sender mode or receiver mode.
 *  
 */
int main(int argc, char** argv)
{
	int sock, status;
	socklen_t socklen;
	char buffer[BUFSIZE];
	struct sockaddr_in saddr;
	int count, realcount, i;
	struct timeval tv_before, tv_after;
	double sec;

	if (argc < 3) {
		fprintf(stderr, "Usage: pps_test <ip> <packet_count> [ srv ]\n");
		exit(1);
	}

	// set content of struct saddr and imreq to zero
	memset(&saddr, 0, sizeof(struct sockaddr_in));

	// open a UDP socket
	sock = socket(PF_INET,SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("Error creating socket");
		exit(0);
	}

	// set destination multicast address
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(11111);
	inet_pton(AF_INET, argv[1], &saddr.sin_addr);

	status = bind(sock, (struct sockaddr *) &saddr,
	              sizeof(struct sockaddr_in));

	count = atoi(argv[2]);
	realcount = 0;

	socklen = sizeof(struct sockaddr_in);

	if (status < 0)
		perror("Error binding socket to interface"), exit(0);

	if (argc <= 3) {
		struct in_addr iaddr;

		memset(&iaddr, 0, sizeof(struct in_addr));
		iaddr.s_addr = INADDR_ANY; // use DEFAULT interface

		// Set the outgoing interface to DEFAULT
		setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &iaddr,
		           sizeof(struct in_addr));


		// warm-up
		for (i = 0; i < 5; ++i) {
			status = sendto(sock, buffer, BUFSIZE, 0,
			                (struct sockaddr *) &saddr, socklen);
		}

		gettimeofday(&tv_before, NULL);
		for (i = 0; i < count; ++i) {
			status = sendto(sock, buffer, BUFSIZE, 0,
			                (struct sockaddr *) &saddr, socklen);
			if (status > 0)
				++realcount;
		}
		gettimeofday(&tv_after, NULL);
	}
	else {
		struct ip_mreq imreq;

		imreq.imr_multiaddr.s_addr = inet_addr(argv[1]);
		imreq.imr_interface.s_addr = INADDR_ANY; // use DEFAULT interface

		// JOIN multicast group on default interface
		status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
		                    (const void *)&imreq, sizeof(struct ip_mreq));

		// first packet
		status = recvfrom(sock, buffer, BUFSIZE, 0,
		                (struct sockaddr *) &saddr, &socklen);

		// receive packet from socket
		gettimeofday(&tv_before, NULL);
		for (i = 0; i < count; ++i) {
			status = recvfrom(sock, buffer, BUFSIZE, 0,
			                (struct sockaddr *) &saddr, &socklen);
			if (status > 0)
				++realcount;
		}
		gettimeofday(&tv_after, NULL);
	}

	sec = (tv_after.tv_sec - tv_before.tv_sec) +
	(tv_after.tv_usec - tv_before.tv_usec) / 1000000.0;

	printf("%d packets in %.3f seconds. PPS=%.2f\n", realcount, sec, realcount / sec);

	// close socket
	close(sock);

	return 0;
}
