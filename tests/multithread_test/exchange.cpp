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

/* 
** Build command: g++ -lpthread exchange.cpp -o exchange
*/

#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>

#define NUM_SOCKETS 2
#define MC_SOCKET 0
#define UC_SOCKET 1
#define NUM_PACKETS 200000
#define IF_ADDRESS "1.1.1.18"
#define UC_SERVER_ADDRESS "1.1.1.19"
#define MC_ADDRESS "224.0.1.2"
#define MC_DEST_PORT 15111
#define UC_LOCAL_PORT 15222
#define UC_SERVER_PORT 15333
#define MC_BUFFLEN 200
#define UC_BUFFLEN 12
#define MIN_UC_BUFFLEN 10
#define SLEEP_TIME_USEC 10
#define MAX_PARAM_LENGTH 20

int fd_list[NUM_SOCKETS];
uint64_t tx_pkt_count, delta_usec_quote;
struct timeval tv_quote_start, tv_quote_end;

char if_address[MAX_PARAM_LENGTH] = "NO IF ADDRESS!!!";
int num_packets = NUM_PACKETS;
char mc_address[MAX_PARAM_LENGTH] = MC_ADDRESS;
uint16_t mc_dest_port = MC_DEST_PORT;
uint16_t uc_local_port = UC_LOCAL_PORT;
int mc_bufflen = MC_BUFFLEN;
int uc_bufflen = UC_BUFFLEN;
uint64_t sleep_time_usec = SLEEP_TIME_USEC;


void usage(void)
{
	printf("Usage:\n");
	printf("\t-l\t<MANDATORY! local interface ip address for mc and uc>\n");
	printf("\t[-n]\t<optional num of mc packets before marking for QUOTE. default 200000>\n");
	printf("\t[-m]\t<optional mc address. default - 224.0.1.2>\n");
	printf("\t[-pm]\t<optional mc destination port. default 15111>\n");
	printf("\t[-lp]\t<optional local uc port. default 15222>\n");
	printf("\t[-sm]\t<optional mc massage payload size. default 200>\n");
	printf("\t[-su]\t<optional uc massage payload size. MIN value = 10. default 12>\n");
	printf("\t[-u]\t<optional sleep time in usec between each mc packet send. default 10usec>\n");
}


int prepare_socket()
{
	struct sockaddr_in groupsock;
	struct in_addr localInterface;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
			perror("Opening datagram socket error");
			exit(1);
	}

	memset(&groupsock, 0, sizeof(groupsock));
	groupsock.sin_family            = AF_INET;
	groupsock.sin_addr.s_addr       = inet_addr(mc_address);
	groupsock.sin_port              = htons(mc_dest_port);

	/* Disable loopback so you do not receive your own datagrams.*/
	char loopch = 0;
	if(setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0)
	{
		perror("Setting IP_MULTICAST_LOOP error");
		close(fd);
		exit(1);
    	}

	/* Set local interface for outbound multicast datagrams. */
	localInterface.s_addr = inet_addr(if_address);
	if(setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0)
	{
		perror("Setting local interface error");
 		exit(1);
	}

	printf("Connecting..\n");
	if(connect(fd, (struct sockaddr *) &groupsock, sizeof(struct sockaddr)))
	{
		perror("connect");
		close(fd);
 		exit(1);
	}

        return fd;
}


void* send_mc_loop(void* num)
{
	int ret;
	char databuf[mc_bufflen];
	char quote[] = "QUOTE";
	uint64_t delta_usec, delta_usec_sleep;

	/* Prepare MC socket */
	printf("Opening datagram MC socket\n");
	fd_list[MC_SOCKET] = prepare_socket();

	// Prepare to start measurements
	tx_pkt_count = 0;
	struct timeval tv_start, tv_sleep_start, tv_sleep_end;
	gettimeofday(&tv_start, NULL);
	gettimeofday(&tv_sleep_start, NULL);
	gettimeofday(&tv_sleep_end, NULL);

	while(true)
	{
		delta_usec_sleep = ((tv_sleep_end.tv_sec - tv_sleep_start.tv_sec) * 1000000) + (tv_sleep_end.tv_usec - tv_sleep_start.tv_usec);
		if (delta_usec_sleep > sleep_time_usec)
		{
			ret = send(fd_list[MC_SOCKET], databuf, mc_bufflen, 0);	// Can use send with UDP socket because called connect() before...
			if (ret < 0)
				printf("ERROR on SEND errno = %s\n", strerror(errno));
			tx_pkt_count++;
			tv_sleep_start = tv_sleep_end;
		}
		else
		{
			gettimeofday(&tv_sleep_end, NULL);
		}


		if ((tx_pkt_count != 0) && (tx_pkt_count % num_packets) == 0) {
			struct timeval tv_now;
			gettimeofday(&tv_now, NULL);
			delta_usec = ((tv_now.tv_sec - tv_start.tv_sec) * 1000000) + (tv_now.tv_usec - tv_start.tv_usec);
			tv_start = tv_now;

			double mps = 1000000 * (tx_pkt_count/(double)delta_usec);
			double bwGbps = mps * mc_bufflen * 8/(1024*1024*1024);
			printf("BW(Gbps)=%6.3f, MPS=%10.0f\n", bwGbps, mps);
			tx_pkt_count = 0;

			gettimeofday(&tv_quote_start, NULL);
			ret = send(fd_list[MC_SOCKET], quote, sizeof(quote), 0);
			if (ret < 0)
				printf("ERROR on SEND errno = %s\n", strerror(errno));
		}
	}

	return 0;
}


void * uc_func(void * num)
{
	struct sockaddr_in localSock, servaddr;
	socklen_t servaddrlen = sizeof(struct sockaddr);
	char buf[uc_bufflen], ord_ack[] = "ORD_ACK", ka_ack[] = "KA_ACK";
	int ret, print = 0;

	fd_list[UC_SOCKET] = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd_list[UC_SOCKET] < 0)
	{
			perror("Opening datagram UC socket error");
			exit(1);
	}
	printf("Opening datagram UC socket....OK.\n");
	memset((char *) &localSock, 0, sizeof(localSock));
	localSock.sin_family = AF_INET;
	localSock.sin_addr.s_addr = inet_addr(if_address);
	localSock.sin_port = htons(uc_local_port);

	if(bind(fd_list[UC_SOCKET], (struct sockaddr*)&localSock, sizeof(struct sockaddr)))
	{
		perror("Binding datagram UC socket error");
		close(fd_list[UC_SOCKET]);
		exit(1);
	}
	else
	{
		printf("Binding datagram UC socket...OK.\n");
	}

	while(1)
	{
		ret = recvfrom(fd_list[UC_SOCKET], buf, uc_bufflen, 0, (struct sockaddr *)&servaddr, &servaddrlen);
		gettimeofday(&tv_quote_end, NULL);
		if (ret < 0)
		{
			printf("ERROR on RECV errno = %s \n", strerror(errno));
			printf("errno value = %d\n", errno);
		}
		else
		{
			if (strcmp(buf, "ORD") == 0)
			{
				ret = sendto(fd_list[UC_SOCKET], ord_ack, sizeof(ord_ack), 0, (struct sockaddr *) &servaddr, sizeof(struct sockaddr));
				if (ret < 0)
				{
					printf("ERROR on SEND UC errno = %s \n", strerror(errno));
					printf("errno value = %d\n", errno);
				}
				print = 1;
			}
			else if (strcmp(buf, "KA") == 0){
				ret = sendto(fd_list[UC_SOCKET], ka_ack, sizeof(ka_ack), 0, (struct sockaddr *) &servaddr, sizeof(struct sockaddr));
				if (ret < 0)
				{
					printf("ERROR on SEND UC errno = %s \n", strerror(errno));
					printf("errno value = %d\n", errno);
				}
			}
			else{
				printf("Internal error: Exchange received UC packet- not ORD or KA\n");
			}

			if (print)
			{
				delta_usec_quote = ((tv_quote_end.tv_sec - tv_quote_start.tv_sec) * 1000000) + (tv_quote_end.tv_usec - tv_quote_start.tv_usec);
				printf("@@@@@@@ QUOTE from port %u RTT in usec = %llu @@@@@@@\n", ntohs(servaddr.sin_port), (long long unsigned int)delta_usec_quote);
				print = 0;
			}
		}
	}

	close(fd_list[UC_SOCKET]);
	printf("closed UC socket\n");
	return 0;
}


int main(int argc, char *argv[])
{
	pthread_t uc_thread;
	int nThreadId = 1, i;

	for (i=1; i<argc; i++)
	{
		if (strcmp(argv[i], "-l") == 0) {
			strcpy(if_address, argv[i+1]);
		} else if (strcmp(argv[i], "-n") == 0) {
			num_packets = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-m") == 0) {
			strcpy(mc_address, argv[i+1]);
		} else if (strcmp(argv[i], "-pm") == 0) {
			mc_dest_port = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-lp") == 0) {
			uc_local_port = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-sm") == 0) {
			mc_bufflen = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-su") == 0) {
			uc_bufflen = atoi(argv[i+1]);
			if (uc_bufflen < MIN_UC_BUFFLEN) {
				uc_bufflen = MIN_UC_BUFFLEN;
			}
		} else if (strcmp(argv[i], "-u") == 0) {
			sleep_time_usec = atoi(argv[i+1]);
		} else if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "-help") == 0) || (strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "--h") == 0)) {
			usage();
			return 0;
		}
	}

	if ((argc == 1) || (strcmp(if_address, "NO IF ADDRESS!!!") == 0)) {
		usage();
		return 0;
	}

	pthread_create(&uc_thread, NULL, uc_func, (void*)nThreadId);

	send_mc_loop(0);

	printf("Going to close MC socket\n");
	close(fd_list[MC_SOCKET]);
	printf("Closed MC socket\n");

	return 0;

}
