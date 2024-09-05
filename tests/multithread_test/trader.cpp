/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2013-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
** Build command: g++ -lpthread trader.cpp -o trader
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
#include <errno.h>

using namespace std;

#define NUM_PAIR_OF_THREADS 2
#define IF_ADDRESS "1.1.1.19"
#define UC_SERVER_ADDRESS "1.1.1.18"
#define MC_ADDRESS "224.0.1.2"
#define UC_SERVER_PORT 15222
#define MC_LOCAL_PORT 15111
#define UC_LOCAL_PORT 15333
#define MC_BUFFLEN 200
#define UC_BUFFLEN 12
#define MIN_UC_BUFFLEN 10
#define RECV_PACKETS_AMOUNT 300000
#define MAX_PARAM_LENGTH 20
#define MAX_THREADS_PAIRS 50
#define KEEP_ALIVE_INTERVAL 20


char if_address[MAX_PARAM_LENGTH] = "NO IF ADDRESS!!!";
char uc_server_address[MAX_PARAM_LENGTH] = "NO UC SERV ADDRESS!";
int num_pair_of_threads = NUM_PAIR_OF_THREADS;
uint64_t recv_packets_amount = RECV_PACKETS_AMOUNT;
char mc_address[MAX_PARAM_LENGTH] = MC_ADDRESS;
uint16_t mc_local_port = MC_LOCAL_PORT;
uint16_t uc_server_port = UC_SERVER_PORT;
uint16_t uc_local_port = UC_LOCAL_PORT;
int mc_bufflen = MC_BUFFLEN;
int uc_bufflen = UC_BUFFLEN;
int keep_alive_interval = KEEP_ALIVE_INTERVAL;


struct ThreadsPair
{
	int mc_fd;
	int uc_fd;
};

ThreadsPair fd_list[MAX_THREADS_PAIRS];
struct timeval tv_order_start, tv_order_end;
pthread_spinlock_t uc_spinlock_arr[MAX_THREADS_PAIRS];

void usage(void)
{
	printf("Usage:\n");
	printf("\t-l\t<MANDATORY! local interface ip address for mc and uc>\n");
	printf("\t-ua\t<MANDATORY! uc server address>\n");
	printf("\t[-nt]\t<optional num pair of threads. default 2>\n");
	printf("\t[-n]\t<optional num of received mc packets before printing. default 300000>\n");
	printf("\t[-m]\t<optional mc address. default - 224.0.1.2>\n");
	printf("\t[-pm]\t<optional mc local port. default 15111>\n");
	printf("\t[-up]\t<optional uc server port. default 15222>\n");
	printf("\t[-lp]\t<optional local uc port. default 15333>\n");
	printf("\t[-sm]\t<optional mc massage payload size. default 200>\n");
	printf("\t[-su]\t<optional uc massage payload size. MIN value = 10. default 12>\n");
	printf("\t[-ka]\t<optional keep alive interval, i.e. time in usec between keep alive packets. default 20 usec>\n");
}


int prepare_mc_socket(int sock_num)
{
	struct sockaddr_in localSock;
	struct ip_mreq group;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		printf("Opening MC datagram socket num = %d error", sock_num);
		exit(1);
	}
	else
	{
		printf("Opening MC datagram socket num = %d....OK.\n", sock_num);
	}

	/* Enable SO_REUSEADDR to allow multiple instances of this */
	/* application to receive copies of the multicast datagrams. */
	int reuse = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
	{
		printf("Setting SO_REUSEADDR for MC datagram socket num = %d error!!!", sock_num);
		close(fd);
		exit(1);
	}
	else
		printf("Setting SO_REUSEADDR on MC socket num = %d...OK.\n", sock_num);

	/* Bind to the proper port number with the IP address */
	/* specified as INADDR_ANY. */
	memset((char *)&localSock, 0, sizeof(localSock));
	localSock.sin_family = AF_INET;
	localSock.sin_addr.s_addr = INADDR_ANY;
	localSock.sin_port = htons(mc_local_port);
	if(bind(fd, (struct sockaddr*)&localSock, sizeof(struct sockaddr)))
	{
		printf("Binding MC datagram socket num = %d error", sock_num);
		close(fd);
		exit(1);
	}
	else
	{
		printf("Binding MC datagram socket num = %d...OK.\n", sock_num);
	}

	/* Join the multicast group on the local 1.1.1.19 */
	/* interface. Note that this IP_ADD_MEMBERSHIP option must be */
	/* called for each local interface over which the multicast */
	/* datagrams are to be received. */
	group.imr_multiaddr.s_addr = inet_addr(mc_address);
	group.imr_interface.s_addr = inet_addr(if_address);
	if(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0)
	{
		printf("Adding multicast group for socket num = %d error", sock_num);
		close(fd);
		exit(1);
	}
	else
	{
		printf("Adding multicast group for socket num = %d...OK.\n", sock_num);
	}

	return fd;
}


int prepare_uc_socket(int sock_num)
{
	struct sockaddr_in localSock;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		perror("Opening datagram socket error");
		exit(1);
	}
	printf("Opening datagram uc socket fd=%d....OK.\n", fd);
	memset((char *) &localSock, 0, sizeof(localSock));
	localSock.sin_family = AF_INET;
	localSock.sin_addr.s_addr = inet_addr(if_address);
	localSock.sin_port = htons(uc_local_port+sock_num-1);

	struct timeval tv_keep_alive_interval;
	tv_keep_alive_interval.tv_sec = 0;
	tv_keep_alive_interval.tv_usec = keep_alive_interval;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv_keep_alive_interval, sizeof(struct timeval));

	if(bind(fd, (struct sockaddr*)&localSock, sizeof(struct sockaddr)))
	{
		perror("Binding datagram uc socket error");
		close(fd);
		exit(1);
	}
	printf("Binding datagram uc socket num %d....OK.\n", sock_num);

	return fd;
}


void * uc_func(void * num)
{
	struct sockaddr_in servaddr;
	char buf[uc_bufflen], ka[] = "KA";
	int ret;
	int thread_num = (long int)num;

	uint64_t delta_usec;

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_port        = htons(uc_server_port);
	if (inet_aton(uc_server_address, &(servaddr.sin_addr)) <= 0)
	{
		printf("ERROR: Invalid IP address.\n");
		exit(1);
	}
	int serveraddrlen = sizeof(servaddr);

/*
	printf("Connecting uc socket..\n");
	if(connect(fd_list[UC_SOCKET], (struct sockaddr *) &servaddr, sizeof(struct sockaddr)))
	{
		printf("error connecting uc socket");
		close(fd_list[UC_SOCKET]);
		exit(1);
	}
*/

	while(1)
	{
		/* Timeout on recvfrom using setsockopt */
		ret = recvfrom(fd_list[thread_num].uc_fd, buf, uc_bufflen, 0, (struct sockaddr *) &servaddr, (socklen_t *)&serveraddrlen);
		if (ret < 0)
		{
			if (errno == EAGAIN){	// meaning that Timeout occured
				//printf("Debug: Keep alive timeout occured, sending KA packet\n");
//DDD			pthread_spin_lock(&uc_spinlock_arr[thread_num]);
				ret = sendto(fd_list[thread_num].uc_fd, ka, sizeof(ka), 0, (struct sockaddr *) &servaddr, sizeof(struct sockaddr));
//DDD			pthread_spin_unlock(&uc_spinlock_arr[thread_num]);
				if (ret < 0)
				{
					printf("ERROR on SEND errno = %s\n", strerror(errno));
					printf("errno value = %d\n", errno);
				}
			} else {
				printf("ERROR on SEND errno = %s\n", strerror(errno));
				printf("errno value = %d\n", errno);
			}
		} else {		// packet received
			if (strcmp(buf, "ORD_ACK") == 0) {
				gettimeofday(&tv_order_end, NULL);
				delta_usec = ((tv_order_end.tv_sec - tv_order_start.tv_sec) * 1000000) + (tv_order_end.tv_usec - tv_order_start.tv_usec);
				printf("#### Thread num = %d - ORDER sent and received ####. RTT time = %llu\n", thread_num+1, (long long unsigned int)delta_usec);
			} else if (strcmp(buf, "KA_ACK") == 0) {
				//printf("DEBUG: *** Keep Alive sent and received ***\n");
			} else {
				printf("Internal error! UC packet received, not ORD_ACK or KA_ACK\n");
			}
		}
	}

	close(fd_list[thread_num].uc_fd);
	printf("closed UC socket\n");
	return 0;
}


void * recv_loop(void * num)
{
	int  ret;
	int thread_num = (long int)num;
	char buf[mc_bufflen], order[] = "ORD";
	struct sockaddr_in servaddr;
	uint64_t rx_pkt_count, delta_usec;

	printf("MC Thread number %d entered recv_loop\n", thread_num+1);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_port        = htons(uc_server_port);
	if (inet_aton(uc_server_address, &(servaddr.sin_addr)) <= 0)
	{
		printf("ERROR: Invalid IP address.\n");
		exit(1);
	}

	rx_pkt_count=0;
	struct timeval tv_start, tv_end;
	gettimeofday(&tv_start, NULL);

	while (true)
	{
		ret = recv(fd_list[thread_num].mc_fd, buf, mc_bufflen, 0);
		if(ret == -1)
		{
			printf("ERROR in recv! errno = %s\n", strerror(errno));
		}
		rx_pkt_count++;
		if (rx_pkt_count > recv_packets_amount)
		{
			gettimeofday(&tv_end, NULL);
			delta_usec = ((tv_end.tv_sec - tv_start.tv_sec) * 1000000) + (tv_end.tv_usec - tv_start.tv_usec);
//			printf("MC thread num %d received %llu packets in usec = %llu\n", thread_num+1, (long long unsigned int)recv_packets_amount, (long long unsigned int)delta_usec);
			rx_pkt_count=0;
			gettimeofday(&tv_start, NULL);
		}
		if (strcmp(buf, "QUOTE") == 0) {
//			printf("MC thread number %d got QUOTE, sending order via UC thread... \n", thread_num+1);
			gettimeofday(&tv_order_start, NULL);
//DDD			pthread_spin_lock(&uc_spinlock_arr[thread_num]);
			ret = sendto(fd_list[thread_num].uc_fd, order, sizeof(order), 0, (struct sockaddr *) &servaddr, sizeof(struct sockaddr));
//DDD			pthread_spin_unlock(&uc_spinlock_arr[thread_num]);
			if (ret < 0)
			{
				printf("ERROR on SEND errno = %s\n", strerror(errno));
				printf("errno value = %d\n", errno);
			}
		}
	}

	return 0;
}


int main(int argc, char *argv[])
{
	int i;

	for (i=1; i<argc; i++)
	{
		if (strcmp(argv[i], "-l") == 0) {
			strcpy(if_address, argv[i+1]);
		} else if (strcmp(argv[i], "-ua") == 0) {
			strcpy(uc_server_address, argv[i+1]);
		} else if (strcmp(argv[i], "-nt") == 0) {
			num_pair_of_threads = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-n") == 0) {
			recv_packets_amount = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-m") == 0) {
			strcpy(mc_address, argv[i+1]);
		} else if (strcmp(argv[i], "-pm") == 0) {
			mc_local_port = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-up") == 0) {
			uc_server_port = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-lp") == 0) {
			uc_local_port = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-sm") == 0) {
			mc_bufflen = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-su") == 0) {
			uc_bufflen = atoi(argv[i+1]);
			if (uc_bufflen < MIN_UC_BUFFLEN) {
				uc_bufflen = MIN_UC_BUFFLEN;
			}
		} else if (strcmp(argv[i], "-ka") == 0) {
			keep_alive_interval = atoi(argv[i+1]);
		} else if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "-help") == 0) || (strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "--h") == 0)) {
			usage();
			return 0;
		}
	}

	if ((argc == 1) || (strcmp(if_address, "NO IF ADDRESS!!!") == 0) || (strcmp(uc_server_address, "NO UC SERV ADDRESS!") == 0)) {
		usage();
		return 0;
	}




	for (i=0; i<num_pair_of_threads; i++)
	{
		printf("Opening MC datagram socket %d\n", i+1);
		fd_list[i].mc_fd = prepare_mc_socket(i+1);
		fd_list[i].uc_fd = prepare_uc_socket(i+1);
		pthread_spin_init(&uc_spinlock_arr[i], 0);
	}

	pthread_t mc_thread_arr[num_pair_of_threads];
	pthread_t uc_thread_arr[num_pair_of_threads];
	for (i=0; i<num_pair_of_threads; i++)
	{
		pthread_create(&mc_thread_arr[i], NULL, recv_loop,(void*)i);
		pthread_detach(mc_thread_arr[i]);
		pthread_create(&uc_thread_arr[i], NULL, uc_func, (void*)i);
		pthread_detach(uc_thread_arr[i]);
	}
	pause();

	for (i=0; i< num_pair_of_threads; i++)
	{
		printf("Closing mc socket %d\n", i+1);
		shutdown(fd_list[i].mc_fd, SHUT_RDWR);
		close(fd_list[i].mc_fd);
	}
	printf("Closed all MC sockets\n");

	return 0;
}
