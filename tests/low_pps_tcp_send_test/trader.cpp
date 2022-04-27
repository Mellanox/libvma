/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
 ** Build command: g++ -lpthread -lrt trader.cpp -o trader
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

#define NUM_PAIR_OF_THREADS 1
#define IF_ADDRESS "1.1.1.19"
#define UC_SERVER_ADDRESS "1.1.1.18"
#define MC_ADDRESS "224.0.1.2"
#define UC_SERVER_PORT 15222
#define MC_LOCAL_PORT 15111
#define UC_LOCAL_PORT 15333
#define MC_BUFFLEN 200
#define UC_BUFFLEN 8
#define MIN_UC_BUFFLEN 10
#define RECV_PACKETS_AMOUNT 300000
#define SEND_PACKETS_AMOUNT 1
#define MAX_PARAM_LENGTH 20
#define MAX_THREADS_PAIRS 50
#define KEEP_ALIVE_INTERVAL 20
#define TCP_DUMMY_SEND_RATE 100
#define TCP_KA_CPU 1
#define MC_CPU 2
#define TCP_RECV_CPU 3


char if_address[MAX_PARAM_LENGTH] = "NO IF ADDRESS!!!";
char uc_server_address[MAX_PARAM_LENGTH] = "NO UC SERV ADDRESS!";
int num_pair_of_threads = NUM_PAIR_OF_THREADS;
uint64_t recv_packets_amount = RECV_PACKETS_AMOUNT;
uint64_t send_packets_amount = SEND_PACKETS_AMOUNT;
char mc_address[MAX_PARAM_LENGTH] = MC_ADDRESS;
uint16_t mc_local_port = MC_LOCAL_PORT;
uint16_t uc_server_port = UC_SERVER_PORT;
uint16_t uc_local_port = UC_LOCAL_PORT;
int mc_bufflen = MC_BUFFLEN;
int uc_bufflen = UC_BUFFLEN;
int keep_alive_interval = KEEP_ALIVE_INTERVAL;
int keep_alive_cpu = TCP_KA_CPU;
int mc_cpu = MC_CPU;
int tcp_recv_cpu = TCP_RECV_CPU;
int tcp_dummy_send_rate = TCP_DUMMY_SEND_RATE;
int disable_ka = 0;
int disable_tcp_recv = 0;


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
	printf("\t-l\t<MANDATORY! local interface ip address for mc and uc (tcp)>\n");
	printf("\t-ua\t<MANDATORY! uc (tcp) server address>\n");
	//printf("\t[-nt]\t<optional num pair of threads. default 1>\n");
	//printf("\t[-n]\t<optional num of received mc packets before printing. default 300000>\n");
	printf("\t[-ns]\t<optional num of tcp send packets before printing. default 1>\n");
	printf("\t[-m]\t<optional mc address. default - 224.0.1.2>\n");
	printf("\t[-pm]\t<optional mc local port. default 15111>\n");
	printf("\t[-up]\t<optional uc server port. default 15222>\n");
	printf("\t[-lp]\t<optional local uc port. default 15333>\n");
	printf("\t[-sm]\t<optional mc massage payload size. default 200>\n");
	printf("\t[-su]\t<optional uc massage payload size. MIN value = 10. default 12>\n");
	printf("\t[-ka]\t<optional keep alive interval, i.e. time in usec between keep alive packets. default 1000000 usec>\n");
	printf("\t[-kac]\t<optional TCP keep alive thread cpu core. default 1>\n");
	printf("\t[-mcc]\t<optional MC recv thread cpu core. default 2>\n");
	printf("\t[-trc]\t<optional TCP recv thread cpu core. default 3>\n");
	printf("\t[-tds]\t<optional TCP dummy send rate, i.e. for each X MC packets, send dummy TCP. default 100>\n");
	printf("\t[-dtr]\t<optional disable TCP recv thread. default 0 (use 1 to disable)>\n");
	printf("\t[-dka]\t<optional disable TCP keep alive thread. default 0 (use 1 to disable)>\n");
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

#include <netinet/tcp.h>
int prepare_tcp_socket(int sock_num)
{
	struct sockaddr_in localSock;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
	{
		perror("Opening tcp socket error");
		exit(1);
	}
	printf("Opening tcp socket fd=%d....OK.\n", fd);
	memset((char *) &localSock, 0, sizeof(localSock));
	localSock.sin_family = AF_INET;
	localSock.sin_addr.s_addr = inet_addr(if_address);
	localSock.sin_port = htons(uc_local_port+sock_num-1);

	int flag = 1;
	if (setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,(char *)&flag,sizeof(flag)) == -1)
	{
		perror("SETSOCKOPT tcp socket error");
		close(fd);
		exit(1);
	}

	if(bind(fd, (struct sockaddr*)&localSock, sizeof(struct sockaddr)))
	{
		perror("Binding tcp socket error");
		close(fd);
		exit(1);
	}

	printf("Binding tcp socket num %d....OK.\n", sock_num);


	struct sockaddr_in remoteSock;
	memset((char *) &remoteSock, 0, sizeof(remoteSock));
	remoteSock.sin_family = AF_INET;
	remoteSock.sin_addr.s_addr = inet_addr(uc_server_address);
	remoteSock.sin_port = htons(uc_server_port);

	if (connect(fd, (struct sockaddr*)&remoteSock, sizeof(struct sockaddr)) != 0) {
		perror("Connect tcp socket error");
		close(fd);
		exit(1);
	}

	printf("Connect tcp socket num %d....OK.\n", sock_num);

	return fd;
}

void * tcp_ka_func(void * num)
{
	int thread_num = (long int)num;
	char ka[] = "KAA";
	int ret;
	while(1)
	{
		if (!fd_list[thread_num].uc_fd) continue;

		ret = send(fd_list[thread_num].uc_fd, ka, sizeof(ka), 0);
		if (ret < 0)
		{
			printf("ERROR on SEND KA errno = %s\n", strerror(errno));
			printf("errno value = %d\n", errno);
		}
		usleep(keep_alive_interval);
	}
	return 0;
}

void * tcp_recv_func(void * num)
{
	struct sockaddr_in servaddr;
	char buf[uc_bufflen], ka[] = "KAA";
	int ret;
	int thread_num = (long int)num;

	uint64_t delta_usec;


	while(1)
	{
		if (!fd_list[thread_num].uc_fd) continue;
		/* Timeout on recvfrom using setsockopt */
		ret = recv(fd_list[thread_num].uc_fd, buf, uc_bufflen, MSG_WAITALL);
		if (ret < 0)
		{
			if (errno == EAGAIN){	// meaning that Timeout occured

				ret = send(fd_list[thread_num].uc_fd, ka, sizeof(ka), 0);

				if (ret < 0)
				{
					printf("ERROR on SEND 1 errno = %s\n", strerror(errno));
					printf("errno value = %d\n", errno);
					for (int i=0; i< num_pair_of_threads; i++)
					{
						close(fd_list[i].uc_fd);
					}
					exit(1);
				}
			} else {
				printf("ERROR on SEND 2 errno = %s\n", strerror(errno));
				printf("errno value = %d\n", errno);
				for (int i=0; i< num_pair_of_threads; i++)
				{
					close(fd_list[i].uc_fd);
				}
				exit(1);
			}
		} else {		// packet received
			if (strcmp(buf, "ORD_ACK") == 0) {
				gettimeofday(&tv_order_end, NULL);
				delta_usec = ((tv_order_end.tv_sec - tv_order_start.tv_sec) * 1000000) + (tv_order_end.tv_usec - tv_order_start.tv_usec);
				//printf("#### Thread num = %d - ORDER sent and received ####. RTT time = %llu\n", thread_num+1, (long long unsigned int)delta_usec);
			} else if (strcmp(buf, "KAA_ACK") == 0) {
				//printf("DEBUG: *** Keep Alive sent and received ***\n");
			} else {
				printf("Internal error! UC packet received, not ORD_ACK or KA_ACK, buf=%s\n", buf);
				for (int i=0; i< num_pair_of_threads; i++)
				{
					close(fd_list[i].uc_fd);
				}
				exit(1);
			}
		}
	}

	return 0;
}

void * recv_loop(void * num)
{
	int  ret;
	int thread_num = (long int)num;
	char buf[mc_bufflen], order[] = "ORD";
	struct sockaddr_in servaddr;
	uint64_t rx_pkt_count, tx_pkt_count, delta_usec;
	int t = 0;
	char ka[] = "KAA";

	printf("MC Thread number %d entered recv_loop\n", thread_num+1);

	int dummy = socket(AF_INET, SOCK_STREAM, 0);
	int flag = 1;
	setsockopt(dummy,IPPROTO_TCP,TCP_NODELAY,(char *)&flag,sizeof(flag));
	struct sockaddr_in remoteSock;
	memset((char *) &remoteSock, 0, sizeof(remoteSock));
	remoteSock.sin_family = AF_INET;
	remoteSock.sin_addr.s_addr = inet_addr(uc_server_address);
	remoteSock.sin_port = htons(uc_server_port);

	connect(dummy, (struct sockaddr*)&remoteSock, sizeof(struct sockaddr));

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_port        = htons(uc_server_port);
	if (inet_aton(uc_server_address, &(servaddr.sin_addr)) <= 0)
	{
		printf("ERROR: Invalid IP address.\n");
		exit(1);
	}

	rx_pkt_count=0;
	tx_pkt_count = 0;

	struct timeval tv_start, tv_end;
	gettimeofday(&tv_start, NULL);

	while (true)
	{
		t++;

		ret = recv(fd_list[thread_num].mc_fd, buf, mc_bufflen, 0);

		if(ret == -1)
		{
			printf("ERROR in recv! errno = %s\n", strerror(errno));
			exit(1);
		}
		/*
		rx_pkt_count++;
		if (rx_pkt_count > recv_packets_amount)
		{
			gettimeofday(&tv_end, NULL);
			delta_usec = ((tv_end.tv_sec - tv_start.tv_sec) * 1000000) + (tv_end.tv_usec - tv_start.tv_usec);
			printf("MC thread num %d received %llu packets in usec = %llu\n", thread_num+1, (long long unsigned int)recv_packets_amount, (long long unsigned int)delta_usec);
			rx_pkt_count=0;
			gettimeofday(&tv_start, NULL);
		}
		 */
		if (strcmp(buf, "QUOTE") == 0) {
			gettimeofday(&tv_order_start, NULL);

			struct timespec ts_start = {0,0}, ts_end = {0,0}, ts_start1 = {0,0}, ts_end1 = {0,0};

			tx_pkt_count++;

			clock_gettime(CLOCK_MONOTONIC, &ts_start);
			ret = send(fd_list[thread_num].uc_fd, order, sizeof(order), 0);
			clock_gettime(CLOCK_MONOTONIC, &ts_end);

			if (tx_pkt_count >= send_packets_amount) {
				tx_pkt_count = 0;
				uint64_t delta_usec = ((ts_end.tv_sec - ts_start.tv_sec) * 1000000000) + (ts_end.tv_nsec - ts_start.tv_nsec);
				printf("MC thread number %d got QUOTE, sending TCP order (send time = %llu nsec)  \n", thread_num+1, (long long unsigned int)delta_usec);
			}
			if (ret < 0)
			{
				printf("ERROR on SEND errno = %s\n", strerror(errno));
				printf("errno value = %d\n", errno);
			}
		} else if (t % tcp_dummy_send_rate == 0){
			//dummy send
			send(fd_list[thread_num].uc_fd, NULL, 1, 0);
		}
	}

	return 0;
}

#include <sched.h>

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
		} else if (strcmp(argv[i], "-ns") == 0) {
			send_packets_amount = atoi(argv[i+1]);
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
		} else if (strcmp(argv[i], "-kac") == 0) {
			keep_alive_cpu = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-mcc") == 0) {
			mc_cpu = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-trc") == 0) {
			tcp_recv_cpu = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-tds") == 0) {
			tcp_dummy_send_rate = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-dka") == 0) {
			disable_ka = atoi(argv[i+1]);
		} else if (strcmp(argv[i], "-dtr") == 0) {
			disable_tcp_recv = atoi(argv[i+1]);
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
		fd_list[i].uc_fd = prepare_tcp_socket(i+1);
		pthread_spin_init(&uc_spinlock_arr[i], 0);
	}

	pthread_t mc_thread_arr[num_pair_of_threads];
	pthread_t tcp_recv_thread_arr[num_pair_of_threads];
	pthread_t tcp_ka_thread_arr[num_pair_of_threads];

	cpu_set_t* cpu_set = NULL;
	cpu_set = CPU_ALLOC(64);
	if (!cpu_set) {
		perror("failed to allocate cpu set");
		return -1;
	}
	size_t cpu_set_size = CPU_ALLOC_SIZE(64);

	for (i=0; i<num_pair_of_threads; i++)
	{
		pthread_create(&mc_thread_arr[i], NULL, recv_loop,(void*)i);
		CPU_ZERO_S(cpu_set_size, cpu_set);
		CPU_SET_S(mc_cpu, cpu_set_size, cpu_set);
		if (pthread_setaffinity_np(mc_thread_arr[i], cpu_set_size, cpu_set)) {
			CPU_FREE(cpu_set);
			perror("failed to SET AFFINITY cpu set");
			return -1;
		}
		printf("attached MC recv thread to cpu = %d\n", mc_cpu);
		pthread_detach(mc_thread_arr[i]);

		if (!disable_tcp_recv) {
			pthread_create(&tcp_recv_thread_arr[i], NULL, tcp_recv_func, (void*)i);
			CPU_ZERO_S(cpu_set_size, cpu_set);
			CPU_SET_S(tcp_recv_cpu, cpu_set_size, cpu_set);
			if (pthread_setaffinity_np(tcp_recv_thread_arr[i], cpu_set_size, cpu_set)) {
				CPU_FREE(cpu_set);
				perror("failed to SET AFFINITY cpu set");
				return -1;
			}
			printf("attached TCP recv thread to cpu = %d\n", tcp_recv_cpu);
			pthread_detach(tcp_recv_thread_arr[i]);
		}

		if (!disable_ka) {
			pthread_create(&tcp_ka_thread_arr[i], NULL, tcp_ka_func, (void*)i);
			CPU_ZERO_S(cpu_set_size, cpu_set);
			CPU_SET_S(keep_alive_cpu, cpu_set_size, cpu_set);
			if (pthread_setaffinity_np(tcp_ka_thread_arr[i], cpu_set_size, cpu_set)) {
				CPU_FREE(cpu_set);
				perror("failed to SET AFFINITY cpu set");
				return -1;
			}
			printf("attached TCP keep alive thread to cpu = %d\n", keep_alive_cpu);
			pthread_detach(tcp_ka_thread_arr[i]);
		}
	}
	pause();

	for (i=0; i< num_pair_of_threads; i++)
	{
		printf("Closing mc socket %d\n", i+1);
		shutdown(fd_list[i].mc_fd, SHUT_RDWR);
		close(fd_list[i].mc_fd);
		shutdown(fd_list[i].uc_fd, SHUT_RDWR);
		close(fd_list[i].uc_fd);
	}
	printf("Closed all MC sockets\n");

	return 0;
}
