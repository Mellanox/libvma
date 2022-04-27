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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>	/* for clock_gettime */
#include <arpa/inet.h>

#include "tcp_wnd_test.h"

/*  gcc -lrt tcp_wnd_test_server.c -o server */
/*  ./server -i 9.9.9.4 -p 5000 -s 1000000 -t 10 -m 500 -M 30000 -c 122 */

int main(int argc, char* argv[])
{
	int option = 0, sleeptimeusec = 1000000, windowtimesec = 10, minwndsize = 500, maxwndsize = 30000, clientmsgsize = 122, rcvwnd = 1450;
	int port  = 0, serverIp = 0;
	char *pServerIp = NULL;
	int socketfd = 0, clientfd = 0, clientsize = 0, readsize = 0;
	unsigned char buffer[BUFFER_SIZE] = {0};
	struct sockaddr_in server, client;
	int optval; /* flag value for setsockopt */
	struct timespec start, end;
	long long diff = 0;

	if (2 > argc) {
		printf("Wrong parameters!!!\n");
		exit(1);
	}

	opterr = 0;
	while (EOF != (option = getopt(argc, argv, "i:p:s:t:m:M:c:h")) ) {
		switch(option) {
			case 'i': {
				pServerIp = optarg;
				serverIp = inet_addr(optarg);
				break;
			}
			case 'p': {
				port = atoi(optarg);
				break;
			}
			case 's': {
				if(atoi(optarg)) {
					sleeptimeusec = atoi(optarg);
				}
				break;
			}
			case 't': {
				if(atoi(optarg)) {
					windowtimesec = atoi(optarg);
				}
				break;
			}
			case 'm': {
				if(atoi(optarg)) {
					minwndsize = atoi(optarg);
				}
				break;
			}
			case 'M': {
				if(atoi(optarg)) {
					maxwndsize = atoi(optarg);
				}
				break;
			}
			case 'c': {
				if(atoi(optarg)) {
					clientmsgsize = atoi(optarg);
				}
				if((MIN_MESSAGE_SIZE > clientmsgsize) || (MAX_MESSAGE_SIZE < clientmsgsize)) {
					printf("Message size should be: %d >= message size >= %d\n",MIN_MESSAGE_SIZE, MAX_MESSAGE_SIZE);
					exit(1);
				}
				break;
			}
			case 'h': {
				printf("-i: Server IP\n");
				printf("-p: Server port\n");
				printf("-s: Sleep time interval [usec]\n");
				printf("-t: Update receive window size every # seconds");
				printf("-m: Minimal receive window size [bytes]\n");
				printf("-M: Maximum receive window size [bytes]\n");
				printf("-c: Client message size [message integrity validation]. Should be: %d > message size > %d\n", MIN_MESSAGE_SIZE, MAX_MESSAGE_SIZE);
				printf("\nExample:  ./server -i 9.9.9.4 -p 5000 -s 1000000 -t 10 -m 500 -M 30000 -c 122\n");
				exit(0);
				break;
			}
			default : {
				printf("%c - Incorrect option!!!\n", option);
				exit(1);
				break;
			}
		}
	}

	printf("Server IP: %s [atoi:%x]\n", pServerIp, serverIp);
	printf("Server Port: %d\n", port);
	printf("Sleep time interval [usec]: %d\n", sleeptimeusec);
	printf("Window update time interval [sec]: %d\n", windowtimesec);
	printf("Minimum receive window size [bytes]: %d\n", minwndsize);
	printf("Maximum receive window size [bytes]: %d\n", maxwndsize);
	printf("Client message size [bytes]: %d\n", clientmsgsize);

	/*Create a socket*/
	socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (0 > socketfd) {
		printf("ERROR opening socket!\n");
		exit(1);
	}
	printf("Socket: OK\n");

	optval = 1;
	setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR,(const void *)&optval , sizeof(int));

	/* Built the server Internet address */
	bzero(&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	inet_pton(AF_INET, pServerIp, &server.sin_addr);

	if (0 != bind(socketfd, (struct sockaddr*) &server, sizeof(server))) {
		printf("ERROR on binding!\n");
		exit(1);
	}
	printf("Bind: OK\n");

	if (0 > listen(socketfd, 6)) {
		printf("ERROR on listen!\n");
		exit(1);
	}
	printf("Listen: OK\n");

	clientsize = sizeof(struct sockaddr_in);

	clientfd = accept(socketfd, ( struct sockaddr*)&client, (socklen_t*)&clientsize);
	if (0 > clientfd) {
		printf("ERROR on accept!\n");
		exit(1);
	}
	printf("Connection accepted: OK [clientfd:%d]\n", clientfd);

	/* Set receive window size to 30k */
	setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF,(const void *)&maxwndsize, sizeof(maxwndsize));
	setsockopt(clientfd, SOL_SOCKET, SO_RCVBUF,(const void *)&maxwndsize, sizeof(maxwndsize));
	rcvwnd = maxwndsize;
	clock_gettime(CLOCK_MONOTONIC, &start);	/* mark start time */

	while (1) {
		readsize = recvfrom(clientfd, buffer, (rand() % sizeof(buffer)), 0, (struct sockaddr*)&client, (socklen_t*)&client);
		if (0 < readsize) {
			printf("readsize: %d\n", readsize);
		}
		else {
			printf("Something went wrong with recvfrom()! %s\n", strerror(errno));
		}

		clock_gettime(CLOCK_MONOTONIC, &end);	/* mark the end time */
		diff = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec)/1000000000;
		if (diff > windowtimesec) {
			rcvwnd = rcvwnd == minwndsize ? maxwndsize : minwndsize;
			printf("Setsockopt: [SO_RCVBUF] window size:%d\n", rcvwnd);
			setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF,(const void *)&rcvwnd , sizeof(rcvwnd));
			setsockopt(clientfd, SOL_SOCKET, SO_RCVBUF,(const void *)&rcvwnd , sizeof(rcvwnd));
			clock_gettime(CLOCK_MONOTONIC, &start);	/* mark start time */
		}

		if (0 < readsize) {
			/* Buffer validation */
			static unsigned int counter = 0;
			int i;
			  /* message integrity validation */
			for(i=0; i<readsize; ++i, ++counter){
				counter %= clientmsgsize;
				if ((counter + 1) != buffer[i]) {
					printf("Error on receive!!!\n");
					printf("buffer[0]=%d\n", buffer[0]);
					printf("buffer[i=%d]=%d, counter= %d\n",i, buffer[i], counter);
					printf("buffer[readsize - 1]=%d\n", buffer[readsize - 1]);
					for(i =0;i<readsize;++i){
					      printf("[%d]=%d, ",i, buffer[i]);
					}
					exit(0);
				}
			}
		}

		usleep(sleeptimeusec);
	}

	if(0 != close(socketfd)) {
		printf("ERROR - close socket!\n");
		exit(1);
	}

	return 0;
}
