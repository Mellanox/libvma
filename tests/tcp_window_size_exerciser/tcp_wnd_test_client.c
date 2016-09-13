/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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
#include <netinet/tcp.h>
#include <fcntl.h>
#include <arpa/inet.h>

/* gcc -lrt  tcp_wnd_test_client.c -o client.o */
/* LD_PRELOAD=libvma.so ./client.o -i 9.9.9.3 -s 9.9.9.4 -p 5000 -m 122 */
/* VMA_TX_BUFS=8192 VMA_RX_BUFS=204800 VMA_TRACELEVEL=3 VMA_STATS_FD_NUM=1024 VMA_RX_POLL=-1 VMA_SELECT_POLL=-1 VMA_SELECT_POLL_OS_RATIO=0 VMA_TCP_3T_RULES=1 VMA_TCP_CTL_THREAD=2 VMA_AVOID_SYS_CALLS_ON_TCP_FD=1  VMA_BUFFER_BATCHING_MODE=0  LD_PRELOAD=libvma.so ./client.o -i 9.9.9.3 -s 9.9.9.4 -p 5000 -m 122 */

#define 	BUFFER_SIZE 		(0x400)

int main( int argc, char* argv[])
{
  int option = 0, msgSize = 0;
  int clientIp = 0, serverPort  = 0, serverIp = 0;
  char *pClientIp = NULL, *pServerIp = NULL;

  if (2 > argc) {
    printf("Wrong parameters!!!\n");
    exit(1);
  }

  printf("\n\n===================================\n");

  opterr = 0;
  while (EOF !=  (option = getopt(argc, argv, "i:p:s:m:h")) ) {
    switch (option) {
      case 'i': {
        pClientIp = optarg;
        clientIp = inet_addr(optarg);
        break;
      }
      case 's': {
        pServerIp = optarg;
        serverIp = inet_addr(optarg);
        break;
      }
      case 'p': {
        serverPort = atoi(optarg);
        break;
      }
      case 'm': {
        msgSize = atoi(optarg);
        break;
      }
      case 'h': {
        printf("-i: Client IP\n");
        printf("-s: Server IP\n");
        printf("-p: Server port\n");
        printf("-m: Client -> Server message size(1024>= X >=4)\n");
        printf("\nExample: ./client.o -i 9.9.9.3 -s 9.9.9.4 -p 5000 -m 122\n");
        printf("===================================\n\n");
        exit(0);
        break;
      }
      default : {
        printf("Incorrect option!!!\n");
        exit(1);
        break;
      }
    }
  }

  /* Client -> Server Message size */
  if (msgSize < 4) {
    msgSize = 4;
  }
  else if (msgSize > BUFFER_SIZE) {
    msgSize = BUFFER_SIZE;
  }

  printf("Client IP: %s [atoi:%x]\n", pClientIp, clientIp);
  printf("Server IP: %s [atoi:%x]\n", pServerIp, serverIp);
  printf("Server Port: %d\n", serverPort);
  printf("Client -> Server message size: %d\n", msgSize);
  printf("===================================\n\n");

  int clientfd = 0;
  char buffer[BUFFER_SIZE] = {0};
  struct sockaddr_in server;
  struct sockaddr_in client;

  /* Init send uffer */
  int i = 1;
  for (; i < BUFFER_SIZE;++i) {
    buffer[i-1] = i;
  }

  /* Create client socket */
  clientfd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (0 > clientfd) {
    printf("ERROR opening socket\n");
    exit(1);
  }
  printf("Client Socket: OK\n");

  /* Built client Internet address */
  bzero( &client, sizeof(client));
  client.sin_family = AF_INET;
  client.sin_port = htons(INADDR_ANY);
    inet_pton( AF_INET, pClientIp, &client.sin_addr);

    if (0 != bind(clientfd, (struct sockaddr*) &client, sizeof(client))) {
    printf("ERROR on binding!\n");
    exit(1);
  }
  printf("Bind: OK\n");

  /* Set server address */
  bzero( &server, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons(serverPort);
  inet_pton( AF_INET, pServerIp, &server.sin_addr);

  /* Connect socket to server */
  if (0 > connect( clientfd, ( struct sockaddr*)&server, sizeof(server))) {
    printf("ERROR on connect\n");
    exit(1);
  }
	printf("Connect: OK\n");

  /* Setsockopt */
  option = 1;
  setsockopt( clientfd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option));

  option = msgSize * 1024;
  setsockopt( clientfd, SOL_SOCKET, SO_SNDBUF, &option, sizeof(option));/* Sets the maximum socket send buffer in bytes */

  fcntl( clientfd, F_SETFL, O_NONBLOCK);

  while (1) {
    int sentsize = 0;
    int rc = 0;

    do{
      rc = write( clientfd, buffer, msgSize);
      if (0 > rc) {
        /* Do nothing */
      }
      else if (msgSize != rc) {
        sentsize = rc;
        while(msgSize > sentsize) {
          rc = write( clientfd, buffer + sentsize, msgSize - sentsize);
          if(rc > 0) {
            sentsize += rc;
          }
        }
      }
    } while (0 > rc);

    usleep(1000);/* sleep for 1 msec */
  }

  if (0 != close(clientfd)) {
    printf("ERROR - close socket!\n");
    exit(1);
  }

  return 0;
}
