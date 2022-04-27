/*
 * Copyright © 2014-2022 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <netdb.h>
#include <sys/select.h>
#include <mellanox/vma_extra.h>

#include "types.h"

extern struct config_t config;

int client_management(int *mngSocket);
int send_data(int testSock, int mngSock);

int client_main(){
	int                     rc;
	int                     result          = -1;
	int                     testSock        = INVALID_SOCKET;
	int                     mngSock         = INVALID_SOCKET;
	struct sockaddr_in      serverAddr;
	
	printf("Enter Function client_main\n");
	
	rc = client_management(&mngSock);
	CHECK_VALUE("client_management", rc, 0, goto cleanup);
	
	/* open client socket */
	testSock = socket(AF_INET, SOCK_STREAM, 0);  
	CHECK_NOT_EQUAL("socket", testSock, INVALID_SOCKET, goto cleanup);
	
	/* Prepare server information (family, port and address) */
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(config.port);
	serverAddr.sin_addr.s_addr = inet_addr(config.sip);

	/* Sync other side is listen*/
	rc = sync_side(mngSock, 0);
	CHECK_VALUE("sync_side", rc, 0, goto cleanup);
	
	rc = connect(testSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
	CHECK_VALUE("connect", rc, 0, goto cleanup);
	
	rc = send_data(testSock, mngSock);
	CHECK_VALUE("send_data", rc, 0, goto cleanup);
	
	/* sync for termination */
	rc = sync_side(mngSock, 0);
	CHECK_VALUE("sync_side", rc, 0, goto cleanup);
	
	result = 0;
 cleanup:
	if(testSock != INVALID_SOCKET){
		close(testSock);
		CHECK_VALUE("close", rc, 0, result = -1);
	}
	if(mngSock != INVALID_SOCKET){
		close(mngSock);
		CHECK_VALUE("close", rc, 0, result = -1);
	}
	return result;
}


int client_management(
                      int            *mngSocket){
	int                     rc;
	int                     result = -1;
	struct sockaddr_in      servAddr;
	struct hostent          *server;
	
	printf("Enter Function client_management\n");
	
	/* Generate a socket */
	*mngSocket = socket(AF_INET, SOCK_STREAM, 0);
	CHECK_NOT_EQUAL("socket", *mngSocket, INVALID_SOCKET, goto cleanup);
	
	server = gethostbyname(config.mngip);
	CHECK_NOT_EQUAL("gethostbyname", server, NULL, goto cleanup);
	
	bzero((char *) &servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr(config.mngip);
	servAddr.sin_port = htons(config.port + 15);
	
	rc = connect(*mngSocket,(struct sockaddr *) &servAddr,sizeof(servAddr));
	CHECK_VALUE("connect", rc, 0, goto cleanup);
	
	printf("Client Connects to host %s pport %d\n",config.mngip, config.port + 15);

	result = 0;
 cleanup:
	return result;
}

/**
 *Send data using TCP socket.
 *
 * Params:
 *		*sock		: File descriptor represent test socket
 *		mngSock		: File descriptor used for management
= * Returns:
 *		These calls return 0, or -1 if an error occurred.
 **/
int send_data(int testSock, int mngSock){

	int	result	= -1;
	int	rc;
	char* message;
	
	printf("Enter Function send_data\n");

	rc = sync_side(mngSock, 0);
	CHECK_VALUE("sync_side", rc, 0, goto cleanup);
	
	if (config.callbackReturn == RECV) {
		message = "recv";
	}
	else if (config.callbackReturn == HOLD){
		message = "hold";
	}
	else {
		message = "drop";
	}
	
	rc = send(testSock, message, 20, 0);
	CHECK_NOT_EQUAL("send", rc, -1, goto cleanup);
	CHECK_NOT_EQUAL("send", rc, 0, goto cleanup);
	
	result = 0;
cleanup:
	return result;
}

