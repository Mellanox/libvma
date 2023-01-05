/*
 * Copyright © 2014-2023 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include "types.h"

extern struct config_t config;

/****************************************
 * FUNCTION: make_socket_non_blocking   *
 ****************************************/
int make_socket_non_blocking (
                              int        sfd){
  int          flags;
  int          rc;

  printf("Enter Function make_socket_non_blocking\n");

  flags = fcntl (sfd, F_GETFL, 0);
  CHECK_NOT_EQUAL("fcntl F_GETFL", flags, -1, return -1);

  flags |= O_NONBLOCK;

  rc = fcntl (sfd, F_SETFL, flags);
  CHECK_NOT_EQUAL("fcntl F_SETFL", rc, -1, return -1);

  return 0;
}

/****************************************
 * FUNCTION: select_read                *
 ****************************************/
int select_read(
		int		*fd,
		int		sec,
		int          usec){
	int		result = -1;
        int 		retval;
	fd_set		rfds;
        struct timeval	tv;

	printf("Enter Function select_read\n");
	
	/* Watch stdin (Passed fd) to see when it has input. */
	FD_ZERO(&rfds);
	FD_SET(*fd, &rfds);

	/* Wait up to five seconds. */
	tv.tv_sec = sec;
	tv.tv_usec = usec;

	retval = select(*fd + 1, &rfds, NULL, NULL, &tv);
	/* Don't rely on the value of tv now! */
	CHECK_NOT_EQUAL("select", retval, -1, goto cleanup);
	result = (retval)? retval : 0;
	/* If retval 0, No data within specific seconds. */
 cleanup:
	return result;
}

/****************************************
 * FUNCTION: sync_side                  *
 ****************************************/
int sync_side(
              int            sock,
              int            front){
  	int     rc;
	int     result = -1;
	char    data;
	
	printf("Enter Function sync_side\n");
	
	if(front){
	  	rc = send(sock, &data, 1, 0);
		CHECK_NOT_EQUAL("send", rc, 0, goto cleanup);
		
		rc = recv(sock, &data, 1, 0);
		CHECK_NOT_EQUAL("recv", rc, 0, goto cleanup);
	}
	else{
	  	rc = recv(sock, &data, 1, 0);
		CHECK_VALUE("recv", rc, 1, goto cleanup);
		
		rc = send(sock, &data, 1, 0);
		CHECK_NOT_EQUAL("send", rc, 0, goto cleanup);
	}
	result = 0;
 cleanup:
	return result;
}
