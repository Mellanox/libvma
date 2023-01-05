/*
 * Copyright © 2016-2023 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

#define MAXEVENTS 64

static int make_socket_non_blocking(int sfd)
{
	int flags, s;

	flags = fcntl(sfd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl(sfd, F_SETFL, flags);
	if (s == -1) {
		perror("fcntl");
		return -1;
	}

	return 0;
}

static int create_and_bind(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;

	memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
	hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
	hints.ai_flags = AI_PASSIVE;     /* All interfaces */

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;

		s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			/* We managed to bind successfully! */
			break;
		}

		close(sfd);
	}

	if (rp == NULL) {
		fprintf(stderr, "Could not bind\n");
		return -1;
	}

	freeaddrinfo(result);

	return sfd;
}

int main(int argc, char *argv[])
{
	int sfd, s, with_vma;
	int efd, efd2;
	struct epoll_event event;
	struct epoll_event *events;

	if (argc != 2) {
		printf("--> Usage: ./2epoll_1socket <with_vma>\n");
		printf("--> With VMA run ./2epoll_1socket 1\n");
		printf("--> With  OS run ./2epoll_1socket 0\n");
		return EXIT_FAILURE;
	}

	with_vma = atoi(argv[1]);
	if (with_vma)
		printf("--> running with VMA\n");
	else
		printf("--> running with OS\n");

	sfd = create_and_bind((char*)"6666");
	if (sfd == -1)
		goto failure;

	printf("--> create socket %d\n", sfd);

	s = make_socket_non_blocking(sfd);
	if (s == -1)
		goto failure;

	printf("--> set socket %d non blocking\n", sfd);

	s = listen(sfd, SOMAXCONN);
	if (s == -1) {
		perror("--> listen");
		goto failure;
	}

	efd = epoll_create1(0);
	if (efd == -1) {
		perror("--> epoll_create");
		goto failure;
	}

	printf("--> created epoll %d\n",efd);

	efd2 = epoll_create1(0);
	if (efd2 == -1) {
		perror("--> epoll_create");
		goto failure;
	}

	printf("--> created epoll %d\n",efd2);

	event.data.fd = sfd;
	event.events = EPOLLIN | EPOLLET;

	s = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
	if (s == -1) {
		perror("--> epoll_ctl 1");
		goto failure;
	}

	printf("--> socket %d was registered to epoll %d\n", sfd, efd);

	s = epoll_ctl(efd2, EPOLL_CTL_ADD, sfd, &event);
	if (with_vma) {
		if (s == -1) {
			if (errno == ENOMEM) {
				printf("--> socket %d was already registered to epoll %d, cant register to another epfd %d, errno = %d\n", sfd, efd, efd2, errno);
				printf("--> SUCCESS\n");
				return EXIT_SUCCESS;
			} else {
				printf("--> socket %d was already registered to epoll %d, cant register to another epfd %d, errno should be set to ENOMEM, errno = %d\n", sfd, efd, efd2, errno);
				goto failure;
			}
		} else {
			printf("--> epoll_ctl didnot return with error, VMA support only 1 epfd for each socket\n", sfd, efd, efd2, errno);
			goto failure;
		}
	} else {
		if (s == -1) {
			printf("--> epoll_ctl return with error, errno = %d\n", errno);
			goto failure;
		}
	}

	printf("--> socket %d was registered to epoll %d\n", sfd, efd);
	printf("--> SUCCESS\n");
	return EXIT_SUCCESS;

failure:
	printf("--> FAILURE\n");
	return EXIT_FAILURE;
}
