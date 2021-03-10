/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hash.h"
#include "tc.h"
#include "daemon.h"
#include "nl.h"


/**
 * @struct nl_object
 * @brief netlink container
 */
struct nl_object {
	int fd;            /**< the netlink socket file descriptor used for communication */
	int seq;           /**< sequence number of send operation */
	char buf[81920];   /**< buffer for receive data */
};

nl_t nl_create(void)
{
	nl_t nt = NULL;
	int fd = -1;

	nt = (struct nl_object *)malloc(sizeof(*nt));
	if (nt) {
		int sndbuf_size = 32768;
		int rcvbuf_size = 32768;
		struct sockaddr_nl local;

		fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
		if (fd < 0) {
			log_error("Unable to create a netlink socket\n");
			goto err;
		}
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(int))) {
			log_error("Unable to set SO_SNDBUF\n");
			goto err;
		}
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(int))) {
			log_error("Unable to set SO_RCVBUF\n");
			goto err;
		}
		memset(&local, 0, sizeof(local));
		local.nl_family = AF_NETLINK;
		local.nl_groups = 0;
		if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
			log_error("Unable to bind to the netlink socket\n");
			goto err;
		}

		memset(nt, 0, sizeof(*nt));
		nt->fd = fd;
		nt->seq = 0;
	}

	return nt;
err:
	if (fd >= 0) {
		close(fd);
	}
	if (nt) {
		free(nt);
	}
	nt = NULL;

	return NULL;
}

void nl_destroy(nl_t nt)
{
	if (nt) {
		close(nt->fd);
		free(nt);
		nt = NULL;
	}
}

int nl_send(nl_t nt, struct nlmsghdr *nl_msg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;
	int ret = -1;

	nl_msg->nlmsg_seq = nt->seq++;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = nl_msg;
	iov.iov_len = nl_msg->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	log_hexdump((void *)nl_msg, nl_msg->nlmsg_len);
	ret = sendmsg(nt->fd, &msg, 0);
	if (ret < 0) {
		log_error("Failed to send netlink message: %s (%d)\n",
			strerror(errno), errno);
		return ret;
	}

	return ret;
}

int nl_recv(nl_t nt, int (*cb)(struct nlmsghdr *, void *arg), void *arg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;
	int ret = 0;
	int multipart = 0;

	memset(&nladdr, 0, sizeof(nladdr));

	iov.iov_base = nt->buf;
	iov.iov_len = sizeof(nt->buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
		struct nlmsghdr *nl_msg;
		int recv_bytes = 0;

		recv_bytes = recvmsg(nt->fd, &msg, 0);
		if (recv_bytes <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				continue;
			}
			return -1;
		}

		for (nl_msg = (struct nlmsghdr *)nt->buf;
		     NLMSG_OK(nl_msg, (unsigned int)recv_bytes);
		     nl_msg = NLMSG_NEXT(nl_msg, recv_bytes)) {
			if (nl_msg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err_data = NLMSG_DATA(nl_msg);

				if (err_data->error < 0) {
					errno = -err_data->error;
					return -1;
				}
				/* Ack message. */
				return 0;
			}
			/* Multi-part msgs and their trailing DONE message. */
			if (nl_msg->nlmsg_flags & NLM_F_MULTI) {
				if (nl_msg->nlmsg_type == NLMSG_DONE) {
					return 0;
				}
				multipart = 1;
			}
			if (cb) {
				ret = cb(nl_msg, arg);
			}
		}
	} while (multipart || (msg.msg_flags & MSG_TRUNC));

	return ret;
}

void nl_attr_add(struct nlmsghdr *nl_msg, unsigned short type,
		const void *data, unsigned int data_len)
{
	struct rtattr *rta;

	if ((NLMSG_ALIGN(nl_msg->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len))) > NLMSG_BUF) {
		log_error("Message size is: %zu that exceeds limit: %d\n",
				(NLMSG_ALIGN(nl_msg->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(data_len))), NLMSG_BUF);
		return ;
	}
	rta = (struct rtattr *)NLMSG_TAIL(nl_msg);
	rta->rta_len = RTA_LENGTH(data_len);
	rta->rta_type = type;
	if (data && data_len) {
		memcpy(RTA_DATA(rta), data, data_len);
	}
	nl_msg->nlmsg_len = NLMSG_ALIGN(nl_msg->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

struct rtattr *nl_attr_nest_start(struct nlmsghdr *nl_msg, int type)
{
	struct rtattr *nest = NLMSG_TAIL(nl_msg);

	nl_attr_add(nl_msg, type, NULL, 0);

	return nest;
}

int nl_attr_nest_end(struct nlmsghdr *nl_msg, struct rtattr *nest)
{
	nest->rta_len = (uintptr_t)NLMSG_TAIL(nl_msg) - (uintptr_t)nest;

	return nest->rta_len;
}
