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

#ifndef TOOLS_DAEMON_NL_H_
#define TOOLS_DAEMON_NL_H_

#include <linux/rtnetlink.h>
#include <linux/netlink.h>


/* The nl_t opaque data type
 */
typedef struct nl_object* nl_t;

#define NLMSG_BUF	(16384)
#define NLMSG_TAIL(nl_msg) \
	((struct rtattr *) (((char *) (nl_msg)) + NLMSG_ALIGN((nl_msg)->nlmsg_len)))

struct nl_req {
	struct nlmsghdr hdr;
	struct tcmsg msg;
	char buf[NLMSG_BUF];
};


/**
 * Initialize a netlink object for communicating with the kernel.
 *
 * @return
 *     the newly allocated netlink object. Must be freed with nl_destory.
 */
nl_t nl_create(void);

/**
 * Destroy up a netlink socket.
 *
 * @param nt
 *     The netlink object.
 *
 * @return
 *     @a none
 */
void nl_destroy(nl_t nt);

/**
 * Send a message to the kernel on the netlink socket.
 *
 * @param nl_t nt
 *   The netlink object used for communication.
 * @param nl_msg
 *   The netlink message send to the kernel.
 *
 * @return
 *   the number of sent bytes on success, -1 otherwise.
 */
int nl_send(nl_t nt, struct nlmsghdr *nl_msg);

/**
 * Receive a message from the kernel on the netlink socket.
 *
 * @param nl_t nt
 *   The netlink object used for communication.
 * @param cb
 *   The callback function to call for each netlink message received.
 * @param arg
 *   Custom arguments for the callback.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int nl_recv(nl_t nt, int (*cb)(struct nlmsghdr *, void *arg), void *arg);

/**
 * Append a netlink attribute to a message.
 *
 * @param nl_msg
 *   The netlink message to parse, received from the kernel.
 * @param type
 *   The type of attribute to append.
 * @param data
 *   The data to append.
 * @param data_len
 *   The length of the data to append.
 *
 * @return
 *     @a none
 */
void nl_attr_add(struct nlmsghdr *nl_msg, unsigned short type,
		const void *data, unsigned int data_len);

struct rtattr *nl_attr_nest_start(struct nlmsghdr *nl_msg, int type);

int nl_attr_nest_end(struct nlmsghdr *nl_msg, struct rtattr *nest);

#endif /* TOOLS_DAEMON_NL_H_ */
