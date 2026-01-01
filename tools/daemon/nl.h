/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
