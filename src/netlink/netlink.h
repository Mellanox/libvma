/*
 * netlink/netlink.h		Netlink Interface
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_NETLINK_H_
#define NETLINK_NETLINK_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netlink/netlink-compat.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <netlink/types.h>
#include <netlink/handlers.h>
#include <netlink/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int nl_debug;
extern struct nl_dump_params nl_debug_dp;

/* Connection Management */
extern int			nl_connect(struct nl_handle *, int);
extern void			nl_close(struct nl_handle *);

/* Send */
extern int			nl_sendto(struct nl_handle *, void *, size_t);
extern int			nl_sendmsg(struct nl_handle *, struct nl_msg *,
					   struct msghdr *);
extern int			nl_send(struct nl_handle *, struct nl_msg *);
extern int			nl_send_auto_complete(struct nl_handle *,
						      struct nl_msg *);
extern int			nl_send_simple(struct nl_handle *, int, int,
					       void *, size_t);

/* Receive */
extern int			nl_recv(struct nl_handle *,
					struct sockaddr_nl *, unsigned char **,
					struct ucred **);

extern int			nl_recvmsgs(struct nl_handle *, struct nl_cb *);

#define nl_recvmsgs_def(handle) nl_recvmsgs_default(handle)
extern int			nl_recvmsgs_default(struct nl_handle *);

extern int			nl_wait_for_ack(struct nl_handle *);

/* Netlink Family Translations */
extern char *			nl_nlfamily2str(int, char *, size_t);
extern int			nl_str2nlfamily(const char *);

#ifdef __cplusplus
}
#endif

#endif
