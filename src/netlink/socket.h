/*
 * netlink/socket.h		Netlink Socket
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_SOCKET_H_
#define NETLINK_SOCKET_H_

#include <netlink/types.h>
#include <netlink/handlers.h>

#ifdef __cplusplus
extern "C" {
#endif

extern struct nl_handle *	nl_handle_alloc(void);
extern struct nl_handle *	nl_handle_alloc_cb(struct nl_cb *);
extern void			nl_handle_destroy(struct nl_handle *);

extern uint32_t			nl_socket_get_local_port(struct nl_handle *);
extern void			nl_socket_set_local_port(struct nl_handle *,
							 uint32_t);

extern int			nl_socket_add_membership(struct nl_handle *,
							 int);
extern int			nl_socket_drop_membership(struct nl_handle *,
							  int);
extern void			nl_join_groups(struct nl_handle *, int);

extern uint32_t			nl_socket_get_peer_port(struct nl_handle *);
extern void			nl_socket_set_peer_port(struct nl_handle *,
							uint32_t);

extern struct nl_cb *		nl_socket_get_cb(struct nl_handle *);
extern void			nl_socket_set_cb(struct nl_handle *,
						 struct nl_cb *);
extern int			nl_socket_modify_cb(struct nl_handle *,
						    enum nl_cb_type,
						    enum nl_cb_kind,
						    nl_recvmsg_msg_cb_t,
						    void *);

extern int			nl_set_buffer_size(struct nl_handle *,
						   int, int);
extern int			nl_set_passcred(struct nl_handle *, int);
extern int			nl_socket_recv_pktinfo(struct nl_handle *, int);

extern void			nl_disable_sequence_check(struct nl_handle *);
extern unsigned int		nl_socket_use_seq(struct nl_handle *);

extern int			nl_socket_get_fd(struct nl_handle *);
extern int			nl_socket_set_nonblocking(struct nl_handle *);
extern void			nl_socket_enable_msg_peek(struct nl_handle *);
extern void			nl_socket_disable_msg_peek(struct nl_handle *);

#ifdef __cplusplus
}
#endif

#endif
