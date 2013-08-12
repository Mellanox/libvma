/*
 * netlink/route/neighbour.h	Neighbours
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_NEIGHBOUR_H_
#define NETLINK_NEIGHBOUR_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/addr.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rtnl_neigh;

/* neighbour object allocation/freeage */
extern struct rtnl_neigh *	rtnl_neigh_alloc(void);
extern void			rtnl_neigh_put(struct rtnl_neigh *);

/* neighbour cache management */
extern struct nl_cache *	rtnl_neigh_alloc_cache(struct nl_handle *);
extern struct rtnl_neigh *	rtnl_neigh_get(struct nl_cache *, int,
					       struct nl_addr *);

/* Neigbour state translations */
extern char *			rtnl_neigh_state2str(int, char *, size_t);
extern int			rtnl_neigh_str2state(const char *);

/* Neighbour flags translations */
extern char *			rtnl_neigh_flags2str(int, char *, size_t);
extern int			rtnl_neigh_str2flag(const char *);

/* Neighbour Addition */
extern int			rtnl_neigh_add(struct nl_handle *,
					       struct rtnl_neigh *, int);
extern struct nl_msg *		rtnl_neigh_build_add_request(struct rtnl_neigh *, int);

/* Neighbour Modification */
extern int			rtnl_neigh_change(struct nl_handle *,
						  struct rtnl_neigh *, int);
extern struct nl_msg *		rtnl_neigh_build_change_request(struct rtnl_neigh *, int);

/* Neighbour Deletion */
extern int			rtnl_neigh_delete(struct nl_handle *,
						  struct rtnl_neigh *, int);
extern struct nl_msg *		rtnl_neigh_build_delete_request(struct rtnl_neigh *, int);

/* Access functions */
extern void			rtnl_neigh_set_state(struct rtnl_neigh *, int);
extern int			rtnl_neigh_get_state(struct rtnl_neigh *);
extern void			rtnl_neigh_unset_state(struct rtnl_neigh *,
						       int);

extern void			rtnl_neigh_set_flags(struct rtnl_neigh *,
						     unsigned int);
extern void			rtnl_neigh_unset_flags(struct rtnl_neigh *,
						       unsigned int);
extern unsigned int		rtnl_neigh_get_flags(struct rtnl_neigh *);

extern void			rtnl_neigh_set_ifindex(struct rtnl_neigh *,
						       int);
extern int			rtnl_neigh_get_ifindex(struct rtnl_neigh *);

extern void			rtnl_neigh_set_lladdr(struct rtnl_neigh *,
						      struct nl_addr *);
extern struct nl_addr *		rtnl_neigh_get_lladdr(struct rtnl_neigh *);

extern int			rtnl_neigh_set_dst(struct rtnl_neigh *,
						   struct nl_addr *);
extern struct nl_addr *		rtnl_neigh_get_dst(struct rtnl_neigh *);

extern void			rtnl_neigh_set_type(struct rtnl_neigh *, int);
extern int			rtnl_neigh_get_type(struct rtnl_neigh *);

extern void			rtnl_neigh_set_family(struct rtnl_neigh *, int);
extern int			rtnl_neigh_get_family(struct rtnl_neigh *);

#ifdef __cplusplus
}
#endif

#endif
