/*
 * netlink/route/route.h	Routes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_ROUTE_H_
#define NETLINK_ROUTE_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/data.h>
#include <netlink/route/nexthop.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rtnl_route;

struct rtnl_rtcacheinfo
{
	uint32_t	rtci_clntref;
	uint32_t	rtci_last_use;
	uint32_t	rtci_expires;
	int32_t		rtci_error;
	uint32_t	rtci_used;
	uint32_t	rtci_id;
	uint32_t	rtci_ts;
	uint32_t	rtci_tsage;
};

extern struct nl_object_ops route_obj_ops;

/* General */
extern struct rtnl_route *	rtnl_route_alloc(void);
extern void			rtnl_route_put(struct rtnl_route *);
extern struct nl_cache *	rtnl_route_alloc_cache(struct nl_handle *);

extern void		rtnl_route_get(struct rtnl_route *);
extern void		rtnl_route_put(struct rtnl_route *);

extern struct nl_msg *rtnl_route_build_add_request(struct rtnl_route *, int);
extern int rtnl_route_add(struct nl_handle *, struct rtnl_route *, int);
extern struct nl_msg *rtnl_route_build_del_request(struct rtnl_route *, int);
extern int rtnl_route_del(struct nl_handle *, struct rtnl_route *, int);

extern void		rtnl_route_set_table(struct rtnl_route *, int);
extern int		rtnl_route_get_table(struct rtnl_route *);
extern void		rtnl_route_set_scope(struct rtnl_route *, int);
extern int		rtnl_route_get_scope(struct rtnl_route *);
extern void		rtnl_route_set_tos(struct rtnl_route *, int);
extern int		rtnl_route_get_tos(struct rtnl_route *);
extern void		rtnl_route_set_realms(struct rtnl_route *, realm_t);
extern realm_t		rtnl_route_get_realms(struct rtnl_route *);
extern void		rtnl_route_set_protocol(struct rtnl_route *, int);
extern int		rtnl_route_get_protocol(struct rtnl_route *);
extern void		rtnl_route_set_prio(struct rtnl_route *, int);
extern int		rtnl_route_get_prio(struct rtnl_route *);
extern void		rtnl_route_set_family(struct rtnl_route *, int);
extern int		rtnl_route_get_family(struct rtnl_route *);
extern void		rtnl_route_set_type(struct rtnl_route *, int);
extern int		rtnl_route_get_type(struct rtnl_route *);
extern void		rtnl_route_set_flags(struct rtnl_route *,
					     unsigned int);
extern void		rtnl_route_unset_flags(struct rtnl_route *,
					       unsigned int);
extern unsigned int	rtnl_route_get_flags(struct rtnl_route *);
extern int		rtnl_route_set_metric(struct rtnl_route *, int,
					      unsigned int);
extern int		rtnl_route_unset_metric(struct rtnl_route *, int);
extern unsigned int	rtnl_route_get_metric(struct rtnl_route *, int);
extern int		rtnl_route_set_dst(struct rtnl_route *,
					   struct nl_addr *);
extern struct nl_addr *	rtnl_route_get_dst(struct rtnl_route *);
extern int		rtnl_route_set_src(struct rtnl_route *,
					   struct nl_addr *);
extern struct nl_addr *	rtnl_route_get_src(struct rtnl_route *);
extern int		rtnl_route_set_gateway(struct rtnl_route *,
					       struct nl_addr *);
extern struct nl_addr *	rtnl_route_get_gateway(struct rtnl_route *);
extern int		rtnl_route_set_pref_src(struct rtnl_route *,
						struct nl_addr *);
extern struct nl_addr *	rtnl_route_get_pref_src(struct rtnl_route *);
extern void		rtnl_route_set_oif(struct rtnl_route *, int);
extern int		rtnl_route_get_oif(struct rtnl_route *);
extern void		rtnl_route_set_iif(struct rtnl_route *, const char *);
extern char *		rtnl_route_get_iif(struct rtnl_route *);
extern int		rtnl_route_get_dst_len(struct rtnl_route *);
extern int		rtnl_route_get_src_len(struct rtnl_route *);

extern void		rtnl_route_add_nexthop(struct rtnl_route *,
					       struct rtnl_nexthop *);
extern void		rtnl_route_remove_nexthop(struct rtnl_nexthop *);
extern struct nl_list_head *	rtnl_route_get_nexthops(struct rtnl_route *);
extern void		rtnl_route_set_cacheinfo(struct rtnl_route *,
						 struct rtnl_rtcacheinfo *);
extern uint32_t		rtnl_route_get_mp_algo(struct rtnl_route *);
extern void		rtnl_route_set_mp_algo(struct rtnl_route *, uint32_t);

extern char *		rtnl_route_table2str(int, char *, size_t);
extern int		rtnl_route_str2table(const char *);
extern int		rtnl_route_read_table_names(const char *);

extern char *		rtnl_route_proto2str(int, char *, size_t);
extern int		rtnl_route_str2proto(const char *);
extern int		rtnl_route_read_protocol_names(const char *);

extern char *		rtnl_route_metric2str(int, char *, size_t);
extern int		rtnl_route_str2metric(const char *);

extern char *		rtnl_route_nh_flags2str(int, char *, size_t);
extern int		rtnl_route_nh_str2flags(const char *);

#ifdef __cplusplus
}
#endif

#endif
