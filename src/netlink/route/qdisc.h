/*
 * netlink/route/qdisc.h         Queueing Disciplines
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_QDISC_H_
#define NETLINK_QDISC_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/tc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rtnl_qdisc;

extern struct nl_object_ops qdisc_obj_ops;

/* General */
extern struct rtnl_qdisc *	rtnl_qdisc_alloc(void);
extern void			rtnl_qdisc_put(struct rtnl_qdisc *);

/* Cache Management */
extern struct nl_cache *	rtnl_qdisc_alloc_cache(struct nl_handle *);
extern struct rtnl_qdisc *	rtnl_qdisc_get(struct nl_cache *,
					       int, uint32_t);
extern struct rtnl_qdisc *	rtnl_qdisc_get_by_parent(struct nl_cache *,
							 int, uint32_t);

/* qdisc addition */
extern struct nl_msg *	rtnl_qdisc_build_add_request(struct rtnl_qdisc *, int);
extern int		rtnl_qdisc_add(struct nl_handle *, struct rtnl_qdisc *,
				       int);

/* qdisc modification */
extern struct nl_msg *	rtnl_qdisc_build_change_request(struct rtnl_qdisc *,
							struct rtnl_qdisc *);
extern int		rtnl_qdisc_change(struct nl_handle *,
					  struct rtnl_qdisc *,
					  struct rtnl_qdisc *);

/* qdisc deletion */
extern struct nl_msg *	rtnl_qdisc_build_delete_request(struct rtnl_qdisc *);
extern int		rtnl_qdisc_delete(struct nl_handle *,
					  struct rtnl_qdisc *);

/* attribute modifications */
extern void		rtnl_qdisc_set_ifindex(struct rtnl_qdisc *, int);
extern int		rtnl_qdisc_get_ifindex(struct rtnl_qdisc *);
extern void		rtnl_qdisc_set_handle(struct rtnl_qdisc *, uint32_t);
extern uint32_t		rtnl_qdisc_get_handle(struct rtnl_qdisc *);
extern void		rtnl_qdisc_set_parent(struct rtnl_qdisc *, uint32_t);
extern uint32_t		rtnl_qdisc_get_parent(struct rtnl_qdisc *);
extern void		rtnl_qdisc_set_kind(struct rtnl_qdisc *, const char *);
extern char *		rtnl_qdisc_get_kind(struct rtnl_qdisc *);
extern uint64_t		rtnl_qdisc_get_stat(struct rtnl_qdisc *,
					    enum rtnl_tc_stats_id);

/* iterators */
extern void		rtnl_qdisc_foreach_child(struct rtnl_qdisc *,
						 struct nl_cache *,
						 void (*cb)(struct nl_object *,
							    void *),
						 void *);

extern void		rtnl_qdisc_foreach_cls(struct rtnl_qdisc *,
					       struct nl_cache *,
					       void (*cb)(struct nl_object *,
							  void *),
					       void *);

/* qdisc specific options */
extern struct nl_msg *	rtnl_qdisc_get_opts(struct rtnl_qdisc *);

#ifdef __cplusplus
}
#endif

#endif
