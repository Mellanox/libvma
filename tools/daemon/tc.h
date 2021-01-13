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

#ifndef TOOLS_DAEMON_TC_H_
#define TOOLS_DAEMON_TC_H_

#include <linux/pkt_sched.h> /* for the TC_H_* macros */
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/tc_act/tc_mirred.h>


/* The tc_t opaque data type
 */
typedef struct tc_object* tc_t;

struct tc_qdisc {
	uint32_t handle;
	uint32_t parent;
	int prio;
};


#define KERNEL_HT 0x800
#define MAX_BKT 0xFF
#define MAX_ID  0xFFE
#define HANDLE_INVALID    (uint32_t)(-1)

#define HANDLE_SET(ht, bkt, id)  \
	(                                          \
	(((uint32_t)(ht)  << 20) & 0xFFF00000) |   \
	(((uint32_t)(bkt) << 12) & 0x000FF000) |   \
	(((uint32_t)(id)  << 0)  & 0x00000FFF)     \
	)

#define HANDLE_HT(value)          ((((uint32_t)(value)) & 0xFFF00000) >> 20)  /* 12bits by offset 20 */
#define HANDLE_BKT(value)         ((((uint32_t)(value)) & 0x000FF000) >> 12)  /* 8bits by offset 12 */
#define HANDLE_ID(value)          ((((uint32_t)(value)) & 0x00000FFF) >> 0)   /* 12bits by offset 0 */

/**
 * Initialize a tc object.
 *
 * @return
 *     the newly allocated netlink object. Must be freed with nl_destory.
 */
tc_t tc_create(void);

/**
 * Destroy up a tc object.
 *
 * @param tc
 *     The tc object.
 *
 * @return
 *     @a none
 */
void tc_destroy(tc_t tc);

/**
 * Initialize a TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 * @param[in] type
 *   The type of TC message to create (RTM_NEWTFILTER, RTM_NEWQDISC, etc.).
 * @param[in] flags
 *   Overrides the default netlink flags for this msg with those specified.
 * @param[in] qdisc
 *   Set qdisc data.
 *
 * @return
 *     @a none
 */
void tc_req(tc_t tc, int ifindex, uint16_t type, uint16_t flags, struct tc_qdisc qdisc);

/**
 * Add qdisc as a TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int tc_add_qdisc(tc_t tc, int ifindex);

/**
 * Remove qdisc as a TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int tc_del_qdisc(tc_t tc, int ifindex);

/**
 * Add filter divisor for hash tables as a TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 * @param[in] prio
 *   Priority value.
 * @param[in] ht
 *   Hash table index.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int tc_add_filter_divisor(tc_t tc, int ifindex, int prio, int ht);

/**
 * Add filter link as a TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 * @param[in] prio
 *   Priority value.
 * @param[in] ht
 *   Hash table index.
 * @param[in] id
 *   Index in link table.
 * @param[in] ip
 *   Destination ip address.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int tc_add_filter_link(tc_t tc, int ifindex, int prio, int ht, int id, uint32_t ip);

/**
 * Add filter to redirect traffic from tap device
 * to Interface device as TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The tap device ifindex.
 * @param[in] prio
 *   Priority value.
 * @param[in] ht
 *   Hash table index.
 * @param[in] id
 *   Item index.
 * @param[in] proto
 *   Protocol type as tcp, udp etc.
 * @param[in] proto
 *   Destination ip.
 * @param[in] proto
 *   Destination port.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int tc_add_filter_tap2dev(tc_t tc, int ifindex, int prio, int id, uint32_t ip, int ifindex_to);

/**
 * Add filter to redirect traffic from ethernet device
 * to tap device using 3tuple or 5tuple as TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 * @param[in] prio
 *   Priority value.
 * @param[in] ht
 *   Hash table index.
 * @param[in] id
 *   Item index.
 * @param[in] proto
 *   Protocol type as tcp, udp etc.
 * @param[in] dst_ip
 *   Destination ip.
 * @param[in] dst_port
 *   Destination port.
 * @param[in] src_ip
 *   Source ip.
 * @param[in] src_port
 *   Source port.
 * @param[in] ifindex
 *   The tap device ifindex.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int tc_add_filter_dev2tap(tc_t tc, int ifindex, int prio, int ht, int bkt, int id,
		int proto, uint32_t dst_ip, uint16_t dst_port, uint32_t src_ip, uint16_t src_port, int ifindex_to);

/**
 * Remove specific filter as a TC request.
 *
 * @param[in] tc
 *   The TC object.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 * @param[in] prio
 *   Priority value.
 * @param[in] ht
 *   Hash table index.
 * @param[in] bkt
 *   Bucket index.
 * @param[in] ht
 *   Item index.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int tc_del_filter(tc_t tc, int ifindex, int prio, int ht, int bkt, int id);

#endif /* TOOLS_DAEMON_TC_H_ */
