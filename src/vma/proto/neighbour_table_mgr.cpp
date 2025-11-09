/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "utils/bullseye.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "vma/dev/net_device_table_mgr.h"

#define MODULE_NAME 		"ntm:"

#define neigh_mgr_logpanic		__log_panic
#define neigh_mgr_logerr		__log_err
#define neigh_mgr_logwarn		__log_warn
#define neigh_mgr_loginfo		__log_info
#define neigh_mgr_logdbg		__log_dbg
#define neigh_mgr_logfunc		__log_func
#define neigh_mgr_logfuncall		__log_funcall

neigh_table_mgr * g_p_neigh_table_mgr = NULL;

#define DEFAULT_GARBAGE_COLLECTOR_TIME 100000

neigh_table_mgr::neigh_table_mgr():m_neigh_cma_event_channel(NULL)
{
	// Creating cma_event_channel

	m_neigh_cma_event_channel = rdma_create_event_channel();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_neigh_cma_event_channel == NULL) {
		neigh_mgr_logdbg("Failed to create neigh_cma_event_channel (errno=%d %m)", errno);
	} else {
		neigh_mgr_logdbg("Creation of neigh_cma_event_channel on fd=%d", m_neigh_cma_event_channel->fd);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	start_garbage_collector(DEFAULT_GARBAGE_COLLECTOR_TIME);
}

neigh_table_mgr::~neigh_table_mgr()
{
	stop_garbage_collector();
	if (m_neigh_cma_event_channel) {
		rdma_destroy_event_channel(m_neigh_cma_event_channel);
	}
}

bool neigh_table_mgr::register_observer(neigh_key key,
				const cache_observer *new_observer,
				cache_entry_subject<neigh_key, class neigh_val*> **cache_entry)
{
	//Register to netlink event handler only if this is the first entry
	if (get_cache_tbl_size() == 0) {
		g_p_netlink_handler->register_event(nlgrpNEIGH, this);
		neigh_mgr_logdbg("Registered to g_p_netlink_handler");
	}
	return cache_table_mgr<neigh_key, class neigh_val*>::register_observer(key, new_observer, cache_entry);
}

neigh_entry* neigh_table_mgr::create_new_entry(neigh_key neigh_key, const observer* new_observer)
{
	NOT_IN_USE(new_observer);
	neigh_mgr_logdbg("Creating new neigh_eth");
	return (new neigh_eth(neigh_key));
}

void neigh_table_mgr::notify_cb(event *ev)
{
	neigh_mgr_logdbg("");
	// Got event from netlink

	neigh_nl_event* nl_ev = dynamic_cast <neigh_nl_event*> (ev);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (nl_ev == NULL) {
		neigh_mgr_logdbg("Non neigh_nl_event type");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	const netlink_neigh_info* nl_info = nl_ev->get_neigh_info();
	struct in_addr in;
	if (1 != inet_pton(AF_INET, (const char *)(nl_info->dst_addr_str.c_str()), &in)) {
		neigh_mgr_logdbg("Ignoring netlink neigh event neigh for IP = %s, not a valid IP", nl_info->dst_addr_str.c_str());
		return;
	}

	in_addr_t neigh_ip = in.s_addr;

	// Search for this neigh ip in cache_table
	m_lock.lock();
	net_device_val* p_ndev = g_p_net_device_table_mgr->get_net_device_val(nl_info->ifindex);

	//find all neigh entries with an appropriate peer_ip and net_device
	if (p_ndev) {
		neigh_entry *p_ne = dynamic_cast <neigh_entry *>(get_entry(neigh_key(ip_address(neigh_ip), p_ndev)));
		if (p_ne) {
			// Call the relevant neigh_entry to handle the event
			p_ne->handle_neigh_event(nl_ev);
		} else {
			neigh_mgr_logdbg("Ignoring netlink neigh event for IP = %s if:%s, index=%d, p_ndev=%p", nl_info->dst_addr_str.c_str(), p_ndev->to_str().c_str(), nl_info->ifindex, p_ndev);
		}
	} else {
		neigh_mgr_logdbg("could not find ndv_val for ifindex=%d", nl_info->ifindex);
	}
	m_lock.unlock();

	return;
}
