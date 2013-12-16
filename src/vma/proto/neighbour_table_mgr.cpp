/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "vma/proto/neighbour_observer.h"
#include "vma/util/verbs_extra.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/util/bullseye.h"

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
		neigh_mgr_logpanic("Failed to create neigh_cma_event_channel (errno=%d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	neigh_mgr_logdbg("Creation of neigh_cma_event_channel on fd=%d", m_neigh_cma_event_channel->fd);

	start_garbage_collector(DEFAULT_GARBAGE_COLLECTOR_TIME);
}

neigh_entry* neigh_table_mgr::create_new_entry(neigh_key neigh_key, const observer* new_observer)
{
	observer * tmp = const_cast<observer *>(new_observer);
	const neigh_observer * dst = dynamic_cast<const neigh_observer *>(tmp) ;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (dst == NULL) {
		//TODO: Need to add handling of this case
		neigh_mgr_logpanic("dynamic_casr failed, new_observer type is not neigh_observer");
	}
	BULLSEYE_EXCLUDE_BLOCK_END


	transport_type_t transport = dst->get_obs_transport_type();

	//Register to netlink event handler only if this is the first entry
	if (get_cache_tbl_size() == 0) {
			g_p_netlink_handler->register_event(nlgrpNEIGH, this);
			neigh_mgr_logdbg("Registered to g_p_netlink_handler");
	}

	if (transport == VMA_TRANSPORT_IB) {
		if(IS_BROADCAST_N(neigh_key.get_in_addr())){
			neigh_mgr_logdbg("Creating new neigh_ib_broadcast");
			return (new neigh_ib_broadcast(neigh_key));
		}
		neigh_mgr_logdbg("Creating new neigh_ib");
		return (new neigh_ib(neigh_key));
	}
	else if (transport == VMA_TRANSPORT_ETH) {
		neigh_mgr_logdbg("Creating new neigh_eth");
		return (new neigh_eth(neigh_key));
	}
	else {
		neigh_mgr_logdbg("Cannot create new entry, transport type is UNKNOWN");
		return NULL;
	}
}

void neigh_table_mgr::notify_cb(event *ev)
{
	neigh_mgr_logfunc("");
	// Got event from netlink

	neigh_nl_event* nl_ev = dynamic_cast <neigh_nl_event*> (ev);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (nl_ev == NULL) {
		neigh_mgr_logfunc("Non neigh_nl_event type");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	const netlink_neigh_info* nl_info = nl_ev->get_neigh_info();
	struct in_addr in;
	if(! inet_aton((const char *)(nl_info->dst_addr_str.c_str()), &in)){
		neigh_mgr_logfunc("Ignoring netlink neigh event for IP = %s, not a valid IP", nl_info->dst_addr_str.c_str());
		return;
	}

	in_addr_t neigh_ip = in.s_addr;

	// Search for this neigh ip in cache_table
	m_lock.lock();
	net_dev_lst_t* p_ndv_val_lst = g_p_net_device_table_mgr->get_net_device_val_lst_from_index(nl_info->ifindex);

	//find all neigh entries with an appropriate peer_ip and net_device
	if (p_ndv_val_lst) {
		net_dev_lst_t::iterator itr;
		for (itr = p_ndv_val_lst->begin(); itr != p_ndv_val_lst->end(); ++itr) {
			net_device_val* p_ndev = dynamic_cast <net_device_val *>(*itr);
			if (p_ndev) {
				std::tr1::unordered_map< neigh_key, cache_entry_subject<neigh_key,neigh_val*> *>::iterator cache_itr;
				cache_itr = m_cache_tbl.find(neigh_key(ip_address(neigh_ip), p_ndev));
				if (cache_itr == m_cache_tbl.end()) {
					neigh_mgr_logfunc("Ignoring netlink neigh event for IP = %s if:%s", nl_info->dst_addr_str.c_str(), p_ndev->to_str().c_str());
				}
				else {

					neigh_entry *p_ne = dynamic_cast <neigh_entry *>(cache_itr->second);

					if (p_ne) {
						// Call the relevant neigh_entry to handle the event
						p_ne->handle_neigh_event(nl_ev);
					}
				}
			}
		}
	}
	m_lock.unlock();

	return;
}
