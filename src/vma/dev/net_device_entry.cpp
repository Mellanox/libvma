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


#include "net_device_entry.h"
#include "net_device_table_mgr.h"
#include "vma/event/event_handler_manager.h"
#include "vma/event/route_net_dev_event.h"
#include "vma/util/bullseye.h"

#define MODULE_NAME             "nde"

#define nde_logdbg             __log_info_dbg
#define nde_logerr             __log_info_err

#define SLAVE_CHECK_TIMER_PERIOD 1000

net_device_entry::net_device_entry(in_addr_t local_ip, net_device_val* ndv) : cache_entry_subject<ip_address,net_device_val*>(ip_address(local_ip))
{
	nde_logdbg("");
	m_val = ndv;
	m_is_valid = false;
	m_cma_id_bind_trial_count = 0;
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_val) {
		nde_logdbg("ERROR: received m_val = NULL");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// ALEXR: TODO, enable once we handle verbs event again
	// This can help handle Link Up/Down
	// We'll need to review this: like handle the un-register calls
	// g_p_event_handler_manager->register_ibverbs_event(cma_id->verbs->async_fd, this, cma_id->verbs, 0);

	m_is_valid = true;
	if(ndv->get_is_bond())
		m_timer_handle = g_p_event_handler_manager->register_timer_event(SLAVE_CHECK_TIMER_PERIOD, this, PERIODIC_TIMER, 0);
	nde_logdbg("Done");
}

net_device_entry::~net_device_entry()
{
	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
	nde_logdbg("Done");
}

bool net_device_entry::get_val(INOUT net_device_val* &val)
{
	auto_unlocker lock(m_lock);
	val = m_val;
	return is_valid();
}

void net_device_entry::handle_event_ibverbs_cb(void *ev_data, void *ctx)
{
	NOT_IN_USE(ctx);

	struct ibv_async_event *ibv_event = (struct ibv_async_event*)ev_data;
	nde_logdbg("received ibv_event '%s' (%d)", priv_ibv_event_desc_str(ibv_event->event_type), ibv_event->event_type);
}

void net_device_entry::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	auto_unlocker lock(m_lock);
	net_device_val* p_ndv = dynamic_cast<net_device_val*>(m_val);
	if (p_ndv) {
		if(p_ndv->update_active_slave()) {
			//active slave was changed
			notify_observers();
		}
	}
}
