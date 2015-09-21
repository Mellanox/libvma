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

#define SLAVE_CHECK_TIMER_PERIOD_MSEC 1000
#define SLAVE_CHECK_FAST_TIMER_PERIOD_MSEC 10
#define SLAVE_CHECK_FAST_NUM_TIMES 10

net_device_entry::net_device_entry(in_addr_t local_ip, net_device_val* ndv) : cache_entry_subject<ip_address,net_device_val*>(ip_address(local_ip))
{
	nde_logdbg("");
	m_val = ndv;
	m_is_valid = false;
	m_cma_id_bind_trial_count = 0;
	m_timer_handle = NULL;
	timer_count = -1;
	m_bond = net_device_val::OFF;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_val) {
		nde_logdbg("ERROR: received m_val = NULL");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_is_valid = true;
	m_bond = ndv->get_is_bond();
	if(m_bond != net_device_val::NO_BOND) {
		m_timer_handle = g_p_event_handler_manager->register_timer_event(SLAVE_CHECK_TIMER_PERIOD_MSEC, this, PERIODIC_TIMER, 0);
	}
	if(ndv->get_is_bond() == net_device_val::LAG_8023ad) {
		ndv->register_to_ibverbs_events(this);
	}
	nde_logdbg("Done");
}

net_device_entry::~net_device_entry()
{
	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
	net_device_val* p_ndv = dynamic_cast<net_device_val*>(m_val);
	if(p_ndv && p_ndv->get_is_bond() == net_device_val::LAG_8023ad) {
		p_ndv->unregister_to_ibverbs_events(this);
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
	if (ibv_event->event_type == IBV_EVENT_PORT_ERR || ibv_event->event_type == IBV_EVENT_PORT_ACTIVE) {
		timer_count = 0;
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = g_p_event_handler_manager->register_timer_event(SLAVE_CHECK_FAST_TIMER_PERIOD_MSEC, this, PERIODIC_TIMER, 0);
	}
}

void net_device_entry::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	auto_unlocker lock(m_lock);
	net_device_val* p_ndv = dynamic_cast<net_device_val*>(m_val);
	if (p_ndv) {
		if(m_bond == net_device_val::ACTIVE_BACKUP) {
			if(p_ndv->update_active_backup_slaves()) {
				//active slave was changed
				notify_observers();
			}
		} else if(m_bond == net_device_val::LAG_8023ad){
			if(p_ndv->update_active_slaves()) {
				//slave state was changed
				g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
				m_timer_handle = g_p_event_handler_manager->register_timer_event(SLAVE_CHECK_TIMER_PERIOD_MSEC, this, PERIODIC_TIMER, 0);
				notify_observers();
			} else {
				if (timer_count >= 0) {
					timer_count++;
					if (timer_count == SLAVE_CHECK_FAST_NUM_TIMES) {
						timer_count = -1;
						g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
						m_timer_handle = g_p_event_handler_manager->register_timer_event(SLAVE_CHECK_TIMER_PERIOD_MSEC, this, PERIODIC_TIMER, 0);
					}
				}
			}
		}
	}
}
