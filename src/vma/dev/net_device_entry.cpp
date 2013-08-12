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

net_device_entry::net_device_entry(in_addr_t local_ip, net_device_val* ndv) : cache_entry_subject<ip_address,net_device_val*>(ip_address(local_ip))
{
	nde_logdbg("");
	m_val = ndv;
	m_is_valid = false;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_val) {
		nde_logdbg("ERROR: received m_val = NULL");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// register to handle events
	rdma_cm_id *cma_id = ndv->get_cma_id();
	g_p_event_handler_manager->register_rdma_cm_event(cma_id->channel->fd, (void*)cma_id, (void*)(cma_id->channel), this);

	// ALEXR: TODO, enable once we handle verbs event again
	// This can help handle Link Up/Down
	// We'll need to review this: like handle the un-register calls
	// g_p_event_handler_manager->register_ibverbs_event(cma_id->verbs->async_fd, this, cma_id->verbs, 0);

	m_is_valid = true;
	nde_logdbg("Done");
}

net_device_entry::~net_device_entry()
{
	nde_logdbg("");

	// un-register from handle events
	rdma_cm_id *cma_id = m_val->get_cma_id();
	g_p_event_handler_manager->unregister_rdma_cm_event(cma_id->channel->fd, (void*)cma_id);

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

void net_device_entry::handle_event_rdma_cm_cb(struct rdma_cm_event* p_event)
{
	nde_logdbg("Got event '%s' (%d)", rdma_event_str(p_event->event), p_event->event);

	if (p_event->event != RDMA_CM_EVENT_ADDR_CHANGE) {
		nde_logdbg("event '%s' (%d) is not handled", rdma_event_str(p_event->event), p_event->event);
		return;
	}

	auto_unlocker lock(m_lock);
	m_is_valid = false;
	rdma_cm_id *old_cma_id = m_val->get_cma_id();

	net_device_val* p_ndv = dynamic_cast<net_device_val*>(m_val);
	if ((p_ndv) && (p_ndv->handle_event_rdma_cm(p_event))) {

		m_is_valid = true;

		// re-new RDMA_CM registration to events (replace old with new cma_id)
		rdma_cm_id *new_cma_id = m_val->get_cma_id();

		// unregister old cma_id
		rdma_event_channel *old_cma_event_channel = new_cma_id->channel; // channel is the same for all cma_ids
		g_p_event_handler_manager->unregister_rdma_cm_event(old_cma_event_channel->fd, (void*)old_cma_id);

		// register new cma_id
		g_p_event_handler_manager->register_rdma_cm_event(new_cma_id->channel->fd, (void*)new_cma_id, (void*)(new_cma_id->channel), this);
	}

	notify_observers();
}
