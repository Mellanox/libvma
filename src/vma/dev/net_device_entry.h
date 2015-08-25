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


#ifndef NET_DEVICE_ENTRY_H
#define NET_DEVICE_ENTRY_H

#include "net_device_val.h"
#include "vma/infra/cache_subject_observer.h"
#include "vma/proto/ip_address.h"
#include "vma/event/route_net_dev_event.h"
#include "vma/event/timer_handler.h"

#define MAX_CMA_ID_BIND_TRIAL_COUNT 10
#define CMA_ID_BIND_TIMER_PERIOD_MSEC 100

class net_device_entry : public cache_entry_subject<ip_address, net_device_val*> , public event_handler_ibverbs, public timer_handler
{
public:
	friend class net_device_table_mgr;

	net_device_entry(in_addr_t local_ip, net_device_val* ndv);
	virtual ~net_device_entry();

	bool get_val(INOUT net_device_val* &val);
	bool is_valid()	{ return m_is_valid; }; // m_val is NULL at first

	virtual void	handle_event_ibverbs_cb(void *ev_data, void *ctx);

	void handle_timer_expired(void* user_data);

private:

	bool m_is_valid;
	size_t m_cma_id_bind_trial_count;
	void* m_timer_handle;
	net_device_val::bond_type m_bond;
	int timer_count;
};

#endif 
