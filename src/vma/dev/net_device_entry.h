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


#ifndef NET_DEVICE_ENTRY_H
#define NET_DEVICE_ENTRY_H

#include "net_device_val.h"
#include "vma/infra/cache_subject_observer.h"
#include "vma/proto/ip_address.h"
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
