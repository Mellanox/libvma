/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef NET_DEVICE_TABLE_MGR_H
#define NET_DEVICE_TABLE_MGR_H

#include <list>
#include <string>
#include <unordered_map>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vma/event/timer_handler.h"
#include "vma/util/sys_vars.h"
#include "vma/proto/ip_address.h"
#include "vma/infra/cache_subject_observer.h"
#include "net_device_val.h"
#include "net_device_entry.h"

typedef std::unordered_map<in_addr_t, net_device_val*> net_device_map_addr_t;
typedef std::unordered_map<int, net_device_val*> net_device_map_index_t;
typedef std::list<ip_data_t> local_ip_list_t;

class net_device_table_mgr : public cache_table_mgr<ip_address, net_device_val*>, public observer
{
public:
	net_device_table_mgr();
	virtual ~net_device_table_mgr();

	void update_tbl();
	void print_val_tbl();

	virtual void 	notify_cb(event *ev);
	net_device_entry*	create_new_entry(ip_address local_ip, const observer* dst);

	net_device_val* 	get_net_device_val(const in_addr_t local_ip);
	net_device_val*		get_net_device_val(int if_index);

	local_ip_list_t     get_ip_list(int if_index = 0); // return list of the table_mgr managed ips

	/**
	 * Arm ALL the managed CQ's notification channel
	 * This call will also check for race condition by polling each CQ after arming the notification channel.
	 * If race condition case occures then that CQ is polled and processed (and the CQ notification is armed)
	 * Returns >=0 the total number of wce processed
	 *         < 0 on error
	 */
	int 	global_ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);


	/**
	 * This will poll one time on the ALL the managed CQ's
	 * If a wce was found 'processing' will occur.
	 * Returns: >=0 the total number of wce processed
	 *          < 0 error
	 */
	int     global_ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);

	int 	global_ring_request_notification(uint64_t poll_sn);

	/**
	 * This will poll one time on the ALL the managed CQ's
	 * If a wce was found 'processing' will occur.
	 * Returns: >=0 the total number of wce processed
	 *          < 0 error
	 */
	int 	global_ring_drain_and_procces();

	void	global_ring_adapt_cq_moderation();

	void	global_ring_wakeup();

	int 	global_ring_epfd_get();

	void	handle_timer_expired(void* user_data);

	uint32_t get_max_mtu();

	inline ts_conversion_mode_t get_ctx_time_conversion_mode() {
		return m_time_conversion_mode;
	};

private:
	void del_link_event(const netlink_link_info* info);
	void new_link_event(const netlink_link_info* info);

	void                            free_ndtm_resources();
	void                            set_max_mtu(uint32_t);
	
	lock_mutex                      m_lock;
	ts_conversion_mode_t            m_time_conversion_mode;
	net_device_map_addr_t           m_net_device_map_addr;
	net_device_map_index_t          m_net_device_map_index;
	int                             m_num_devices;

	int			        m_global_ring_epfd;
	int 			    m_global_ring_pipe_fds[2];

	uint32_t			m_max_mtu;
};

extern net_device_table_mgr* g_p_net_device_table_mgr; 

#endif
