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


#ifndef NET_DEVICE_TABLE_MGR_H
#define NET_DEVICE_TABLE_MGR_H

#include <list>
#include <string>
#include <tr1/unordered_map>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vma/event/timer_handler.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/sys_vars.h"
#include "vma/proto/ip_address.h"
#include "vma/infra/cache_subject_observer.h"
#include "net_device_val.h"
#include "net_device_entry.h"

typedef std::tr1::unordered_map<in_addr_t, net_device_val*> net_device_map_t;
typedef std::list<in_addr_t> local_ip_list_t;
typedef std::list<net_device_val*> net_dev_lst_t;
typedef std::tr1::unordered_map<int, net_dev_lst_t > if_index_to_net_dev_lst_t;

class net_device_table_mgr : public cache_table_mgr<ip_address, net_device_val*>
{
public:
	net_device_table_mgr();
	virtual ~net_device_table_mgr();

	net_device_entry*	create_new_entry(in_addr_t local_ip);
	net_device_entry*	create_new_entry(ip_address local_ip, const observer* dst);

	void 			map_net_devices();
	net_device_val* 	get_net_device_val(const in_addr_t local_ip);
	net_dev_lst_t*		get_net_device_val_lst_from_index(int if_index);

	local_ip_list_t         get_ip_list(); // return list of the table_mgr managed ips

	std::string 		to_str();

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

private:
	lock_mutex                      m_lock;
	net_device_map_t                m_net_device_map;
	if_index_to_net_dev_lst_t	m_if_indx_to_nd_val_lst;
	int                             m_num_devices;

	struct rdma_event_channel       *m_p_cma_event_channel;

	int			        m_global_ring_epfd;
	int 			        m_global_ring_pipe_fds[2];

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	const std::string 	to_str() const { return std::string("nd_mgr");};
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	void 			verify_ipoib_mode(struct ifaddrs* ifa);
	void 			verify_bonding_mode(in_addr_t l_if);
};

extern net_device_table_mgr* g_p_net_device_table_mgr; 

#endif
