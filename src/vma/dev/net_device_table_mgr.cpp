/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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


#include <list>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/epoll.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/event/event_handler_manager.h"
#include "vma/util/vtypes.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/utils.h"
#include "vma/util/valgrind.h"
#include "vma/sock/sock-redirect.h"
#include "vma/sock/fd_collection.h"
#include "vma/dev/ring.h"
#include "net_device_table_mgr.h"
#include "ib_ctx_handler_collection.h"

#define MODULE_NAME             "ndtm"


#define ndtm_logpanic           __log_panic
#define ndtm_logerr             __log_err
#define ndtm_logwarn            __log_warn
#define ndtm_loginfo            __log_info
#define ndtm_logdbg             __log_info_dbg
#define ndtm_logfunc            __log_info_func
#define ndtm_logfuncall         __log_info_funcall

net_device_table_mgr* g_p_net_device_table_mgr = NULL;

enum net_device_table_mgr_timers {
	RING_PROGRESS_ENGINE_TIMER,
	RING_ADAPT_CQ_MODERATION_TIMER
};

net_device_table_mgr::net_device_table_mgr() : cache_table_mgr<ip_address,net_device_val*>("net_device_table_mgr"), m_lock("net_device_table_mgr")
{
	m_num_devices = 0;
	m_global_ring_epfd = 0;
	m_max_mtu = 0;

	ndtm_logdbg("");

	m_global_ring_epfd = orig_os_api.epoll_create(48);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_global_ring_epfd == -1) {
		ndtm_logerr("epoll_create failed. (errno=%d %m)", errno);
		free_ndtm_resources(); 
		throw_vma_exception("epoll_create failed"); 
	}

	if (orig_os_api.pipe(m_global_ring_pipe_fds)) {
		ndtm_logerr("pipe create failed. (errno=%d %m)", errno);
		free_ndtm_resources();
		throw_vma_exception("pipe create failed");
	}
	if (orig_os_api.write(m_global_ring_pipe_fds[1], "#", 1) != 1) {
		ndtm_logerr("pipe write failed. (errno=%d %m)", errno);
		free_ndtm_resources();
		throw_vma_exception("pipe write failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (map_net_devices()) {
		ndtm_logdbg("map_net_devices failed");
		free_ndtm_resources();
		throw_vma_exception("map_net_devices failed");
	}

#ifndef DEFINED_NO_THREAD_LOCK
	if (safe_mce_sys().progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED && safe_mce_sys().progress_engine_wce_max != 0) {
		ndtm_logdbg("registering timer for ring draining with %d msec intervales", safe_mce_sys().progress_engine_interval_msec);
		g_p_event_handler_manager->register_timer_event(safe_mce_sys().progress_engine_interval_msec, this, PERIODIC_TIMER, (void*)RING_PROGRESS_ENGINE_TIMER);
	}

	if (safe_mce_sys().cq_aim_interval_msec != MCE_CQ_ADAPTIVE_MODERATION_DISABLED) {
		ndtm_logdbg("registering timer for cq adaptive moderation with %d msec intervales", safe_mce_sys().cq_aim_interval_msec);
		g_p_event_handler_manager->register_timer_event(safe_mce_sys().cq_aim_interval_msec, this, PERIODIC_TIMER, (void*)RING_ADAPT_CQ_MODERATION_TIMER);
	}
#endif // DEFINED_NO_THREAD_LOCK
}

void net_device_table_mgr::free_ndtm_resources()
{
	m_lock.lock();

	if (m_global_ring_epfd > 0) {
		orig_os_api.close(m_global_ring_epfd);
		m_global_ring_epfd = 0;
	}

	orig_os_api.close(m_global_ring_pipe_fds[1]);
	orig_os_api.close(m_global_ring_pipe_fds[0]);

	net_device_map_t::iterator iter;
	while ((iter = m_net_device_map.begin()) != m_net_device_map.end()) {
		delete iter->second;
		m_net_device_map.erase(iter);
	}
	m_lock.unlock();
}

net_device_table_mgr::~net_device_table_mgr()
{
	free_ndtm_resources();
}

int net_device_table_mgr::map_net_devices()
{
	int count = 0;
	net_device_val* p_net_device_val;
	struct ifaddrs *ifaddr, *ifa;

	ndtm_logdbg("Checking for offload capable network interfaces...");

	BULLSEYE_EXCLUDE_BLOCK_START
	if (getifaddrs(&ifaddr) == -1) {
		ndtm_logerr("getifaddrs() failed (errno = %d %m)", errno); 
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

		if (ifa->ifa_addr == NULL) {
			ndtm_logdbg("Blocking offload: Interface ('%s') addr info in NULL", ifa->ifa_name);
			continue;
		}
		if (AF_INET != ifa->ifa_addr->sa_family) {
			ndtm_logdbg("Blocking offload: Interface ('%s') is not of type AF_INET", ifa->ifa_name);
			continue;
		}
		if (ifa->ifa_flags & IFF_SLAVE) {
			ndtm_logdbg("Blocking offload: Interface ('%s') is a bonding slave", ifa->ifa_name);
			continue;
		}

		// arriving here means this is an offloadable device and VMA need to create a net_device.
		m_lock.lock();
		switch (get_iftype_from_ifname(ifa->ifa_name)) {
		case ARPHRD_ETHER:
			p_net_device_val = new net_device_val_eth(ifa);
			break;
		case ARPHRD_INFINIBAND:
			p_net_device_val = new net_device_val_ib(ifa);
			break;
		default:
			m_lock.unlock();
			continue;
		}
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!p_net_device_val) {
			ndtm_logerr("failed allocating new net_device (errno=%d %m)", errno);
			m_lock.unlock();
			freeifaddrs(ifaddr);
			return -1;
		}
		if (p_net_device_val->get_state() == net_device_val::INVALID) {
			delete p_net_device_val;
			m_lock.unlock();
			continue;
		}

		BULLSEYE_EXCLUDE_BLOCK_END
	        if ((int)get_max_mtu() < p_net_device_val->get_mtu()) {
			set_max_mtu(p_net_device_val->get_mtu());
		}
		m_net_device_map[((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr] = p_net_device_val;
		m_if_indx_to_nd_val_lst[p_net_device_val->get_if_idx()].push_back(p_net_device_val);
		m_lock.unlock();

		count++;

	} //for

	freeifaddrs(ifaddr);

	ndtm_logdbg("Check completed. Found %d offload capable network interfaces", count);

	return 0;
}

net_device_val* net_device_table_mgr::get_net_device_val(in_addr_t local_addr)
{
	auto_unlocker lock(m_lock);
	// return only valid net_device
	net_device_map_t::iterator net_device_iter = m_net_device_map.find(local_addr);
	if (net_device_iter != m_net_device_map.end()) {
		net_device_val* net_dev = net_device_iter->second;
		ndtm_logdbg("Found %s for %d.%d.%d.%d", net_dev->to_str().c_str(), NIPQUAD(local_addr));
		if (net_dev->get_state() == net_device_val::INVALID) {
			ndtm_logdbg("invalid net_device %s", net_dev->to_str().c_str());
			return NULL;
		}
		return net_device_iter->second;
	}
	ndtm_logdbg("Can't find net_device for %d.%d.%d.%d", NIPQUAD(local_addr));
	return NULL;
}

net_dev_lst_t* net_device_table_mgr::get_net_device_val_lst_from_index(int if_index)
{
	m_lock.lock();
	net_dev_lst_t* ret_val = NULL;

	if_index_to_net_dev_lst_t::iterator itr = m_if_indx_to_nd_val_lst.find(if_index);
	if (itr != m_if_indx_to_nd_val_lst.end()) {
		ret_val = &itr->second;
	}
	m_lock.unlock();

	return ret_val;
}

net_device_entry* net_device_table_mgr::create_new_entry(ip_address local_ip, const observer* obs)
{
	ndtm_logdbg("");
	NOT_IN_USE(obs);

	net_device_val *p_ndv = get_net_device_val(local_ip.get_in_addr());

	if (p_ndv) {
		return new net_device_entry(local_ip.get_in_addr(), p_ndv);
	}
	return NULL;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

std::string net_device_table_mgr::to_str()
{
	std::string rv("net_device_table_mgr:\n");
	net_device_map_t::iterator net_device_iter = m_net_device_map.begin();
	while (net_device_iter != m_net_device_map.end()) {
		rv += net_device_iter->second->to_str();
		rv += "\n";
		net_device_iter++;
	}
	return rv;}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

local_ip_list_t net_device_table_mgr::get_ip_list(int if_index)
{
	if_index_to_net_dev_lst_t::iterator itr_if_indx;
	local_ip_list_t ip_list;
	size_t i;

	m_lock.lock();

	itr_if_indx = (if_index > 0 ?
			m_if_indx_to_nd_val_lst.find(if_index) :
			m_if_indx_to_nd_val_lst.begin());

	for (; itr_if_indx != m_if_indx_to_nd_val_lst.end(); itr_if_indx++) {
		net_dev_lst_t* p_ndv_val_lst = &itr_if_indx->second;
		net_dev_lst_t::iterator itr_dev_lst;
		for (itr_dev_lst = p_ndv_val_lst->begin(); itr_dev_lst != p_ndv_val_lst->end(); ++itr_dev_lst) {
			net_device_val* p_ndev = dynamic_cast <net_device_val *>(*itr_dev_lst);
			ip_data_vector_t* p_ip = p_ndev->get_ip_array();
			for (i = 0; i < p_ip->size(); i++) {
				ip_list.push_back(*(p_ip->at(i)));
                        }
		}
		if (if_index > 0) {
			break;
		}
	}

	m_lock.unlock();

	return ip_list;
}

int net_device_table_mgr::global_ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array/*= NULL*/)
{
	ndtm_logfunc("");
	int ret_total = 0;

	net_device_map_t::iterator net_dev_iter;
	for (net_dev_iter=m_net_device_map.begin(); net_dev_iter!=m_net_device_map.end(); net_dev_iter++) {
		int ret = net_dev_iter->second->global_ring_poll_and_process_element(p_poll_sn, pv_fd_ready_array);
		if (ret < 0) {
			ndtm_logdbg("Error in net_device_val[%p]->poll_and_process_element() (errno=%d %m)", net_dev_iter->second, errno);
			return ret;
		}
		ret_total += ret;
	}
	if (ret_total) {
		ndtm_logfunc("ret_total=%d", ret_total);
	} else {
		ndtm_logfuncall("ret_total=%d", ret_total);
	}
	return ret_total;
}

int net_device_table_mgr::global_ring_request_notification(uint64_t poll_sn)
{
	ndtm_logfunc("");
	int ret_total = 0;
	net_device_map_t::iterator net_dev_iter;
	for (net_dev_iter = m_net_device_map.begin(); m_net_device_map.end() != net_dev_iter; net_dev_iter++) {
		int ret = net_dev_iter->second->global_ring_request_notification(poll_sn);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0) {
			ndtm_logerr("Error in net_device_val[%p]->request_notification() (errno=%d %m)", net_dev_iter->second, errno);
			return ret;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		ret_total += ret;
	}
	return ret_total;

}

int net_device_table_mgr::global_ring_epfd_get()
{
	return m_global_ring_epfd;
}

int net_device_table_mgr::global_ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array /*=NULL*/)
{
	ndtm_logfunc("");
	int ret_total = 0;
	int max_fd = 16;
	struct epoll_event events[max_fd];

	int res = orig_os_api.epoll_wait(global_ring_epfd_get(), events, max_fd, 0);
	if (res > 0) {
		for (int event_idx = 0; event_idx < res ; ++event_idx) {
			int fd = events[event_idx].data.fd;	// This is the Rx cq channel fd
			cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
			if (p_cq_ch_info) {
				ring* p_ready_ring = p_cq_ch_info->get_ring();
				// Handle the CQ notification channel
				int ret = p_ready_ring->wait_for_notification_and_process_element(fd, p_poll_sn, pv_fd_ready_array);
				if (ret < 0) {
					if (errno == EAGAIN || errno == EBUSY) {
						ndtm_logdbg("Error in ring[%d]->wait_for_notification_and_process_element() of %p (errno=%d %m)", event_idx, p_ready_ring, errno);
					}
					else {
						ndtm_logerr("Error in ring[%d]->wait_for_notification_and_process_element() of %p (errno=%d %m)", event_idx, p_ready_ring, errno);
					}
					continue;
				}
				if (ret > 0) {
					ndtm_logfunc("ring[%p] Returned with: %d (sn=%d)", p_ready_ring, ret, *p_poll_sn);
				}
				ret_total += ret;
			}
			else {
				ndtm_logdbg("removing wakeup fd from epfd");
				BULLSEYE_EXCLUDE_BLOCK_START
				if ((orig_os_api.epoll_ctl(m_global_ring_epfd, EPOLL_CTL_DEL,
						m_global_ring_pipe_fds[0], NULL)) && (!(errno == ENOENT || errno == EBADF))) {
					ndtm_logerr("failed to del pipe channel fd from internal epfd (errno=%d %m)", errno);
				}
				BULLSEYE_EXCLUDE_BLOCK_END
			}
		}
	}
	if (ret_total) {
		ndtm_logfunc("ret_total=%d", ret_total);
	} else {
		ndtm_logfuncall("ret_total=%d", ret_total);
	}
	return ret_total;
}

int net_device_table_mgr::global_ring_drain_and_procces()
{
	ndtm_logfuncall("");
	int ret_total = 0;

        net_device_map_t::iterator net_dev_iter;
        for (net_dev_iter=m_net_device_map.begin(); m_net_device_map.end() != net_dev_iter; net_dev_iter++) {
		int ret = net_dev_iter->second->ring_drain_and_proccess();
		if (ret < 0 && errno!= EBUSY) {
			ndtm_logerr("Error in ring[%p]->drain() (errno=%d %m)", net_dev_iter->second, errno);
			return ret;
		}
		ret_total += ret;
	}
	if (ret_total) {
		ndtm_logfunc("ret_total=%d", ret_total);
	} else {
		ndtm_logfuncall("ret_total=%d", ret_total);
	}
	return ret_total;
}

void net_device_table_mgr::global_ring_adapt_cq_moderation()
{
	ndtm_logfuncall("");

	net_device_map_t::iterator net_dev_iter;
	for (net_dev_iter=m_net_device_map.begin(); m_net_device_map.end() != net_dev_iter; net_dev_iter++) {
		net_dev_iter->second->ring_adapt_cq_moderation();
	}
}

void net_device_table_mgr::handle_timer_expired(void* user_data)
{
	int timer_type = (uint64_t)user_data;
	switch (timer_type) {
	case RING_PROGRESS_ENGINE_TIMER:
#ifdef DEFINED_SOCKETXTREME
#if 0 /* TODO: see explanation */
		/* Do not call draining RX logic from internal thread for socketxtreme mode
		 * It is disable by default
		 * See: cq_mgr::drain_and_proccess()
		 */
#endif // 0
#else
		global_ring_drain_and_procces();
#endif // DEFINED_SOCKETXTREME		
		break;
	case RING_ADAPT_CQ_MODERATION_TIMER:
		global_ring_adapt_cq_moderation();
		break;
	default:
		ndtm_logerr("unrecognized timer %d", timer_type);
	}
}

void net_device_table_mgr::global_ring_wakeup()
{
	ndtm_logdbg("");
	epoll_event ev = {0, {0}};

	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	int errno_tmp = errno; //don't let wakeup affect errno, as this can fail with EEXIST
	BULLSEYE_EXCLUDE_BLOCK_START
	if ((orig_os_api.epoll_ctl(m_global_ring_epfd, EPOLL_CTL_ADD, 
			   m_global_ring_pipe_fds[0], &ev)) && (errno != EEXIST)) {
		ndtm_logerr("failed to add pipe channel fd to internal epfd (errno=%d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	errno = errno_tmp;
}

void net_device_table_mgr::set_max_mtu(uint32_t mtu)
{
	m_max_mtu = mtu;
}

uint32_t net_device_table_mgr::get_max_mtu()
{
	return m_max_mtu;
}
