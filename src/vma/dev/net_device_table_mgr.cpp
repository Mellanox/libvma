/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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

#include "vma/event/event_handler_manager.h"
#include "vlogger/vlogger.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/utils.h"
#include "vma/sock/sock-redirect.h"
#include "vma/sock/fd_collection.h"
#include "vma/dev/ring.h"
#include "net_device_table_mgr.h"
#include "ib_ctx_handler_collection.h"
#include "vma/util/bullseye.h"

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

net_device_table_mgr::net_device_table_mgr() : cache_table_mgr<ip_address,net_device_val*>(), m_lock("net_device_table_mgr")
{
	m_num_devices = 0;
	m_p_cma_event_channel = NULL;
	m_global_ring_epfd = 0;
	m_max_mtu = 0;
	/* I have no idea why - but if I create the channel here - it doesn't bind well - grrrr
        m_p_cma_event_channel = rdma_create_event_channel();
        if (m_p_cma_event_channel == NULL) {
                ndtm_logpanic("Failed to create event channel (errno=%d %m)", errno);
        }
        ndtm_logfunc("On-demand creation of cma event channel on fd=%d", m_p_cma_event_channel->fd);
	 */
	m_global_ring_epfd = orig_os_api.epoll_create(48);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_global_ring_epfd == -1) {
		ndtm_logerr("epoll_create failed. (errno=%d %m)", errno);
		free_ndtm_resources(); 
		throw_vma_exception_no_msg(); 
	}

	if (orig_os_api.pipe(m_global_ring_pipe_fds)) {
		ndtm_logerr("pipe create failed. (errno=%d %m)", errno);
		free_ndtm_resources();
		throw_vma_exception_no_msg();
	}
	if (orig_os_api.write(m_global_ring_pipe_fds[1], "#", 1) != 1) {
		ndtm_logerr("pipe write failed. (errno=%d %m)", errno);
		free_ndtm_resources();
		throw_vma_exception_no_msg();
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (map_net_devices()) {
		ndtm_logdbg("map_net_devices failed");
		free_ndtm_resources();
		throw_vma_exception_no_msg();
	}

	if (safe_mce_sys().progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED && safe_mce_sys().progress_engine_wce_max != 0) {
		ndtm_logdbg("registering timer for ring draining with %d msec intervales", safe_mce_sys().progress_engine_interval_msec);
		g_p_event_handler_manager->register_timer_event(safe_mce_sys().progress_engine_interval_msec, this, PERIODIC_TIMER, (void*)RING_PROGRESS_ENGINE_TIMER);
	}

	if (safe_mce_sys().cq_aim_interval_msec != MCE_CQ_ADAPTIVE_MODERATION_DISABLED) {
		ndtm_logdbg("registering timer for cq adaptive moderation with %d msec intervales", safe_mce_sys().cq_aim_interval_msec);
		g_p_event_handler_manager->register_timer_event(safe_mce_sys().cq_aim_interval_msec, this, PERIODIC_TIMER, (void*)RING_ADAPT_CQ_MODERATION_TIMER);
	}
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

	net_device_map_t::iterator net_dev_iter;
	for (net_dev_iter=m_net_device_map.begin(); net_dev_iter!=m_net_device_map.end(); net_dev_iter++)
	{
		delete net_dev_iter->second;
	}
	m_lock.unlock();

	if (m_p_cma_event_channel != NULL) {
		rdma_destroy_event_channel(m_p_cma_event_channel);
		m_p_cma_event_channel = NULL;
	}
}

net_device_table_mgr::~net_device_table_mgr()
{
	free_ndtm_resources();
}

int net_device_table_mgr::map_net_devices()
{
	int count = 0;
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
		if (!(ifa->ifa_flags & IFF_RUNNING)) {
			ndtm_logdbg("Blocking offload: Interface ('%s') is not running", ifa->ifa_name);
			continue;
		}

		ndtm_logdbg("Checking if can offload on interface '%s' (addr=%d.%d.%d.%d, flags=%X)",
				ifa->ifa_name, NIPQUAD(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr), ifa->ifa_flags);

		// I have no idea why - but if I do it in the c'tor - it doesn't bind well - grrrr
		if (m_p_cma_event_channel == NULL) {
			m_p_cma_event_channel = rdma_create_event_channel();
		}

		rdma_cm_id* cma_id = NULL;
		IF_RDMACM_FAILURE(rdma_create_id(m_p_cma_event_channel, &cma_id, NULL, RDMA_PS_UDP)) { // UDP vs IP_OVER_IB?
			ndtm_logerr("Failed in rdma_create_id (RDMA_PS_UDP) (errno=%d %m)", errno);
			continue;
		} ENDIF_RDMACM_FAILURE;

		// avoid nesting calls to IF_RDMACM_FAILURE macro - because it will raise gcc warning "declaration of '__ret__' shadows a previous local" in case -Wshadow is used
		bool rdma_bind_addr_failed = false;
		IF_RDMACM_FAILURE(rdma_bind_addr(cma_id, (struct sockaddr*)ifa->ifa_addr)) {
			rdma_bind_addr_failed = true;
		} ENDIF_RDMACM_FAILURE;
		if (rdma_bind_addr_failed) {
			ndtm_logdbg("Failed in rdma_bind_addr (src=%d.%d.%d.%d) (errno=%d %m)", NIPQUAD(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr), errno);
			errno = 0; //in case of not-offloade, resource is not available (errno=11), but this is normal and we don't want the user to know about this
			// Close the cma_id which does not support offload
			IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
				ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
			} ENDIF_RDMACM_FAILURE;
			continue;
		}

		// loopback might get here but without ibv_context in the cma_id
		if (NULL == cma_id->verbs) {
			ndtm_logdbg("Blocking offload: No verbs context in cma_id on interfaces ('%s')", ifa->ifa_name);

			// Close the cma_id which will not be offload
			IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
				ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
			} ENDIF_RDMACM_FAILURE;
			continue;
		}

		//get and check ib context
		ib_ctx_handler* ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(cma_id->verbs);
		if (NULL == ib_ctx) {
			ndtm_logdbg("Blocking offload: can't create ib_ctx on interfaces ('%s')", ifa->ifa_name);

			// Close the cma_id which will not be offload
			IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
				ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
			} ENDIF_RDMACM_FAILURE;
			continue;
		}

		//check if port is in active mode. if not, dont create net_device_val_ib.
		if (ib_ctx->get_port_state(cma_id->port_num) != IBV_PORT_ACTIVE) {
			ndtm_logdbg("Blocking offload: non-active interfaces ('%s')", ifa->ifa_name);

			// Close the cma_id which will not be offload
			IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
				ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
			} ENDIF_RDMACM_FAILURE;
			continue;
		}

		if ((!safe_mce_sys().enable_ipoib) && (get_iftype_from_ifname(ifa->ifa_name) == ARPHRD_INFINIBAND)) {
			ndtm_logdbg("Blocking offload: IPoIB interfaces ('%s')", ifa->ifa_name);

			// Close the cma_id which will not be offload
			IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
				ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
			} ENDIF_RDMACM_FAILURE;
			continue;
		}

		// arriving here means this is an offloadable device and VMA need to create a net_device.
		m_lock.lock();
		net_device_val* p_net_device_val = NULL;
		if (get_iftype_from_ifname(ifa->ifa_name) == ARPHRD_INFINIBAND) {
			verify_ipoib_mode(ifa);
			p_net_device_val = new net_device_val_ib();
		}
		else {
			p_net_device_val = new net_device_val_eth();
		}
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!p_net_device_val) {
			ndtm_logerr("failed allocating new net_device (errno=%d %m)", errno);
			m_lock.unlock();
			freeifaddrs(ifaddr);
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		p_net_device_val->configure(ifa, cma_id);
	        if ((int)get_max_mtu() < p_net_device_val->get_mtu()) {
			set_max_mtu(p_net_device_val->get_mtu());
		}
		m_net_device_map[((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr] = p_net_device_val;
		m_if_indx_to_nd_val_lst[p_net_device_val->get_if_idx()].push_back(p_net_device_val);
		m_lock.unlock();

		ibv_device* ibvdevice = ib_ctx->get_ibv_device();
		ndtm_logdbg("Offload interface '%s': Mapped to ibv device '%s' [%p] on port %d",
				ifa->ifa_name, ibvdevice->name, ibvdevice, cma_id->port_num);

		IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
			ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
		} ENDIF_RDMACM_FAILURE;

		count++;
	} //for

	freeifaddrs(ifaddr);

	ndtm_logdbg("Check completed. Found %d offload capable network interfaces", count);

	return 0;
}

// Verify IPoIB is in 'datagram mode' for proper VMA with flow steering operation
// Also verify umcast is disabled for IB flow
void net_device_table_mgr::verify_ipoib_mode(struct ifaddrs* ifa)
{
	char filename[256] = "\0";
	char ifname[IFNAMSIZ] = "\0";
	if (validate_ipoib_prop(ifa->ifa_name, ifa->ifa_flags, IPOIB_MODE_PARAM_FILE, "datagram", 8, filename, ifname)) {
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
		vlog_printf(VLOG_WARNING,"IPoIB mode of interface '%s' is \"connected\" !\n", ifa->ifa_name);
		vlog_printf(VLOG_WARNING,"Please change it to datagram: \"echo datagram > %s\" \n", filename);
		vlog_printf(VLOG_WARNING,"before loading your application with VMA library\n");
		vlog_printf(VLOG_WARNING,"VMA doesn't support IPoIB in connected mode.\n");
		vlog_printf(VLOG_WARNING,"Please refer to VMA Release Notes for more information\n");
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
	}
	else {
		ndtm_logdbg("verified interface '%s' is running in datagram mode", ifa->ifa_name);
	}

	if (validate_ipoib_prop(ifa->ifa_name, ifa->ifa_flags, UMCAST_PARAM_FILE, "0", 1, filename, ifname)) { // Extract UMCAST flag (only for IB transport types)
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
		vlog_printf(VLOG_WARNING,"UMCAST flag is Enabled for interface %s !\n", ifa->ifa_name);
		vlog_printf(VLOG_WARNING,"Please disable it: \"echo 0 > %s\" \n", filename);
		vlog_printf(VLOG_WARNING,"before loading your application with VMA library\n");
		vlog_printf(VLOG_WARNING,"This option in no longer needed in this version\n");
		vlog_printf(VLOG_WARNING,"Please refer to Release Notes for more information\n");
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
	}
	else {
		ndtm_logdbg("verified interface '%s' is running with umcast disabled", ifa->ifa_name);
	}
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

net_device_entry* net_device_table_mgr::create_new_entry(in_addr_t local_ip)
{
	ndtm_logdbg("");
	net_device_val *p_ndv = get_net_device_val(local_ip);

	if (p_ndv) { //net device is offloaded
		return new net_device_entry(local_ip, p_ndv);
	}
	return NULL; // Fail the observer registeration
}

net_device_entry* net_device_table_mgr::create_new_entry(ip_address local_ip, const observer* dst)
{
	NOT_IN_USE(dst);
	return create_new_entry(local_ip.get_in_addr());
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

local_ip_list_t net_device_table_mgr::get_ip_list()
{
	local_ip_list_t ip_list;
	net_device_map_t::iterator net_dev_iter;
	for (net_dev_iter=m_net_device_map.begin(); net_dev_iter!=m_net_device_map.end(); net_dev_iter++) {
		ip_list.push_back(net_dev_iter->first);
	}
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
	if (ret_total)
		ndtm_logfunc("ret_total=%d", ret_total);
	else
		ndtm_logfuncall("ret_total=%d", ret_total);
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
				int ret = p_ready_ring->wait_for_notification_and_process_element(CQT_RX, fd, p_poll_sn, pv_fd_ready_array);
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
	if (ret_total)
		ndtm_logfunc("ret_total=%d", ret_total);
	else
		ndtm_logfuncall("ret_total=%d", ret_total);
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
	if (ret_total)
		ndtm_logfunc("ret_total=%d", ret_total);
	else
		ndtm_logfuncall("ret_total=%d", ret_total);
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
		global_ring_drain_and_procces();
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
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	BULLSEYE_EXCLUDE_BLOCK_START
	if ((orig_os_api.epoll_ctl(m_global_ring_epfd, EPOLL_CTL_ADD, 
			   m_global_ring_pipe_fds[0], &ev)) && (errno != EEXIST)) {
		ndtm_logerr("failed to add pipe channel fd to internal epfd (errno=%d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

void net_device_table_mgr::set_max_mtu(uint32_t mtu)
{
	m_max_mtu = mtu;
}

uint32_t net_device_table_mgr::get_max_mtu()
{
	return m_max_mtu;
}
