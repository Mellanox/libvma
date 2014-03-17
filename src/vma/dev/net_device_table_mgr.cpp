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
		ndtm_logpanic("epoll_create failed. (errno=%d %m)", errno);
	}

	if (orig_os_api.pipe(m_global_ring_pipe_fds)) {
		ndtm_logpanic("pipe create failed. (errno=%d %m)", errno);
	}
	if (orig_os_api.write(m_global_ring_pipe_fds[1], "#", 1) != 1) {
		ndtm_logpanic("pipe write failed. (errno=%d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	map_net_devices();

	if (mce_sys.progress_engine_interval_msec != MCE_CQ_DRAIN_INTERVAL_DISABLED && mce_sys.progress_engine_wce_max != 0) {
		ndtm_logdbg("registering timer for ring draining with %d msec intervales", mce_sys.progress_engine_interval_msec);
		g_p_event_handler_manager->register_timer_event(mce_sys.progress_engine_interval_msec, this, PERIODIC_TIMER, (void*)RING_PROGRESS_ENGINE_TIMER);
	}

	if (mce_sys.cq_aim_interval_msec != MCE_CQ_ADAPTIVE_MODERATION_DISABLED) {
		ndtm_logdbg("registering timer for cq adaptive moderation with %d msec intervales", mce_sys.cq_aim_interval_msec);
		g_p_event_handler_manager->register_timer_event(mce_sys.cq_aim_interval_msec, this, PERIODIC_TIMER, (void*)RING_ADAPT_CQ_MODERATION_TIMER);
	}
}

net_device_table_mgr::~net_device_table_mgr()
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

	if (m_p_cma_event_channel == NULL) {
		rdma_destroy_event_channel(m_p_cma_event_channel);
		m_p_cma_event_channel = NULL;
	}
}

void net_device_table_mgr::map_net_devices()
{
	struct ifaddrs *ifaddr, *ifa;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (getifaddrs(&ifaddr) == -1) {
		// log perror("getifaddrs");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		ndtm_logdbg("Checking if can offload on interface '%s' (addr=%d.%d.%d.%d, flags=%X)",
				ifa->ifa_name, NIPQUAD(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr), ifa->ifa_flags);

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

		// I have no idea why - but if I do it in the c'tor - it doesn't bind well - grrrr
		if (m_p_cma_event_channel == NULL) {
			m_p_cma_event_channel = rdma_create_event_channel();
		}

		rdma_cm_id* cma_id = NULL;
		IF_RDMACM_FAILURE(rdma_create_id(m_p_cma_event_channel, &cma_id, NULL, RDMA_PS_UDP)) { // UDP vs IP_OVER_IB?
			ndtm_logerr("Failed in rdma_create_id (RDMA_PS_UDP) (errno=%d %m)", errno);
			continue;
		} ENDIF_RDMACM_FAILURE;

		IF_RDMACM_FAILURE(rdma_bind_addr(cma_id, (struct sockaddr*)ifa->ifa_addr)) {
			ndtm_logdbg("Failed in rdma_bind_addr (src=%d.%d.%d.%d) (errno=%d %m)", NIPQUAD(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr), errno);
			errno = 0; //in case of not-offloade, resource is not available (errno=11), but this is normal and we don't want the user to know about this
			// Close the cma_id which does not support offload
			IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
				ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
			} ENDIF_RDMACM_FAILURE;
			continue;
		} ENDIF_RDMACM_FAILURE;

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

		if ((!mce_sys.enable_ipoib) && (get_iftype_from_ifname(ifa->ifa_name) == ARPHRD_INFINIBAND)) {
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
			ndtm_logpanic("failed allocating new net_device!");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		p_net_device_val->configure(ifa, cma_id);
		m_net_device_map[((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr] = p_net_device_val;
		m_if_indx_to_nd_val_lst[p_net_device_val->get_if_idx()].push_back(p_net_device_val);
		m_lock.unlock();

		verify_bonding_mode(p_net_device_val->get_local_addr());

		ibv_device* ibvdevice = ib_ctx->get_ibv_device();
		ndtm_logdbg("Offload interface '%s': Mapped to ibv device '%s' [%p] on port %d",
				ifa->ifa_name, ibvdevice->name, ibvdevice, cma_id->port_num);
	} //for

	freeifaddrs(ifaddr);
}

void net_device_table_mgr::verify_bonding_mode(in_addr_t l_if)
{
	char if_name[IFNAMSIZ] = "\0";
	unsigned int if_flags; /* Flags as from SIOCGIFFLAGS ioctl. */

	sockaddr_in local_addr;
	local_addr.sin_addr.s_addr = l_if;
	struct sockaddr* local_sock_addr = (struct sockaddr*)&local_addr;  //m_local_sockaddr;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (get_ifinfo_from_ip(*local_sock_addr, if_name, if_flags)) {
		ndtm_logdbg("ERROR from get_ifaddrs_from_ip() (errno=%d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	//verify that this is a bonding master device
	if (if_flags & IFF_MASTER) {
		// this is a bond interface, lets get its mode.
		char bond_mode_file_content[FILENAME_MAX];
		char bond_failover_mac_file_content[FILENAME_MAX];
		char bond_mode_param_file[FILENAME_MAX];
		char bond_failover_mac_param_file[FILENAME_MAX];
		char *p_failover_mac_value = NULL;

		char base_ifname[IFNAMSIZ];
		if (get_base_interface_name((const char*)if_name, base_ifname, sizeof(base_ifname))) {
			vlog_printf(VLOG_ERROR,"VMA couldn't map %s for bonding mode validation\n", if_name);
			return;
		}

		memset(bond_mode_file_content, 0, FILENAME_MAX);
		sprintf(bond_mode_param_file, BONDING_MODE_PARAM_FILE, base_ifname);
		sprintf(bond_failover_mac_param_file, BONDING_FAILOVER_MAC_PARAM_FILE, base_ifname);

		if (priv_read_file(bond_mode_param_file, bond_mode_file_content, FILENAME_MAX) > 0) {
			char *bond_mode = NULL;

			bond_mode = strtok(bond_mode_file_content, " ");
			if (bond_mode && !strcmp(bond_mode, "active-backup"))
				if (priv_read_file(bond_failover_mac_param_file, bond_failover_mac_file_content, FILENAME_MAX) > 0) {
					p_failover_mac_value = strstr(bond_failover_mac_file_content, "1");
				}
		}

		if (!p_failover_mac_value) {
			vlog_printf(VLOG_WARNING,"******************************************************************************\n");
			vlog_printf(VLOG_WARNING,"VMA doesn't support current bonding configuration of %s.\n", base_ifname);
			vlog_printf(VLOG_WARNING,"The only supported bonding mode is \"active-backup(#1)\" with \"fail_over_mac=1\".\n");
			vlog_printf(VLOG_WARNING,"The effect of working in unsupported bonding mode is undefined.\n");
			vlog_printf(VLOG_WARNING,"Read more about Bonding in the VMA's User Manual\n");
			vlog_printf(VLOG_WARNING,"******************************************************************************\n");
		}
	}
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
					return ret;
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
						m_global_ring_pipe_fds[0], NULL)) && (errno != ENOENT)) {
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
