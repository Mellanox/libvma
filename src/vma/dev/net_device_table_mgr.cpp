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
	struct ifaddrs *ifaddr, *ifa;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (getifaddrs(&ifaddr) == -1) {
		ndtm_logerr("getifaddrs() failed (errno = %d %m)", errno); 
		return -1;
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

		bool valid = false;
		char base_ifname[IFNAMSIZ];
		get_base_interface_name((const char*)(ifa->ifa_name), base_ifname, sizeof(base_ifname));
		if (check_device_exist(base_ifname, BOND_DEVICE_FILE)) {
			// this is a bond interface (or a vlan/alias over bond), find the slaves
			valid = verify_bond_ipoib_or_eth_qp_creation(ifa, cma_id->port_num);
		} else {
			valid = verify_ipoib_or_eth_qp_creation(ifa->ifa_name, ifa, cma_id->port_num);
		}
		if (!valid) {
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

		ndtm_logdbg("Offload interface '%s': Mapped to ibv device '%s' [%p] on port %d",
				ifa->ifa_name, ib_ctx->get_ibv_device()->name, ib_ctx->get_ibv_device(), cma_id->port_num);

		IF_RDMACM_FAILURE(rdma_destroy_id(cma_id)) {
			ndtm_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
		} ENDIF_RDMACM_FAILURE;
	} //for

	freeifaddrs(ifaddr);

	return 0;
}

bool net_device_table_mgr::verify_bond_ipoib_or_eth_qp_creation(struct ifaddrs * ifa, uint8_t port_num)
{
	char base_ifname[IFNAMSIZ];
	get_base_interface_name((const char*)(ifa->ifa_name), base_ifname, sizeof(base_ifname));
	char slaves[IFNAMSIZ * MAX_SLAVES] = {0};
	if (!get_bond_slaves_name_list(base_ifname, slaves, sizeof slaves)) {
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded, slave list or bond name could not be found\n", ifa->ifa_name);
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		return false;
	}
	//go over all slaves and check preconditions
	bool bond_ok = true;
	char * slave_name;
	slave_name = strtok (slaves," ");
	while (slave_name != NULL)
	{
		char* p = strchr(slave_name, '\n');
		if (p) *p = '\0'; // Remove the tailing 'new line" char
		if (!verify_ipoib_or_eth_qp_creation(slave_name, ifa, port_num)) {
			//check all slaves but print only once for bond
			bond_ok =  false;
		}
		slave_name = strtok (NULL, " ");
	}
	if (!bond_ok) {
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* Bond %s will not be offloaded due to problem with it's slaves.\n", ifa->ifa_name);
		vlog_printf(VLOG_WARNING,"* Check warning messages for more information.\n");
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
	}
	return bond_ok;
}

//interface name can be slave while ifa struct can describe bond
bool net_device_table_mgr::verify_ipoib_or_eth_qp_creation(const char* interface_name, struct ifaddrs * ifa, uint8_t port_num)
{
	int iftype = get_iftype_from_ifname(interface_name);
	if (iftype == ARPHRD_INFINIBAND) {
		if (verify_enable_ipoib(interface_name) && verify_ipoib_mode(ifa)) {
			return true;
		}
	} else {
		if (verify_eth_qp_creation(interface_name, port_num)) {
			return true;
		}
	}
	return false;
}

bool net_device_table_mgr::verify_enable_ipoib(const char* ifname)
{
	NOT_IN_USE(ifname);
	if(!safe_mce_sys().enable_ipoib) {
		ndtm_logdbg("Blocking offload: IPoIB interfaces ('%s')", ifname);
		return false;
	}
	return true;
}

// Verify IPoIB is in 'datagram mode' for proper VMA with flow steering operation
// Also verify umcast is disabled for IB flow
bool net_device_table_mgr::verify_ipoib_mode(struct ifaddrs* ifa)
{
	char filename[256] = "\0";
	char ifname[IFNAMSIZ] = "\0";
	if (validate_ipoib_prop(ifa->ifa_name, ifa->ifa_flags, IPOIB_MODE_PARAM_FILE, "datagram", 8, filename, ifname)) {
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* IPoIB mode of interface '%s' is \"connected\" !\n", ifa->ifa_name);
		vlog_printf(VLOG_WARNING,"* Please change it to datagram: \"echo datagram > %s\" before loading your application with VMA library\n", filename);
		vlog_printf(VLOG_WARNING,"* VMA doesn't support IPoIB in connected mode.\n");
		vlog_printf(VLOG_WARNING,"* Please refer to VMA Release Notes for more information\n");
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		return false;
	}
	else {
		ndtm_logdbg("verified interface '%s' is running in datagram mode", ifa->ifa_name);
	}

	if (validate_ipoib_prop(ifa->ifa_name, ifa->ifa_flags, UMCAST_PARAM_FILE, "0", 1, filename, ifname)) { // Extract UMCAST flag (only for IB transport types)
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* UMCAST flag is Enabled for interface %s !\n", ifa->ifa_name);
		vlog_printf(VLOG_WARNING,"* Please disable it: \"echo 0 > %s\" before loading your application with VMA library\n", filename);
		vlog_printf(VLOG_WARNING,"* This option in no longer needed in this version\n");
		vlog_printf(VLOG_WARNING,"* Please refer to Release Notes for more information\n");
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		return false;
	}
	else {
		ndtm_logdbg("verified interface '%s' is running with umcast disabled", ifa->ifa_name);
	}
	return true;
}

//ifname should point to a physical device
bool net_device_table_mgr::verify_eth_qp_creation(const char* ifname, uint8_t port_num)
{
	int num_devices = 0;
	bool success = false;
	struct ibv_cq* cq = NULL;
	struct ibv_comp_channel *channel = NULL;
	struct ibv_qp* qp = NULL;

	struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	vma_ibv_cq_init_attr attr;
	memset(&attr, 0, sizeof(attr));

	qp_init_attr.cap.max_send_wr = safe_mce_sys().tx_num_wr;
	qp_init_attr.cap.max_recv_wr = safe_mce_sys().rx_num_wr;
	qp_init_attr.cap.max_inline_data = safe_mce_sys().tx_max_inline;
	qp_init_attr.cap.max_send_sge = MCE_DEFAULT_TX_NUM_SGE;
	qp_init_attr.cap.max_recv_sge = MCE_DEFAULT_RX_NUM_SGE;
	qp_init_attr.sq_sig_all = 0;
	qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;

	//find ib_cxt
	char base_ifname[IFNAMSIZ];
	get_base_interface_name((const char*)(ifname), base_ifname, sizeof(base_ifname));
	struct ibv_context** pp_ibv_context_list = rdma_get_devices(&num_devices);
	char resource_path[256];
	sprintf(resource_path, VERBS_DEVICE_RESOURCE_PARAM_FILE, base_ifname);
	char sys_res[1024] = {0};
	priv_safe_read_file(resource_path, sys_res, 1024);
	for (int j=0; j<num_devices; j++) {
		char ib_res[1024] = {0};
		char ib_path[256] = {0};
		sprintf(ib_path, "%s/device/resource", pp_ibv_context_list[j]->device->ibdev_path);
		priv_safe_read_file(ib_path, ib_res, 1024);
		if (strcmp(sys_res, ib_res) == 0) {
			//create qp resources
			ib_ctx_handler* p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(pp_ibv_context_list[j]);
			channel = ibv_create_comp_channel(p_ib_ctx->get_ibv_context());
			if (!channel) {
				ndtm_logdbg("channel creation failed for interface %s (errno=%d %m)", ifname, errno);
				success = false;
				break;
			}
			cq = vma_ibv_create_cq(p_ib_ctx->get_ibv_context(), safe_mce_sys().tx_num_wr, (void*)this, channel, 0, &attr);
			if (!cq) {
				ndtm_logdbg("cq creation failed for interface %s (errno=%d %m)", ifname, errno);
				success = false;
				break;
			}
			qp_init_attr.recv_cq = cq;
			qp_init_attr.send_cq = cq;
			qp = ibv_create_qp(p_ib_ctx->get_ibv_pd(), &qp_init_attr);
			if (qp) {
				success = true;

				if (!priv_ibv_query_flow_tag_state(qp, port_num)) {
					p_ib_ctx->set_flow_tag_capability(true);
				}
				ndtm_logdbg("verified interface %s for flow tag capabilities : %s", ifname, p_ib_ctx->get_flow_tag_capability() ? "enabled" : "disabled");

			} else {
				ndtm_logdbg("QP creation failed on interface %s (errno=%d %m), Traffic will not be offloaded \n", ifname, errno);
				success = false;
				int err = errno; //verify_raw_qp_privliges can overwrite errno so keep it before the call
				if (validate_raw_qp_privliges() == 0) {
					//// MLNX_OFED raw_qp_privliges file exist with bad value
					vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
					vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded.\n", ifname);
					vlog_printf(VLOG_WARNING,"* Working in this mode might causes VMA malfunction over Ethernet interfaces\n");
					vlog_printf(VLOG_WARNING,"* WARNING: the following steps will restart your network interface!\n");
					vlog_printf(VLOG_WARNING,"* 1. \"echo options ib_uverbs disable_raw_qp_enforcement=1 > /etc/modprobe.d/ib_uverbs.conf\"\n");
					vlog_printf(VLOG_WARNING,"* 2. \"/etc/init.d/openibd restart\"\n");
					vlog_printf(VLOG_WARNING,"* Read the RAW_PACKET QP root access enforcement section in the VMA's User Manual for more information\n");
					vlog_printf(VLOG_WARNING,"******************************************************************************************************\n");
				}
				else if (err == EPERM) {
					// file doesn't exists, print msg if errno is a permission problem
					vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
					vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded.\n", ifname);
					vlog_printf(VLOG_WARNING,"* Offloaded resources are restricted to root or user with CAP_NET_RAW privileges\n");
					vlog_printf(VLOG_WARNING,"* Read the CAP_NET_RAW and root access section in the VMA's User Manual for more information\n");
					vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
				}
			}
			break;
		}
	}
	//release resources
	if(qp) {
		IF_VERBS_FAILURE(ibv_destroy_qp(qp)) {
			ndtm_logdbg("qp destroy failed on interface %s (errno=%d %m)", ifname, errno);
			success = false;
		} ENDIF_VERBS_FAILURE;
	}
	if (cq) {
		IF_VERBS_FAILURE(ibv_destroy_cq(cq)) {
			ndtm_logdbg("cq destroy failed on interface %s (errno=%d %m)", ifname, errno);
			success = false;
		} ENDIF_VERBS_FAILURE;
	}
	if (channel) {
		IF_VERBS_FAILURE(ibv_destroy_comp_channel(channel)) {
			ndtm_logdbg("channel destroy failed on interface %s (errno=%d %m)", ifname, errno);
			success = false;
		} ENDIF_VERBS_FAILURE;
	}
	rdma_free_devices(pp_ibv_context_list);
	return success;
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
#if 0 /* TODO: see explanation */
		/* Do not call draining RX logic from internal thread for vma_poll mode
		 * It is disable by default
		 * See: cq_mgr::drain_and_proccess()
		 */
		global_ring_drain_and_procces();
#endif
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
