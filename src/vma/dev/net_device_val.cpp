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



#include "vma/dev/net_device_val.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if_infiniband.h>
#include <linux/if_ether.h>
#include <sys/epoll.h>

#include "vma/util/utils.h"
#include "vma/event/event_handler_manager.h"
#include "vma/proto/L2_address.h"
#include "vma/dev/ib_ctx_handler_collection.h"
#include "vma/dev/ring.h"
#include "vma/sock/sock-redirect.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/proto/neighbour_table_mgr.h"

#include "vma/util/bullseye.h"


#define MODULE_NAME             "ndv"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[%s]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_name.c_str()


#define nd_logpanic           __log_panic
#define nd_logerr             __log_err
#define nd_logwarn            __log_warn
#define nd_loginfo            __log_info
#define nd_logdbg             __log_info_dbg
#define nd_logfunc            __log_info_func
#define nd_logfuncall         __log_info_funcall


net_device_val::net_device_val(transport_type_t transport_type) : m_if_idx(0), m_local_addr(0), m_netmask(0), m_mtu(0), m_state(INVALID), m_p_L2_addr(NULL), m_p_br_addr(NULL), m_transport_type(transport_type),  m_lock("net_device_val lock"), m_cma_id(NULL)
{
}

net_device_val::~net_device_val()
{
	auto_unlocker lock(m_lock);
	rings_hash_map_t::iterator ring_iter;
	while ((ring_iter = m_h_ring_map.begin()) != m_h_ring_map.end()) {
		delete THE_RING;
		m_h_ring_map.erase(ring_iter);
	}

	if (m_p_br_addr) {
		delete m_p_br_addr;
		m_p_br_addr = NULL;
	}

	if (m_p_L2_addr) {
		delete m_p_L2_addr;
		m_p_L2_addr = NULL;
	}
	IF_RDMACM_FAILURE(rdma_destroy_id(m_cma_id)) {
		nd_logerr("Failed in rdma_destroy_id (errno=%d %m)", errno);
	} ENDIF_RDMACM_FAILURE;
}

void net_device_val::configure(struct ifaddrs* ifa, struct rdma_cm_id* cma_id)
{
	nd_logdbg("");

	if (NULL == ifa) {
		// invalid net_device_val
		nd_logerr("Invalid net_device_val name=%s", "NA");
		m_state = INVALID;
		return;
	}

	m_name = ifa->ifa_name;

	if (NULL == cma_id) {
		// invalid net_device_val
		nd_logerr("Invalid net_device_val name=%s", ifa->ifa_name);
		m_state = INVALID;
		return;
	}

	m_p_L2_addr	= NULL;
	m_cma_id        = cma_id;
	m_if_idx        = if_nametoindex(m_name.c_str());
	m_mtu           = get_if_mtu_from_ifname(m_name.c_str(), (m_transport_type != VMA_TRANSPORT_IB));
	if (m_mtu != (int)mce_sys.mtu) {
		nd_logwarn("Mismatch between interface %s MTU=%d and VMA_MTU=%d. Make sure VMA_MTU and all offloaded interfaces MTUs match.", m_name.c_str(), m_mtu, mce_sys.mtu);
	}
	m_local_addr    = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
	m_netmask       = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;

	if (ifa->ifa_flags & IFF_RUNNING) {
		m_state = RUNNING;
	}
	else {
		if (ifa->ifa_flags & IFF_UP) {
			m_state = UP;
		}
		else {
			m_state = DOWN;
		}
	}

	// gather the slave data -
	char active_slave[IFNAMSIZ] = {0};
	if (ifa->ifa_flags & IFF_MASTER) {
		// bond device

		char base_ifname[IFNAMSIZ];
		if (get_base_interface_name(m_name.c_str(), base_ifname, sizeof(base_ifname))) {
			nd_logerr("couldn't resolve bonding base interface name from %s", m_name.c_str());
			return;
		}

		// get list of all slave devices
		char slaves_list[IFNAMSIZ*16] = {0};
		get_bond_slaves_name_list(base_ifname, slaves_list, sizeof(slaves_list));
		char* slave = strtok(slaves_list, " ");
		while (slave) {
			slave_data_t* s = new slave_data_t;
			s->if_name = strdup(slave);
			char* p = strchr(s->if_name, '\n');
			if (p) *p = '\0'; // Remove the tailing 'new line" char
			m_slaves.push_back(s);
			slave = strtok(NULL, " ");
		}

		// find the active slave
		if (get_bond_active_slave_name(base_ifname, active_slave, sizeof(active_slave))) {
			nd_logdbg("found the active slave: '%s'", active_slave);
		}
		else {
			nd_logdbg("failed to find the active slave!");
		}
	}
	else {
		slave_data_t* s = new slave_data_t;
		s->if_name = strdup(m_name.c_str());
		m_slaves.push_back(s);
	}
	int num_devices = 0;
	struct ibv_context** pp_ibv_context_list = rdma_get_devices(&num_devices);
	for (uint16_t i=0; i<m_slaves.size(); i++) {

		// Save L2 address
		m_slaves[i]->p_L2_addr = create_L2_address(m_slaves[i]->if_name);
		m_slaves[i]->is_active_slave = false;

		if (strcmp(active_slave, m_slaves[i]->if_name) == 0)
			m_slaves[i]->is_active_slave = true;

		char base_ifname[IFNAMSIZ];
		if (get_base_interface_name((const char*)m_slaves[i]->if_name, base_ifname, sizeof(base_ifname))) {
			strcpy(base_ifname, m_slaves[i]->if_name);
		}

		char resource_path[256];
		sprintf(resource_path, VERBS_DEVICE_RESOURCE_PARAM_FILE, base_ifname);
		char sys_res[1024] = {0};
		priv_read_file(resource_path, sys_res, 1024);
		// find the ibv context and port num
		for (int j=0; j<num_devices; j++) {
			char ib_res[1024] = {0};
			char ib_path[256] = {0};
			sprintf(ib_path, "%s/device/resource", pp_ibv_context_list[j]->device->ibdev_path);
			priv_read_file(ib_path, ib_res, 1024);
			if (strcmp(sys_res, ib_res) == 0) {
				m_slaves[i]->p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(pp_ibv_context_list[j]);
				char num_buf[24] = {0};
				char dev_id_path[256] = {0};
				sprintf(dev_id_path, VERBS_DEVICE_ID_PARAM_FILE, base_ifname);
				priv_read_file(dev_id_path, num_buf, 24);
				int port_num;
				char *endptr;
				port_num = strtol(num_buf, &endptr, 16);
				m_slaves[i]->port_num = port_num + 1;
				break;
			}
		}
	}
	rdma_free_devices(pp_ibv_context_list);
}

bool net_device_val::handle_event_rdma_cm(struct rdma_cm_event* p_event)
{
	// locked by caller
	nd_logdbg("Got event %s (%d)", rdma_event_str(p_event->event), p_event->event);

	bool ret = false;

	switch(p_event->event) {
	case RDMA_CM_EVENT_ADDR_CHANGE:
		delete_L2_address();
		m_p_L2_addr = create_L2_address(m_name.c_str());
		ret = handle_event_ADDR_CHANGE();
		break;
	default:
		break;
	}

	return ret;
}

bool net_device_val::handle_event_ADDR_CHANGE()
{
	// locked by caller
	nd_logdbg("Handling RDMA_CM_EVENT_ADDR_CHANGE");

	// save the event channel
	struct rdma_event_channel* saved_channel = m_cma_id->channel;

	// release the old cma_id
	IF_RDMACM_FAILURE(rdma_destroy_id(m_cma_id)) {
		nd_logerr("Handling RDMA_CM_EVENT_ADDR_CHANGE Event: Failed in rdma_destroy_id (errno=%d %m)", errno);
	} ENDIF_RDMACM_FAILURE;

	// create new cma_id
	IF_RDMACM_FAILURE(rdma_create_id(saved_channel, &m_cma_id, NULL, RDMA_PS_UDP)) { // UDP vs IP_OVER_IB?
		nd_logerr("Handling RDMA_CM_EVENT_ADDR_CHANGE Event: Failed in rdma_create_id (RDMA_PS_UDP) (errno=%d %m)", errno);
		return false;
	} ENDIF_RDMACM_FAILURE;

	struct sockaddr_in local_sockaddr;
	local_sockaddr.sin_family = AF_INET;
	local_sockaddr.sin_port = INPORT_ANY;
	local_sockaddr.sin_addr.s_addr = m_local_addr;

	IF_RDMACM_FAILURE(rdma_bind_addr(m_cma_id, (struct sockaddr*)&local_sockaddr)) {
		nd_logerr("Handling RDMA_CM_EVENT_ADDR_CHANGE Event: Failed in rdma_bind_addr (src=%d.%d.%d.%d) (errno=%d %m)", NIPQUAD(m_local_addr), errno);
		return false;
	} ENDIF_RDMACM_FAILURE;

	// update the active slave
	// /sys/class/net/bond0/bonding/active_slave
	char active_slave[IFNAMSIZ] = {0};
	if (get_bond_active_slave_name(m_name.c_str(), active_slave, IFNAMSIZ)) {
		nd_logdbg("Found the active slave: '%s'", active_slave);
	}
	else {
		nd_logdbg("failed to find the active slave!");

	}

	bool found_active_slave = false;
	size_t slave_count = m_slaves.size();
	ring_resource_creation_info_t p_ring_info[1];
	for (size_t i = 0; i<slave_count; i++) {
		if (strcmp(active_slave, m_slaves[i]->if_name) == 0) {
			p_ring_info[0].p_ib_ctx = m_slaves[i]->p_ib_ctx;
			p_ring_info[0].port_num = m_slaves[i]->port_num;
			p_ring_info[0].p_l2_addr = m_slaves[i]->p_L2_addr;
			found_active_slave = true;
			break;
		}
	}

	if (!found_active_slave) {
		nd_logdbg("Failed to locate new active slave details");
	}
	else {
		struct ibv_device* p_ibv_device = p_ring_info[0].p_ib_ctx->get_ibv_device();
		nd_logdbg("Offload interface '%s': Re-mapped to ibv device '%s' [%p] on port %d",
				m_name.c_str(), p_ibv_device->name, p_ibv_device, p_ring_info[0].port_num);

		// restart rings
		rings_hash_map_t::iterator ring_iter;
		for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
			THE_RING->restart(p_ring_info);
		}
	}

	return true;
}

std::string net_device_val::to_str()
{
	return std::string("Net Device: " + m_name);
}

ring* net_device_val::reserve_ring(IN resource_allocation_key key)
{
	nd_logfunc("");
	auto_unlocker lock(m_lock);
	key = ring_key_redirection_reserve(key);
	ring* the_ring = NULL;
	rings_hash_map_t::iterator ring_iter = m_h_ring_map.find(key);
	if (m_h_ring_map.end() == ring_iter) {
		nd_logdbg("Creating new RING for key %#x", key);

		the_ring = create_ring();

		m_h_ring_map[key] = std::make_pair(the_ring, 0); // each ring is born with ref_count = 0
		ring_iter = m_h_ring_map.find(key);
		struct epoll_event ev;
		int num_ring_rx_fds = the_ring->get_num_resources();
		int *ring_rx_fds_array = the_ring->get_rx_channel_fds();
		ev.events = EPOLLIN;
		for (int i = 0; i < num_ring_rx_fds; i++) {
			int cq_ch_fd = ring_rx_fds_array[i];
			ev.data.fd = cq_ch_fd;
			BULLSEYE_EXCLUDE_BLOCK_START
			if (unlikely( orig_os_api.epoll_ctl(g_p_net_device_table_mgr->global_ring_epfd_get(),
					EPOLL_CTL_ADD, cq_ch_fd, &ev))) {
				nd_logerr("Failed to add RING notification fd to global_table_mgr_epfd (errno=%d %m)", errno);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}

		g_p_net_device_table_mgr->global_ring_wakeup();
	}
	// now we are sure the ring is in the map

	ADD_RING_REF_CNT;
	the_ring = GET_THE_RING(key);

	nd_logdbg("Ref usage of RING %p for key %#x is %d", the_ring, key, RING_REF_CNT);

	return the_ring;
}

bool net_device_val::release_ring(IN resource_allocation_key key)
{
	nd_logfunc("");
	auto_unlocker lock(m_lock);
	key = ring_key_redirection_release(key);
	rings_hash_map_t::iterator ring_iter = m_h_ring_map.find(key);
	if (m_h_ring_map.end() != ring_iter) {
		DEC_RING_REF_CNT;
		if ( TEST_REF_CNT_ZERO ) {
			int num_ring_rx_fds = THE_RING->get_num_resources();
			int *ring_rx_fds_array = THE_RING->get_rx_channel_fds();
			nd_logdbg("Deleting RING %p for key %#x and removing notification fd from global_table_mgr_epfd (epfd=%d)", THE_RING, key,
					g_p_net_device_table_mgr->global_ring_epfd_get());
			for (int i = 0; i < num_ring_rx_fds; i++) {
				int cq_ch_fd = ring_rx_fds_array[i];
				BULLSEYE_EXCLUDE_BLOCK_START
				if (unlikely(orig_os_api.epoll_ctl(g_p_net_device_table_mgr->global_ring_epfd_get(),
						EPOLL_CTL_DEL, cq_ch_fd, NULL))) {
					nd_logerr("Failed to delete RING notification fd to global_table_mgr_epfd (errno=%d %m)", errno);
				}
				BULLSEYE_EXCLUDE_BLOCK_END
			}

			delete THE_RING;
			m_h_ring_map.erase(ring_iter);
		}
		else {
			nd_logdbg("Deref usage of RING %p for key %#x (count is %d)", THE_RING, key, RING_REF_CNT);
		}
		return true;
	}
	return false;
}

resource_allocation_key net_device_val::ring_key_redirection_reserve(IN resource_allocation_key key)
{
	if (!mce_sys.ring_limit_per_interface) return key;

	if (m_h_ring_key_redirection_map.find(key) != m_h_ring_key_redirection_map.end()) {
		m_h_ring_key_redirection_map[key].second++;
		nd_logdbg("redirecting key=%lu (ref-count:%d) to key=%lu", key,
			m_h_ring_key_redirection_map[key].second, m_h_ring_key_redirection_map[key].first);
		return m_h_ring_key_redirection_map[key].first;
	}

	int ring_map_size = (int)m_h_ring_map.size();
	if (mce_sys.ring_limit_per_interface > ring_map_size) {
		m_h_ring_key_redirection_map[key] = std::make_pair(ring_map_size, 1);
		nd_logdbg("redirecting key=%lu (ref-count:1) to key=%lu", key, ring_map_size);
		return ring_map_size;
	}

	rings_hash_map_t::iterator ring_iter = m_h_ring_map.begin();
	int min_ref_count = ring_iter->second.second;
	resource_allocation_key min_key = ring_iter->first;
	while (ring_iter != m_h_ring_map.end()) {
		if (ring_iter->second.second < min_ref_count) {
			min_ref_count = ring_iter->second.second;
			min_key = ring_iter->first;
		}
		ring_iter++;
	}
	m_h_ring_key_redirection_map[key] = std::make_pair(min_key, 1);
	nd_logdbg("redirecting key=%lu (ref-count:1) to key=%lu", key, min_key);
	return min_key;
}

resource_allocation_key net_device_val::ring_key_redirection_release(IN resource_allocation_key key)
{
	resource_allocation_key ret_key = key;

	if (!mce_sys.ring_limit_per_interface) return ret_key;

	if (m_h_ring_key_redirection_map.find(key) == m_h_ring_key_redirection_map.end()) {
		nd_logdbg("key = %lu is not found in the redirection map", key);
		return ret_key;
	}

	nd_logdbg("release redirecting key=%lu (ref-count:%d) to key=%lu", key,
			m_h_ring_key_redirection_map[key].second, m_h_ring_key_redirection_map[key].first);
	ret_key = m_h_ring_key_redirection_map[key].first;
	if (--m_h_ring_key_redirection_map[key].second == 0) {
		m_h_ring_key_redirection_map.erase(key);
	}

	return ret_key;
}

int net_device_val::global_ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array /*=NULL*/)
{
	nd_logfuncall("");
	int ret_total = 0;
	auto_unlocker lock(m_lock);
	rings_hash_map_t::iterator ring_iter;
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		int ret = THE_RING->poll_and_process_element_rx(p_poll_sn, pv_fd_ready_array);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0 && errno != EAGAIN) {
			nd_logerr("Error in ring->poll_and_process_element() of %p (errno=%d %m)", THE_RING, errno);
			return ret;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (ret > 0)
			nd_logfunc("ring[%p] Returned with: %d (sn=%d)", THE_RING, ret, *p_poll_sn);
		ret_total += ret;
	}
	return ret_total;
}

int net_device_val::global_ring_request_notification(uint64_t poll_sn)
{
	int ret_total = 0;
	auto_unlocker lock(m_lock);
	rings_hash_map_t::iterator ring_iter;
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		int ret = THE_RING->request_notification(CQT_RX, poll_sn);
		if (ret < 0) {
			nd_logerr("Error ring[%p]->request_notification() (errno=%d %m)", THE_RING, errno);
			return ret;
		}
		nd_logfunc("ring[%p] Returned with: %d (sn=%d)", THE_RING, ret, poll_sn);
		ret_total += ret;
	}
	return ret_total;
}

int net_device_val::ring_drain_and_proccess()
{
	nd_logfuncall();
	int ret_total = 0;

	auto_unlocker lock(m_lock);
	rings_hash_map_t::iterator ring_iter;
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		int ret = THE_RING->drain_and_proccess(CQT_RX);
		if (ret < 0)
			return ret;
		if (ret > 0)
			nd_logfunc("cq[%p] Returned with: %d", THE_RING, ret);
		ret_total += ret;
	}
	return ret_total;
}

void net_device_val::ring_adapt_cq_moderation()
{
	nd_logfuncall();

	auto_unlocker lock(m_lock);
	rings_hash_map_t::iterator ring_iter;
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		THE_RING->adapt_cq_moderation();
	}
}

void net_device_val::delete_L2_address()
{
	if (m_p_L2_addr) {
		delete m_p_L2_addr;
		m_p_L2_addr = NULL;
	}
}

void net_device_val_eth::configure(struct ifaddrs* ifa, struct rdma_cm_id* cma_id)
{
	net_device_val::configure(ifa, cma_id);

	delete_L2_address();
	m_p_L2_addr = create_L2_address(m_name.c_str());

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_L2_addr == NULL) {
		nd_logpanic("m_p_L2_addr allocation error");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	create_br_address(m_name.c_str());

	m_vlan = get_vlan_id_from_ifname(m_name.c_str());
	if(!m_vlan && ifa->ifa_flags & IFF_MASTER) {
		//in case vlan is configured on slave
		m_vlan = get_vlan_id_from_ifname(m_slaves[0]->if_name);
	}
}

ring* net_device_val_eth::create_ring()
{
	// Prepare list of all slave
	int active_slave = 0;
	size_t slave_count = m_slaves.size();
	if(slave_count == 0) {
		nd_logpanic("Bonding configuration problem. No slave found.");
	}
	ring_resource_creation_info_t p_ring_info[slave_count];
	for (size_t i = 0; i<slave_count; i++) {
		p_ring_info[i].p_ib_ctx = m_slaves[i]->p_ib_ctx;
		p_ring_info[i].port_num = m_slaves[i]->port_num;
		p_ring_info[i].p_l2_addr = m_slaves[i]->p_L2_addr;
		if (m_slaves[i]->is_active_slave)
			active_slave = i;
	}

	return new ring_eth(m_local_addr, p_ring_info, slave_count, active_slave, get_vlan());
}

L2_address* net_device_val_eth::create_L2_address(const char* ifname)
{
	unsigned char hw_addr[ETH_ALEN];
	get_local_ll_addr(ifname, hw_addr, ETH_ALEN, false);
	return new ETH_addr(hw_addr);
}

void net_device_val_eth::create_br_address(const char* ifname)
{
	if(m_p_br_addr) {
		delete m_p_br_addr;
		m_p_br_addr = NULL;
	}
	uint8_t hw_addr[ETH_ALEN];
	get_local_ll_addr(ifname, hw_addr, ETH_ALEN, true);
	m_p_br_addr = new ETH_addr(hw_addr);

	BULLSEYE_EXCLUDE_BLOCK_START
	if(m_p_br_addr == NULL) {
		nd_logpanic("m_p_br_addr allocation error");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}
std::string net_device_val_eth::to_str()
{
	return std::string("ETH: " + net_device_val::to_str());
}

net_device_val_ib::~net_device_val_ib()
{
	g_p_neigh_table_mgr->unregister_observer(neigh_key(ip_address((in_addr_t)(inet_addr(BROADCAST_IP))), this), this);
}

void net_device_val_ib::configure(struct ifaddrs* ifa, struct rdma_cm_id* cma_id)
{
	net_device_val::configure(ifa, cma_id);

	delete_L2_address();
	m_p_L2_addr = create_L2_address(m_name.c_str());

	BULLSEYE_EXCLUDE_BLOCK_START
	if(m_p_L2_addr == NULL) {
		nd_logpanic("m_p_L2_addr allocation error");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	create_br_address(m_name.c_str());

	g_p_neigh_table_mgr->unregister_observer(neigh_key(ip_address((in_addr_t)(inet_addr(BROADCAST_IP))), this), this);

	//Register to IB BR neigh
	cache_entry_subject<neigh_key, neigh_val*>* p_ces = NULL;
	g_p_neigh_table_mgr->register_observer(neigh_key(ip_address((in_addr_t)(inet_addr(BROADCAST_IP))), this), this, &p_ces);
	m_br_neigh = dynamic_cast<neigh_ib_broadcast*>(p_ces);

	m_pkey = m_cma_id->route.addr.addr.ibaddr.pkey; // In order to create a UD QP outside the RDMA_CM API we need the pkey value (qp_mgr will convert it to pkey_index)
}

ring* net_device_val_ib::create_ring()
{
	// Prepare list of all slave
	int active_slave = 0;
	size_t slave_count = m_slaves.size();
	if(slave_count == 0) {
		nd_logpanic("Bonding configuration problem. No slave found.");
	}
	ring_resource_creation_info_t p_ring_info[slave_count];
	for (size_t i = 0; i<slave_count; i++) {
		p_ring_info[i].p_ib_ctx = m_slaves[i]->p_ib_ctx;
		p_ring_info[i].port_num = m_slaves[i]->port_num;
		p_ring_info[i].p_l2_addr = m_slaves[i]->p_L2_addr;
		if (m_slaves[i]->is_active_slave)
			active_slave = i;
	}

	return new ring_ib(m_local_addr, p_ring_info, slave_count, active_slave, m_pkey);
}

L2_address* net_device_val_ib::create_L2_address(const char* ifname)
{
	unsigned char hw_addr[IPOIB_HW_ADDR_LEN];
	get_local_ll_addr(ifname, hw_addr, IPOIB_HW_ADDR_LEN, false);
	return new IPoIB_addr(hw_addr);
}

void net_device_val_ib::create_br_address(const char* ifname)
{
	if (m_p_br_addr) {
		delete m_p_br_addr;
		m_p_br_addr = NULL;
	}
	unsigned char hw_addr[IPOIB_HW_ADDR_LEN];
	get_local_ll_addr(ifname, hw_addr, IPOIB_HW_ADDR_LEN, true);
	m_p_br_addr = new IPoIB_addr(hw_addr);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_br_addr == NULL) {
		nd_logpanic("m_p_br_addr allocation error");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

std::string net_device_val_ib::to_str()
{
	return std::string("IB: " + net_device_val::to_str());
}



