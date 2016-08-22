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



#include "vma/dev/net_device_val.h"
#include <string.h>
#include <ifaddrs.h>
#include "vma/util/if.h"
#include <sys/epoll.h>
#include <linux/if_infiniband.h>
#include <linux/if_ether.h>
#include <sys/epoll.h>

#include "utils/bullseye.h"
#include "vma/util/utils.h"
#include "vma/event/event_handler_manager.h"
#include "vma/proto/L2_address.h"
#include "vma/dev/ib_ctx_handler_collection.h"
#include "vma/dev/ring_simple.h"
#include "vma/dev/ring_bond.h"
#include "vma/sock/sock-redirect.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/proto/neighbour_table_mgr.h"



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

net_device_val::net_device_val(transport_type_t transport_type) : m_if_idx(0), m_local_addr(0),
m_netmask(0), m_mtu(0), m_state(INVALID), m_p_L2_addr(NULL), m_p_br_addr(NULL),
m_transport_type(transport_type),  m_lock("net_device_val lock"), m_bond(NO_BOND),
m_bond_xmit_hash_policy(XHP_LAYER_2), m_bond_fail_over_mac(0)
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
}

void net_device_val::try_read_dev_id_and_port(const char *base_ifname, int *dev_id, int *dev_port)
{
	// Depending of kernel version and OFED stack the files containing dev_id and dev_port may not exist.
	// if file reading fails *dev_id or *dev_port may remain unmodified
	char num_buf[24] = {0};
	char dev_path[256] = {0};
	sprintf(dev_path, VERBS_DEVICE_PORT_PARAM_FILE, base_ifname);
	if (priv_safe_try_read_file(dev_path, num_buf, sizeof(num_buf)) > 0) {
		*dev_port = strtol(num_buf, NULL, 0); // base=0 means strtol() can parse hexadecimal and decimal
		nd_logdbg("dev_port file=%s dev_port str=%s dev_port val=%d", dev_path, num_buf, *dev_port);
	}
	sprintf(dev_path, VERBS_DEVICE_ID_PARAM_FILE, base_ifname);
	if (priv_safe_try_read_file(dev_path, num_buf, sizeof(num_buf)) > 0) {
		*dev_id = strtol(num_buf, NULL, 0); // base=0 means strtol() can parse hexadecimal and decimal
		nd_logdbg("dev_id file= %s dev_id str=%s dev_id val=%d", dev_path, num_buf, *dev_id);
	}
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

	m_if_idx        = if_nametoindex(m_name.c_str());
	m_mtu           = get_if_mtu_from_ifname(m_name.c_str());
	if (safe_mce_sys().mtu != 0 && (int)safe_mce_sys().mtu != m_mtu) {
		nd_logwarn("Mismatch between interface %s MTU=%d and VMA_MTU=%d. Make sure VMA_MTU and all offloaded interfaces MTUs match.", m_name.c_str(), m_mtu, safe_mce_sys().mtu);
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

	if (get_base_interface_name(m_name.c_str(), m_base_name, sizeof(m_base_name))) {
		nd_logerr("couldn't resolve bonding base interface name from %s", m_name.c_str());
		return;
	}

	// gather the slave data (only for active-backup)-
	char active_slave[IFNAMSIZ] = {0};

	if (ifa->ifa_flags & IFF_MASTER || check_device_exist(m_base_name, BOND_DEVICE_FILE)) {
		// bond device

		verify_bonding_mode();
		// get list of all slave devices
		char slaves_list[IFNAMSIZ * MAX_SLAVES] = {0};
		if (get_bond_slaves_name_list(m_base_name, slaves_list, sizeof(slaves_list))) {
			char* slave = strtok(slaves_list, " ");
			while (slave) {
				slave_data_t* s = new slave_data_t;
				s->if_name = strdup(slave);
				char* p = strchr(s->if_name, '\n');
				if (p) *p = '\0'; // Remove the tailing 'new line" char
				m_slaves.push_back(s);
				slave = strtok(NULL, " ");
			}
		}

		// find the active slave
		if (get_bond_active_slave_name(m_base_name, active_slave, sizeof(active_slave))) {
			nd_logdbg("found the active slave: '%s'", active_slave);
			strncpy(m_active_slave_name, active_slave, sizeof(m_active_slave_name) - 1);
			m_active_slave_name[sizeof(m_active_slave_name) - 1] = '\0';
		}
		else {
			nd_logdbg("failed to find the active slave, Moving to LAG state");
		}
	}
	else {
		slave_data_t* s = new slave_data_t;
		s->if_name = strdup(m_name.c_str());
		m_slaves.push_back(s);
	}

	bool up_and_active_slaves[m_slaves.size()];
	memset(up_and_active_slaves, 0, sizeof(up_and_active_slaves));

	if (m_bond == LAG_8023ad) {
		get_up_and_active_slaves(up_and_active_slaves, m_slaves.size());
	}

	int num_devices = 0;
	struct ibv_context** pp_ibv_context_list = rdma_get_devices(&num_devices);
	for (uint16_t i=0; i<m_slaves.size(); i++) {
		// Save L2 address
		m_slaves[i]->p_L2_addr = create_L2_address(m_slaves[i]->if_name);
		m_slaves[i]->is_active_slave = false;

		if (m_bond == ACTIVE_BACKUP && strstr(active_slave, m_slaves[i]->if_name) != NULL){
			m_slaves[i]->is_active_slave = true;
		}

		if (m_bond == LAG_8023ad) {
			if (up_and_active_slaves[i]) {
				m_slaves[i]->is_active_slave = true;
			}
		}

		char base_ifname[IFNAMSIZ];
		if (get_base_interface_name((const char*)m_slaves[i]->if_name, base_ifname, sizeof(base_ifname))) {
			strncpy(base_ifname, m_slaves[i]->if_name, sizeof(base_ifname) - 1);
			base_ifname[sizeof(base_ifname) - 1] = '\0';
		}

		char resource_path[256];
		sprintf(resource_path, VERBS_DEVICE_RESOURCE_PARAM_FILE, base_ifname);
		char sys_res[1024] = {0};
		if (priv_read_file(resource_path, sys_res, 1024) > 0) {
			// find the ibv context and port num
			for (int j=0; j<num_devices; j++) {
				char ib_res[1024] = {0};
				char ib_path[256] = {0};
				sprintf(ib_path, "%s/device/resource", pp_ibv_context_list[j]->device->ibdev_path);
				if (priv_read_file(ib_path, ib_res, 1024) <= 0) {
					continue;
				}
				if (strcmp(sys_res, ib_res) == 0) {
					m_slaves[i]->p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(pp_ibv_context_list[j]);
					int dev_id = -1;
					int dev_port = -1;
					try_read_dev_id_and_port(base_ifname, &dev_id, &dev_port);
					// take the max between dev_port and dev_id as port number
					int port_num = (dev_port > dev_id) ? dev_port : dev_id;
					m_slaves[i]->port_num = port_num + 1;
					if (m_slaves[i]->port_num < 1) {
						nd_logdbg("Error: port %d ==> ifname=%s base_ifname=%s", m_slaves[i]->port_num, (const char*)m_slaves[i]->if_name, base_ifname);					
					}
					break;
				}
			}
		}
	}
	rdma_free_devices(pp_ibv_context_list);
}

void net_device_val::verify_bonding_mode()
{
	// this is a bond interface, lets get its mode.
	char bond_mode_file_content[FILENAME_MAX];
	char bond_failover_mac_file_content[FILENAME_MAX];
	char bond_mode_param_file[FILENAME_MAX];
	char bond_failover_mac_param_file[FILENAME_MAX];
	char bond_xmit_hash_policy_file_content[FILENAME_MAX];
	char bond_xmit_hash_policy_param_file[FILENAME_MAX];

	memset(bond_mode_file_content, 0, FILENAME_MAX);
	sprintf(bond_mode_param_file, BONDING_MODE_PARAM_FILE, m_base_name);
	sprintf(bond_failover_mac_param_file, BONDING_FAILOVER_MAC_PARAM_FILE, m_base_name);

	if (priv_safe_read_file(bond_mode_param_file, bond_mode_file_content, FILENAME_MAX) > 0) {
		char *bond_mode = NULL;
		bond_mode = strtok(bond_mode_file_content, " ");
		if (bond_mode) {
			if (!strcmp(bond_mode, "active-backup")) {
				m_bond = ACTIVE_BACKUP;
			} else if (strstr(bond_mode, "802.3ad")) {
				m_bond = LAG_8023ad;
			}
			if (priv_safe_read_file(bond_failover_mac_param_file, bond_failover_mac_file_content, FILENAME_MAX) > 0) {
				if(strstr(bond_failover_mac_file_content, "0")){
					m_bond_fail_over_mac = 0;
				} else if(strstr(bond_failover_mac_file_content, "1")){
					m_bond_fail_over_mac = 1;
				} else if(strstr(bond_failover_mac_file_content, "2")){
					m_bond_fail_over_mac = 2;
				}
			}
		}
	}

	memset(bond_xmit_hash_policy_file_content, 0, FILENAME_MAX);
	sprintf(bond_xmit_hash_policy_param_file, BONDING_XMIT_HASH_POLICY_PARAM_FILE, m_base_name);
	if (priv_safe_try_read_file(bond_xmit_hash_policy_param_file, bond_xmit_hash_policy_file_content, FILENAME_MAX) > 0) {
		char *bond_xhp = NULL;
		char *saveptr = NULL;

		bond_xhp = strtok_r(bond_xmit_hash_policy_file_content, " ", &saveptr);
		if (NULL == bond_xhp) {
			vlog_printf(VLOG_DEBUG, "could not parse bond xmit hash policy, staying with default (L2)\n");
		} else {
			bond_xhp = strtok_r(NULL, " ", &saveptr);
			if (bond_xhp) {
				m_bond_xmit_hash_policy = (bond_xmit_hash_policy)strtol(bond_xhp, NULL , 10);
				if (m_bond_xmit_hash_policy < XHP_LAYER_2 || m_bond_xmit_hash_policy > XHP_ENCAP_3_4) {
					vlog_printf(VLOG_WARNING,"VMA does not support xmit hash policy = %d\n", m_bond_xmit_hash_policy);
					m_bond_xmit_hash_policy = XHP_LAYER_2;
				}
			}
			vlog_printf(VLOG_DEBUG, "got bond xmit hash policy = %d\n", m_bond_xmit_hash_policy);
		}
	} else {
		vlog_printf(VLOG_DEBUG, "could not read bond xmit hash policy, staying with default (L2)\n");
	}

	if (m_bond == NO_BOND || m_bond_fail_over_mac > 1) {
		vlog_printf(VLOG_WARNING,"******************************************************************************\n");
		vlog_printf(VLOG_WARNING,"VMA doesn't support current bonding configuration of %s.\n", m_base_name);
		vlog_printf(VLOG_WARNING,"The only supported bonding mode is \"802.3ad 4(#4)\" or \"active-backup(#1)\"\n");
		vlog_printf(VLOG_WARNING,"with \"fail_over_mac=1\" or \"fail_over_mac=0\".\n");
		vlog_printf(VLOG_WARNING,"The effect of working in unsupported bonding mode is undefined.\n");
		vlog_printf(VLOG_WARNING,"Read more about Bonding in the VMA's User Manual\n");
		vlog_printf(VLOG_WARNING,"******************************************************************************\n");
	}
}

/**
 * only for active-backup bond
 */
bool net_device_val::update_active_backup_slaves()
{
	// update the active slave
	// /sys/class/net/bond0/bonding/active_slave
	char active_slave[IFNAMSIZ*MAX_SLAVES] = {0};
	if (!get_bond_active_slave_name(m_base_name, active_slave, IFNAMSIZ)) {
		nd_logdbg("failed to find the active slave!");
		return 0;
	}

	//nothing changed
	if (strcmp(m_active_slave_name, active_slave) == 0) {
		return 0;
	}

	delete_L2_address();
	m_p_L2_addr = create_L2_address(m_name.c_str());
	nd_logdbg("Slave changed old=%s new=%s",m_active_slave_name, active_slave);
	bool found_active_slave = false;
	size_t slave_count = m_slaves.size();
	ring_resource_creation_info_t p_ring_info[slave_count];
	for (size_t i = 0; i<slave_count; i++) {
		p_ring_info[i].p_ib_ctx = m_slaves[i]->p_ib_ctx;
		p_ring_info[i].port_num = m_slaves[i]->port_num;
		p_ring_info[i].p_l2_addr = m_slaves[i]->p_L2_addr;
		if (m_slaves[i]->is_active_slave)
			m_slaves[i]->is_active_slave = false;
		if (strstr(active_slave, m_slaves[i]->if_name) != NULL) {
			m_slaves[i]->is_active_slave = true;
			found_active_slave = true;
			nd_logdbg("Offload interface '%s': Re-mapped to ibv device '%s' [%p] on port %d",
					m_name.c_str(), p_ring_info[i].p_ib_ctx->get_ibv_device()->name, p_ring_info[i].p_ib_ctx->get_ibv_device(), p_ring_info[i].port_num);
		} else {
			m_slaves[i]->is_active_slave = false;
		}
		p_ring_info[i].active = m_slaves[i]->is_active_slave;
	}
	strncpy(m_active_slave_name,  active_slave, sizeof(m_active_slave_name) - 1);
	m_active_slave_name[sizeof(m_active_slave_name) - 1] = '\0';
	if (!found_active_slave) {
		nd_logdbg("Failed to locate new active slave details");
		return 0;
	}
	// restart rings
	rings_hash_map_t::iterator ring_iter;
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		THE_RING->restart(p_ring_info);
	}
	return 1;
}

/*
 * this function assume m_slaves[i]->if_name and m_slaves.size() are already set.
 */
bool net_device_val::get_up_and_active_slaves(bool* up_and_active_slaves, size_t size)
{
	bool up_slaves[m_slaves.size()];
	int num_up = 0;
	bool active_slaves[m_slaves.size()];
	int num_up_and_active = 0;
	size_t i = 0;

	if (size != m_slaves.size()) {
		nd_logwarn("programmer error! array size is not correct");
		return false;
	}

	/* get slaves operstate and active state */
	for (i = 0; i < m_slaves.size(); i++) {
		char oper_state[5] = {0};
		char slave_state[10] = {0};

		// get interface operstate
		get_interface_oper_state(m_slaves[i]->if_name, oper_state, sizeof(oper_state));
		if (strstr(oper_state, "up")) {
			num_up++;
			up_slaves[i] = true;
		} else {
			up_slaves[i] = false;
		}

		active_slaves[i] = true;
		// get slave state
		if (get_bond_slave_state(m_slaves[i]->if_name, slave_state, sizeof(slave_state))){
			if (!strstr(slave_state, "active"))
				active_slaves[i] = false;
		}

		if (active_slaves[i] && up_slaves[i]) {
			up_and_active_slaves[i] = true;
			num_up_and_active++;
		} else {
			up_and_active_slaves[i] = false;
		}
	}

	/* make sure at least one up interface is active */
	if (!num_up_and_active && num_up) {
		for (i = 0; i < m_slaves.size(); i++) {
			if (up_slaves[i]) {
				up_and_active_slaves[i] = true;
				break;
			}
		}
	}

	return true;
}

bool net_device_val::update_active_slaves() {
	bool changed = false;
	ring_resource_creation_info_t p_ring_info[m_slaves.size()];
	bool up_and_active_slaves[m_slaves.size()];
	size_t i = 0;

	get_up_and_active_slaves(up_and_active_slaves, m_slaves.size());

	/* compare to current status and prepare for restart */
	for (i = 0; i< m_slaves.size(); i++) {
		p_ring_info[i].p_ib_ctx = m_slaves[i]->p_ib_ctx;
		p_ring_info[i].port_num = m_slaves[i]->port_num;
		p_ring_info[i].p_l2_addr = m_slaves[i]->p_L2_addr;

		if (up_and_active_slaves[i]) {
			//slave came up
			if (!m_slaves[i]->is_active_slave) {
				nd_logdbg("slave %s is up ", m_slaves[i]->if_name);
				m_slaves[i]->is_active_slave = true;
				changed = true;
			}
		}
		else {
			//slave went down
			if (m_slaves[i]->is_active_slave) {
				nd_logdbg("slave %s is down ", m_slaves[i]->if_name);
				m_slaves[i]->is_active_slave = false;
				changed = true;
			}
		}
		p_ring_info[i].active = m_slaves[i]->is_active_slave;
	}

	/* restart if status changed */
	if (changed) {
		delete_L2_address();
		m_p_L2_addr = create_L2_address(m_name.c_str());
		// restart rings
		rings_hash_map_t::iterator ring_iter;
		for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
			THE_RING->restart(p_ring_info);
		}
		return 1;
	}
	return 0;
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
		if (!the_ring) {
			return NULL;
		}

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
	if (!safe_mce_sys().ring_limit_per_interface) return key;

	if (m_h_ring_key_redirection_map.find(key) != m_h_ring_key_redirection_map.end()) {
		m_h_ring_key_redirection_map[key].second++;
		nd_logdbg("redirecting key=%lu (ref-count:%d) to key=%lu", key,
			m_h_ring_key_redirection_map[key].second, m_h_ring_key_redirection_map[key].first);
		return m_h_ring_key_redirection_map[key].first;
	}

	int ring_map_size = (int)m_h_ring_map.size();
	if (safe_mce_sys().ring_limit_per_interface > ring_map_size) {
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

	if (!safe_mce_sys().ring_limit_per_interface) return ret_key;

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

void net_device_val::register_to_ibverbs_events(event_handler_ibverbs *handler) {
	for (size_t i = 0; i < m_slaves.size(); i++) {
		bool found = false;
		for (size_t j = 0; j < i; j++) {
			if (m_slaves[i]->p_ib_ctx == m_slaves[j]->p_ib_ctx) {
				found = true; //two slaves might be on two ports of the same device, register only once
				break;
			}
		}
		if (found)
			continue;
		nd_logfunc("registering slave to ibverbs events slave=%p", m_slaves[i]);
		g_p_event_handler_manager->register_ibverbs_event(m_slaves[i]->p_ib_ctx->get_ibv_context()->async_fd, handler, m_slaves[i]->p_ib_ctx->get_ibv_context(), 0);
	}
}

void net_device_val::unregister_to_ibverbs_events(event_handler_ibverbs *handler) {
	for (size_t i = 0; i < m_slaves.size(); i++) {
		bool found = false;
		for (size_t j = 0; j < i; j++) {
			if (m_slaves[i]->p_ib_ctx == m_slaves[j]->p_ib_ctx) {
				found = true; //two slaves might be on two ports of the same device, unregister only once
				break;
			}
		}
		if (found)
			continue;
		nd_logfunc("unregistering slave to ibverbs events slave=%p", m_slaves[i]);
		g_p_event_handler_manager->unregister_ibverbs_event(m_slaves[i]->p_ib_ctx->get_ibv_context()->async_fd, handler);
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
	if (m_vlan && m_bond != NO_BOND && m_bond_fail_over_mac == 1) {
		vlog_printf(VLOG_WARNING, " ******************************************************************\n");
		vlog_printf(VLOG_WARNING, "%s: vlan over bond while fail_over_mac=1 is not offloaded\n", m_name.c_str());
		vlog_printf(VLOG_WARNING, " ******************************************************************\n");
		m_state = INVALID;
	}
	if(!m_vlan && ifa->ifa_flags & IFF_MASTER) {
		//in case vlan is configured on slave
		m_vlan = get_vlan_id_from_ifname(m_slaves[0]->if_name);
	}
}

ring* net_device_val_eth::create_ring()
{
	size_t slave_count = m_slaves.size();
	if(slave_count == 0) {
		nd_logpanic("Bonding configuration problem. No slave found.");
	}
	ring_resource_creation_info_t p_ring_info[slave_count];
	bool active_slaves[slave_count];
	for (size_t i = 0; i<slave_count; i++) {
		p_ring_info[i].p_ib_ctx = m_slaves[i]->p_ib_ctx;
		p_ring_info[i].port_num = m_slaves[i]->port_num;
		p_ring_info[i].p_l2_addr = m_slaves[i]->p_L2_addr;
		active_slaves[i] = m_slaves[i]->is_active_slave;
	}

	 //TODO check if need to create bond ring even if slave count is 1
	if (m_bond != NO_BOND) {
		ring_bond_eth* ring;
		try {
			ring = new ring_bond_eth(m_local_addr, p_ring_info, slave_count, active_slaves, get_vlan(), m_bond, m_bond_xmit_hash_policy, m_mtu);
		} catch (vma_error &error) {
			return NULL;
		}
		return ring;
	} else {
		ring_eth* ring;
		try {
			ring = new ring_eth(m_local_addr, p_ring_info, slave_count, true, get_vlan(), m_mtu);
		} catch (vma_error &error) {
			return NULL;
		}
		return ring;
	}
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
	struct in_addr in;
	if (1 == inet_pton(AF_INET, BROADCAST_IP, &in)) {
		g_p_neigh_table_mgr->unregister_observer(neigh_key(ip_address(in.s_addr), this), this);
	}
}

void net_device_val_ib::configure(struct ifaddrs* ifa, struct rdma_cm_id* cma_id)
{
	struct in_addr in;

	net_device_val::configure(ifa, cma_id);

	delete_L2_address();
	m_p_L2_addr = create_L2_address(m_name.c_str());

	BULLSEYE_EXCLUDE_BLOCK_START
	if(m_p_L2_addr == NULL) {
		nd_logpanic("m_p_L2_addr allocation error");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	create_br_address(m_name.c_str());

	if (1 == inet_pton(AF_INET, BROADCAST_IP, &in)) {
		g_p_neigh_table_mgr->unregister_observer(neigh_key(ip_address(in.s_addr), this), this);
	}

	//Register to IB BR neigh
	cache_entry_subject<neigh_key, neigh_val*>* p_ces = NULL;
	if (1 == inet_pton(AF_INET, BROADCAST_IP, &in)) {
		g_p_neigh_table_mgr->register_observer(neigh_key(ip_address(in.s_addr), this), this, &p_ces);
	}
	m_br_neigh = dynamic_cast<neigh_ib_broadcast*>(p_ces);

	m_pkey = cma_id->route.addr.addr.ibaddr.pkey; // In order to create a UD QP outside the RDMA_CM API we need the pkey value (qp_mgr will convert it to pkey_index)
}

ring* net_device_val_ib::create_ring()
{
	size_t slave_count = m_slaves.size();
	if(slave_count == 0) {
		nd_logpanic("Bonding configuration problem. No slave found.");
	}
	ring_resource_creation_info_t p_ring_info[slave_count];
	bool active_slaves[slave_count];
	for (size_t i = 0; i<slave_count; i++) {
		p_ring_info[i].p_ib_ctx = m_slaves[i]->p_ib_ctx;
		p_ring_info[i].port_num = m_slaves[i]->port_num;
		p_ring_info[i].p_l2_addr = m_slaves[i]->p_L2_addr;
		active_slaves[i] = m_slaves[i]->is_active_slave;
	}

	if (m_bond != NO_BOND) {
		ring_bond_ib* ring;
		try {
			ring = new ring_bond_ib(m_local_addr, p_ring_info, slave_count, active_slaves, m_pkey, m_bond, m_bond_xmit_hash_policy, m_mtu);
		} catch (vma_error &error) {
			return NULL;
		}
		return ring;
	} else {
		ring_ib* ring;
		try {
			ring = new ring_ib(m_local_addr, p_ring_info, slave_count, true, m_pkey, m_mtu);
		} catch (vma_error &error) {
			return NULL;
		}
		return ring;
	}
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



