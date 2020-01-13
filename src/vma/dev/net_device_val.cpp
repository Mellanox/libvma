/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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



#include <string.h>
#include <ifaddrs.h>
#include <sys/epoll.h>
#include <linux/if_infiniband.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/if_tun.h>
#include <sys/epoll.h>

#include "utils/bullseye.h"
#include "vma/util/if.h"
#include "vma/dev/net_device_val.h"
#include "vma/util/vtypes.h"
#include "vma/util/utils.h"
#include "vma/util/valgrind.h"
#include "vma/event/event_handler_manager.h"
#include "vma/proto/L2_address.h"
#include "vma/dev/ib_ctx_handler_collection.h"
#include "vma/dev/ring_tap.h"
#include "vma/dev/ring_simple.h"
#include "vma/dev/ring_eth_cb.h"
#include "vma/dev/ring_eth_direct.h"
#include "vma/dev/ring_slave.h"
#include "vma/dev/ring_bond.h"
#include "vma/sock/sock-redirect.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "ring_profile.h"

#ifdef HAVE_LIBNL3
#include <netlink/route/link/vlan.h>
#endif

#define MODULE_NAME             "ndv"

#define nd_logpanic           __log_panic
#define nd_logerr             __log_err
#define nd_logwarn            __log_warn
#define nd_loginfo            __log_info
#define nd_logdbg             __log_info_dbg
#define nd_logfunc            __log_info_func
#define nd_logfuncall         __log_info_funcall

ring_alloc_logic_attr::ring_alloc_logic_attr():
				m_ring_alloc_logic(RING_LOGIC_PER_INTERFACE),
				m_ring_profile_key(0),
				m_user_id_key(0)
{
	m_mem_desc.iov_base = NULL;
	m_mem_desc.iov_len = 0;
	init();
}

ring_alloc_logic_attr::ring_alloc_logic_attr(ring_logic_t ring_logic):
				m_ring_alloc_logic(ring_logic),
				m_ring_profile_key(0),
				m_user_id_key(0)
{
	m_mem_desc.iov_base = NULL;
	m_mem_desc.iov_len = 0;
	init();
}

ring_alloc_logic_attr::ring_alloc_logic_attr(const ring_alloc_logic_attr &other):
	m_hash(other.m_hash),
	m_ring_alloc_logic(other.m_ring_alloc_logic),
	m_ring_profile_key(other.m_ring_profile_key),
	m_user_id_key(other.m_user_id_key),
	m_mem_desc(other.m_mem_desc)
{
	snprintf(m_str, RING_ALLOC_STR_SIZE, "%s", other.m_str);
}

void ring_alloc_logic_attr::init()
{
	size_t h = 5381;
	int c;
	char buff[RING_ALLOC_STR_SIZE];

	snprintf(m_str, RING_ALLOC_STR_SIZE,
		 "allocation logic %d profile %d key %ld user address %p "
		 "user length %zd", m_ring_alloc_logic, m_ring_profile_key,
		 m_user_id_key, m_mem_desc.iov_base, m_mem_desc.iov_len);
	snprintf(buff, RING_ALLOC_STR_SIZE, "%d%d%ld%p%zd", m_ring_alloc_logic,
		 m_ring_profile_key, m_user_id_key, m_mem_desc.iov_base,
		 m_mem_desc.iov_len);
	const char* chr = buff;
	while ((c = *chr++))
		h = ((h << 5) + h) + c; /* m_hash * 33 + c */
	m_hash = h;
}

void ring_alloc_logic_attr::set_ring_alloc_logic(ring_logic_t logic)
{
	if (m_ring_alloc_logic != logic) {
		m_ring_alloc_logic = logic;
		init();
	}
}

void ring_alloc_logic_attr::set_ring_profile_key(vma_ring_profile_key profile)
{
	if (m_ring_profile_key != profile) {
		m_ring_profile_key = profile;
		init();
	}
}

void ring_alloc_logic_attr::set_memory_descriptor(iovec &mem_desc)
{
	if (m_mem_desc.iov_base != mem_desc.iov_base ||
	    m_mem_desc.iov_len != mem_desc.iov_len) {
		m_mem_desc = mem_desc;
		init();
	}
}

void ring_alloc_logic_attr::set_user_id_key(uint64_t user_id_key)
{
	if (m_user_id_key != user_id_key) {
		m_user_id_key = user_id_key;
		init();
	}
}

net_device_val::net_device_val(struct net_device_val_desc *desc) : m_lock("net_device_val lock")
{
	bool valid = false;
	ib_ctx_handler* ib_ctx;
	struct nlmsghdr *nl_msg = NULL;
	struct ifinfomsg *nl_msgdata = NULL;
	int nl_attrlen;
	struct rtattr *nl_attr;

	m_if_idx = 0;
	m_if_link = 0;
	m_type = 0;
	m_flags = 0;
	m_mtu = 0;
	m_state = INVALID;
	m_p_L2_addr = NULL;
	m_p_br_addr = NULL;
	m_bond = NO_BOND;
	m_if_active = 0;
	m_bond_xmit_hash_policy = XHP_LAYER_2;
	m_bond_fail_over_mac = 0;
	m_transport_type = VMA_TRANSPORT_UNKNOWN;

	if (NULL == desc) {
		nd_logerr("Invalid net_device_val name=%s", "NA");
		m_state = INVALID;
		return;
	}

	nl_msg = desc->nl_msg;
	nl_msgdata = (struct ifinfomsg *)NLMSG_DATA(nl_msg);

	nl_attr = (struct rtattr *)IFLA_RTA(nl_msgdata);
	nl_attrlen = IFLA_PAYLOAD(nl_msg);

	set_type(nl_msgdata->ifi_type);
	set_if_idx(nl_msgdata->ifi_index);
	set_flags(nl_msgdata->ifi_flags);
	while (RTA_OK(nl_attr, nl_attrlen)) {
		char *nl_attrdata = (char *)RTA_DATA(nl_attr);
		size_t nl_attrpayload = RTA_PAYLOAD(nl_attr);

		switch (nl_attr->rta_type) {
		case IFLA_MTU:
			set_mtu(*(int32_t *)nl_attrdata);
			break;
		case IFLA_LINK:
			set_if_link(*(int32_t *)nl_attrdata);
			break;
		case IFLA_IFNAME:
			set_ifname(nl_attrdata);
			break;
		case IFLA_ADDRESS:
			set_l2_if_addr((uint8_t *)nl_attrdata, nl_attrpayload);
			break;
		case IFLA_BROADCAST:
			set_l2_bc_addr((uint8_t *)nl_attrdata, nl_attrpayload);
			break;
		default:
			break;
		}
		nl_attr = RTA_NEXT(nl_attr, nl_attrlen);
	}

	/* Valid interface should have at least one IP address */
	set_ip_array();
	if (m_ip.empty()) {
		return;
	}

	/* Identify device type */
	if ((get_flags() & IFF_MASTER) || check_device_exist(get_ifname_link(), BOND_DEVICE_FILE)) {
		verify_bonding_mode();
	} else if (check_netvsc_device_exist(get_ifname_link())) {
		m_bond = NETVSC;
	} else {
		m_bond = NO_BOND;
	}

	set_str();

	nd_logdbg("Check interface '%s' (index=%d addr=%d.%d.%d.%d flags=%X)",
			get_ifname(), get_if_idx(), NIPQUAD(get_local_addr()), get_flags());

	valid = false;
	ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(get_ifname_link());
	switch (m_bond) {
	case NETVSC:
		if (get_type() == ARPHRD_ETHER) {
			char slave_ifname[IFNAMSIZ] = {0};
			unsigned int slave_flags = 0;
			/* valid = true; uncomment it is valid flow to operate w/o SRIOV */
			if (get_netvsc_slave(get_ifname_link(), slave_ifname, slave_flags)) {
				valid = verify_qp_creation(slave_ifname, IBV_QPT_RAW_PACKET);
			}
		}
		break;
	case LAG_8023ad:
	case ACTIVE_BACKUP:
		// this is a bond interface (or a vlan/alias over bond), find the slaves
		valid = verify_bond_ipoib_or_eth_qp_creation();
		break;
	default:
		valid = (bool)(ib_ctx && verify_ipoib_or_eth_qp_creation(get_ifname_link()));
		break;
	}

	if (!valid) {
		nd_logdbg("Skip interface '%s'", get_ifname());
		return;
	}

	if (safe_mce_sys().mtu != 0 && (int)safe_mce_sys().mtu != get_mtu()) {
		nd_logwarn("Mismatch between interface %s MTU=%d and VMA_MTU=%d."
				"Make sure VMA_MTU and all offloaded interfaces MTUs match.",
				get_ifname(), get_mtu(), safe_mce_sys().mtu);
	}

	/* Set interface state after all verifications */
	if (m_flags & IFF_RUNNING) {
		m_state = RUNNING;
	}
	else {
		if (m_flags & IFF_UP) {
			m_state = UP;
		}
		else {
			m_state = DOWN;
		}
	}

	nd_logdbg("Use interface '%s'", get_ifname());
	if (ib_ctx) {
		nd_logdbg("%s ==> %s port %d (%s)",
				get_ifname(),
				ib_ctx->get_ibname(), get_port_from_ifname(get_ifname_link()),
				(ib_ctx->is_active(get_port_from_ifname(get_ifname_link())) ? "Up" : "Down"));
	} else {
		nd_logdbg("%s ==> none",
				get_ifname());
	}
}

net_device_val::~net_device_val()
{
	auto_unlocker lock(m_lock);

	rings_hash_map_t::iterator ring_iter;
	while ((ring_iter = m_h_ring_map.begin()) != m_h_ring_map.end()) {
		delete THE_RING;
		resource_allocation_key *tmp = ring_iter->first;
		m_h_ring_map.erase(ring_iter);
		delete tmp;
	}

	rings_key_redirection_hash_map_t::iterator redirect_iter;
	while ((redirect_iter = m_h_ring_key_redirection_map.begin()) !=
		m_h_ring_key_redirection_map.end()) {
		delete redirect_iter->second.first;
		m_h_ring_key_redirection_map.erase(redirect_iter);
	}
	if (m_p_br_addr) {
		delete m_p_br_addr;
		m_p_br_addr = NULL;
	}

	if (m_p_L2_addr) {
		delete m_p_L2_addr;
		m_p_L2_addr = NULL;
	}

	slave_data_vector_t::iterator slave = m_slaves.begin();
	for (; slave != m_slaves.end(); ++slave) {
		delete *slave;
	}
	m_slaves.clear();

	ip_data_vector_t::iterator ip = m_ip.begin();
	for (; ip != m_ip.end(); ++ip) {
		delete *ip;
	}
	m_ip.clear();
}

void net_device_val::set_ip_array()
{
	int rc = 0;
	int fd = -1;
	struct {
		struct nlmsghdr hdr;
		struct ifaddrmsg addrmsg;
	} nl_req;
	struct nlmsghdr *nl_msg;
	int nl_msglen = 0;
	char nl_res[8096];
	static int _seq = 0;

	/* Set up the netlink socket */
	fd = orig_os_api.socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		nd_logerr("netlink socket() creation");
		return;
	}

	/* Prepare RTM_GETADDR request */
	memset(&nl_req, 0, sizeof(nl_req));
	nl_req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nl_req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_req.hdr.nlmsg_type = RTM_GETADDR;
	nl_req.hdr.nlmsg_seq = _seq++;
	nl_req.hdr.nlmsg_pid = getpid();
	nl_req.addrmsg.ifa_family = AF_INET;
	nl_req.addrmsg.ifa_index = m_if_idx;

	/* Send the netlink request */
	rc = orig_os_api.send(fd, &nl_req, nl_req.hdr.nlmsg_len, 0);
	if (rc < 0) {
		nd_logerr("netlink send() operation");
		goto ret;
	}

	do {
		/* Receive the netlink reply */
		rc = orig_os_api.recv(fd, nl_res, sizeof(nl_res), 0);
		if (rc < 0) {
			nd_logerr("netlink recv() operation");
			goto ret;
		}

		nl_msg = (struct nlmsghdr *)nl_res;
		nl_msglen = rc;
		while (NLMSG_OK(nl_msg, (size_t)nl_msglen) && (nl_msg->nlmsg_type != NLMSG_ERROR)) {
			int nl_attrlen;
			struct ifaddrmsg *nl_msgdata;
			struct rtattr *nl_attr;
			ip_data_t* p_val = NULL;

			nl_msgdata = (struct ifaddrmsg *)NLMSG_DATA(nl_msg);

			/* Process just specific if index */
			if ((int)nl_msgdata->ifa_index == m_if_idx) {
				nl_attr = (struct rtattr *)IFA_RTA(nl_msgdata);
				nl_attrlen = IFA_PAYLOAD(nl_msg);

				p_val = new ip_data_t;
				p_val->flags = nl_msgdata->ifa_flags;
				memset(&p_val->netmask, 0, sizeof(in_addr_t));
				p_val->netmask = prefix_to_netmask(nl_msgdata->ifa_prefixlen);
				while (RTA_OK(nl_attr, nl_attrlen)) {
					char *nl_attrdata = (char *)RTA_DATA(nl_attr);

					switch (nl_attr->rta_type) {
					case IFA_ADDRESS:
						memset(&p_val->local_addr, 0, sizeof(in_addr_t));
						memcpy(&p_val->local_addr, (in_addr_t *)nl_attrdata, sizeof(in_addr_t));
						break;
					default:
						break;
					}
					nl_attr = RTA_NEXT(nl_attr, nl_attrlen);
				}

				m_ip.push_back(p_val);
			}

			/* Check if it is the last message */
			if(nl_msg->nlmsg_type == NLMSG_DONE) {
				goto ret;
			}
			nl_msg = NLMSG_NEXT(nl_msg, nl_msglen);
		}
	} while (1);

ret:
	orig_os_api.close(fd);
}

void net_device_val::set_str()
{
	char str_x[BUFF_SIZE] = {0};

	m_str[0] = '\0';

	str_x[0] = '\0';
	sprintf(str_x, "%d:", m_if_idx);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	if (!strcmp(get_ifname(), get_ifname_link())) {
		sprintf(str_x, " %s:", get_ifname());
	} else {
		sprintf(str_x, " %s@%s:", get_ifname(), get_ifname_link());
	}
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " <%s%s%s%s%s%s%s%s%s%s%s>:",
			(m_flags & IFF_UP        ? "UP," : ""),
			(m_flags & IFF_RUNNING   ? "RUNNING," : ""),
			(m_flags & IFF_NOARP     ? "NO_ARP," : ""),
			(m_flags & IFF_LOOPBACK  ? "LOOPBACK," : ""),
			(m_flags & IFF_BROADCAST ? "BROADCAST," : ""),
			(m_flags & IFF_MULTICAST ? "MULTICAST," : ""),
			(m_flags & IFF_MASTER    ? "MASTER," : ""),
			(m_flags & IFF_SLAVE     ? "SLAVE," : ""),
			(m_flags & IFF_LOWER_UP  ? "LOWER_UP," : ""),
			(m_flags & IFF_DEBUG     ? "DEBUG," : ""),
			(m_flags & IFF_PROMISC   ? "PROMISC," : ""));
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " mtu %d", m_mtu);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	switch (m_type) {
	case ARPHRD_LOOPBACK:
		sprintf(str_x, " type %s", "loopback");
		break;
	case ARPHRD_ETHER:
		sprintf(str_x, " type %s", "ether");
		break;
	case ARPHRD_INFINIBAND:
		sprintf(str_x, " type %s", "infiniband");
		break;
	default:
		sprintf(str_x, " type %s", "unknown");
		break;
	}

	str_x[0] = '\0';
	switch (m_bond) {
	case NETVSC:
		sprintf(str_x, " (%s)", "netvsc");
		break;
	case LAG_8023ad:
		sprintf(str_x, " (%s)", "lag 8023ad");
		break;
	case ACTIVE_BACKUP:
		sprintf(str_x, " (%s)", "active backup");
		break;
	default:
		sprintf(str_x, " (%s)", "normal");
		break;
	}
	strcat(m_str, str_x);
}

void net_device_val::print_val()
{
	size_t i = 0;
	rings_hash_map_t::iterator ring_iter;

	set_str();
	nd_logdbg("%s", m_str);

	nd_logdbg("  ip list: %s", (m_ip.empty() ? "empty " : ""));
	for (i = 0; i < m_ip.size(); i++) {
		nd_logdbg("    inet: %d.%d.%d.%d netmask: %d.%d.%d.%d flags: 0x%X",
				NIPQUAD(m_ip[i]->local_addr), NIPQUAD(m_ip[i]->netmask), m_ip[i]->flags);
	}

	nd_logdbg("  slave list: %s", (m_slaves.empty() ? "empty " : ""));
	for (i = 0; i < m_slaves.size(); i++) {
		char if_name[IFNAMSIZ] = {0};

		if_name[0] = '\0';
		if_indextoname(m_slaves[i]->if_index, if_name);
		nd_logdbg("    %d: %s: %s active: %d",
				m_slaves[i]->if_index, if_name, m_slaves[i]->p_L2_addr->to_str().c_str(), m_slaves[i]->active);
	}

	nd_logdbg("  ring list: %s", (m_h_ring_map.empty() ? "empty " : ""));
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		ring *cur_ring = ring_iter->second.first;
		NOT_IN_USE(cur_ring); // Suppress --enable-opt-log=high warning
		nd_logdbg("    %d: 0x%X: parent 0x%X ref %d",
				cur_ring->get_if_index(), cur_ring, cur_ring->get_parent(), ring_iter->second.second);
	}
}

void net_device_val::set_slave_array()
{
	char active_slave[IFNAMSIZ] = {0}; // gather the slave data (only for active-backup)-

	nd_logdbg("");

	if (m_bond == NETVSC) {
		slave_data_t* s = NULL;
		unsigned int slave_flags = 0;
		if (get_netvsc_slave(get_ifname_link(), active_slave, slave_flags)) {
			if ((slave_flags & IFF_UP) &&
					verify_qp_creation(active_slave, IBV_QPT_RAW_PACKET)) {
				s = new slave_data_t(if_nametoindex(active_slave));
				m_slaves.push_back(s);
			}
		}
	} else if (m_bond == NO_BOND) {
		slave_data_t* s = new slave_data_t(if_nametoindex(get_ifname()));
		m_slaves.push_back(s);
	} else {
		// bond device

		// get list of all slave devices
		char slaves_list[IFNAMSIZ * MAX_SLAVES] = {0};
		if (get_bond_slaves_name_list(get_ifname_link(), slaves_list, sizeof(slaves_list))) {
			char* slave = strtok(slaves_list, " ");
			while (slave) {
				char* p = strchr(slave, '\n');
				if (p) *p = '\0'; // Remove the tailing 'new line" char

				slave_data_t* s = new slave_data_t(if_nametoindex(slave));
				m_slaves.push_back(s);
				slave = strtok(NULL, " ");
			}
		}

		// find the active slave
		if (get_bond_active_slave_name(get_ifname_link(), active_slave, sizeof(active_slave))) {
			m_if_active = if_nametoindex(active_slave);
			nd_logdbg("found the active slave: %d: '%s'", m_if_active, active_slave);
		}
		else {
			nd_logdbg("failed to find the active slave, Moving to LAG state");
		}
	}

	bool up_and_active_slaves[m_slaves.size()];

	memset(up_and_active_slaves, 0, sizeof(up_and_active_slaves));

	if (m_bond == LAG_8023ad) {
		get_up_and_active_slaves(up_and_active_slaves, m_slaves.size());
	}

	for (uint16_t i = 0; i < m_slaves.size(); i++) {
		char if_name[IFNAMSIZ] = {0};
		char base_ifname[IFNAMSIZ];

		if (!if_indextoname(m_slaves[i]->if_index, if_name)) {
			nd_logerr("Can not find interface name by index=%d", m_slaves[i]->if_index);
			continue;
		}
		get_base_interface_name((const char*)if_name, base_ifname, sizeof(base_ifname));

		// Save L2 address
		m_slaves[i]->p_L2_addr = create_L2_address(if_name);
		m_slaves[i]->active = false;

		if (m_bond == ACTIVE_BACKUP && m_if_active == m_slaves[i]->if_index) {
			m_slaves[i]->active = true;
		}

		if (m_bond == LAG_8023ad) {
			if (up_and_active_slaves[i]) {
				m_slaves[i]->active = true;
			}
		}

		if (m_bond == NETVSC) {
			m_slaves[i]->active = true;
		}

		if (m_bond == NO_BOND) {
			m_slaves[i]->active = true;
		}

		m_slaves[i]->p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(base_ifname);
		m_slaves[i]->port_num = get_port_from_ifname(base_ifname);
		if (m_slaves[i]->port_num < 1) {
			nd_logdbg("Error: port %d ==> ifname=%s base_ifname=%s",
					m_slaves[i]->port_num, if_name, base_ifname);
		}
	}

	if (m_slaves.empty() && NETVSC != m_bond) {
		m_state = INVALID;
		nd_logpanic("No slave found.");
	}
}

const slave_data_t* net_device_val::get_slave(int if_index)
{
	auto_unlocker lock(m_lock);

	slave_data_vector_t::iterator iter;
	for (iter = m_slaves.begin(); iter != m_slaves.end(); iter++) {
		slave_data_t *cur_slave = *iter;
		if (cur_slave->if_index == if_index) {
			return cur_slave;
		}
	}
	return NULL;
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
	sprintf(bond_mode_param_file, BONDING_MODE_PARAM_FILE, get_ifname_link());
	sprintf(bond_failover_mac_param_file, BONDING_FAILOVER_MAC_PARAM_FILE, get_ifname_link());

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
	sprintf(bond_xmit_hash_policy_param_file, BONDING_XMIT_HASH_POLICY_PARAM_FILE, get_ifname_link());
	if (priv_safe_try_read_file(bond_xmit_hash_policy_param_file, bond_xmit_hash_policy_file_content, FILENAME_MAX) > 0) {
		char *bond_xhp = NULL;
		char *saveptr = NULL;

		bond_xhp = strtok_r(bond_xmit_hash_policy_file_content, " ", &saveptr);
		if (NULL == bond_xhp) {
			nd_logdbg("could not parse bond xmit hash policy, staying with default (L2)\n");
		} else {
			bond_xhp = strtok_r(NULL, " ", &saveptr);
			if (bond_xhp) {
				m_bond_xmit_hash_policy = (bond_xmit_hash_policy)strtol(bond_xhp, NULL , 10);
				if (m_bond_xmit_hash_policy < XHP_LAYER_2 || m_bond_xmit_hash_policy > XHP_ENCAP_3_4) {
					vlog_printf(VLOG_WARNING,"VMA does not support xmit hash policy = %d\n", m_bond_xmit_hash_policy);
					m_bond_xmit_hash_policy = XHP_LAYER_2;
				}
			}
			nd_logdbg("got bond xmit hash policy = %d\n", m_bond_xmit_hash_policy);
		}
	} else {
		nd_logdbg("could not read bond xmit hash policy, staying with default (L2)\n");
	}

	if (m_bond == NO_BOND || m_bond_fail_over_mac > 1) {
		vlog_printf(VLOG_WARNING,"******************************************************************************\n");
		vlog_printf(VLOG_WARNING,"VMA doesn't support current bonding configuration of %s.\n", get_ifname_link());
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
	int if_active_slave = 0;

	if (!get_bond_active_slave_name(get_ifname_link(), active_slave, IFNAMSIZ)) {
		nd_logdbg("failed to find the active slave!");
		return 0;
	}

	//nothing changed
	if_active_slave = if_nametoindex(active_slave);
	if (m_if_active == if_active_slave) {
		return 0;
	}

	m_p_L2_addr = create_L2_address(get_ifname());
	bool found_active_slave = false;
	for (size_t i = 0; i < m_slaves.size(); i++) {
		if (if_active_slave == m_slaves[i]->if_index) {
			m_slaves[i]->active = true;
			found_active_slave = true;
			nd_logdbg("Slave changed old=%d new=%d", m_if_active, if_active_slave);
			m_if_active = if_active_slave;
		} else {
			m_slaves[i]->active = false;
		}
	}
	if (!found_active_slave) {
		nd_logdbg("Failed to locate new active slave details");
		return 0;
	}
	// restart rings
	rings_hash_map_t::iterator ring_iter;
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		THE_RING->restart();
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
		char if_name[IFNAMSIZ] = {0};

		if (!if_indextoname(m_slaves[i]->if_index, if_name)) {
			nd_logerr("Can not find interface name by index=%d", m_slaves[i]->if_index);
			continue;
		}

		// get interface operstate
		get_interface_oper_state(if_name, oper_state, sizeof(oper_state));
		if (strstr(oper_state, "up")) {
			num_up++;
			up_slaves[i] = true;
		} else {
			up_slaves[i] = false;
		}

		active_slaves[i] = true;
		// get slave state
		if (get_bond_slave_state(if_name, slave_state, sizeof(slave_state))){
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

bool net_device_val::update_active_slaves()
{
	bool changed = false;
	bool up_and_active_slaves[m_slaves.size()];
	size_t i = 0;

	memset(&up_and_active_slaves, 0, m_slaves.size() * sizeof(bool));
	get_up_and_active_slaves(up_and_active_slaves, m_slaves.size());

	/* compare to current status and prepare for restart */
	for (i = 0; i< m_slaves.size(); i++) {
		if (up_and_active_slaves[i]) {
			//slave came up
			if (!m_slaves[i]->active) {
				nd_logdbg("slave %d is up ", m_slaves[i]->if_index);
				m_slaves[i]->active = true;
				changed = true;
			}
		}
		else {
			//slave went down
			if (m_slaves[i]->active) {
				nd_logdbg("slave %d is down ", m_slaves[i]->if_index);
				m_slaves[i]->active = false;
				changed = true;
			}
		}
	}

	/* restart if status changed */
	if (changed) {
		m_p_L2_addr = create_L2_address(get_ifname());
		// restart rings
		rings_hash_map_t::iterator ring_iter;
		for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
			THE_RING->restart();
		}
		return 1;
	}
	return 0;
}

void net_device_val::update_netvsc_slaves(int if_index, int if_flags)
{
	slave_data_t* s = NULL;
	bool found = false;
	ib_ctx_handler *ib_ctx = NULL, *up_ib_ctx = NULL;
	char if_name[IFNAMSIZ] = {0};

	m_lock.lock();

	if (if_indextoname(if_index, if_name) && (if_flags & IFF_UP) && (if_flags & IFF_RUNNING)) {
		nd_logdbg("slave %d is up", if_index);

		g_p_ib_ctx_handler_collection->update_tbl(if_name);
		if ((up_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(if_name))) {
			s = new slave_data_t(if_index);
			s->active = true;
			s->p_ib_ctx = up_ib_ctx;
			s->p_L2_addr = create_L2_address(if_name);
			s->port_num = get_port_from_ifname(if_name);
			m_slaves.push_back(s);

			up_ib_ctx->set_ctx_time_converter_status(g_p_net_device_table_mgr->get_ctx_time_conversion_mode());
			g_buffer_pool_rx->register_memory(s->p_ib_ctx);
			g_buffer_pool_tx->register_memory(s->p_ib_ctx);
			found = true;
		}
	} else {
		if (!m_slaves.empty()) {
			s = m_slaves.back();
			m_slaves.pop_back();

			nd_logdbg("slave %d is down ", s->if_index);

			ib_ctx = s->p_ib_ctx;
			delete s;
			found = true;
		}
	}

	m_lock.unlock();

	if (!found) {
		nd_logdbg("Unable to detect any changes for interface %d. ignoring", if_index);
		return;
	}

	/* restart if status changed */
	m_p_L2_addr = create_L2_address(get_ifname());
	// restart rings
	rings_hash_map_t::iterator ring_iter;
	for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
		THE_RING->restart();
	}

	if (ib_ctx) {
		g_p_ib_ctx_handler_collection->del_ib_ctx(ib_ctx);
	}
}

std::string net_device_val::to_str()
{
	return std::string("Net Device: " + m_name);
}

ring* net_device_val::reserve_ring(resource_allocation_key *key)
{
	nd_logfunc("");
	auto_unlocker lock(m_lock);
	key = ring_key_redirection_reserve(key);
	ring* the_ring = NULL;
	rings_hash_map_t::iterator ring_iter = m_h_ring_map.find(key);

	if (m_h_ring_map.end() == ring_iter) {
		nd_logdbg("Creating new RING for %s", key->to_str());
		// copy key since we keep pointer and socket can die so map will lose pointer
		resource_allocation_key *new_key = new resource_allocation_key(*key);
		the_ring = create_ring(new_key);
		if (!the_ring) {
			return NULL;
		}
		m_h_ring_map[new_key] = std::make_pair(the_ring, 0); // each ring is born with ref_count = 0
		ring_iter = m_h_ring_map.find(new_key);
		epoll_event ev = {0, {0}};
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

	nd_logdbg("0x%X: if_index %d parent 0x%X ref %d key %s",
			the_ring, the_ring->get_if_index(),
			the_ring->get_parent(), RING_REF_CNT, key->to_str());

	return the_ring;
}

bool net_device_val::release_ring(resource_allocation_key *key)
{
	nd_logfunc("");

	resource_allocation_key *red_key;

	auto_unlocker lock(m_lock);
	red_key = get_ring_key_redirection(key);
	ring* the_ring = NULL;
	rings_hash_map_t::iterator ring_iter = m_h_ring_map.find(red_key);

	if (m_h_ring_map.end() != ring_iter) {
		DEC_RING_REF_CNT;
		the_ring = GET_THE_RING(red_key);

		nd_logdbg("0x%X: if_index %d parent 0x%X ref %d key %s",
				the_ring, the_ring->get_if_index(),
				the_ring->get_parent(), RING_REF_CNT, red_key->to_str());

		if ( TEST_REF_CNT_ZERO ) {
			int num_ring_rx_fds = the_ring->get_num_resources();
			int *ring_rx_fds_array = the_ring->get_rx_channel_fds();
			nd_logdbg("Deleting RING %p for key %s and removing notification fd from global_table_mgr_epfd (epfd=%d)",
					the_ring, red_key->to_str(), g_p_net_device_table_mgr->global_ring_epfd_get());
			for (int i = 0; i < num_ring_rx_fds; i++) {
				int cq_ch_fd = ring_rx_fds_array[i];
				BULLSEYE_EXCLUDE_BLOCK_START
				if (unlikely(orig_os_api.epoll_ctl(g_p_net_device_table_mgr->global_ring_epfd_get(),
						EPOLL_CTL_DEL, cq_ch_fd, NULL))) {
					nd_logerr("Failed to delete RING notification fd to global_table_mgr_epfd (errno=%d %m)", errno);
				}
				BULLSEYE_EXCLUDE_BLOCK_END
			}

			ring_key_redirection_release(key);

			delete the_ring;
			delete ring_iter->first;
			m_h_ring_map.erase(ring_iter);
		}
		return true;
	}
	return false;
}

/*
 * this function maps key to new keys that it created
 * the key that it creates is the size of the map
 */
resource_allocation_key* net_device_val::ring_key_redirection_reserve(resource_allocation_key *key)
{
	// if allocation logic is usr idx feature disabled
	if (!safe_mce_sys().ring_limit_per_interface ||
	    key->get_ring_alloc_logic() == RING_LOGIC_PER_USER_ID)
		return key;

	if (m_h_ring_key_redirection_map.find(key) != m_h_ring_key_redirection_map.end()) {
		m_h_ring_key_redirection_map[key].second++;
		nd_logdbg("redirecting key=%s (ref-count:%d) to key=%s", key->to_str(),
			m_h_ring_key_redirection_map[key].second,
			m_h_ring_key_redirection_map[key].first->to_str());
		return m_h_ring_key_redirection_map[key].first;
	}

	int ring_map_size = (int)m_h_ring_map.size();
	if (safe_mce_sys().ring_limit_per_interface > ring_map_size) {
		resource_allocation_key *key2 = new resource_allocation_key(*key);
		// replace key to redirection key
		key2->set_user_id_key(ring_map_size);
		m_h_ring_key_redirection_map[key] = std::make_pair(key2, 1);
		nd_logdbg("redirecting key=%s (ref-count:1) to key=%s",
			  key->to_str(), key2->to_str());
		return key2;
	}

	rings_hash_map_t::iterator ring_iter = m_h_ring_map.begin();
	int min_ref_count = ring_iter->second.second;
	resource_allocation_key *min_key = ring_iter->first;
	while (ring_iter != m_h_ring_map.end()) {
		// redirect only to ring with the same profile
		if (ring_iter->first->get_ring_profile_key() ==
		    key->get_ring_profile_key() &&
		    ring_iter->second.second < min_ref_count) {
			min_ref_count = ring_iter->second.second;
			min_key = ring_iter->first;
		}
		ring_iter++;
	}
	m_h_ring_key_redirection_map[key] = std::make_pair(new resource_allocation_key(*min_key), 1);
	nd_logdbg("redirecting key=%s (ref-count:1) to key=%s",
		  key->to_str(), min_key->to_str());
	return min_key;
}

resource_allocation_key* net_device_val::get_ring_key_redirection(resource_allocation_key *key)
{
	if (!safe_mce_sys().ring_limit_per_interface) return key;

	if (m_h_ring_key_redirection_map.find(key) == m_h_ring_key_redirection_map.end()) {
		nd_logdbg("key = %s is not found in the redirection map",
			  key->to_str());
		return key;
	}

	return m_h_ring_key_redirection_map[key].first;
}

void net_device_val::ring_key_redirection_release(resource_allocation_key *key)
{
	if (safe_mce_sys().ring_limit_per_interface && m_h_ring_key_redirection_map.find(key) != m_h_ring_key_redirection_map.end()
		&& --m_h_ring_key_redirection_map[key].second == 0) {
		// this is allocated in ring_key_redirection_reserve
		nd_logdbg("release redirecting key=%s (ref-count:%d) to key=%s", key->to_str(),
			m_h_ring_key_redirection_map[key].second,
			m_h_ring_key_redirection_map[key].first->to_str());
		delete m_h_ring_key_redirection_map[key].first;
		m_h_ring_key_redirection_map.erase(key);
	}
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
		int ret = THE_RING->drain_and_proccess();
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

void net_device_val_eth::configure()
{
	m_p_L2_addr = create_L2_address(get_ifname());

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_L2_addr == NULL) {
		nd_logpanic("m_p_L2_addr allocation error");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	create_br_address(get_ifname());

	m_vlan = get_vlan_id_from_ifname(get_ifname());
	if (m_vlan) {
		parse_prio_egress_map();
	}
	if (m_vlan && m_bond != NO_BOND && m_bond_fail_over_mac == 1) {
		vlog_printf(VLOG_WARNING, " ******************************************************************\n");
		vlog_printf(VLOG_WARNING, "%s: vlan over bond while fail_over_mac=1 is not offloaded\n", get_ifname());
		vlog_printf(VLOG_WARNING, " ******************************************************************\n");
		m_state = INVALID;
	}
	if(!m_vlan && (get_flags() & IFF_MASTER)) {
		char if_name[IFNAMSIZ] = {0};

		if (!if_indextoname(m_slaves[0]->if_index, if_name)) {
			nd_logerr("Can not find interface name by index=%d", m_slaves[0]->if_index);
		}

		//in case vlan is configured on slave
		m_vlan = get_vlan_id_from_ifname(if_name);
	}
}

int net_device_val::get_priority_by_tc_class(uint32_t tc_class)
{
	tc_class_priority_map::iterator it = m_class_prio_map.find(tc_class);
	if (it == m_class_prio_map.end()) {
		return VMA_DEFAULT_ENGRESS_MAP_PRIO;
	}
	return it->second;
}

void net_device_val_eth::parse_prio_egress_map()
{
#ifdef HAVE_LIBNL3
	int len, ret;
	nl_cache *cache = NULL;
	rtnl_link *link;
	vlan_map *map;

	nl_socket_handle *nl_socket = nl_socket_handle_alloc();
	if (!nl_socket) {
		nd_logdbg("unable to allocate socket socket %m", errno);
		goto out;
	}
	nl_socket_set_local_port(nl_socket, 0);
	ret = nl_connect(nl_socket, NETLINK_ROUTE);
	if (ret < 0) {
		nd_logdbg("unable to connect to libnl socket %d %m", ret, errno);
		goto out;
	}
	ret = rtnl_link_alloc_cache(nl_socket, AF_UNSPEC, &cache);
	if (!cache) {
		nd_logdbg("unable to create libnl cache %d %m", ret, errno);
		goto out;
	}
	link = rtnl_link_get_by_name(cache, get_ifname());
	if (!link) {
		nd_logdbg("unable to get libnl link %d %m", ret, errno);
		goto out;
	}
	map = rtnl_link_vlan_get_egress_map(link, &len);
	if (!map || !len) {
		nd_logdbg("no egress map found %d %p",len, map);
		goto out;
	}
	for (int i = 0; i < len; i++) {
		m_class_prio_map[map[i].vm_from] = map[i].vm_to;
	}
out:
	if (cache) {
		nl_cache_free(cache);
	}
	if (nl_socket) {
		nl_socket_handle_free(nl_socket);
	}
#else
	nd_logdbg("libnl3 not found, cannot read engress map, "
		  "SO_PRIORITY will not work properly");
#endif
}

ring* net_device_val_eth::create_ring(resource_allocation_key *key)
{
	ring* ring = NULL;

	// if this is a ring profile key get the profile from the global map
	if (key->get_ring_profile_key()) {
		if (!g_p_ring_profile) {
			nd_logdbg("could not find ring profile");
			return NULL;
		}
		ring_profile *prof =
			g_p_ring_profile->get_profile(key->get_ring_profile_key());
		if (prof == NULL) {
			nd_logerr("could not find ring profile %d",
				  key->get_ring_profile_key());
			return NULL;
		}
		try {
			switch (prof->get_ring_type()) {
#ifdef HAVE_MP_RQ
			case VMA_RING_CYCLIC_BUFFER:
				ring = new ring_eth_cb(get_if_idx(),
						       &prof->get_desc()->ring_cyclicb,
						       key->get_memory_descriptor());
			break;
#endif
			case VMA_RING_EXTERNAL_MEM:
				ring = new ring_eth_direct(get_if_idx(),
							   &prof->get_desc()->ring_ext);
			break;
			default:
				nd_logdbg("Unknown ring type");
				break;
			}
		} catch (vma_error &error) {
			nd_logdbg("failed creating ring %s", error.message);
		}
	} else {
		try {
			switch (m_bond) {
			case NO_BOND:
				ring = new ring_eth(get_if_idx());
				break;
			case ACTIVE_BACKUP:
			case LAG_8023ad:
				ring = new ring_bond_eth(get_if_idx());
				break;
			case NETVSC:
				ring = new ring_bond_netvsc(get_if_idx());
				break;
			default:
				nd_logdbg("Unknown ring type");
				break;
			}
		} catch (vma_error &error) {
			nd_logdbg("failed creating ring %s", error.message);
		}
	}
	return ring;
}

L2_address* net_device_val_eth::create_L2_address(const char* ifname)
{
	if (m_p_L2_addr) {
		delete m_p_L2_addr;
		m_p_L2_addr = NULL;
	}
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

void net_device_val_ib::configure()
{
	ib_ctx_handler* p_ib_ctx = NULL;
	struct in_addr in;

	m_p_L2_addr = create_L2_address(get_ifname());

	BULLSEYE_EXCLUDE_BLOCK_START
	if(m_p_L2_addr == NULL) {
		nd_logpanic("m_p_L2_addr allocation error");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	create_br_address(get_ifname());

	if (1 == inet_pton(AF_INET, BROADCAST_IP, &in)) {
		g_p_neigh_table_mgr->unregister_observer(neigh_key(ip_address(in.s_addr), this), this);
	}

	//Register to IB BR neigh
	cache_entry_subject<neigh_key, neigh_val*>* p_ces = NULL;
	if (1 == inet_pton(AF_INET, BROADCAST_IP, &in)) {
		g_p_neigh_table_mgr->register_observer(neigh_key(ip_address(in.s_addr), this), this, &p_ces);
	}
	m_br_neigh = dynamic_cast<neigh_ib_broadcast*>(p_ces);

	p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(get_ifname_link());
	if (!p_ib_ctx || ibv_query_pkey(p_ib_ctx->get_ibv_context(), get_port_from_ifname(get_ifname_link()), 0, &m_pkey)) {
		nd_logerr("failed querying pkey");
	}
	nd_logdbg("pkey: %d", m_pkey);
}

ring* net_device_val_ib::create_ring(resource_allocation_key *key)
{
	ring* ring = NULL;

	NOT_IN_USE(key);
	try {
		switch (m_bond) {
		case NO_BOND:
			ring = new ring_ib(get_if_idx());
			break;
		case ACTIVE_BACKUP:
		case LAG_8023ad:
			ring = new ring_bond_ib(get_if_idx());
			break;
		default:
			nd_logdbg("Unknown ring type");
			break;
		}
	} catch (vma_error &error) {
		nd_logdbg("failed creating ring %s", error.message);
	}

	return ring;
}

L2_address* net_device_val_ib::create_L2_address(const char* ifname)
{
	if (m_p_L2_addr) {
		delete m_p_L2_addr;
		m_p_L2_addr = NULL;
	}
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


bool net_device_val::verify_bond_ipoib_or_eth_qp_creation()
{
	char slaves[IFNAMSIZ * MAX_SLAVES] = {0};
	if (!get_bond_slaves_name_list(get_ifname_link(), slaves, sizeof slaves)) {
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded, slave list or bond name could not be found\n", get_ifname());
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		return false;
	}
	//go over all slaves and check preconditions
	bool bond_ok = true;
	char* slave_name;
	char* save_ptr;
	slave_name = strtok_r(slaves, " ", &save_ptr);
	while (slave_name != NULL)
	{
		char* p = strchr(slave_name, '\n');
		if (p) *p = '\0'; // Remove the tailing 'new line" char
		if (!verify_ipoib_or_eth_qp_creation(slave_name)) {
			//check all slaves but print only once for bond
			bond_ok =  false;
		}
		slave_name = strtok_r(NULL, " ", &save_ptr);
	}
	if (!bond_ok) {
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* Bond %s will not be offloaded due to problem with its slaves.\n", get_ifname());
		vlog_printf(VLOG_WARNING,"* Check warning messages for more information.\n");
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
	} else {
		/*
		 * Print warning message while bond device contains two slaves of the same HCA
		 * while RoCE LAG is enabled for both slaves.
		 */
		sys_image_guid_map_t::iterator guid_iter;
		for (guid_iter = m_sys_image_guid_map.begin(); guid_iter != m_sys_image_guid_map.end(); guid_iter++) {
			char bond_roce_lag_path[256] = {0};
			if (guid_iter->second.size() > 1 &&
					check_bond_roce_lag_exist(bond_roce_lag_path, sizeof(bond_roce_lag_path), guid_iter->second.front().c_str()) &&
					check_bond_roce_lag_exist(bond_roce_lag_path, sizeof(bond_roce_lag_path), guid_iter->second.back().c_str())) {
				print_roce_lag_warnings(get_ifname_link(), bond_roce_lag_path, guid_iter->second.front().c_str(), guid_iter->second.back().c_str());
			}
		}
	}
	return bond_ok;
}

//interface name can be slave while ifa struct can describe bond
bool net_device_val::verify_ipoib_or_eth_qp_creation(const char* interface_name)
{
	if (m_type == ARPHRD_INFINIBAND) {
		if (verify_enable_ipoib(interface_name) && verify_qp_creation(interface_name, IBV_QPT_UD)) {
			return true;
		}
	} else {
		if (verify_qp_creation(interface_name, IBV_QPT_RAW_PACKET)) {
			return true;
		}
	}
	return false;
}

bool net_device_val::verify_enable_ipoib(const char* interface_name)
{
	char filename[256] = "\0";
	char ifname[IFNAMSIZ] = "\0";
	NOT_IN_USE(interface_name); // Suppress --enable-opt-log=high warning

	if(!safe_mce_sys().enable_ipoib) {
		nd_logdbg("Blocking offload: IPoIB interfaces ('%s')", interface_name);
		return false;
	}

#ifndef DEFINED_IBV_QP_INIT_SOURCE_QPN
	// Note: mlx4 does not support this capability
	ib_ctx_handler* ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(get_ifname_link());
	if (!ib_ctx->is_mlx4()) {
		nd_logwarn("Blocking offload: SOURCE_QPN is not supported for this driver ('%s')", interface_name);
		return false;
	}
#endif

	// Verify IPoIB is in 'datagram mode' for proper VMA with flow steering operation
	if (validate_ipoib_prop(get_ifname(), m_flags, IPOIB_MODE_PARAM_FILE, "datagram", 8, filename, ifname)) {
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* IPoIB mode of interface '%s' is \"connected\" !\n", get_ifname());
		vlog_printf(VLOG_WARNING,"* Please change it to datagram: \"echo datagram > %s\" before loading your application with VMA library\n", filename);
		vlog_printf(VLOG_WARNING,"* VMA doesn't support IPoIB in connected mode.\n");
		vlog_printf(VLOG_WARNING,"* Please refer to VMA Release Notes for more information\n");
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		return false;
	}
	else {
		nd_logdbg("verified interface '%s' is running in datagram mode", get_ifname());
	}

	// Verify umcast is disabled for IB flow
	if (validate_ipoib_prop(get_ifname(), m_flags, UMCAST_PARAM_FILE, "0", 1, filename, ifname)) { // Extract UMCAST flag (only for IB transport types)
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		vlog_printf(VLOG_WARNING,"* UMCAST flag is Enabled for interface %s !\n", get_ifname());
		vlog_printf(VLOG_WARNING,"* Please disable it: \"echo 0 > %s\" before loading your application with VMA library\n", filename);
		vlog_printf(VLOG_WARNING,"* This option in no longer needed in this version\n");
		vlog_printf(VLOG_WARNING,"* Please refer to Release Notes for more information\n");
		vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		return false;
	}
	else {
		nd_logdbg("verified interface '%s' is running with umcast disabled", get_ifname());
	}

	return true;
}

//ifname should point to a physical device
bool net_device_val::verify_qp_creation(const char* ifname, enum ibv_qp_type qp_type)
{
	bool success = false;
	char bond_roce_lag_path[256] = {0};
	struct ibv_cq* cq = NULL;
	struct ibv_comp_channel *channel = NULL;
	struct ibv_qp* qp = NULL;

	vma_ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));

	vma_ibv_cq_init_attr attr;
	memset(&attr, 0, sizeof(attr));

	qp_init_attr.cap.max_send_wr = MCE_DEFAULT_TX_NUM_WRE;
	qp_init_attr.cap.max_recv_wr = MCE_DEFAULT_RX_NUM_WRE;
	qp_init_attr.cap.max_inline_data = MCE_DEFAULT_TX_MAX_INLINE;
	qp_init_attr.cap.max_send_sge = MCE_DEFAULT_TX_NUM_SGE;
	qp_init_attr.cap.max_recv_sge = MCE_DEFAULT_RX_NUM_SGE;
	qp_init_attr.sq_sig_all = 0;
	qp_init_attr.qp_type = qp_type;

	//find ib_cxt
	char base_ifname[IFNAMSIZ];
	get_base_interface_name((const char*)(ifname), base_ifname, sizeof(base_ifname));
	int port_num = get_port_from_ifname(base_ifname);
	ib_ctx_handler* p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(base_ifname);

	if (!p_ib_ctx) {
		nd_logdbg("Cant find ib_ctx for interface %s", base_ifname);
		if (qp_type == IBV_QPT_RAW_PACKET && m_bond != NO_BOND) {
			if (check_bond_roce_lag_exist(bond_roce_lag_path, sizeof(bond_roce_lag_path), ifname)) {
				print_roce_lag_warnings(get_ifname_link(), bond_roce_lag_path);
			} else if ((p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(get_ifname_link()))
					&& strstr(p_ib_ctx->get_ibname(), "bond")) {
				print_roce_lag_warnings(get_ifname_link());
			}
		}
		goto release_resources;
	} else if (port_num > p_ib_ctx->get_ibv_device_attr()->phys_port_cnt) {
		nd_logdbg("Invalid port for interface %s", base_ifname);
		if (qp_type == IBV_QPT_RAW_PACKET && m_bond != NO_BOND && p_ib_ctx->is_mlx4()) {
			print_roce_lag_warnings(get_ifname_link());
		}
		goto release_resources;
	}

	// Add to guid map in order to detect roce lag issue
	if (qp_type == IBV_QPT_RAW_PACKET && m_bond != NO_BOND) {
		m_sys_image_guid_map[p_ib_ctx->get_ibv_device_attr()->sys_image_guid].push_back(base_ifname);
	}

	//create qp resources
	channel = ibv_create_comp_channel(p_ib_ctx->get_ibv_context());
	if (!channel) {
		nd_logdbg("channel creation failed for interface %s (errno=%d %m)", ifname, errno);
		goto release_resources;
	}
	VALGRIND_MAKE_MEM_DEFINED(channel, sizeof(ibv_comp_channel));
	cq = vma_ibv_create_cq(p_ib_ctx->get_ibv_context(), safe_mce_sys().tx_num_wr, (void*)this, channel, 0, &attr);
	if (!cq) {
		nd_logdbg("cq creation failed for interface %s (errno=%d %m)", ifname, errno);
		goto release_resources;
	}

	vma_ibv_qp_init_attr_comp_mask(p_ib_ctx->get_ibv_pd(), qp_init_attr);
	qp_init_attr.recv_cq = cq;
	qp_init_attr.send_cq = cq;

	// Set source qpn for non mlx4 IPoIB devices
	if (qp_type == IBV_QPT_UD && !p_ib_ctx->is_mlx4()) {
		unsigned char hw_addr[IPOIB_HW_ADDR_LEN];
		get_local_ll_addr(ifname, hw_addr, IPOIB_HW_ADDR_LEN, false);
		IPoIB_addr ipoib_addr(hw_addr);
		ibv_source_qpn_set(qp_init_attr, ipoib_addr.get_qpn());
	}

	qp = vma_ibv_create_qp(p_ib_ctx->get_ibv_pd(), &qp_init_attr);
	if (qp) {
		if (qp_type == IBV_QPT_UD && priv_ibv_create_flow_supported(qp, port_num) == -1) {
			nd_logdbg("Create_ibv_flow failed on interface %s (errno=%d %m), Traffic will not be offloaded", ifname, errno);
			goto qp_failure;
		} else {
			success = true;

			if (qp_type == IBV_QPT_RAW_PACKET && !priv_ibv_query_flow_tag_supported(qp, port_num)) {
				p_ib_ctx->set_flow_tag_capability(true);
			}
			nd_logdbg("verified interface %s for flow tag capabilities : %s", ifname, p_ib_ctx->get_flow_tag_capability() ? "enabled" : "disabled");

			if (qp_type == IBV_QPT_RAW_PACKET && p_ib_ctx->is_packet_pacing_supported() && !priv_ibv_query_burst_supported(qp, port_num)) {
				p_ib_ctx->set_burst_capability(true);
			}
			nd_logdbg("verified interface %s for burst capabilities : %s", ifname, p_ib_ctx->get_burst_capability() ? "enabled" : "disabled");
		}
	} else {
		nd_logdbg("QP creation failed on interface %s (errno=%d %m), Traffic will not be offloaded", ifname, errno);
qp_failure:
		int err = errno; //verify_raw_qp_privliges can overwrite errno so keep it before the call
		if (validate_raw_qp_privliges() == 0) {
			// MLNX_OFED raw_qp_privliges file exist with bad value
			vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
			vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded.\n", ifname);
			vlog_printf(VLOG_WARNING,"* Working in this mode might causes VMA malfunction over Ethernet/InfiniBand interfaces\n");
			vlog_printf(VLOG_WARNING,"* WARNING: the following steps will restart your network interface!\n");
			vlog_printf(VLOG_WARNING,"* 1. \"echo options ib_uverbs disable_raw_qp_enforcement=1 > /etc/modprobe.d/ib_uverbs.conf\"\n");
			vlog_printf(VLOG_WARNING,"* 2. Restart openibd or rdma service depending on your system configuration\n");
			vlog_printf(VLOG_WARNING,"* Read the RAW_PACKET QP root access enforcement section in the VMA's User Manual for more information\n");
			vlog_printf(VLOG_WARNING,"******************************************************************************************************\n");
		}
		else if (validate_user_has_cap_net_raw_privliges() == 0 || err == EPERM) {
			vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
			vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded.\n", ifname);
			vlog_printf(VLOG_WARNING,"* Offloaded resources are restricted to root or user with CAP_NET_RAW privileges\n");
			vlog_printf(VLOG_WARNING,"* Read the CAP_NET_RAW and root access section in the VMA's User Manual for more information\n");
			vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		} else {
			vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
			vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded.\n", ifname);
			vlog_printf(VLOG_WARNING,"* VMA was not able to create QP for this device (errno = %d).\n", err);
			vlog_printf(VLOG_WARNING,"*******************************************************************************************************\n");
		}
	}

release_resources:
	if(qp) {
		IF_VERBS_FAILURE(ibv_destroy_qp(qp)) {
			nd_logdbg("qp destroy failed on interface %s (errno=%d %m)", ifname, errno);
			success = false;
		} ENDIF_VERBS_FAILURE;
	}
	if (cq) {
		IF_VERBS_FAILURE(ibv_destroy_cq(cq)) {
			nd_logdbg("cq destroy failed on interface %s (errno=%d %m)", ifname, errno);
			success = false;
		} ENDIF_VERBS_FAILURE;
	}
	if (channel) {
		IF_VERBS_FAILURE(ibv_destroy_comp_channel(channel)) {
			nd_logdbg("channel destroy failed on interface %s (errno=%d %m)", ifname, errno);
			success = false;
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(channel, sizeof(ibv_comp_channel));
	}
	return success;
}
