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


#include "utils/bullseye.h"
#include "dst_entry.h"
#include "vma/proto/rule_table_mgr.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/util/utils.h"

#define MODULE_NAME             "dst"

#define dst_logpanic           __log_panic
#define dst_logerr             __log_err
#define dst_logwarn            __log_warn
#define dst_loginfo            __log_info
#define dst_logdbg             __log_info_dbg
#define dst_logfunc            __log_info_func
#define dst_logfuncall         __log_info_funcall


dst_entry::dst_entry(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, socket_data &sock_data, resource_allocation_key &ring_alloc_logic):
	m_dst_ip(dst_ip), m_dst_port(dst_port), m_src_port(src_port), m_bound_ip(0),
	m_so_bindtodevice_ip(0), m_route_src_ip(0), m_pkt_src_ip(0),
	m_ring_alloc_logic(sock_data.fd, ring_alloc_logic, this),
	m_p_tx_mem_buf_desc_list(NULL), m_b_tx_mem_buf_desc_list_pending(false),
	m_tos(sock_data.tos), m_pcp(sock_data.pcp), m_id(0)
{
	dst_logdbg("dst:%s:%d src: %d", m_dst_ip.to_str().c_str(), ntohs(m_dst_port), ntohs(m_src_port));
	init_members();
}

dst_entry::~dst_entry()
{
	dst_logdbg("%s", to_str().c_str());

	if (m_p_neigh_entry) {
		ip_address dst_addr = m_dst_ip;
		if (m_p_rt_val && m_p_rt_val->get_gw_addr() != INADDR_ANY && !dst_addr.is_mc()) {
			dst_addr = m_p_rt_val->get_gw_addr();
		}
		g_p_neigh_table_mgr->unregister_observer(neigh_key(dst_addr, m_p_net_dev_val),this);
	}

	if (m_p_rt_entry) {
		g_p_route_table_mgr->unregister_observer(route_rule_table_key(m_dst_ip.get_in_addr(), m_route_src_ip, m_tos), this);
		m_p_rt_entry = NULL;
	}

	if (m_p_ring) {
		if (m_p_tx_mem_buf_desc_list) {
			m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true);
			m_p_tx_mem_buf_desc_list = NULL;
		}

		m_p_net_dev_val->release_ring(m_ring_alloc_logic.get_key());
		m_p_ring = NULL;
	}

	if (m_p_net_dev_entry && m_p_net_dev_val) {
		g_p_net_device_table_mgr->unregister_observer(m_p_net_dev_val->get_local_addr(), this);
	}

	if (m_p_send_wqe_handler) {
		delete m_p_send_wqe_handler;
		m_p_send_wqe_handler = NULL;
	}

	if (m_p_neigh_val) {
		delete m_p_neigh_val;
		m_p_neigh_val = NULL;
	}

	dst_logdbg("Done %s", to_str().c_str());
}

void dst_entry::init_members()
{
	set_state(false);
	m_p_rt_val = NULL;
	m_p_net_dev_val = NULL;
	m_p_ring = NULL;
	m_p_net_dev_entry = NULL;
	m_p_neigh_entry = NULL;
	m_p_neigh_val = NULL;
	m_p_rt_entry = NULL;
	m_num_sge = 0;
	memset(&m_inline_send_wqe, 0, sizeof(m_inline_send_wqe));
	memset(&m_not_inline_send_wqe, 0, sizeof(m_not_inline_send_wqe));
	memset(&m_fragmented_send_wqe, 0, sizeof(m_not_inline_send_wqe));
	m_p_send_wqe_handler = NULL;
	memset(&m_sge, 0, sizeof(m_sge));
	m_ttl = 64;
	m_b_is_offloaded = true;
	m_b_is_initialized = false;
	m_p_send_wqe = NULL;
	m_max_inline = 0;
	m_max_ip_payload_size = 0;
	m_max_udp_payload_size = 0;
	m_b_force_os = false;
}

void dst_entry::set_src_addr()
{
	m_pkt_src_ip = INADDR_ANY;
	if (m_route_src_ip) {
		m_pkt_src_ip = m_route_src_ip;
	}
	else if (m_p_rt_val && m_p_rt_val->get_src_addr()) {
		m_pkt_src_ip = m_p_rt_val->get_src_addr();
	}
	else if (m_p_net_dev_val && m_p_net_dev_val->get_local_addr()) {
		m_pkt_src_ip = m_p_net_dev_val->get_local_addr();
	}
}

bool dst_entry::update_net_dev_val()
{
	bool ret_val = false;

	net_device_val* new_nd_val = m_p_net_dev_val;
	if (m_so_bindtodevice_ip && g_p_net_device_table_mgr) {
		new_nd_val = g_p_net_device_table_mgr->get_net_device_val(m_so_bindtodevice_ip);
		// TODO should we register to g_p_net_device_table_mgr  with m_p_net_dev_entry?
		// what should we do with an old one?
		dst_logdbg("getting net_dev_val by bindtodevice ip");
	} else if (m_p_rt_entry) {
		new_nd_val = m_p_rt_entry->get_net_dev_val();
	}

	if (m_p_net_dev_val != new_nd_val) {
		dst_logdbg("updating net_device");

		if (m_p_neigh_entry) {
			ip_address dst_addr = m_dst_ip;
			if (m_p_rt_val && m_p_rt_val->get_gw_addr() != INADDR_ANY && !dst_addr.is_mc()) {
				dst_addr = m_p_rt_val->get_gw_addr();
			}
			g_p_neigh_table_mgr->unregister_observer(neigh_key(dst_addr, m_p_net_dev_val),this);
			m_p_neigh_entry = NULL;
		}

		// Change the net_device, clean old resources...
		release_ring();

		// Save the new net_device
		m_p_net_dev_val = new_nd_val;

		if (m_p_net_dev_val) {
			// more resource clean and alloc...
			ret_val = alloc_transport_dep_res();
		}
		else {
			dst_logdbg("Netdev is not offloaded fallback to OS");
		}
	}
	else {
		if (m_p_net_dev_val) {
			// Only if we already had a valid net_device_val which did not change
			dst_logdbg("no change in net_device");
			ret_val = true;
		}
		else {
			dst_logdbg("Netdev is not offloaded fallback to OS");
		}
	}

	return ret_val;
}

bool dst_entry::update_rt_val()
{
	bool ret_val = true;
	route_val* p_rt_val = NULL;

	if (m_p_rt_entry && m_p_rt_entry->get_val(p_rt_val)) {
		if (m_p_rt_val == p_rt_val) {
			dst_logdbg("no change in route_val");
		}
		else {
			dst_logdbg("updating route val");
			m_p_rt_val = p_rt_val;
		}
	}
	else {
		dst_logdbg("Route entry is not valid");
		ret_val = false;
	}

	return ret_val;
}

bool dst_entry::resolve_net_dev(bool is_connect)
{
	bool ret_val = false;

	cache_entry_subject<route_rule_table_key, route_val*>* p_ces = NULL;
	
	if (ZERONET_N(m_dst_ip.get_in_addr())) {
		dst_logdbg("VMA does not offload zero net IP address");
		return ret_val;
	}

	if (LOOPBACK_N(m_dst_ip.get_in_addr())) {
		dst_logdbg("VMA does not offload local loopback IP address");
		return ret_val;
	}
	
	//When VMA will support routing with OIF, we need to check changing in outgoing interface
	//Source address changes is not checked since multiple bind is not allowed on the same socket
	if (!m_p_rt_entry) {
		m_route_src_ip = m_bound_ip;
		route_rule_table_key rtk(m_dst_ip.get_in_addr(), m_route_src_ip, m_tos);
		if (g_p_route_table_mgr->register_observer(rtk, this, &p_ces)) {
			// In case this is the first time we trying to resolve route entry,
			// means that register_observer was run
			m_p_rt_entry = dynamic_cast<route_entry*>(p_ces);
			if (is_connect && !m_route_src_ip) {
				route_val* p_rt_val = NULL;
				if (m_p_rt_entry && m_p_rt_entry->get_val(p_rt_val) && p_rt_val->get_src_addr()) {
					g_p_route_table_mgr->unregister_observer(rtk, this);
					m_route_src_ip = p_rt_val->get_src_addr();
					route_rule_table_key new_rtk(m_dst_ip.get_in_addr(), m_route_src_ip, m_tos);
					if (g_p_route_table_mgr->register_observer(new_rtk, this, &p_ces)) {
						m_p_rt_entry = dynamic_cast<route_entry*>(p_ces);
					}
					else {
						dst_logdbg("Error in route resolving logic");
						return ret_val;
					}
				}
			}
		}
		else {
			dst_logdbg("Error in registering route entry");
			return ret_val;
		}
	}

	if (update_rt_val()) {
		ret_val = update_net_dev_val();
	}
	return ret_val;
}

bool dst_entry::resolve_neigh()
{
	dst_logdbg("");
	bool ret_val = false;
	ip_address dst_addr = m_dst_ip;

	if (m_p_rt_val && m_p_rt_val->get_gw_addr() != INADDR_ANY && !dst_addr.is_mc()) {
		dst_addr = m_p_rt_val->get_gw_addr();
	}
	cache_entry_subject<neigh_key, neigh_val*>* p_ces = NULL;
	if (m_p_neigh_entry || g_p_neigh_table_mgr->register_observer(neigh_key(dst_addr, m_p_net_dev_val), this, &p_ces)) {
		if(m_p_neigh_entry == NULL)
			m_p_neigh_entry = dynamic_cast<neigh_entry*>(p_ces);
		if (m_p_neigh_entry) {
			if (m_p_neigh_entry->get_peer_info(m_p_neigh_val)) {
				dst_logdbg("neigh is valid");
				ret_val = true;
			}
			else {
				dst_logdbg("neigh is not valid");
			}
		}
	}
	return ret_val;
}

bool dst_entry::resolve_ring()
{
	bool ret_val = false;

	if (m_p_net_dev_val) {
		if (!m_p_ring) {
			dst_logdbg("getting a ring");
			m_p_ring = m_p_net_dev_val->reserve_ring(m_ring_alloc_logic.create_new_key());
		}
		if (m_p_ring) {
			m_max_inline = std::min<uint32_t>(m_p_ring->get_max_tx_inline(),
					get_route_mtu() + m_header.m_transport_header_len);
			ret_val = true;
		}
	}
	return ret_val;
}

bool dst_entry::release_ring()
{
	bool ret_val = false;
	if (m_p_net_dev_val) {
		if (m_p_ring) {
			if (m_p_tx_mem_buf_desc_list) {
				m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true);
				m_p_tx_mem_buf_desc_list = NULL;
			}
			dst_logdbg("releasing a ring");
			if (m_p_net_dev_val->release_ring(m_ring_alloc_logic.get_key())) {
				dst_logerr("Failed to release ring for allocation key %s",
					   m_ring_alloc_logic.get_key()->to_str());
			}
			m_p_ring = NULL;
		}
		ret_val = true;
	}
	return ret_val;
}

void dst_entry::notify_cb()
{
	dst_logdbg("");
	set_state(false);
}

void dst_entry::configure_ip_header(header *h, uint16_t packet_id)
{
	h->configure_ip_header(get_protocol_type(), m_pkt_src_ip, m_dst_ip.get_in_addr(), m_ttl, m_tos, packet_id);
}

bool dst_entry::conf_l2_hdr_and_snd_wqe_eth()
{
	bool ret_val = false;

	//Maybe we after invalidation so we free the wqe_handler since we are going to build it from scratch
	if (m_p_send_wqe_handler) {
		delete m_p_send_wqe_handler;
		m_p_send_wqe_handler = NULL;
	}

	m_p_send_wqe_handler = new wqe_send_handler();
	if (!m_p_send_wqe_handler) {
		dst_logpanic("%s Failed to allocate send WQE handler", to_str().c_str());
	}
	m_p_send_wqe_handler->init_inline_wqe(m_inline_send_wqe, get_sge_lst_4_inline_send(), get_inline_sge_num());
	m_p_send_wqe_handler->init_not_inline_wqe(m_not_inline_send_wqe, get_sge_lst_4_not_inline_send(), 1);
	m_p_send_wqe_handler->init_wqe(m_fragmented_send_wqe, get_sge_lst_4_not_inline_send(), 1);

	net_device_val_eth *netdevice_eth = dynamic_cast<net_device_val_eth*>(m_p_net_dev_val);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (netdevice_eth) {
	BULLSEYE_EXCLUDE_BLOCK_END
		const L2_address *src = m_p_net_dev_val->get_l2_address();
		const L2_address *dst = m_p_neigh_val->get_l2_address();

		BULLSEYE_EXCLUDE_BLOCK_START
		if (src && dst) {
		BULLSEYE_EXCLUDE_BLOCK_END
			if (netdevice_eth->get_vlan()) { //vlan interface
				uint16_t vlan_tci = (m_pcp << 12) | netdevice_eth->get_vlan();
				m_header.configure_vlan_eth_headers(*src, *dst, vlan_tci);
			}
			else {
				m_header.configure_eth_headers(*src, *dst);
			}
			init_sge();
			ret_val = true;
		}
		else {
			dst_logerr("Can't build proper L2 header, L2 address is not available");
		}
	}
	else {
		dst_logerr("Dynamic cast failed, can't build proper L2 header");
	}

	return ret_val;
}


bool  dst_entry::conf_l2_hdr_and_snd_wqe_ib()
{
	bool ret_val = false;
	neigh_ib_val *neigh_ib = dynamic_cast<neigh_ib_val*>(m_p_neigh_val);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!neigh_ib) {
		dst_logerr("Dynamic cast to neigh_ib failed, can't build proper ibv_send_wqe: header");
	BULLSEYE_EXCLUDE_BLOCK_END
	}
	else {
		uint32_t qpn = neigh_ib->get_qpn();
		uint32_t qkey = neigh_ib->get_qkey();
		struct ibv_ah *ah = (struct ibv_ah *)neigh_ib->get_ah();

		//Maybe we after invalidation so we free the wqe_handler since we are going to build it from scratch
		if (m_p_send_wqe_handler) {
			delete m_p_send_wqe_handler;
			m_p_send_wqe_handler = NULL;
		}
		m_p_send_wqe_handler = new wqe_send_ib_handler();

		BULLSEYE_EXCLUDE_BLOCK_START
		if (!m_p_send_wqe_handler) {
			dst_logpanic("%s Failed to allocate send WQE handler", to_str().c_str());
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		((wqe_send_ib_handler *)(m_p_send_wqe_handler))->init_inline_ib_wqe(m_inline_send_wqe, get_sge_lst_4_inline_send(), get_inline_sge_num(), ah, qpn, qkey);
		((wqe_send_ib_handler*)(m_p_send_wqe_handler))->init_not_inline_ib_wqe(m_not_inline_send_wqe, get_sge_lst_4_not_inline_send(), 1, ah, qpn, qkey);
		((wqe_send_ib_handler*)(m_p_send_wqe_handler))->init_ib_wqe(m_fragmented_send_wqe, get_sge_lst_4_not_inline_send(), 1, ah, qpn, qkey);
		m_header.configure_ipoib_headers();
		init_sge();

		ret_val = true;
	}
	return ret_val;
}

bool dst_entry::conf_hdrs_and_snd_wqe()
{
	transport_type_t tranposrt = VMA_TRANSPORT_IB;
	bool ret_val = true;

	dst_logdbg("dst_entry %s configuring the header template", to_str().c_str());

	configure_ip_header(&m_header);

	if (m_p_net_dev_val) {
		tranposrt = m_p_net_dev_val->get_transport_type();
	}

	switch (tranposrt) {
	case VMA_TRANSPORT_ETH:
		ret_val = conf_l2_hdr_and_snd_wqe_eth();
		break;
	case VMA_TRANSPORT_IB:
	default:
		ret_val = conf_l2_hdr_and_snd_wqe_ib();
		break;
	}
	return ret_val;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

bool dst_entry::get_net_dev_val()
{
	bool ret_val = false;

	if (m_p_rt_entry) {
		m_p_rt_entry->get_val(m_p_rt_val);
		ret_val = true;
	}
	else {
		dst_logdbg("%s doesn't use route table to resolve netdev", to_str().c_str());
	}
	return ret_val;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

//Implementation of pure virtual function of neigh_observer
transport_type_t dst_entry::get_obs_transport_type() const
{
	if(m_p_net_dev_val)
		return(m_p_net_dev_val->get_transport_type());
	return VMA_TRANSPORT_UNKNOWN;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

flow_tuple dst_entry::get_flow_tuple() const
{
	in_addr_t dst_ip = 0;
	in_protocol_t protocol = PROTO_UNDEFINED;

	dst_ip = m_dst_ip.get_in_addr();
	protocol = (in_protocol_t)get_protocol_type();

	return flow_tuple(dst_ip, m_dst_port, m_pkt_src_ip, m_src_port, protocol);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

bool dst_entry::offloaded_according_to_rules()
{
	bool ret_val = true;
	transport_t target_transport;

	sockaddr_in to;
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = m_dst_ip.get_in_addr();
	to.sin_port = m_dst_port;


	target_transport = get_transport(to);

	if (target_transport == TRANS_OS) {
		ret_val = false;
	}
	return ret_val;
}

bool dst_entry::prepare_to_send(struct vma_rate_limit_t &rate_limit, bool skip_rules, bool is_connect)
{
	bool resolved = false;
	m_slow_path_lock.lock();
	if (!m_b_is_initialized) {
		if((!skip_rules) && (!offloaded_according_to_rules())) {
			dst_logdbg("dst_entry in BLACK LIST!");
			m_b_is_offloaded = false;
			m_b_force_os = true;
		}
		m_b_is_initialized = true;
	}
	dst_logdbg("%s", to_str().c_str());
	if (!m_b_force_os && !is_valid()) {
		bool is_ofloaded = false;
		set_state(true);
		if (resolve_net_dev(is_connect)) {
			set_src_addr();
			// overwrite mtu from route if exists
			m_max_udp_payload_size = get_route_mtu() - sizeof(struct iphdr);
			m_max_ip_payload_size = m_max_udp_payload_size & ~0x7;
			if (resolve_ring()) {
				is_ofloaded = true;
				modify_ratelimit(rate_limit);
				if (resolve_neigh()) {
					if (get_obs_transport_type() == VMA_TRANSPORT_ETH) {
						dst_logdbg("local mac: %s peer mac: %s", m_p_net_dev_val->get_l2_address()->to_str().c_str(), m_p_neigh_val->get_l2_address()->to_str().c_str());
					} else {
						dst_logdbg("peer L2 address: %s", m_p_neigh_val->get_l2_address()->to_str().c_str());
					}
					configure_headers();
					m_id = m_p_ring->generate_id(m_p_net_dev_val->get_l2_address()->get_address(),
								     m_p_neigh_val->get_l2_address()->get_address(),
								     ((ethhdr*)(m_header.m_actual_hdr_addr))->h_proto /* if vlan, use vlan proto */,
								     htons(ETH_P_IP),
								     m_pkt_src_ip,
								     m_dst_ip.get_in_addr(),
								     m_src_port,
								     m_dst_port);
					if (m_p_tx_mem_buf_desc_list) {
						m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true);
						m_p_tx_mem_buf_desc_list = NULL;
					}
					resolved = true;
				}
			}
		}
		m_b_is_offloaded = is_ofloaded;
		if (m_b_is_offloaded) {
			dst_logdbg("dst_entry is offloaded!");
		}
		else {
			dst_logdbg("dst_entry is NOT offloaded!");
		}
		if (!resolved) {
			set_state(false);
		}
	}
	m_slow_path_lock.unlock();

	return m_b_is_offloaded;
}

bool dst_entry::try_migrate_ring(lock_base& socket_lock)
{
	if (m_ring_alloc_logic.should_migrate_ring()) {
		do_ring_migration(socket_lock);
		return true;
	}
	return false;
}

int dst_entry::get_route_mtu()
{
	if (m_p_rt_val && m_p_rt_val->get_mtu() > 0 ) {
		return m_p_rt_val->get_mtu();
	}
	return m_p_net_dev_val->get_mtu();
}

void dst_entry::do_ring_migration(lock_base& socket_lock)
{
	m_slow_path_lock.lock();

	if (!m_p_net_dev_val || !m_p_ring) {
		m_slow_path_lock.unlock();
		return;
	}

	resource_allocation_key *new_key = m_ring_alloc_logic.get_key();
	uint64_t new_calc_id = m_ring_alloc_logic.calc_res_key_by_logic();
	// Check again if migration is needed before migration
	if (new_key->get_user_id_key() == new_calc_id) {
		m_slow_path_lock.unlock();
		return;
	}
	// Save old key for release
	resource_allocation_key old_key(*m_ring_alloc_logic.get_key());
	// Update key to new ID
	new_key->set_user_id_key(new_calc_id);
	m_slow_path_lock.unlock();
	socket_lock.unlock();

	ring* new_ring = m_p_net_dev_val->reserve_ring(new_key);
	if (!new_ring) {
		socket_lock.lock();
		return;
	}
	if (new_ring == m_p_ring) {
		if (!m_p_net_dev_val->release_ring(&old_key)) {
			dst_logerr("Failed to release ring for allocation key %s",
				  old_key.to_str());
		}
		socket_lock.lock();
		return;
	}

	dst_logdbg("migrating from key=%s and ring=%p to key=%s and ring=%p",
		   old_key.to_str(), m_p_ring, new_key->to_str(), new_ring);

	socket_lock.lock();
	m_slow_path_lock.lock();

	set_state(false);

	ring* old_ring = m_p_ring;
	m_p_ring = new_ring;
	m_max_inline = m_p_ring->get_max_tx_inline();
	m_max_inline = std::min<uint32_t>(m_max_inline,
				get_route_mtu() + m_header.m_transport_header_len);

	mem_buf_desc_t* tmp_list = m_p_tx_mem_buf_desc_list;
	m_p_tx_mem_buf_desc_list = NULL;

	m_slow_path_lock.unlock();
	socket_lock.unlock();

	if (tmp_list) {
		old_ring->mem_buf_tx_release(tmp_list, true);
	}

	m_p_net_dev_val->release_ring(&old_key);

	socket_lock.lock();
}

void dst_entry::set_bound_addr(in_addr_t addr)
{
	dst_logdbg("");
	m_bound_ip = addr;
	set_state(false);
}

void dst_entry::set_so_bindtodevice_addr(in_addr_t addr)
{
	dst_logdbg("");
	m_so_bindtodevice_ip = addr;
	set_state(false);
}

in_addr_t dst_entry::get_dst_addr()
{
	return m_dst_ip.get_in_addr();
}

uint16_t dst_entry::get_dst_port()
{
	return m_dst_port;
}

ssize_t dst_entry::pass_buff_to_neigh(const iovec * p_iov, size_t & sz_iov, uint16_t packet_id)
{
	ssize_t ret_val = 0;

	dst_logdbg("");

	configure_ip_header(&m_header_neigh, packet_id);

	if (m_p_neigh_entry) {
		neigh_send_info n_send_info(const_cast<iovec *>(p_iov),
				sz_iov, &m_header_neigh,
				get_protocol_type(), get_route_mtu(),
				m_tos);
		ret_val = m_p_neigh_entry->send(n_send_info);
	}

	return ret_val;
}

bool dst_entry::alloc_transport_dep_res()
{
	return alloc_neigh_val(get_obs_transport_type());
}

bool dst_entry::alloc_neigh_val(transport_type_t tranport)
{
	bool ret_val = false;

	if (m_p_neigh_val) {
		delete m_p_neigh_val;
		m_p_neigh_val = NULL;
	}

	switch (tranport) {
		case VMA_TRANSPORT_IB:
			m_p_neigh_val = new neigh_ib_val;
			break;
		case VMA_TRANSPORT_ETH:
		default:
			m_p_neigh_val = new neigh_eth_val;
			break;
	}
	if (m_p_neigh_val) {
		ret_val = true;
	}
	return ret_val;
}

void dst_entry::return_buffers_pool()
{
	if (m_p_tx_mem_buf_desc_list == NULL) {
		return;
	}

	if (m_b_tx_mem_buf_desc_list_pending && m_p_ring &&
		m_p_ring->mem_buf_tx_release(m_p_tx_mem_buf_desc_list, true, true)) {
		m_p_tx_mem_buf_desc_list = NULL;
		set_tx_buff_list_pending(false);
	} else {
		set_tx_buff_list_pending(true);
	}
}

int dst_entry::modify_ratelimit(struct vma_rate_limit_t &rate_limit)
{
	if (m_p_ring) {
		return m_p_ring->modify_ratelimit(rate_limit);
	}
	return 0;
}
