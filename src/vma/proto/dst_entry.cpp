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


#include "dst_entry.h"
#include "vma/proto/rule_table_mgr.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/util/utils.h"
#include "vma/util/bullseye.h"

#define MODULE_NAME             "dst"

#define dst_logpanic           __log_panic
#define dst_logerr             __log_err
#define dst_logwarn            __log_warn
#define dst_loginfo            __log_info
#define dst_logdbg             __log_info_dbg
#define dst_logfunc            __log_info_func
#define dst_logfuncall         __log_info_funcall


dst_entry::dst_entry(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, int owner_fd):
	m_dst_ip(dst_ip), m_dst_port(dst_port), m_src_port(src_port), m_bound_ip(0),
	m_so_bindtodevice_ip(0), m_ring_alloc_logic(owner_fd, this), m_p_tx_mem_buf_desc_list(NULL)
{
	dst_logdbg("dst:%s:%d src: %d", m_dst_ip.to_str().c_str(), ntohs(m_dst_port), ntohs(m_src_port));
	init_members();
}

dst_entry::~dst_entry()
{
	dst_logdbg("%s", to_str().c_str());

	if (m_p_neigh_entry) {
		g_p_neigh_table_mgr->unregister_observer(neigh_key(m_dst_ip, m_p_net_dev_val),this);
	}

	if (m_p_rt_entry) {
		g_p_route_table_mgr->unregister_observer(route_table_key(m_dst_ip.get_in_addr(),
				m_p_rr_val->get_table_id()), this);
		m_p_rt_entry = NULL;
	}

	if (m_p_rr_entry) {
		g_p_rule_table_mgr->unregister_observer(
				rule_table_key(m_dst_ip.get_in_addr(), m_bound_ip ? m_bound_ip : m_so_bindtodevice_ip, m_tos),
				this);
		m_p_rr_entry = NULL;
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
	m_p_rr_val = NULL;
	m_p_net_dev_val = NULL;
	m_p_ring = NULL;
	m_p_net_dev_entry = NULL;
	m_p_neigh_entry = NULL;
	m_p_neigh_val = NULL;
	m_p_rt_entry = NULL;
	m_p_rr_entry = NULL;
	m_num_sge = 0;
	memset(&m_inline_send_wqe, 0, sizeof(vma_ibv_send_wr));
	memset(&m_not_inline_send_wqe, 0, sizeof(vma_ibv_send_wr));
	m_p_send_wqe_handler = NULL;
	memset(&m_sge, 0, sizeof(m_sge));
	m_tos = 0;
	m_ttl = 64;
	m_b_is_offloaded = true;
	m_b_is_initialized = false;
	m_p_send_wqe = NULL;
	m_max_inline = 0;
	m_b_force_os = false;
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
			g_p_neigh_table_mgr->unregister_observer(neigh_key(m_dst_ip, m_p_net_dev_val),this);
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

bool dst_entry::resolve_net_dev()
{
	bool ret_val = false;

	cache_entry_subject<rule_table_key, rule_val*>* rr_entry = NULL;
	cache_entry_subject<route_table_key, route_val*>* p_ces = NULL;
	
	if (ZERONET_N(m_dst_ip.get_in_addr())) {
		dst_logdbg("VMA does not offload zero net IP address");
		return ret_val;
	}

	if (LOOPBACK_N(m_dst_ip.get_in_addr())) {
		dst_logdbg("VMA does not offload local loopback IP address");
		return ret_val;
	}
		
	if (m_p_rr_entry == NULL) {
	
		rule_table_key rrk(m_dst_ip.get_in_addr(), m_bound_ip ? m_bound_ip : m_so_bindtodevice_ip, m_tos);
		g_p_rule_table_mgr->register_observer(rrk, this, &rr_entry);
		m_p_rr_entry = dynamic_cast<rule_entry*>(rr_entry);
	
		if (m_p_rr_entry) {
			m_p_rr_entry->get_val(m_p_rr_val);
		}
		else {
			dst_logdbg("rule entry is not exist");
			return ret_val;
		}
	}
	
	
	route_table_key rtk(m_dst_ip.get_in_addr(), m_p_rr_val->get_table_id());
	
	if (m_p_rt_entry || g_p_route_table_mgr->register_observer(rtk, this, &p_ces)) {
	
		if (m_p_rt_entry == NULL) {
			// In case this is the first time we trying to resolve route entry,
			// means that register_observer was run
			m_p_rt_entry = dynamic_cast<route_entry*>(p_ces);
		}

		if(update_rt_val()) {
			ret_val = update_net_dev_val();
		}
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
			m_max_inline = m_p_ring->get_max_tx_inline();
			m_max_inline = std::min(m_max_inline, m_p_net_dev_val->get_mtu() + (uint32_t)m_header.m_transport_header_len);
		}
		ret_val = true;
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
			m_p_net_dev_val->release_ring(m_ring_alloc_logic.get_key());
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

void dst_entry::configure_ip_header(uint16_t packet_id)
{
	m_header.configure_ip_header(get_protocol_type(), m_bound_ip ? m_bound_ip : m_p_net_dev_val->get_local_addr(), m_dst_ip.get_in_addr(), m_ttl, m_tos, packet_id);
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
	m_p_send_wqe_handler->init_wqe(m_not_inline_send_wqe, get_sge_lst_4_not_inline_send(), 1);

	net_device_val_eth *netdevice_eth = dynamic_cast<net_device_val_eth*>(m_p_net_dev_val);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (netdevice_eth) {
	BULLSEYE_EXCLUDE_BLOCK_END
		const L2_address *src = m_p_net_dev_val->get_l2_address();
		const L2_address *dst = m_p_neigh_val->get_l2_address();

		BULLSEYE_EXCLUDE_BLOCK_START
		if (src && dst) {
		BULLSEYE_EXCLUDE_BLOCK_END
			if (netdevice_eth->get_vlan()) { //vlam interface
				m_header.configure_vlan_eth_headers(*src, *dst, netdevice_eth->get_vlan());
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
		((wqe_send_ib_handler *)(m_p_send_wqe_handler))->init_inline_wqe(m_inline_send_wqe, get_sge_lst_4_inline_send(), get_inline_sge_num(), ah, qpn, qkey);
		((wqe_send_ib_handler*)(m_p_send_wqe_handler))->init_wqe(m_not_inline_send_wqe, get_sge_lst_4_not_inline_send(), 1, ah, qpn, qkey);
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

	configure_ip_header();

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
		ret_val = m_p_rt_entry->get_val(m_p_rt_val);
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
	in_addr_t src_ip = 0;
	in_addr_t dst_ip = 0;
	in_protocol_t protocol = PROTO_UNDEFINED;

	if (m_p_net_dev_val) {
		src_ip = m_p_net_dev_val->get_local_addr();
	}
	dst_ip = m_dst_ip.get_in_addr();
	protocol = (in_protocol_t)get_protocol_type();

	return flow_tuple(dst_ip, m_dst_port, src_ip, m_src_port, protocol);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

bool dst_entry::offloaded_according_to_rules()
{
	bool ret_val = true;
	transport_t target_transport;

	sockaddr_in to;
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = m_dst_ip.get_in_addr();
	to.sin_port = m_dst_port;
	memset(&to.sin_zero, 0, sizeof(to.sin_zero));


	target_transport = get_transport(to);

	if (target_transport == TRANS_OS) {
		ret_val = false;
	}
	return ret_val;
}

bool dst_entry::prepare_to_send(bool skip_rules)
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
		if (resolve_net_dev()) {
			if (resolve_ring()) {
				is_ofloaded = true;
				if (resolve_neigh()) {
					if (get_obs_transport_type() == VMA_TRANSPORT_ETH)
						dst_logdbg("local mac: %s peer mac: %s", m_p_net_dev_val->get_l2_address()->to_str().c_str(), m_p_neigh_val->get_l2_address()->to_str().c_str());
					else
						dst_logdbg("peer L2 address: %s", m_p_neigh_val->get_l2_address()->to_str().c_str());
					configure_headers();
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

void dst_entry::do_ring_migration(lock_base& socket_lock)
{
	m_slow_path_lock.lock();

	if (!m_p_net_dev_val || !m_p_ring) {
		m_slow_path_lock.unlock();
		return;
	}

	resource_allocation_key old_key = m_ring_alloc_logic.get_key();
	resource_allocation_key new_key = m_ring_alloc_logic.create_new_key(old_key);

	if (old_key == new_key) {
		m_slow_path_lock.unlock();
		return;
	}

	m_slow_path_lock.unlock();
	socket_lock.unlock();

	ring* new_ring = m_p_net_dev_val->reserve_ring(new_key);
	if (new_ring == m_p_ring) {
		m_p_net_dev_val->release_ring(old_key);
		return;
	}

	dst_logdbg("migrating from key=%lu and ring=%p to key=%lu and ring=%p", old_key, m_p_ring, new_key, new_ring);

	socket_lock.lock();
	m_slow_path_lock.lock();

	set_state(false);

	ring* old_ring = m_p_ring;
	m_p_ring = new_ring;
	m_max_inline = m_p_ring->get_max_tx_inline();
	m_max_inline = std::min(m_max_inline, m_p_net_dev_val->get_mtu() + (uint32_t)m_header.m_transport_header_len);

	mem_buf_desc_t* tmp_list = m_p_tx_mem_buf_desc_list;
	m_p_tx_mem_buf_desc_list = NULL;

	m_slow_path_lock.unlock();
	socket_lock.unlock();

	if (tmp_list) {
		old_ring->mem_buf_tx_release(tmp_list, true);
	}

	m_p_net_dev_val->release_ring(old_key);

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

in_addr_t dst_entry::get_src_addr()
{
	in_addr_t ret_val = INADDR_ANY;

	if (m_p_net_dev_val) {
		ret_val = m_p_net_dev_val->get_local_addr();
	}
	return ret_val;
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
	neigh_send_info n_send_info;

	dst_logdbg("");

	configure_ip_header(packet_id);

	if (m_p_neigh_entry) {
		n_send_info.m_p_iov = const_cast<iovec *>(p_iov);
		n_send_info.m_sz_iov = sz_iov;
		n_send_info.m_protocol = get_protocol_type();
		n_send_info.m_p_header = &m_header;
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
