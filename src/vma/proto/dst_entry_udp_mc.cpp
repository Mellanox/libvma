/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "dst_entry_udp_mc.h"

#define MODULE_NAME             "dst_mc"

#define dst_udp_mc_logpanic           __log_panic
#define dst_udp_mc_logerr             __log_err
#define dst_udp_mc_logwarn            __log_warn
#define dst_udp_mc_loginfo            __log_info
#define dst_udp_mc_logdbg             __log_info_dbg
#define dst_udp_mc_logfunc            __log_info_func
#define dst_udp_mc_logfuncall         __log_info_funcall


dst_entry_udp_mc::dst_entry_udp_mc(in_addr_t dst_ip, uint16_t dst_port,
				   uint16_t src_port, in_addr_t tx_if_ip,
				   bool mc_b_loopback ,socket_data &sock_data,
				   resource_allocation_key &ring_alloc_logic):
					dst_entry_udp(dst_ip, dst_port, src_port, sock_data, ring_alloc_logic),
					m_mc_tx_if_ip(tx_if_ip), m_b_mc_loopback_enabled(mc_b_loopback)
{
	dst_udp_mc_logdbg("%s", to_str().c_str());
}

dst_entry_udp_mc::~dst_entry_udp_mc()
{
	dst_udp_mc_logdbg("%s", to_str().c_str());
}

void dst_entry_udp_mc::set_src_addr()
{
	m_pkt_src_ip = INADDR_ANY;
	
	if (m_bound_ip) {
		m_pkt_src_ip = m_bound_ip;
	}
	else if (m_mc_tx_if_ip.get_in_addr() && !m_mc_tx_if_ip.is_mc()) {
		m_pkt_src_ip = m_mc_tx_if_ip.get_in_addr();
	}
	else if (m_p_rt_val && m_p_rt_val->get_src_addr()) {
		m_pkt_src_ip = m_p_rt_val->get_src_addr();
	}
	else if (m_p_net_dev_val && m_p_net_dev_val->get_local_addr()) {
		m_pkt_src_ip = m_p_net_dev_val->get_local_addr();
	}
}

//The following function supposed to be called under m_lock
bool dst_entry_udp_mc::resolve_net_dev(bool is_connect)
{
	NOT_IN_USE(is_connect);
	bool ret_val = false;
	cache_entry_subject<ip_address, net_device_val*>* p_ces = NULL;

	if (m_mc_tx_if_ip.get_in_addr() != INADDR_ANY && !m_mc_tx_if_ip.is_mc()) {
		if(m_p_net_dev_entry == NULL && g_p_net_device_table_mgr->register_observer(m_mc_tx_if_ip.get_in_addr(), this, &p_ces)) {
			m_p_net_dev_entry = dynamic_cast<net_device_entry*>(p_ces);
		}
		if (m_p_net_dev_entry) {
			m_p_net_dev_entry->get_val(m_p_net_dev_val);
			if (m_p_net_dev_val) {
				ret_val = alloc_neigh_val();
			}
			else {
				dst_udp_mc_logdbg("Valid netdev value not found");
			}
		}
		else {
			m_b_is_offloaded = false;
			dst_udp_mc_logdbg("Netdev is not offloaded fallback to OS");
		}
	}
	else {
		ret_val = dst_entry::resolve_net_dev();
	}
	return ret_val;
}
