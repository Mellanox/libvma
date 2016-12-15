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


#include "dst_entry_udp_mc.h"

#define MODULE_NAME             "dst_mc"

#define dst_udp_mc_logpanic           __log_panic
#define dst_udp_mc_logerr             __log_err
#define dst_udp_mc_logwarn            __log_warn
#define dst_udp_mc_loginfo            __log_info
#define dst_udp_mc_logdbg             __log_info_dbg
#define dst_udp_mc_logfunc            __log_info_func
#define dst_udp_mc_logfuncall         __log_info_funcall


dst_entry_udp_mc::dst_entry_udp_mc(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, in_addr_t tx_if_ip, bool mc_b_loopback, uint8_t mc_ttl, int owner_fd) :
					dst_entry_udp(dst_ip, dst_port, src_port, owner_fd),
					m_mc_tx_if_ip(tx_if_ip), m_b_mc_loopback_enabled(mc_b_loopback)
{
	m_ttl = mc_ttl;
	dst_udp_mc_logdbg("%s", to_str().c_str());
}

dst_entry_udp_mc::~dst_entry_udp_mc()
{
	dst_udp_mc_logdbg("%s", to_str().c_str());
}

//The following function supposed to be called under m_lock
bool dst_entry_udp_mc::conf_l2_hdr_and_snd_wqe_ib()
{
	bool ret_val = false;

	dst_udp_mc_logfunc("%s", to_str().c_str());

	ret_val = dst_entry_udp::conf_l2_hdr_and_snd_wqe_ib();

	if (ret_val && !m_b_mc_loopback_enabled && m_p_send_wqe_handler) {
		wqe_send_ib_handler *wqe_ib = dynamic_cast<wqe_send_ib_handler*>(m_p_send_wqe_handler);
		if (wqe_ib) {
			//Since checksum fails when packet contains an immediate header we don't enable an immediate header
			//So MC loopback disable is NOT SUPPORTED!
			//wqe_ib->enable_imm_data(m_inline_send_wqe);
			//wqe_ib->enable_imm_data(m_not_inline_send_wqe);
		}
		else {
			ret_val = false;
		}
	}
	return ret_val;
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
			if (m_p_net_dev_val && m_p_net_dev_val->is_valid()) {
				ret_val = alloc_transport_dep_res();
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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
//The following function supposed to be called under m_lock
bool dst_entry_udp_mc::get_net_dev_val()
{
	bool ret_val = false;

	if (m_p_rt_entry) {
		dst_udp_mc_logfunc("%s Using rt table to get netdev", to_str().c_str());
		ret_val = m_p_rt_entry->get_val(m_p_rt_val);
	}
	else {
		if (m_p_net_dev_entry) {
			m_p_net_dev_entry->get_val(m_p_net_dev_val);
			dst_udp_mc_logfunc("%s Using directly netdev entry to get net_dev", to_str().c_str());
			ret_val = true;
		}
		else {
			dst_udp_mc_logdbg("%s netdev is not offloaded", to_str().c_str());
		}
	}
	return ret_val;
}

void dst_entry_udp_mc::set_mc_tx_if_ip(in_addr_t tx_if_ip)
{
	m_mc_tx_if_ip = tx_if_ip;
	set_state(false);
}

void dst_entry_udp_mc::set_mc_loopback(bool b_mc_loopback)
{
	m_b_mc_loopback_enabled = b_mc_loopback;
	set_state(false);
}

void dst_entry_udp_mc::set_mc_ttl(uint8_t mc_ttl)
{
	m_ttl = mc_ttl;
	set_state(false);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif


