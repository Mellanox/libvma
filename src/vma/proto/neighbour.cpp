/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include <errno.h>
#include <arpa/inet.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/utils.h"
#include "vma/dev/ib_ctx_handler_collection.h"
#include "vma/proto/neighbour.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "vma/proto/route_rule_table_key.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/dev/wqe_send_handler.h"

//This include should be after vma includes
#include <netinet/tcp.h>

#define MODULE_NAME 		"ne"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[%s]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_to_str.c_str()

#define neigh_logpanic		__log_info_panic
#define neigh_logerr		__log_info_err
#define neigh_logwarn		__log_info_warn
#define neigh_loginfo		__log_info_info
#define neigh_logdbg		__log_info_dbg
#define neigh_logfunc		__log_info_func
#define neigh_logfuncall	__log_info_funcall

#define run_helper_func(func, event)				\
		{if (my_neigh->func) { 				\
			my_neigh->priv_event_handler_no_locks((event));	\
			return;						\
		}}

#define RDMA_CM_TIMEOUT 3500


/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

// This function create new val and initiate it with Multicast MAC
inline int neigh_eth::build_mc_neigh_val()
{
	neigh_logdbg("");

	//We need lock in any case that we change entry
	auto_unlocker lock(m_lock);

	m_state = false;

	if (m_val == NULL)
		//This is the first time we are trying to allocate new val or it failed last time
		m_val = new neigh_val;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_val == NULL) {
		neigh_logdbg("m_val allocation has failed");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	address_t address = new unsigned char[ETH_ALEN];
	create_multicast_mac_from_ip(address, get_key().get_in_addr());
	m_val->m_l2_address = new ETH_addr(address);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_val->m_l2_address == NULL) {
		neigh_logdbg("m_val->m_l2_address allocation has failed");
		delete [] address;
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_state = true;
	neigh_logdbg("Peer MAC = %s", m_val->m_l2_address->to_str().c_str());
	delete [] address;
	return 0;

}

inline int neigh_eth::build_uc_neigh_val()
{
	neigh_logdbg("");

	// We need lock in any case that we change entry
	auto_unlocker lock(m_lock);

	if (m_val == NULL) {
		// This is the first time we are trying to allocate new val or it failed last time
		m_val = new neigh_val;
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_val == NULL)
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END

	unsigned char tmp[ETH_ALEN];
	address_t address = (address_t)tmp;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!priv_get_neigh_l2(address)) {
		neigh_logdbg("Failed in priv_get_neigh_l2()");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_val->m_l2_address = new ETH_addr(address);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_val->m_l2_address == NULL) {
		neigh_logdbg("m_val->m_l2_address allocation has failed");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	neigh_logdbg("Peer MAC = %s", m_val->m_l2_address->to_str().c_str());
	return 0;
}

neigh_entry::neigh_entry(neigh_key key, bool is_init_resources):
	cache_entry_subject<neigh_key, neigh_val *>(key),
	m_cma_id(NULL),
	m_rdma_port_space((enum rdma_port_space)0),
	m_state_machine(NULL),
	m_type(UNKNOWN),
	m_state(false),
	m_err_counter(0),
	m_timer_handle(NULL),
	m_arp_counter(0),
	m_p_dev(key.get_net_device_val()),
	m_p_ring(NULL),
	m_is_loopback(false),
	m_to_str(get_key().to_str()), m_id(0),
	m_is_first_send_arp(true), m_n_sysvar_neigh_wait_till_send_arp_msec(safe_mce_sys().neigh_wait_till_send_arp_msec),
	m_n_sysvar_neigh_uc_arp_quata(safe_mce_sys().neigh_uc_arp_quata),
	m_n_sysvar_neigh_num_err_retries(safe_mce_sys().neigh_num_err_retries)
{
	m_val = NULL;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_dev == NULL) {
		neigh_logpanic("get_net_dev return NULL");
	}

	ring_alloc_logic_attr ring_attr(safe_mce_sys().ring_allocation_logic_tx);
	m_ring_allocation_logic = ring_allocation_logic_tx(m_p_dev->get_local_addr(), ring_attr, this);

	if(is_init_resources) {
		m_p_ring = m_p_dev->reserve_ring(m_ring_allocation_logic.get_key());
		if (m_p_ring == NULL) {
			neigh_logpanic("reserve_ring return NULL");
		}
		m_id = m_p_ring->generate_id();
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	memset(&m_dst_addr, 0, sizeof(m_dst_addr));
	memset(&m_src_addr, 0, sizeof(m_src_addr));
	m_dst_addr.sin_addr.s_addr = get_key().get_in_addr(); /*(peer_ip)*/
	m_dst_addr.sin_family = AF_INET;

	m_src_addr.sin_addr.s_addr = m_p_dev->get_local_addr();
	m_src_addr.sin_family = AF_INET;

	memset(&m_send_wqe, 0, sizeof(m_send_wqe));
	memset(&m_sge, 0, sizeof(m_sge));

	/* Verify if neigh is local (loopback) checking into account
	 * primary and secondary ip-addresses
	 */
	{
		const ip_data_vector_t& ip = m_p_dev->get_ip_array();
		for (size_t i = 0; i < ip.size(); i++) {
			if (ip[i]->local_addr == m_dst_addr.sin_addr.s_addr) {
				neigh_logdbg("This is loopback neigh");
				m_is_loopback = true;
				break;
			}
		}
	}

	neigh_logdbg("Created new neigh_entry");
}

neigh_entry::~neigh_entry()
{
	neigh_logdbg("");

	if (m_state_machine) {
		delete m_state_machine;
		m_state_machine = NULL;
	}
	if (m_p_dev && m_p_ring) {
		m_p_dev->release_ring(m_ring_allocation_logic.get_key());
		m_p_ring = NULL;
	}
	if (m_val) {
		delete m_val;
		m_val = NULL;
	}
	//TODO:Do we want to check here that unsent queue is empty and if not to send everything?

	neigh_logdbg("Done");
}

bool neigh_entry::is_deletable()
{
	if(m_state_machine == NULL) {
		return true;
	}

	int state = m_state_machine->get_curr_state();

	//Wait for steady state in which unsent_queue is empty
	if(state == ST_NOT_ACTIVE || state == ST_READY) {
		return true;
	}
	return false;
}

void neigh_entry::clean_obj()
{
	if (is_cleaned()) {
		return ;
	}

	m_lock.lock();
	set_cleaned();
	m_timer_handle = NULL;
	if (g_p_event_handler_manager->is_running()) {
		g_p_event_handler_manager->unregister_timers_event_and_delete(this);
		m_lock.unlock();
	} else {
		m_lock.unlock();
		cleanable_obj::clean_obj();
	}
}

int neigh_entry::send(neigh_send_info &s_info)
{
	neigh_logdbg("");
	auto_unlocker lock(m_lock);
	//Need to copy send info
	neigh_send_data *ns_data = new neigh_send_data(&s_info);

	m_unsent_queue.push_back(ns_data);
	int ret = ns_data->m_iov.iov_len;
	if (m_state)
		empty_unsent_queue();
	// coverity[leaked_storage]
	return ret;
}

void neigh_entry::empty_unsent_queue()
{
	neigh_logdbg("");
	auto_unlocker lock(m_lock);

	while (!m_unsent_queue.empty())
	{
		neigh_send_data * n_send_data = m_unsent_queue.front();
		if (prepare_to_send_packet(n_send_data->m_header)) {
			if (post_send_packet(n_send_data)) {
				neigh_logdbg("sent one packet");
			}
			else {
				neigh_logdbg("Failed in post_send_packet(). Dropping the packet");
			}
		}
		else {
			neigh_logdbg("Failed in prepare_to_send_packet(). Dropping the packet");
		}
		m_unsent_queue.pop_front();
		delete n_send_data;
	}
}

void neigh_entry::handle_timer_expired(void* ctx)
{
	NOT_IN_USE(ctx);
	neigh_logdbg("Timeout expired!");

	// Clear Timer Handler
	m_timer_handle = NULL;

	m_sm_lock.lock();
	int sm_state = m_state_machine->get_curr_state();
	m_sm_lock.unlock();

	if(sm_state == ST_INIT) {
		event_handler(EV_START_RESOLUTION);
		return;
	}

	// Check if neigh_entry state is reachable
	int state;
	if(!priv_get_neigh_state(state)) {
		neigh_logdbg("neigh state not valid!\n");
		return;
	}

	if(!priv_is_failed(state)) {
		//We want to verify that L2 address wasn't changed
		unsigned char tmp[ETH_ALEN];
		address_t l2_addr = (address_t)tmp;
		if(!priv_get_neigh_l2(l2_addr)) {
			return;
		}
		if(priv_handle_neigh_is_l2_changed(l2_addr)) {
			return;
		}
	}

	if (!priv_is_reachable(state)) {
		neigh_logdbg("State (%d) is not reachable and L2 address wasn't changed. Sending ARP", state);
		send_arp();
		m_timer_handle = priv_register_timer_event(m_n_sysvar_neigh_wait_till_send_arp_msec, this, ONE_SHOT_TIMER, NULL);
	}
	else {
		neigh_logdbg("State is reachable (%s %d) and L2 address wasn't changed. Stop sending ARP", (state == NUD_REACHABLE) ? "NUD_REACHABLE" : "NUD_PERMANENT", state);
	}
}

void neigh_entry::send_arp()
{
	// In case we already sent the quota number of unicast ARPs, start sending broadcast ARPs
	// or we want to send broadcast ARP for the first time
	// or m_val is not valid
	bool is_broadcast = (m_arp_counter >= m_n_sysvar_neigh_uc_arp_quata) || m_is_first_send_arp || !m_val;
	if (post_send_arp(is_broadcast)) {
		m_is_first_send_arp = false;
		m_arp_counter++;
	}
}

bool neigh_entry::post_send_packet(neigh_send_data *p_n_send_data)
{
	neigh_logdbg("ENTER post_send_packet protocol = %d", p_n_send_data->m_protocol);
	m_id = generate_ring_user_id(p_n_send_data->m_header);
	switch(p_n_send_data->m_protocol)
	{
		case  IPPROTO_UDP:
			return (post_send_udp(p_n_send_data));
		case  IPPROTO_TCP:
			return (post_send_tcp(p_n_send_data));
		default:
			neigh_logdbg("Unsupported protocol");
			return false;

	}
}

bool neigh_entry::post_send_udp(neigh_send_data *n_send_data)
{
	// Find number of ip fragments (-> packets, buffers, buffer descs...)
	neigh_logdbg("ENTER post_send_udp");
	int n_num_frags = 1;
	bool b_need_sw_csum = false;
#ifdef DEFINED_SW_CSUM
	b_need_sw_csum = true;
#endif
	mem_buf_desc_t* p_mem_buf_desc, *tmp = NULL;
	tx_packet_template_t *p_pkt;
	size_t sz_data_payload = n_send_data->m_iov.iov_len;
	header *h = n_send_data->m_header;

	size_t max_ip_payload_size = ((n_send_data->m_mtu - sizeof(struct iphdr)) & ~0x7);

	if (sz_data_payload > 65536) {
		neigh_logdbg("sz_data_payload=%zd exceeds max of 64KB", sz_data_payload);
		errno = EMSGSIZE;
		return false;
	}

	size_t sz_udp_payload = sz_data_payload + sizeof(struct udphdr);

	// Usually max inline < MTU!
	if (sz_udp_payload > max_ip_payload_size) {
		b_need_sw_csum = true;
		n_num_frags = (sz_udp_payload + max_ip_payload_size - 1) / max_ip_payload_size;
	}

	neigh_logdbg("udp info: payload_sz=%zd, frags=%d, scr_port=%d, dst_port=%d", sz_data_payload, n_num_frags, ntohs(h->m_header.hdr.m_udp_hdr.source), ntohs(h->m_header.hdr.m_udp_hdr.dest));

	// Get all needed tx buf descriptor and data buffers
	p_mem_buf_desc = m_p_ring->mem_buf_tx_get(m_id, false, n_num_frags);

	if (unlikely(p_mem_buf_desc == NULL)) {
		neigh_logdbg("Packet dropped. not enough tx buffers");
		return false;
	}

	// Int for counting offset inside the ip datagram payload
	uint32_t n_ip_frag_offset = 0;
	size_t sz_user_data_offset = 0;

	while (n_num_frags--) {
		// Calc this ip datagram fragment size (include any udp header)
		size_t sz_ip_frag = min(max_ip_payload_size, (sz_udp_payload - n_ip_frag_offset));
		size_t sz_user_data_to_copy = sz_ip_frag;
		size_t hdr_len = h->m_transport_header_len + h->m_ip_header_len; // Add count of L2 (ipoib or mac) header length

		p_pkt = (tx_packet_template_t*)p_mem_buf_desc->p_buffer;

		uint16_t frag_off = 0;
		if (n_num_frags) {
			frag_off |= MORE_FRAGMENTS_FLAG;
		}

		if (n_ip_frag_offset == 0) {
			h->copy_l2_ip_udp_hdr(p_pkt);
			// Add count of udp header length
			hdr_len += sizeof(udphdr);

			// Copy less from user data
			sz_user_data_to_copy -= sizeof(udphdr);

			// Only for first fragment add the udp header
			p_pkt->hdr.m_udp_hdr.len = htons((uint16_t)sz_udp_payload);
		}
		else {
			h->copy_l2_ip_hdr(p_pkt);
			frag_off |= FRAGMENT_OFFSET & (n_ip_frag_offset / 8);
		}

		p_pkt->hdr.m_ip_hdr.frag_off = htons(frag_off);
		// Update ip header specific values
		p_pkt->hdr.m_ip_hdr.tot_len = htons(h->m_ip_header_len + sz_ip_frag);

		// Calc payload start point (after the udp header if present else just after ip header)
		uint8_t* p_payload = p_mem_buf_desc->p_buffer + h->m_transport_header_tx_offset + hdr_len;

		// Copy user data to our tx buffers
		int ret = memcpy_fromiovec(p_payload, &n_send_data->m_iov, 1, sz_user_data_offset, sz_user_data_to_copy);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret != (int)sz_user_data_to_copy) {
			neigh_logerr("memcpy_fromiovec error (sz_user_data_to_copy=%zd, ret=%d)", sz_user_data_to_copy, ret);
			m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
			errno = EINVAL;
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		wqe_send_handler wqe_sh;
		vma_wr_tx_packet_attr attr = (vma_wr_tx_packet_attr)(VMA_TX_PACKET_L3_CSUM);
		if (b_need_sw_csum) {
			attr = (vma_wr_tx_packet_attr)(attr|VMA_TX_SW_CSUM);
			wqe_sh.disable_hw_csum(m_send_wqe);
		} else {
			neigh_logdbg("using HW checksum calculation");
			wqe_sh.enable_hw_csum(m_send_wqe);
		}

		p_mem_buf_desc->tx.p_ip_h = &p_pkt->hdr.m_ip_hdr;
		p_mem_buf_desc->tx.p_udp_h = &p_pkt->hdr.m_udp_hdr;

		m_sge.addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)h->m_transport_header_tx_offset);
		m_sge.length = sz_user_data_to_copy + hdr_len;
		m_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;

		neigh_logdbg("%s packet_sz=%d, payload_sz=%zd, ip_offset=%d id=%d", h->to_str().c_str(),
				m_sge.length - h->m_transport_header_len, sz_user_data_to_copy,
				n_ip_frag_offset, ntohs(p_pkt->hdr.m_ip_hdr.id));

		tmp = p_mem_buf_desc->p_next_desc;
		p_mem_buf_desc->p_next_desc = NULL;

		// We don't check the return value of post send when we reach the HW we consider that we completed our job
		m_p_ring->send_ring_buffer(m_id, &m_send_wqe, attr);

		p_mem_buf_desc = tmp;

		// Update ip frag offset position
		n_ip_frag_offset += sz_ip_frag;

		// Update user data start offset copy location
		sz_user_data_offset += sz_user_data_to_copy;

	} // while(n_num_frags)

	return true;
}


bool neigh_entry::post_send_tcp(neigh_send_data *p_data)
{
	tx_packet_template_t* p_pkt;
	mem_buf_desc_t *p_mem_buf_desc;
	size_t total_packet_len = 0;
	header *h = p_data->m_header;

	wqe_send_handler wqe_sh;
	wqe_sh.enable_hw_csum(m_send_wqe);

	p_mem_buf_desc = m_p_ring->mem_buf_tx_get(m_id, false, 1);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(p_mem_buf_desc == NULL)) {
		neigh_logdbg("Packet dropped. not enough tx buffers");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	p_mem_buf_desc->lwip_pbuf.pbuf.payload = (u8_t *)p_mem_buf_desc->p_buffer + h->m_total_hdr_len;

	p_mem_buf_desc->p_next_desc = NULL;

	//copy L4 neigh buffer to tx buffer
	memcpy((void*)(p_mem_buf_desc->p_buffer + h->m_aligned_l2_l3_len),
			p_data->m_iov.iov_base, p_data->m_iov.iov_len);

	p_pkt = (tx_packet_template_t*)(p_mem_buf_desc->p_buffer);
	total_packet_len = p_data->m_iov.iov_len + h->m_total_hdr_len;
	h->copy_l2_ip_hdr(p_pkt);
	// We've copied to aligned address, and now we must update p_pkt to point to real
	// L2 header

	p_pkt->hdr.m_ip_hdr.tot_len = (htons)(p_data->m_iov.iov_len + h->m_ip_header_len);

	// The header is aligned for fast copy but we need to maintain this diff in order to get the real header pointer easily
	size_t hdr_alignment_diff = h->m_aligned_l2_l3_len - h->m_total_hdr_len;
	m_sge.addr = (uintptr_t)((uint8_t*)p_pkt + hdr_alignment_diff);
	m_sge.length = total_packet_len;

	/* for DEBUG */
	if ((uint8_t*)m_sge.addr < p_mem_buf_desc->p_buffer) {
		neigh_logerr("p_buffer - addr=%d, m_total_hdr_len=%u, p_buffer=%p, type=%d, len=%d, tot_len=%d, payload=%p, hdr_alignment_diff=%zd\n",
				(int)(p_mem_buf_desc->p_buffer - (uint8_t*)m_sge.addr), h->m_total_hdr_len,
				p_mem_buf_desc->p_buffer, p_mem_buf_desc->lwip_pbuf.pbuf.type,
				p_mem_buf_desc->lwip_pbuf.pbuf.len, p_mem_buf_desc->lwip_pbuf.pbuf.tot_len,
				p_mem_buf_desc->lwip_pbuf.pbuf.payload, hdr_alignment_diff);
	}

	m_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;
	vma_wr_tx_packet_attr attr = (vma_wr_tx_packet_attr)(VMA_TX_PACKET_L3_CSUM|VMA_TX_PACKET_L4_CSUM);
	p_mem_buf_desc->tx.p_ip_h = &p_pkt->hdr.m_ip_hdr;
	p_mem_buf_desc->tx.p_tcp_h = (struct tcphdr*)(((uint8_t*)(&(p_pkt->hdr.m_ip_hdr))+sizeof(p_pkt->hdr.m_ip_hdr)));

	m_p_ring->send_ring_buffer(m_id, &m_send_wqe, attr);
#ifndef __COVERITY__
	struct tcphdr* p_tcp_h = (struct tcphdr*)(((uint8_t*)(&(p_pkt->hdr.m_ip_hdr))+sizeof(p_pkt->hdr.m_ip_hdr)));
	NOT_IN_USE(p_tcp_h); /* to supress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	neigh_logdbg("Tx TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
			ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest),
			p_tcp_h->urg?"U":"", p_tcp_h->ack?"A":"", p_tcp_h->psh?"P":"",
			p_tcp_h->rst?"R":"", p_tcp_h->syn?"S":"", p_tcp_h->fin?"F":"",
			ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window),
			total_packet_len- p_tcp_h->doff*4 -34);
#endif
	return true;
}

void neigh_entry::priv_handle_neigh_reachable_event()
{
	//In case this is reachable event we should set ARP counter to 0 and stop the timer
	//(we don't want to continue sending ARPs)
	m_arp_counter = 0;
	priv_unregister_timer();
}

//==========================================  cache_observer functions implementation ============================


bool neigh_entry::get_peer_info(neigh_val * p_val)
{
	neigh_logfunc("calling neigh_entry get_peer_info. state = %d", m_state);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_val == NULL) {
		neigh_logdbg("p_val is NULL, return false");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	auto_unlocker lock(m_lock);
	if (m_state) {
		neigh_logdbg("There is a valid val");
		*p_val = *m_val;
		return m_state;
	}

	/* If state is NOT_ACTIVE need to kick start state machine,
	 otherwise it means that it was already started*/
	if ((state_t)m_state_machine->get_curr_state() == ST_NOT_ACTIVE)
		priv_kick_start_sm();

	if (m_state) {
		neigh_logdbg("There is a valid val");
		*p_val = *m_val;
		return m_state;
	}

	return false;
}

// Overriding subject's register_observer
bool neigh_entry::register_observer(const observer* const new_observer)
{
	/* register_observer should kick start neigh state machine in case m_state is not valid
	 * and state of State Machine is NOT_ACTIVE
	 */
	neigh_logdbg("Observer = %p ", new_observer);

	if (subject::register_observer(new_observer))
	{
		if (!m_state && ((state_t) m_state_machine->get_curr_state()== ST_NOT_ACTIVE))
		{
			neigh_logdbg("SM state is ST_NOT_ACTIVE Kicking SM start");
			priv_kick_start_sm();
		}
		return true;
	}
	return false;
}

const std::string neigh_entry::to_str() const
{
	return m_to_str;
}

void neigh_entry::handle_neigh_event(neigh_nl_event* nl_ev)
{
	const netlink_neigh_info* nl_info = nl_ev->get_neigh_info();

	int neigh_state = nl_info->state;
	switch (neigh_state)
	{

	case NUD_REACHABLE:
	case NUD_PERMANENT:
	{
		BULLSEYE_EXCLUDE_BLOCK_START
		if(m_state_machine == NULL) {
			neigh_logerr("m_state_machine: not a valid case");
			break;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		neigh_logdbg("state = '%s' (%d) L2 address = %s", nl_info->get_state2str().c_str(), neigh_state, nl_info->lladdr_str.c_str());
		priv_handle_neigh_reachable_event();
		/* In case we got REACHABLE event need to do the following
		 * Check that neigh has L2 address
		 * if not send event to neigh
		 * else need to check that the new l2 address is equal to the old one
		 * if not equal this is a remote bonding event - issue an EV_ERROR
		 */
		auto_unlocker lock(m_lock);
		// This if and priv_handle_neigh_ha_event should be done under lock
		if (m_state_machine->get_curr_state() != ST_READY) {
			// This is new entry
			event_handler(EV_ARP_RESOLVED);
			break;
		}

		// Check if neigh L2 address changed (HA event) and restart the state machine
		priv_handle_neigh_is_l2_changed(nl_info->lladdr);
		break;
	}

	case NUD_STALE:
	{
		BULLSEYE_EXCLUDE_BLOCK_START
		if(m_state_machine == NULL) {
			neigh_logerr("m_state_machine: not a valid case");
			break;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		m_lock.lock();
		if (m_state_machine->get_curr_state() != ST_READY) {
			// This is new entry, neigh entry state != READY
			neigh_logdbg("state = '%s' m_state_machine != ST_READY - Doing nothing", nl_info->get_state2str().c_str());
			m_lock.unlock();
			break;
		}
		// Check if neigh L2 address changed (HA event) and restart the state machine
		neigh_logdbg("state = '%s' (%d) L2 address = %s", nl_info->get_state2str().c_str(), neigh_state, nl_info->lladdr_str.c_str());
		bool ret = priv_handle_neigh_is_l2_changed(nl_info->lladdr);
		m_lock.unlock();

		if(! ret ) {
			//If L2 address wasn't changed we need to send ARP
			send_arp();
			m_timer_handle = priv_register_timer_event(m_n_sysvar_neigh_wait_till_send_arp_msec, this, ONE_SHOT_TIMER, NULL);
		}
		break;
	}

	case NUD_INCOMPLETE:
	{
		neigh_logdbg("state = INCOMPLETE");
		break;
	}

	case NUD_FAILED:
	{
		neigh_logdbg("state = FAILED");
		event_handler(EV_ERROR);
		break;
	}

	default:
	{
		neigh_logdbg("Unhandled state = '%s' (%d)", nl_info->get_state2str().c_str(), neigh_state);
		break;
	}
	}
}

//============================ Functions that handling events for state machine  ===================================

const char* neigh_entry::event_to_str(event_t event) const
{
	switch (event)
	{
	case EV_KICK_START:
		return "EV_KICK_START";
	case EV_START_RESOLUTION:
		return "EV_START_RESOLUTION";
	case EV_ARP_RESOLVED:
		return "EV_ARP_RESOLVED";
	case EV_ADDR_RESOLVED:
		return "EV_ADDR_RESOLVED";
	case EV_PATH_RESOLVED:
		return "EV_PATH_RESOLVED";
	case EV_ERROR:
		return "EV_ERROR";
	case EV_UNHANDLED:
		return "EV_UNHANDELED";
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		return "Undefined";
	BULLSEYE_EXCLUDE_BLOCK_END
	}

}

const char* neigh_entry::state_to_str(state_t state) const
{
	switch (state)
	{
	case ST_NOT_ACTIVE:
		return "NEIGH_NOT_ACTIVE";
	case ST_ERROR:
		return "NEIGH_ERROR";
	case ST_INIT:
		return "NEIGH_INIT";
	case ST_INIT_RESOLUTION:
		return "NEIGH_INIT_RESOLUTION";
	case ST_ADDR_RESOLVED:
		return "NEIGH_ADDR_RESOLVED";
	case ST_ARP_RESOLVED:
		return "NEIGH_ARP_RESOLVED";
	case ST_PATH_RESOLVED:
		return "NEIGH_PATH_RESOLVED";
	case ST_READY:
		return "NEIGH_READY";
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		return "Undefined";
	BULLSEYE_EXCLUDE_BLOCK_END
	}
}

/*
 * RDMA_CM_EVENT_ADDR_RESOLVED will be mapped to neigh_entry:event_t::ADDRESS_RESOLVED
 * RDMA_CM_EVENT_ADDR_ERROR, RDMA_CM_EVENT_ROUTE_ERROR, RDMA_CM_EVENT_MULTICAST_ERROR will be mapped to neigh_entry:event_t::RESTART
 * RDMA_CM_EVENT_MULTICAST_JOIN and RDMA_CM_EVENT_ROUTE_RESOLVED  will be mapped to neigh_entry:event_t::PATH_RESOLVED
 * We are not going to handle local errors events, what is interesting is remote error events or fabric events in case of IB.
 * For local errors we will have netlink event that entry is deleted - need to think where it will be handled in neigh_tbl_mgr or neigh_entry
 */
neigh_entry::event_t neigh_entry::rdma_event_mapping(struct rdma_cm_event* p_rdma_cm_event)
{
	// General check of cma_id
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_cma_id != NULL && m_cma_id != p_rdma_cm_event->id) {
		neigh_logerr("cma_id %p != event->cma_id %p", m_cma_id, p_rdma_cm_event->id);
		return EV_UNHANDLED;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	neigh_logdbg("Got event %s (%d)", rdma_event_str(p_rdma_cm_event->event), p_rdma_cm_event->event);

	switch (p_rdma_cm_event->event)
	{
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		return EV_ADDR_RESOLVED;

	case RDMA_CM_EVENT_MULTICAST_JOIN:
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		return EV_PATH_RESOLVED;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_MULTICAST_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		return EV_ERROR;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		neigh_logdbg("Un-handled rdma_cm event %d", p_rdma_cm_event->event);
		return EV_UNHANDLED;
	BULLSEYE_EXCLUDE_BLOCK_END
	}
}

// call this function from the transition functions only (instead of using recursive lock)
void neigh_entry::priv_event_handler_no_locks(event_t event, void* p_event_info)
{
	neigh_logfunc("Enter: event %s", event_to_str(event));
	m_state_machine->process_event(event, p_event_info);
}

void neigh_entry::event_handler(event_t event, void* p_event_info)
{
	neigh_logfunc("Enter: event %s", event_to_str(event));
	BULLSEYE_EXCLUDE_BLOCK_START
	if (event == EV_UNHANDLED) {
		neigh_logdbg("Enter: event %s. UNHANDLED event - Ignored!", event_to_str(event));
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	m_sm_lock.lock();
	priv_event_handler_no_locks(event, p_event_info);
	m_sm_lock.unlock();
}

void neigh_entry::handle_event_rdma_cm_cb(struct rdma_cm_event* p_event)
{
	event_t event = rdma_event_mapping(p_event);
	event_handler(event, p_event);
}

//==================================   Static functions for state machine dofunc  ===========================
//General entry dofunc
void neigh_entry::general_st_entry(const sm_info_t& func_info)
{
	neigh_entry* my_neigh = (neigh_entry *) func_info.app_hndl;
	my_neigh->priv_general_st_entry(func_info);
}

//General leave dofunc
void neigh_entry::general_st_leave(const sm_info_t& func_info)
{
	neigh_entry* my_neigh = (neigh_entry *) func_info.app_hndl;
	my_neigh->priv_general_st_leave(func_info);

	/*
	 if (my_conn_mgr->m_timer_handle) {
	 g_p_event_handler_manager->unregister_timer_event(my_conn_mgr, my_conn_mgr->m_timer_handle);
	 my_conn_mgr->m_timer_handle = NULL;
	 }
	 */
}

void neigh_entry::print_event_info(int state, int event, void* app_data)
{
	neigh_entry * my_neigh = (neigh_entry *) app_data;
	my_neigh->priv_print_event_info((state_t) state, (event_t) event);
}

//Static enter function for NOT_ACTIVE state
void neigh_entry::dofunc_enter_not_active(const sm_info_t& func_info)
{
	//Need to change entry state to false
	neigh_entry * my_neigh = (neigh_entry *) func_info.app_hndl;
	general_st_entry(func_info);
	my_neigh->priv_enter_not_active();
}

//Static enter function for ERROR state
void neigh_entry::dofunc_enter_error(const sm_info_t& func_info)
{
	//Need to change entry state to false
	neigh_entry * my_neigh = (neigh_entry *) func_info.app_hndl;
	general_st_entry(func_info);
	my_neigh->priv_enter_error();
}

//Static enter function for INIT state
void neigh_entry::dofunc_enter_init(const sm_info_t& func_info)
{
	neigh_entry * my_neigh = (neigh_entry *) func_info.app_hndl;
	general_st_entry(func_info);
	run_helper_func(priv_enter_init(), EV_ERROR);
}

//Static enter function for INIT_RESOLUTION state
void neigh_entry::dofunc_enter_init_resolution(const sm_info_t& func_info)
{
	neigh_entry * my_neigh = (neigh_entry *) func_info.app_hndl;
	general_st_entry(func_info);
	run_helper_func(priv_enter_init_resolution(), EV_ERROR);
}

//Static enter function for ADDR_RESOLVED state
void neigh_entry::dofunc_enter_addr_resolved(const sm_info_t& func_info)
{
	neigh_entry * my_neigh = (neigh_entry *) func_info.app_hndl;
	general_st_entry(func_info);
	run_helper_func(priv_enter_addr_resolved(), EV_ERROR);
}

//Static enter function for READY state
void neigh_entry::dofunc_enter_ready(const sm_info_t& func_info)
{
	neigh_entry * my_neigh = (neigh_entry *) func_info.app_hndl;
	general_st_entry(func_info);
	run_helper_func(priv_enter_ready(), EV_ERROR);
}

// ==================================  private functions for sate machine ============================================

void neigh_entry::priv_general_st_entry(const sm_info_t& func_info)
{
	NOT_IN_USE(func_info); /* to supress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	neigh_logdbg("State change: %s (%d) => %s (%d) with event %s (%d)",
		state_to_str((state_t) func_info.old_state), func_info.old_state,
		state_to_str((state_t) func_info.new_state), func_info.new_state,
		event_to_str((event_t) func_info.event), func_info.event);
}

void neigh_entry::priv_general_st_leave(const sm_info_t& func_info)
{
	NOT_IN_USE(func_info);
}

void neigh_entry::priv_print_event_info(state_t state, event_t event)
{
	NOT_IN_USE(state); /* to supress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	NOT_IN_USE(event); /* to supress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	neigh_logdbg("Got event '%s' (%d) in state '%s' (%d)",
		event_to_str(event), event, state_to_str(state), state);
}

//Function that start neigh State Machine (SM)
void neigh_entry::priv_kick_start_sm()
{
	neigh_logdbg("Kicking connection start");
	event_handler(EV_KICK_START);
}

//Private enter function for INIT state
int neigh_entry::priv_enter_init()
{
	m_timer_handle = priv_register_timer_event(0, this, ONE_SHOT_TIMER, NULL);
	return 0;
}

//Private enter function for INIT_RESOLUTION state
int neigh_entry::priv_enter_init_resolution()
{
	if (NULL == g_p_neigh_table_mgr->m_neigh_cma_event_channel) {
		return 0;
	}

	// 1. Delete old cma_id
	priv_destroy_cma_id();

	// 2. Create cma_id
	neigh_logdbg("Calling rdma_create_id");
	IF_RDMACM_FAILURE(rdma_create_id(g_p_neigh_table_mgr->m_neigh_cma_event_channel, &m_cma_id, (void *)this, m_rdma_port_space))
	{
		neigh_logerr("Failed in rdma_create_id (errno=%d %m)", errno);
		return -1;
	} ENDIF_RDMACM_FAILURE;


	// 3. Register our handler on internal channel event listener thread
	g_p_event_handler_manager->register_rdma_cm_event
	(g_p_neigh_table_mgr->m_neigh_cma_event_channel->fd,
			(void*) m_cma_id,
			(void*) g_p_neigh_table_mgr->m_neigh_cma_event_channel,
			this);

	// 4. Start RDMA address resolution
	neigh_logdbg("Calling rdma_resolve_addr, src=%d.%d.%d.%d, dst=%d.%d.%d.%d", NIPQUAD(m_src_addr.sin_addr.s_addr), NIPQUAD(m_dst_addr.sin_addr.s_addr));

	/* we had issues passing unicast src addr, let it find the correct one itself */
	struct sockaddr* src = IN_MULTICAST_N(m_dst_addr.sin_addr.s_addr) ? (struct sockaddr*)&m_src_addr : NULL;

	IF_RDMACM_FAILURE(rdma_resolve_addr(m_cma_id, src, (struct sockaddr*)&m_dst_addr, 2000))
	{
		neigh_logdbg("Failed in rdma_resolve_addr  m_cma_id = %p (errno=%d %m)", m_cma_id, errno);
		return -1;
	} ENDIF_RDMACM_FAILURE;

	return 0;
}

//Private enter function for ADDR_RESOLVED state
int neigh_entry::priv_enter_addr_resolved()
{
	neigh_logfunc("");

	m_lock.lock();

	int state = 0;

	if (!priv_get_neigh_state(state) || !priv_is_reachable(state)) {
		neigh_logdbg("got addr_resolved but state=%d", state);
		send_arp();
		m_timer_handle = priv_register_timer_event(m_n_sysvar_neigh_wait_till_send_arp_msec, this, ONE_SHOT_TIMER, NULL);
		m_lock.unlock();
		return 0;
	} else {
		event_handler(EV_ARP_RESOLVED);
	}

	m_lock.unlock();
	return 0;
}

//Private enter function for NOT_ACTIVE state
void neigh_entry::priv_enter_not_active()
{
	neigh_logfunc("");

	auto_unlocker lock(m_lock);

	m_state = false;

	priv_destroy_cma_id();
	priv_unregister_timer();
	m_is_first_send_arp = true; // force send boardcast next cycle
	m_arp_counter = 0;

	// Flush unsent_queue in case that neigh entry is in error state

	if (!m_unsent_queue.empty()) {
		neigh_logdbg("Flushing unsent queue");

		while (!m_unsent_queue.empty())
		{
			neigh_send_data * packet = m_unsent_queue.front();
			m_unsent_queue.pop_front();
			delete packet;
		}
	}

	if (m_val) {
		neigh_logdbg("calling to zero_all_members()");
		m_val->zero_all_members();
	}

	return;
}

//Private enter function for NOT_ERROR state
void neigh_entry::priv_enter_error()
{
	neigh_logfunc("");

	m_lock.lock();

	m_state = false;

	priv_destroy_cma_id();
	priv_unregister_timer();
	m_is_first_send_arp = true; // force send boardcast next cycle
	m_arp_counter = 0;

	if (m_val) {
		neigh_logdbg("calling to zero_all_members()");
		m_val->zero_all_members();
	}

	m_lock.unlock();

	//Need to notify observers that now this entry is not valid
	//We don't want to do it under neigh lock - can cause dead lock with prepare_to_send() of dst
	notify_observers(NULL);

	m_lock.lock();
	//If unsent queue is not empty we will try to KICK START the connection, but only once
	if (!m_unsent_queue.empty() && (m_err_counter < m_n_sysvar_neigh_num_err_retries)) {
		neigh_logdbg("unsent_queue is not empty calling KICK_START");
		m_err_counter++;
		event_handler(EV_KICK_START);
	}
	else {
		neigh_logdbg("unsent_queue is empty or this is the #%d retry", m_err_counter + 1);
		m_err_counter = 0;
		event_handler(EV_ERROR);
	}
	m_lock.unlock();

}

//Private enter function for READY state
int neigh_entry::priv_enter_ready()
{
	neigh_logfunc("");
	auto_unlocker lock(m_lock);

	m_state = true;
	empty_unsent_queue();

	int state = 0;
	// Need to send ARP in case neigh state is not REACHABLE and this is not MC neigh
	// This is the case when VMA was started with neigh in STALE state and
	// rdma_adress_resolve() in this case will not initiate ARP
	if (m_type == UC && ! m_is_loopback) {
		if (priv_get_neigh_state(state) && !priv_is_reachable(state)) {
			send_arp();
			m_timer_handle = priv_register_timer_event(m_n_sysvar_neigh_wait_till_send_arp_msec, this, ONE_SHOT_TIMER, NULL);
		}
	}
	return 0;
}

bool neigh_entry::priv_get_neigh_state(int & state)
{
	netlink_neigh_info info;
	char str_addr[INET_ADDRSTRLEN];

	if (m_is_loopback) {
		state = NUD_REACHABLE;
		return true;
	}

	if (inet_ntop(AF_INET, &(m_dst_addr.sin_addr), str_addr, sizeof(str_addr)) &&
			g_p_netlink_handler->get_neigh(str_addr, m_p_dev->get_if_idx(), &info)) {
		state = info.state;
		neigh_logdbg("state = %s", info.get_state2str().c_str());
		return true;
	}

	neigh_logdbg("Entry doesn't exist in netlink cache");
	return false;
}

bool neigh_entry::priv_get_neigh_l2(address_t & l2_addr)
{
	netlink_neigh_info info;
	char str_addr[INET_ADDRSTRLEN];

	if (m_is_loopback) {
		memcpy(l2_addr, m_p_dev->get_l2_address()->get_address(), m_p_dev->get_l2_address()->get_addrlen());
		return true;
	}

	if (inet_ntop(AF_INET, &(m_dst_addr.sin_addr), str_addr, sizeof(str_addr)) &&
			g_p_netlink_handler->get_neigh(str_addr, m_p_dev->get_if_idx(), &info)){
		if (!priv_is_failed(info.state)) {
			memcpy(l2_addr, info.lladdr, info.lladdr_len);
			return true;
		}
		neigh_logdbg("Entry exists in netlink cache but state = %s", info.get_state2str().c_str());
	}

	neigh_logdbg("Entry doesn't exist in netlink cache");
	return false;

}

void neigh_entry::priv_destroy_cma_id()
{
	if (m_cma_id) {
		g_p_event_handler_manager->unregister_rdma_cm_event(
		                g_p_neigh_table_mgr->m_neigh_cma_event_channel->fd,
		                (void*) m_cma_id);
		neigh_logdbg("Calling rdma_destroy_id");
		IF_RDMACM_FAILURE(rdma_destroy_id(m_cma_id))
		{
			neigh_logdbg("Failed in rdma_destroy_id (errno=%d %m)", errno);
		} ENDIF_RDMACM_FAILURE;
		m_cma_id = NULL;
	}
}

void* neigh_entry::priv_register_timer_event(int timeout_msec, timer_handler* handler, timer_req_type_t req_type, void* user_data){
	void* _timer_handler = NULL;
	m_lock.lock();
	if(!is_cleaned()){
		_timer_handler = g_p_event_handler_manager->register_timer_event(timeout_msec, handler, req_type, user_data);
	}
	m_lock.unlock();
	return _timer_handler;
}

void neigh_entry::priv_unregister_timer()
{
	if (m_timer_handle) {
		// All timers in neigh are currently ONESHOT timers.
		// Unregister of ONESHOT timer can lead to double free of timer,
		// as ONESHOT timer free itself after it run.
		// TODO: unregister all timers? is there just one or more?
		//g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
}
//============================================================== neigh_eth ==================================================

neigh_eth::neigh_eth(neigh_key key) :
	neigh_entry(key)
{
	neigh_logdbg("");
	m_rdma_port_space = RDMA_PS_UDP;

	if (IN_MULTICAST_N(key.get_in_addr())) {
		//This is Multicast neigh
		m_type = MC;
		build_mc_neigh_val();
		return;
	}
	// This is Unicast neigh
	m_type = UC;

	sm_short_table_line_t short_sm_table[] =
	{
			// 	{curr state,            event,                  next state,             action func   }

				{ ST_NOT_ACTIVE, 	EV_KICK_START, 		ST_INIT, 		NULL },
				{ ST_ERROR, 		EV_KICK_START, 		ST_INIT, 		NULL },
				{ ST_INIT, 		EV_ARP_RESOLVED,	ST_READY,		NULL },
				{ ST_INIT, 		EV_START_RESOLUTION,	ST_INIT_RESOLUTION,	NULL },
				{ ST_INIT_RESOLUTION, 	EV_ADDR_RESOLVED,	ST_ADDR_RESOLVED,	NULL },
				{ ST_INIT_RESOLUTION, 	EV_ARP_RESOLVED,	ST_READY,		NULL },
				{ ST_ADDR_RESOLVED, 	EV_ARP_RESOLVED,	ST_READY,		NULL },
				{ ST_READY, 		EV_ERROR, 		ST_ERROR,		NULL },
				{ ST_INIT, 		EV_ERROR, 		ST_ERROR, 		NULL },
				{ ST_INIT_RESOLUTION, 	EV_ERROR, 		ST_ERROR, 		NULL },
				{ ST_ERROR, 		EV_ERROR, 		ST_NOT_ACTIVE, 		NULL },
	                 //Entry functions
	                        { ST_INIT, 		SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_init },
	                        { ST_INIT_RESOLUTION, 	SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_init_resolution },
	                        { ST_ERROR, 		SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_error },
	                        { ST_NOT_ACTIVE, 	SM_STATE_ENTRY,		SM_NO_ST,		neigh_entry::dofunc_enter_not_active },
	                        { ST_ADDR_RESOLVED, 	SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_addr_resolved},
	                        { ST_READY, 		SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_ready },
	                 SM_TABLE_END };

	// Create state_nachine
	m_state_machine = new state_machine(this,		// app hndl
	                ST_NOT_ACTIVE,		// start state_t
	                ST_LAST,		// max states
	                EV_LAST,		// max events
	                short_sm_table,		// short table
	                general_st_entry,	// default entry function
	                NULL,			// default leave function
	                NULL,			// default func
	                print_event_info	// debug function
	                );

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_state_machine == NULL)
		neigh_logpanic("Failed allocating state_machine");
	BULLSEYE_EXCLUDE_BLOCK_END

	priv_kick_start_sm();
}

neigh_eth::~neigh_eth()
{
	neigh_logdbg("");
	priv_enter_not_active();
}

bool neigh_eth::is_deletable()
{
	if(m_type == MC)
		return true;
	return(neigh_entry::is_deletable());
}

bool neigh_eth::get_peer_info(neigh_val * p_val)
{
	neigh_logfunc("calling neigh_eth get_peer_info");
	if (m_type == MC) {
		auto_unlocker lock(m_lock);
		if (m_state) {
			*p_val = *m_val;
			return true;
		}
		else {
			if (build_mc_neigh_val())
				return false;
			else {
				*p_val = *m_val;
				return true;
			}
		}
	}

	return (neigh_entry::get_peer_info(p_val));
}

bool neigh_eth::register_observer(const observer* const new_observer)
{
	neigh_logdbg("neigh_eth register_observer");
	// In case of ETH Multicast we should change neigh_entry register_observer behavior
	if (m_type == MC) {
		if (subject::register_observer(new_observer)) {
			auto_unlocker lock(m_lock);
			if (!m_state)
				// Try to build it again
				build_mc_neigh_val();
			return true;
		}
		return false;
	}

	return (neigh_entry::register_observer(new_observer));
}

int neigh_eth::priv_enter_init()
{
	int state;

	if (priv_get_neigh_state(state) && !priv_is_failed(state)) {
		event_handler(EV_ARP_RESOLVED);
		return 0;
	}

	return neigh_entry::priv_enter_init();
}

int neigh_eth::priv_enter_init_resolution()
{
	int state;

	if (!(neigh_entry::priv_enter_init_resolution())) {
		// query netlink - if this entry already exist and REACHABLE we can use it
		if (priv_get_neigh_state(state) && !priv_is_failed(state)) {
				event_handler(EV_ARP_RESOLVED);
		}
		return 0;
	}

	return -1;
}

bool neigh_eth::priv_handle_neigh_is_l2_changed(address_t new_l2_address_str)
{
	auto_unlocker lock(m_lock);
	ETH_addr new_l2_address(new_l2_address_str);
	if(m_val) {
		if(m_val->get_l2_address()) {
			if (!((m_val->get_l2_address())->compare(new_l2_address))) {
				neigh_logdbg("l2 address was changed (%s => %s)", (m_val->get_l2_address())->to_str().c_str(), new_l2_address.to_str().c_str());
				event_handler(EV_ERROR);
				return true;
			}
			else
			{
				neigh_logdbg("No change in l2 address");
				return false;
			}
		}
		else {
			neigh_logdbg("l2 address is NULL");
		}
	}
	else {
		neigh_logerr("m_val is NULL");
	}

	event_handler(EV_ERROR);
	return true;
}

int neigh_eth::priv_enter_ready()
{
	neigh_logfunc("");

	// In case of ETH, we want to unregister from events and destroy rdma cm handle
	priv_destroy_cma_id();
	if (!build_uc_neigh_val())
		return (neigh_entry::priv_enter_ready());

	return -1;
}

bool neigh_eth::post_send_arp(bool is_broadcast)
{
	header h;
	neigh_logdbg("Sending %s ARP", is_broadcast?"BC":"UC");

	net_device_val_eth *netdevice_eth = dynamic_cast<net_device_val_eth*>(m_p_dev);
	if (netdevice_eth == NULL) {
		neigh_logdbg("Net dev is NULL not sending ARP");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	const L2_address *src = m_p_dev->get_l2_address();
	const L2_address *dst;
	if (!is_broadcast) {
		dst = m_val->get_l2_address();
	}
	else {
		dst = m_p_dev->get_br_address();
	}


	const unsigned char* peer_mac = dst->get_address();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (src == NULL || dst == NULL) {
		neigh_logdbg("src or dst is NULL not sending ARP");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_id = m_p_ring->generate_id(src->get_address(), dst->get_address(), netdevice_eth->get_vlan() ? htons(ETH_P_8021Q) : htons(ETH_P_ARP), htons(ETH_P_ARP), 0, 0, 0, 0);
	mem_buf_desc_t* p_mem_buf_desc = m_p_ring->mem_buf_tx_get(m_id, false, 1);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(p_mem_buf_desc == NULL)) {
		neigh_logdbg("No free TX buffer, not sending ARP");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	wqe_send_handler wqe_sh;
	wqe_sh.init_wqe(m_send_wqe, &m_sge, 1);

	h.init();
	if (netdevice_eth->get_vlan()) { //vlan interface
		h.configure_vlan_eth_headers(*src, *dst, netdevice_eth->get_vlan(), ETH_P_ARP);
	}
	else {
		h.configure_eth_headers(*src, *dst, ETH_P_ARP);
	}

	tx_packet_template_t *p_pkt = (tx_packet_template_t*)p_mem_buf_desc->p_buffer;
	h.copy_l2_hdr(p_pkt);

	eth_arp_hdr* p_arphdr = (eth_arp_hdr*) (p_mem_buf_desc->p_buffer + h.m_transport_header_tx_offset + h.m_total_hdr_len);
	set_eth_arp_hdr(p_arphdr, m_p_dev->get_local_addr(), get_key().get_in_addr(), m_p_dev->get_l2_address()->get_address(), peer_mac);

	m_sge.addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)h.m_transport_header_tx_offset);
	m_sge.length = sizeof(eth_arp_hdr) + h.m_total_hdr_len;
	m_sge.lkey = p_mem_buf_desc->lkey;
	p_mem_buf_desc->p_next_desc = NULL;
	m_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;

	m_p_ring->send_ring_buffer(m_id, &m_send_wqe, (vma_wr_tx_packet_attr)0);

	neigh_logdbg("ARP Sent");
	return true;
}

bool neigh_eth::prepare_to_send_packet(header * h)
{
	neigh_logdbg("");

	net_device_val_eth *netdevice_eth = dynamic_cast<net_device_val_eth*>(m_p_dev);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (netdevice_eth == NULL) {
		neigh_logerr("Net dev is NULL dropping the packet");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	const L2_address *src = m_p_dev->get_l2_address();
	const L2_address *dst = m_val->get_l2_address();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (src == NULL || dst == NULL) {
		neigh_logdbg("src or dst is NULL not sending ARP");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	wqe_send_handler wqe_sh;
	wqe_sh.init_wqe(m_send_wqe, &m_sge, 1);

	if (netdevice_eth->get_vlan()) { //vlan interface
		h->configure_vlan_eth_headers(*src, *dst, netdevice_eth->get_vlan());
	}
	else {
		h->configure_eth_headers(*src, *dst);
	}

	return(true);
}

ring_user_id_t neigh_eth::generate_ring_user_id(header * h /* = NULL */)
{
	if (!h)
		return m_p_ring->generate_id();

	ethhdr *actual_header = (ethhdr*)h->m_actual_hdr_addr;
	return m_p_ring->generate_id(actual_header->h_source,
				     actual_header->h_dest,
				     actual_header->h_proto,
				     htons(ETH_P_IP),
				     h->m_header.hdr.m_ip_hdr.saddr,
				     h->m_header.hdr.m_ip_hdr.daddr,
				     h->m_header.hdr.m_udp_hdr.source,
				     h->m_header.hdr.m_udp_hdr.dest);
}
