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


#include <errno.h>
#include <arpa/inet.h>

#include "vma/proto/neighbour.h"
#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/utils.h"
#include "vma/dev/ib_ctx_handler_collection.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "vma/dev/wqe_send_handler.h"
#include "vma/dev/wqe_send_ib_handler.h"
#include "vma/util/bullseye.h"

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
#define RING_KEY 0


neigh_val & neigh_ib_val::operator=(const neigh_val & val)
{
	IPoIB_addr* l2_addr = NULL;
	neigh_val* tmp_val = const_cast<neigh_val *>(&val);
	const neigh_ib_val* ib_val = dynamic_cast<const neigh_ib_val*>(tmp_val);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ib_val == NULL) {
		__log_panic("neigh_ib_val is NULL");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	m_l2_address = new IPoIB_addr((ib_val->get_l2_address())->get_address());
	l2_addr = (IPoIB_addr *)m_l2_address; //no need to do dynamic casting here
	m_ah = ib_val->get_ah(); //TODO: we need to handle this - in case ah is used in post_send we cannot destroy it
	m_qkey = ib_val->get_qkey();
	l2_addr->set_qpn(ib_val->get_qpn());
	m_ah_attr = ib_val->get_ah_attr();
	return *this;
}

neigh_entry::neigh_entry(neigh_key key, transport_type_t type, bool is_init_resources):
	cache_entry_subject<neigh_key, neigh_val *>(key),
	m_cma_id(NULL), m_rdma_port_space((enum rdma_port_space)0), m_state_machine(NULL), m_type(UNKNOWN), m_trans_type(type),
	m_state(false), m_err_counter(0), m_timer_handle(NULL),
	m_arp_counter(0), m_p_dev(NULL), m_p_ring(NULL), m_is_loopback(false),
	m_to_str(std::string(priv_vma_transport_type_str(m_trans_type)) + ":" + get_key().to_str()),
	m_is_first_send_arp(true)
{
	m_val = NULL;
	m_p_dev = key.get_net_device_val();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_dev == NULL) {
		neigh_logpanic("get_net_dev return NULL");
	}

	if(is_init_resources) {
		m_p_ring = m_p_dev->reserve_ring(RING_KEY);
		if (m_p_ring == NULL) {
			neigh_logpanic("reserve_ring return NULL");
		}
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	memset(&m_dst_addr, 0, sizeof(struct sockaddr_in));
	memset(&m_src_addr, 0, sizeof(struct sockaddr_in));
	m_dst_addr.sin_addr.s_addr = get_key().get_in_addr(); /*(peer_ip)*/
	m_dst_addr.sin_family = AF_INET;

	m_src_addr.sin_addr.s_addr = m_p_dev->get_local_addr();
	m_src_addr.sin_family = AF_INET;

	memset(&m_send_wqe, 0, sizeof(vma_ibv_send_wr));
	memset(&m_sge, 0, sizeof(struct ibv_sge));

	if (m_dst_addr.sin_addr.s_addr == m_src_addr.sin_addr.s_addr) {
		neigh_logdbg("This is loopback neigh");
		m_is_loopback = true;
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
		m_p_dev->release_ring(RING_KEY);
		m_p_ring = NULL;
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
	m_lock.lock();
	set_cleaned();
	m_timer_handle = NULL;
	g_p_event_handler_manager->unregister_timers_event_and_delete(this);
	m_lock.unlock();
}

int neigh_entry::send(neigh_send_info &s_info)
{
	neigh_logdbg("");
	auto_unlocker lock(m_lock);
	//Need to copy send info
	neigh_send_data * ns_data = new neigh_send_data(&s_info);
	BULLSEYE_EXCLUDE_BLOCK_START
	if(ns_data == NULL) {
		neigh_logerr("Send() failed, failed to allocate ns_info");
		return 0;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_unsent_queue.push_back(ns_data);
	return ns_data->m_iov.iov_len;
}

void neigh_entry::empty_unsent_queue()
{
	neigh_logdbg("");
	auto_unlocker lock(m_lock);

	while (!m_unsent_queue.empty())
	{
		neigh_send_data * n_send_data = m_unsent_queue.front();
		if(prepare_to_send_packet(n_send_data->m_header)) {
			if(post_send_packet(n_send_data->m_protocol, &n_send_data->m_iov, n_send_data->m_header)) {
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

	// Check if neigh_entry state is reachable
	int state;
	if(!priv_get_neigh_state(state)) {
		return;
	}

	if(state != NUD_FAILED) {
		//We want to verify that L2 address wasn't changed
		unsigned char tmp[IPOIB_HW_ADDR_LEN];
		address_t l2_addr = (address_t)tmp;
		if(!priv_get_neigh_l2(l2_addr)) {
			return;
		}
		if(priv_handle_neigh_is_l2_changed(l2_addr)) {
			return;
		}
	}

	if (state != NUD_REACHABLE) {
		neigh_logdbg("State is different from NUD_REACHABLE and L2 address wasn't changed. Sending ARP");
		send_arp();
		m_timer_handle = priv_register_timer_event(mce_sys.neigh_wait_till_send_arp_msec, this, ONE_SHOT_TIMER, NULL);
	}
	else {
		neigh_logdbg("State is NUD_REACHABLE and L2 address wasn't changed. Stop sending ARP");
	}
}

void neigh_entry::send_arp()
{
	// In case we already sent the quota number of unicast ARPs, start sending broadcast ARPs
	// or we want to send broadcast ARP for the first time
	bool is_broadcast = (m_arp_counter >= mce_sys.neigh_uc_arp_quata) || m_is_first_send_arp;
	if (post_send_arp(is_broadcast)) {
		m_is_first_send_arp = false;
		m_arp_counter++;
	}
}

bool neigh_entry::post_send_packet(uint8_t protocol, iovec * iov, header * h)
{
	neigh_logdbg("ENTER post_send_packet protocol = %d", protocol);
	switch(protocol)
	{
		case  IPPROTO_UDP:
			return (post_send_udp(iov, h));
		case  IPPROTO_TCP:
			return(post_send_tcp(iov, h));
		default:
			neigh_logdbg("Unsupported protocol");
			return false;

	}
}

bool neigh_entry::post_send_udp(iovec * iov, header *h)
{
	// Find number of ip fragments (-> packets, buffers, buffer descs...)
	neigh_logdbg("ENTER post_send_udp");
	int n_num_frags = 1;
	bool b_need_to_fragment = false;
	mem_buf_desc_t* p_mem_buf_desc, *tmp = NULL;
	tx_packet_template_t *p_pkt;

	size_t sz_data_payload = iov->iov_len;

	if (sz_data_payload > 65536) {
		neigh_logdbg("sz_data_payload=%d exceeds max of 64KB", sz_data_payload);
		errno = EMSGSIZE;
		return false;
	}

	size_t sz_udp_payload = sz_data_payload + sizeof(struct udphdr);

	// Usually max inline < MTU!
	if (sz_udp_payload > MAX_IP_PAYLOAD_SZ) {
		b_need_to_fragment = true;
		n_num_frags = (sz_udp_payload + MAX_IP_PAYLOAD_SZ - 1) / MAX_IP_PAYLOAD_SZ;
	}

	neigh_logdbg("udp info: payload_sz=%d, frags=%d, scr_port=%d, dst_port=%d", sz_data_payload, n_num_frags, ntohs(h->m_header.hdr.m_udp_hdr.source), ntohs(h->m_header.hdr.m_udp_hdr.dest));

	// Get all needed tx buf descriptor and data buffers
	p_mem_buf_desc = m_p_ring->mem_buf_tx_get(false, n_num_frags);

	if (unlikely(p_mem_buf_desc == NULL)) {
		neigh_logdbg("Packet dropped. not enough tx buffers");
		return false;
	}

	// Int for counting offset inside the ip datagram payload
	uint32_t n_ip_frag_offset = 0;
	size_t sz_user_data_offset = 0;

	while (n_num_frags--) {
		// Calc this ip datagram fragment size (include any udp header)
		size_t sz_ip_frag = min(MAX_IP_PAYLOAD_SZ, (sz_udp_payload - n_ip_frag_offset));
		size_t sz_user_data_to_copy = sz_ip_frag;
		size_t hdr_len = h->m_transport_header_len + IPV4_HDR_LEN; // Add count of L2 (ipoib or mac) header length

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
		p_pkt->hdr.m_ip_hdr.tot_len = htons(IPV4_HDR_LEN + sz_ip_frag);

		// Calc payload start point (after the udp header if present else just after ip header)
		uint8_t* p_payload = p_mem_buf_desc->p_buffer + h->m_transport_header_tx_offset + hdr_len;

		// Copy user data to our tx buffers
		int ret = memcpy_fromiovec(p_payload, iov, 1, sz_user_data_offset, sz_user_data_to_copy);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret != (int)sz_user_data_to_copy) {
			neigh_logerr("memcpy_fromiovec error (sz_user_data_to_copy=%d, ret=%d)", sz_user_data_to_copy, ret);
			m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
			errno = EINVAL;
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		wqe_send_handler wqe_sh;
		if (b_need_to_fragment) {
			neigh_logdbg("ip fragmentation detected, using SW checksum calculation");
			p_pkt->hdr.m_ip_hdr.check = 0;
			p_pkt->hdr.m_ip_hdr.check = csum((unsigned short*)&p_pkt->hdr.m_ip_hdr, IPV4_HDR_LEN_WORDS * 2);
			wqe_sh.disable_hw_csum(m_send_wqe);
		} else {
			neigh_logdbg("using HW checksum calculation");
			wqe_sh.enable_hw_csum(m_send_wqe);
		}

		m_sge.addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)h->m_transport_header_tx_offset);
		m_sge.length = sz_user_data_to_copy + hdr_len;
		m_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;

		neigh_logdbg("%s packet_sz=%d, payload_sz=%d, ip_offset=%d id=%d", h->to_str().c_str(),
				m_sge.length - h->m_transport_header_len, sz_user_data_to_copy,
				n_ip_frag_offset, ntohs(p_pkt->hdr.m_ip_hdr.id));

		tmp = p_mem_buf_desc->p_next_desc;
		p_mem_buf_desc->p_next_desc = NULL;

		// We don't check the return value of post send when we reach the HW we consider that we completed our job
		m_p_ring->send_ring_buffer(&m_send_wqe, false);

		p_mem_buf_desc = tmp;

		// Update ip frag offset position
		n_ip_frag_offset += sz_ip_frag;

		// Update user data start offset copy location
		sz_user_data_offset += sz_user_data_to_copy;

	} // while(n_num_frags)

	return true;
}


bool neigh_entry::post_send_tcp(iovec *iov, header *h)
{
	tx_packet_template_t* p_pkt;
	mem_buf_desc_t *p_mem_buf_desc;
	size_t total_packet_len = 0;

	wqe_send_handler wqe_sh;
	wqe_sh.enable_hw_csum(m_send_wqe);

	p_mem_buf_desc = m_p_ring->mem_buf_tx_get(false, 1);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(p_mem_buf_desc == NULL)) {
		neigh_logdbg("Packet dropped. not enough tx buffers");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	p_mem_buf_desc->p_next_desc = NULL;

	//copy L4 neigh buffer to tx buffer
	memcpy((void*)(p_mem_buf_desc->p_buffer +h->m_aligned_l2_l3_len), iov->iov_base, iov->iov_len);

	p_pkt = (tx_packet_template_t*)(p_mem_buf_desc->p_buffer);
	total_packet_len = iov->iov_len + h->m_total_hdr_len;
	h->copy_l2_ip_hdr(p_pkt);
	// We've copied to aligned address, and now we must update p_pkt to point to real
	// L2 header

	p_pkt->hdr.m_ip_hdr.tot_len = (htons)(iov->iov_len + h->m_ip_header_len);

	// The header is aligned for fast copy but we need to maintain this diff in order to get the real header pointer easily
	size_t hdr_alignment_diff = h->m_aligned_l2_l3_len - h->m_total_hdr_len;
	m_sge.addr = (uintptr_t)((uint8_t*)p_pkt + hdr_alignment_diff);
	m_sge.length = total_packet_len;

	m_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;
	m_p_ring->send_ring_buffer(&m_send_wqe, false);
#ifndef __COVERITY__
	struct tcphdr* p_tcp_h = (struct tcphdr*)(((uint8_t*)(&(p_pkt->hdr.m_ip_hdr))+sizeof(p_pkt->hdr.m_ip_hdr)));
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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
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

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void neigh_entry::handle_neigh_event(neigh_nl_event* nl_ev)
{
	const netlink_neigh_info* nl_info = nl_ev->get_neigh_info();

	int neigh_state = nl_info->state;
	switch (neigh_state)
	{
	case NUD_FAILED:
		neigh_logdbg("state = FAILED");
		event_handler(EV_ERROR);
		break;

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
			m_timer_handle = priv_register_timer_event(mce_sys.neigh_wait_till_send_arp_msec, this, ONE_SHOT_TIMER, NULL);
		}
		break;
	}
	case NUD_REACHABLE:
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
	case EV_ARP_RESOLVED:
		return "EV_ARP_RESOLVED";
	case EV_ADDR_RESOLVED:
		return "EV_ADDR_RESOLVED";
	case EV_PATH_RESOLVED:
		return "EV_PATH_RESOLVED";
	case EV_ERROR:
		return "EV_ERROR";
	case EV_TIMEOUT_EXPIRED:
		return "EV_TIMEOUT_EXPIRED";
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
	neigh_logdbg("Got event %s (%d)", priv_rdma_cm_event_type_str(p_rdma_cm_event->event), p_rdma_cm_event->event);

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

	//3. Start RDMA address resolution
	neigh_logdbg("Calling rdma_resolve_addr");

	IF_RDMACM_FAILURE(rdma_resolve_addr(m_cma_id, (struct sockaddr*)&m_src_addr, (struct sockaddr*)&m_dst_addr, 2000))
	{
		neigh_logdbg("Failed in rdma_resolve_addr  m_cma_id = %p (errno=%d %m)", m_cma_id, errno);
		return -1;
	} ENDIF_RDMACM_FAILURE;

	return 0;
}


//Private enter function for NOT_ACTIVE state
void neigh_entry::priv_enter_not_active()
{
	neigh_logfunc("");

	m_lock.lock();

	m_state = false;

	priv_destroy_cma_id();
	priv_unregister_timer();
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

	m_lock.unlock();
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
	if (!m_unsent_queue.empty() && (m_err_counter < mce_sys.neigh_num_err_retries)) {
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
	m_lock.lock();

	m_state = true;
	empty_unsent_queue();

	int state;
	// Need to send ARP in case neigh state is not REACHABLE and this is not MC neigh
	// This is the case when VMA was started with neigh in STALE state and
	// rdma_adress_resolve() in this case will not initiate ARP
	if (m_type == UC && ! m_is_loopback) {
		if (priv_get_neigh_state(state) && (state != NUD_REACHABLE)) {
			send_arp();
			m_timer_handle = priv_register_timer_event(mce_sys.neigh_wait_till_send_arp_msec, this, ONE_SHOT_TIMER, NULL);
		}
	}
	m_lock.unlock();
	return 0;
}

bool neigh_entry::priv_get_neigh_state(int & state)
{
	netlink_neigh_info info;
	if (m_is_loopback) {
		state = NUD_REACHABLE;
		return true;
	}

	if (g_p_netlink_handler->get_neigh(inet_ntoa(m_dst_addr.sin_addr), &info)) {
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

	if (m_is_loopback) {
		memcpy(l2_addr, m_p_dev->get_l2_address()->get_address(), m_p_dev->get_l2_address()->get_addrlen());
		return true;
	}

	if (g_p_netlink_handler->get_neigh(inet_ntoa(m_dst_addr.sin_addr), &info)){
		if (info.state != NUD_FAILED) {
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
	void* timer_handler = NULL;
	m_lock.lock();
	if(!is_cleaned()){
		timer_handler = g_p_event_handler_manager->register_timer_event(timeout_msec, handler, req_type, user_data);
	}
	m_lock.unlock();
	return timer_handler;
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
		neigh_entry(key, VMA_TRANSPORT_ETH)
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
				{ ST_READY, 		EV_ERROR, 		ST_ERROR,		NULL },
				{ ST_INIT, 		EV_ERROR, 		ST_ERROR, 		NULL },
				{ ST_ERROR, 		EV_ERROR, 		ST_NOT_ACTIVE, 		NULL },
	                 //Entry functions
	                        { ST_INIT, 		SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_init },
	                        { ST_ERROR, 		SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_error },
	                        { ST_NOT_ACTIVE, 	SM_STATE_ENTRY,		SM_NO_ST,		neigh_entry::dofunc_enter_not_active },
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

// This function create new val and initiate it with Multicast MAC
inline int neigh_eth::build_mc_neigh_val()
{
	neigh_logdbg("");
	m_state = false;

	//We need lock in any case that we change entry
	auto_unlocker lock(m_lock);

	if (m_val == NULL)
		//This is the first time we are trying to allocate new val or it failed last time
		m_val = new neigh_eth_val;

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

int neigh_eth::priv_enter_init()
{
	int state;

	if (priv_get_neigh_state(state) && (state != NUD_FAILED)) {
		event_handler(EV_ARP_RESOLVED);
		return 0;
	}

	if (!(neigh_entry::priv_enter_init())) {
		// query netlink - if this entry already exist and REACHABLE we can use it
		if (priv_get_neigh_state(state) && (state != NUD_FAILED)) {
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

inline int neigh_eth::build_uc_neigh_val()
{
	neigh_logdbg("");

	// We need lock in any case that we change entry
	auto_unlocker lock(m_lock);

	if (m_val == NULL) {
		// This is the first time we are trying to allocate new val or it failed last time
		m_val = new neigh_eth_val;
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

bool neigh_eth::post_send_arp(bool is_broadcast)
{
	header h;
	neigh_logdbg("Sending %s ARP", is_broadcast?"BC":"UC");

	mem_buf_desc_t* p_mem_buf_desc = m_p_ring->mem_buf_tx_get(false, 1);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(p_mem_buf_desc == NULL)) {
		neigh_logdbg("No free TX buffer, not sending ARP");
		return false;
	}

	net_device_val_eth *netdevice_eth = dynamic_cast<net_device_val_eth*>(m_p_dev);
	if (netdevice_eth == NULL) {
		m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
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
		m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
		neigh_logdbg("src or dst is NULL not sending ARP");
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

	m_p_ring->send_ring_buffer(&m_send_wqe, false);

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

//============================================================== neigh_ib ==================================================

neigh_ib::neigh_ib(neigh_key key, bool is_init_resources) :
				neigh_entry(key, VMA_TRANSPORT_IB, is_init_resources), m_pd(NULL)
{
	neigh_logdbg("");

	m_rdma_port_space = RDMA_PS_IPOIB;

	if(IS_BROADCAST_N(key.get_in_addr())) {
		//In case of broadcast neigh we don't want to have state machine
		m_type = MC;
		return;
	}

	if (IN_MULTICAST_N(key.get_in_addr())) {
		//This is Multicast neigh
		m_type = MC;
	}
	else {
		// This is Unicast neigh
		m_type = UC;
	}
	//Do we need to handle case when we get EV_ERROR but in case this error is not related to the state
	//Like Address Resolve Error when we at ST_ARP_RESOLVED or ST_PATH_RESOLVED ....

	sm_short_table_line_t short_sm_table[] =
	{
			// 	{curr state,            event,                  next state,             action func   }
			{ ST_NOT_ACTIVE, 	EV_KICK_START, 		ST_INIT,		NULL },
			{ ST_ERROR, 		EV_KICK_START, 		ST_INIT, 		NULL },
			{ ST_INIT, 		EV_ADDR_RESOLVED,	ST_ARP_RESOLVED, 	NULL },
			{ ST_ARP_RESOLVED, 	EV_PATH_RESOLVED,	ST_PATH_RESOLVED, 	NULL },
			{ ST_PATH_RESOLVED, 	EV_TIMEOUT_EXPIRED,	ST_READY, 		NULL },
			{ ST_PATH_RESOLVED, 	EV_ERROR,		ST_ERROR, 		NULL },
			{ ST_ARP_RESOLVED, 	EV_ERROR,		ST_ERROR, 		NULL },
			{ ST_READY, 		EV_ERROR, 		ST_ERROR,		NULL },
			{ ST_INIT, 		EV_ERROR, 		ST_ERROR, 		NULL },
			{ ST_ERROR, 		EV_ERROR, 		ST_NOT_ACTIVE, 		NULL },
			//Entry functions
			{ ST_INIT, 		SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_init },
			{ ST_ARP_RESOLVED, 	SM_STATE_ENTRY,		SM_NO_ST,		neigh_ib::dofunc_enter_arp_resolved },
			{ ST_PATH_RESOLVED, 	SM_STATE_ENTRY,		SM_NO_ST, 		neigh_ib::dofunc_enter_path_resolved },
			{ ST_READY, 		SM_STATE_ENTRY, 	SM_NO_ST,		neigh_entry::dofunc_enter_ready },
			{ ST_NOT_ACTIVE, 	SM_STATE_ENTRY,		SM_NO_ST,		neigh_entry::dofunc_enter_not_active },
			{ ST_ERROR, 		SM_STATE_ENTRY,		SM_NO_ST,		neigh_entry::dofunc_enter_error },
			SM_TABLE_END };

	// Create state_nachine
	m_state_machine = new state_machine(this,		// app hndl
			ST_NOT_ACTIVE,		// start state_t
			ST_LAST,		// max states
			EV_LAST,		// max events
			short_sm_table,	// short table
			general_st_entry,	// default entry function
			general_st_leave,	// default leave function
			NULL,		// default func
			print_event_info	// debug function
	);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_state_machine == NULL)
		neigh_logpanic("Failed allocating state_machine");
	BULLSEYE_EXCLUDE_BLOCK_END

	priv_kick_start_sm();
}

neigh_ib::~neigh_ib()
{
	priv_enter_not_active();
}

void neigh_ib::handle_event_ibverbs_cb(void* ev_data, void* ctx)
{
	NOT_IN_USE(ctx);
	event_t event = ibverbs_event_mapping(ev_data);
	event_handler(event, ev_data);
}

// called when timer expired
void neigh_ib::handle_timer_expired(void* ctx)
{
	neigh_logdbg("general timeout expired!");
	int state = m_state_machine->get_curr_state();

	if(state == ST_PATH_RESOLVED) {
		// Clear Timer Handler
		m_timer_handle = NULL;
		event_handler(EV_TIMEOUT_EXPIRED);
	}
	else if(state == ST_READY) {
		neigh_entry::handle_timer_expired(ctx);
	}
}

bool neigh_ib::priv_handle_neigh_is_l2_changed(address_t new_l2_addr)
{
	auto_unlocker lock(m_lock);
	IPoIB_addr new_l2_address(new_l2_addr);
	if (m_val) {
		if(m_val->get_l2_address()) {
			if (!(m_val->get_l2_address()->compare(new_l2_address))) {
				neigh_logdbg("l2 address was changed (%s => %s)", (m_val->get_l2_address())->to_str().c_str(), new_l2_address.to_str().c_str());
				event_handler(EV_ERROR);
				return true;
			}
			else {
				neigh_logdbg("No change in l2 address");
				return false;
			}
		}
		else {
			neigh_logdbg("l2 address is NULL\n");
		}
	}
	else {
		neigh_logerr("m_val is NULL");
	}

	event_handler(EV_ERROR);
	return true;
}

bool neigh_ib::post_send_arp(bool is_broadcast)
{
	neigh_logdbg("Sending %s ARP", is_broadcast?"BC":"UC");

	mem_buf_desc_t* p_mem_buf_desc = m_p_ring->mem_buf_tx_get(false, 1);
	if (unlikely(p_mem_buf_desc == NULL)) {
		neigh_logdbg("No free TX buffer, not sending ARP");
		return false;
	}

	net_device_val_ib *netdevice_ib = dynamic_cast<net_device_val_ib*>(m_p_dev);
	if (netdevice_ib == NULL) {
		m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
		neigh_logdbg("Net dev is NULL not sending ARP");
		return false;
	}

	const L2_address *src = netdevice_ib->get_l2_address();
	const L2_address *dst;
	neigh_ib_val br_neigh_val;
	ibv_ah* ah = NULL;
	uint32_t qpn;
	uint32_t qkey;
	const unsigned char* peer_mac = NULL;
	if (!is_broadcast) {
		dst = m_val->get_l2_address();
		peer_mac = dst->get_address();
		ah = ((neigh_ib_val *)m_val)->get_ah();
		qpn = ((neigh_ib_val *)m_val)->get_qpn();
		qkey = ((neigh_ib_val *)m_val)->get_qkey();
	}
	else {
		dst = m_p_dev->get_br_address();
		neigh_ib_broadcast * br_neigh = const_cast<neigh_ib_broadcast *>(((net_device_val_ib*)m_p_dev)->get_br_neigh());
		bool ret = br_neigh->get_peer_info(&br_neigh_val);
		if (ret) {
			ah = br_neigh_val.get_ah();
			qpn = br_neigh_val.get_qpn();
			qkey = br_neigh_val.get_qkey();
		}
		else {
			m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
			neigh_logdbg("BR Neigh is not valid, not sending BR ARP");
			return false;
		}
	}

	if (src == NULL || dst == NULL) {
		m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
		neigh_logdbg("src or dst is NULL not sending ARP");
		return false;
	}

	wqe_send_ib_handler wqe_sh;
	wqe_sh.init_wqe(m_send_wqe, &m_sge, 1, ah, qpn, qkey);
	neigh_logdbg("ARP: ah=%#x, qkey=%#x, qpn=%#x", ah ,qkey, qpn);
	header h;
	h.init();
	h.configure_ipoib_headers(IPOIB_ARP_HEADER);


	tx_packet_template_t *p_pkt = (tx_packet_template_t*)p_mem_buf_desc->p_buffer;
	h.copy_l2_hdr(p_pkt);

	ib_arp_hdr* p_arphdr = (ib_arp_hdr*) (p_mem_buf_desc->p_buffer + h.m_transport_header_tx_offset + h.m_total_hdr_len);
	set_ib_arp_hdr(p_arphdr, m_p_dev->get_local_addr(), get_key().get_in_addr(), m_p_dev->get_l2_address()->get_address(), peer_mac);

	m_sge.addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)h.m_transport_header_tx_offset);
	m_sge.length = sizeof(ib_arp_hdr) + h.m_total_hdr_len;
	m_sge.lkey = p_mem_buf_desc->lkey;
	p_mem_buf_desc->p_next_desc = NULL;
	m_send_wqe.wr_id = (uintptr_t)p_mem_buf_desc;

	m_p_ring->send_ring_buffer(&m_send_wqe, false);

	neigh_logdbg("ARP Sent");
	return true;
}

bool neigh_ib::prepare_to_send_packet(header * h)
{
	neigh_logdbg("");
	wqe_send_ib_handler wqe_sh;
	wqe_sh.init_wqe(m_send_wqe, &m_sge , 1, ((neigh_ib_val *)m_val)->get_ah(), ((neigh_ib_val *)m_val)->get_qpn(), ((neigh_ib_val *)m_val)->get_qkey());
	h->configure_ipoib_headers();

	return true;
}

neigh_entry::event_t neigh_ib::ibverbs_event_mapping(void* p_event_info)
{
	struct ibv_async_event *ev = (struct ibv_async_event *) p_event_info;
	neigh_logdbg("Got event %s (%d) ", priv_ibv_event_desc_str(ev->event_type), ev->event_type);

	switch (ev->event_type)
	{
	case IBV_EVENT_SM_CHANGE:
	case IBV_EVENT_CLIENT_REREGISTER:
		return EV_ERROR;
	default:
		return EV_UNHANDLED;
	}
}

void neigh_ib::dofunc_enter_arp_resolved(const sm_info_t& func_info)
{
	neigh_ib * my_neigh = (neigh_ib *) func_info.app_hndl;
	neigh_entry::general_st_entry(func_info);

	run_helper_func(priv_enter_arp_resolved(), EV_ERROR);
}

void neigh_ib::dofunc_enter_path_resolved(const sm_info_t& func_info)
{
	neigh_ib * my_neigh = (neigh_ib *) func_info.app_hndl;
	neigh_entry::general_st_entry(func_info);

	uint32_t wait_after_join_msec;

	run_helper_func(priv_enter_path_resolved((struct rdma_cm_event*)func_info.ev_data, wait_after_join_msec),
			EV_ERROR);
	my_neigh->m_timer_handle = my_neigh->priv_register_timer_event(wait_after_join_msec, my_neigh, ONE_SHOT_TIMER, NULL);
}

int neigh_ib::priv_enter_arp_resolved()
{
	neigh_logfunc("");

	if (find_pd())
		return -1;

	//Register Verbs event in case there was Fabric change
	if (m_cma_id->verbs) {
		g_p_event_handler_manager->register_ibverbs_event(
				m_cma_id->verbs->async_fd, this,
				m_cma_id->verbs, 0);
	}

	if (m_type == UC)
		return (handle_enter_arp_resolved_uc());
	else
		// MC
		return (handle_enter_arp_resolved_mc());
}

int neigh_ib::priv_enter_path_resolved(struct rdma_cm_event* event_data,
		uint32_t & wait_after_join_msec)
{
	neigh_logfunc("");

	if (m_val == NULL)
		//This is the first time we are trying to allocate new val or it failed last time
		m_val = new neigh_ib_val;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_val == NULL)
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END

	if (m_type == UC)
		return (build_uc_neigh_val(event_data, wait_after_join_msec));
	else
		//MC
		return (build_mc_neigh_val(event_data, wait_after_join_msec));
}

void  neigh_ib::priv_enter_error()
{
	auto_unlocker lock(m_lock);

	m_state = false;
	m_pd = NULL;

	destroy_ah();
	priv_unregister_timer();

	if (m_cma_id && m_cma_id->verbs) {
		neigh_logdbg("Unregister Verbs event");
		g_p_event_handler_manager->unregister_ibverbs_event(m_cma_id->verbs->async_fd, this);
	}

	neigh_entry::priv_enter_error();
}

void neigh_ib::priv_enter_not_active()
{
	neigh_logfunc("");

	auto_unlocker lock(m_lock);

	m_state = false;
	m_pd = NULL;

	destroy_ah();

	if (m_cma_id && m_cma_id->verbs) {
		neigh_logdbg("Unregister Verbs event");
		g_p_event_handler_manager->unregister_ibverbs_event(m_cma_id->verbs->async_fd, this);
	}

	neigh_entry::priv_enter_not_active();
}

int neigh_ib::priv_enter_ready()
{
	neigh_logfunc("");
	priv_unregister_timer();
	return (neigh_entry::priv_enter_ready());
}

int neigh_ib::handle_enter_arp_resolved_mc()
{
	neigh_logdbg("");

	IF_RDMACM_FAILURE(rdma_join_multicast( m_cma_id, (struct sockaddr*)&m_dst_addr, (void *)this))
	{
		neigh_logdbg("Failed in rdma_join_multicast (errno=%d %m)", errno);
		return -1;
	} ENDIF_RDMACM_FAILURE;

	return 0;
}

int neigh_ib::handle_enter_arp_resolved_uc()
{
	neigh_logdbg("");

	IF_RDMACM_FAILURE(rdma_resolve_route(m_cma_id, RDMA_CM_TIMEOUT))
	{
		neigh_logdbg("Resolve address error (errno=%d %m)", errno);
		return -1;
	} ENDIF_RDMACM_FAILURE;

	return 0;
}

int neigh_ib::build_mc_neigh_val(struct rdma_cm_event* event_data,
		uint32_t & wait_after_join_msec)
{
	neigh_logdbg("");

	m_val->m_l2_address = new IPoIB_addr(event_data->param.ud.qp_num, (address_t)event_data->param.ud.ah_attr.grh.dgid.raw);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_val->m_l2_address == NULL) {
		neigh_logdbg("Failed allocating m_val->m_l2_address");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	((neigh_ib_val *) m_val)->m_qkey = event_data->param.ud.qkey;

	memcpy(&((neigh_ib_val *) m_val)->m_ah_attr,
			&event_data->param.ud.ah_attr,
			sizeof(struct ibv_ah_attr));

	BULLSEYE_EXCLUDE_BLOCK_START
	if (create_ah())
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END

	neigh_logdbg("IB multicast neigh params are : ah=%#x, qkey=%#x, sl=%#x, rate=%#x, port_num = %#x,  qpn=%#x dlid=%#x dgid = " IPOIB_HW_ADDR_PRINT_FMT_16,
				((neigh_ib_val *) m_val)->m_ah, ((neigh_ib_val *) m_val)->m_qkey, ((neigh_ib_val *) m_val)->m_ah_attr.sl, ((neigh_ib_val *) m_val)->m_ah_attr.static_rate,
				((neigh_ib_val *) m_val)->m_ah_attr.port_num, ((neigh_ib_val *) m_val)->get_qpn(), ((neigh_ib_val *) m_val)->m_ah_attr.dlid,
				IPOIB_HW_ADDR_PRINT_ADDR_16(((neigh_ib_val *) m_val)->m_ah_attr.grh.dgid.raw));
	/*neigh_logerr("flow_label = %#x, sgid_index=%#x, hop_limit=%#x, traffic_class=%#x", ((neigh_ib_val *) m_val)->m_ah_attr.grh.flow_label, ((neigh_ib_val *) m_val)->m_ah_attr.grh.sgid_index,
				((neigh_ib_val *) m_val)->m_ah_attr.grh.hop_limit, ((neigh_ib_val *) m_val)->m_ah_attr.grh.traffic_class);
	*/
	wait_after_join_msec = mce_sys.wait_after_join_msec;

	return 0;
}

int neigh_ib::build_uc_neigh_val(struct rdma_cm_event* event_data,
		uint32_t & wait_after_join_msec)
{
	NOT_IN_USE(event_data);
	neigh_logdbg("");

	// Find peer's IPoIB row address
	unsigned char tmp[IPOIB_HW_ADDR_LEN];
	address_t address = (address_t) tmp;
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!priv_get_neigh_l2(address)) {
		neigh_logdbg("Failed in priv_get_neigh_l2()");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_val->m_l2_address = new IPoIB_addr(address);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_val->m_l2_address == NULL) {
		neigh_logdbg("Failed creating m_val->m_l2_address");
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	neigh_logdbg("IPoIB MAC = %s", m_val->m_l2_address->to_str().c_str());
	// IPoIB qkey is hard coded in SM . Do we want to take it from event or leave it hard coded
	//((neigh_ib_val *) m_val)->m_qkey = event_data->param.ud.qkey; //0x0b1b;
	((neigh_ib_val *) m_val)->m_qkey = IPOIB_QKEY;

	//memcpy(&m_val.ib_addr.m_ah_attr, &event_data->param.ud.ah_attr, sizeof(struct ibv_ah_attr));

	if (!m_cma_id || m_cma_id->route.num_paths <= 0) {
		neigh_logdbg("Can't prepare AH attr (cma_id=%p, num_paths=%d)", m_cma_id, m_cma_id ? m_cma_id->route.num_paths : 0);
		return -1;
	}

	memset(&((neigh_ib_val *) m_val)->m_ah_attr, 0, sizeof(((neigh_ib_val *) m_val)->m_ah_attr));
	((neigh_ib_val *) m_val)->m_ah_attr.dlid 	  = 	ntohs(m_cma_id->route.path_rec->dlid);
	((neigh_ib_val *) m_val)->m_ah_attr.sl 	 	  = 	m_cma_id->route.path_rec->sl;
	((neigh_ib_val *) m_val)->m_ah_attr.src_path_bits = 	0;
	((neigh_ib_val *) m_val)->m_ah_attr.static_rate   = 	m_cma_id->route.path_rec->rate;
	((neigh_ib_val *) m_val)->m_ah_attr.is_global 	  = 	0;
	((neigh_ib_val *) m_val)->m_ah_attr.port_num 	  = 	m_cma_id->port_num;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (create_ah())
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END

	neigh_logdbg("IB unicast neigh params  ah=%#x, qkey=%#x, qpn=%#x, dlid=%#x", ((neigh_ib_val *) m_val)->m_ah,
			((neigh_ib_val *) m_val)->m_qkey, ((neigh_ib_val *) m_val)->get_qpn(), ((neigh_ib_val *) m_val)->m_ah_attr.dlid);

	wait_after_join_msec = 0;

	return 0;
}

int neigh_ib::find_pd()
{
	neigh_logdbg("");

	if (m_cma_id->verbs == NULL) {
		neigh_logdbg("m_cma_id->verbs is NULL");
		return -1;
	}
	ib_ctx_handler* ib_ctx_h = g_p_ib_ctx_handler_collection->get_ib_ctx(
			m_cma_id->verbs);

	if (ib_ctx_h) {
		m_pd = ib_ctx_h->get_ibv_pd();
		return 0;
	}

	return -1;
}

int neigh_ib::create_ah()
{
	neigh_logdbg("");

	/*	if (((neigh_ib_val *) m_val)->m_ah) {
		// if there's ah we want to destroy it - shouldn't happen
		neigh_logerr("destroy ah %p (shouldn't happen)", ((neigh_ib_val *) m_val)->m_ah);
		if (destroy_ah())
			return -1;
	}
	 */
	((neigh_ib_val *) m_val)->m_ah = ibv_create_ah(m_pd, &((neigh_ib_val *) m_val)->m_ah_attr);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!((neigh_ib_val *) m_val)->m_ah) {
		neigh_logdbg("failed creating address handler (errno=%d %m)", errno);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return 0;
}

int neigh_ib::destroy_ah()
{
	neigh_logdbg("");
	//For now we whouldn't destroy it
	//We cannot destroy ah till each post_send with this ah has ended
	//TODO: Need to think how to  handle this - for now there will be ah leak
	return 0;
//unreachable code
#ifndef __COVERITY__
	if (m_val && ((neigh_ib_val *) m_val)->m_ah) {
		IF_VERBS_FAILURE(ibv_destroy_ah(((neigh_ib_val *) m_val)->m_ah))
		{
			neigh_logdbg("failed destroying address handle (errno=%d %m)", errno);
			return -1;
		}ENDIF_VERBS_FAILURE;
	}
	return 0;
#endif
}

//==================================================================================================================

neigh_ib_broadcast::neigh_ib_broadcast(neigh_key key) : neigh_ib(key, false)
{
	neigh_logdbg("Calling rdma_create_id");
	IF_RDMACM_FAILURE(rdma_create_id(g_p_neigh_table_mgr->m_neigh_cma_event_channel, &m_cma_id, (void *)this, m_rdma_port_space))
	{
		neigh_logerr("Failed in rdma_create_id (errno=%d %m)", errno);
		return;
	} ENDIF_RDMACM_FAILURE;


	neigh_logdbg("Calling rdma_bind_addr");
	struct sockaddr_in local_sockaddr;
	local_sockaddr.sin_family = AF_INET;
	local_sockaddr.sin_port = INPORT_ANY;
	local_sockaddr.sin_addr.s_addr = m_p_dev->get_local_addr();

	IF_RDMACM_FAILURE(rdma_bind_addr(m_cma_id, (struct sockaddr*)&local_sockaddr)) {
		neigh_logerr("Failed in rdma_bind_addr (src=%d.%d.%d.%d) (errno=%d %m)", NIPQUAD(m_p_dev->get_local_addr()), errno);
		return;
	} ENDIF_RDMACM_FAILURE;

	build_mc_neigh_val();

	m_state = true;
}

void neigh_ib_broadcast::build_mc_neigh_val()
{
	m_val = new neigh_ib_val;
	if(m_val == NULL) {
		neigh_logerr("Failed allocating m_val");
		return;
	}

	m_val->m_l2_address = new IPoIB_addr(((m_p_dev->get_br_address())->get_address()));
	if (m_val->m_l2_address == NULL) {
		neigh_logerr("Failed allocating m_val->m_l2_address");
		return;
	}

	((neigh_ib_val *) m_val)->m_qkey = IPOIB_QKEY;

	memset(&((neigh_ib_val *) m_val)->m_ah_attr, 0, sizeof(((neigh_ib_val *) m_val)->m_ah_attr));
	memcpy( ((neigh_ib_val *) m_val)->m_ah_attr.grh.dgid.raw , &((m_val->m_l2_address->get_address())[4]), 16*sizeof(char));

	((neigh_ib_val *) m_val)->m_ah_attr.dlid 	  = 	0xc000;
	((neigh_ib_val *) m_val)->m_ah_attr.static_rate   = 	0x3;
	((neigh_ib_val *) m_val)->m_ah_attr.port_num 	  = 	m_cma_id->port_num;
	((neigh_ib_val *) m_val)->m_ah_attr.is_global	  =	0x1;

	if(find_pd()) {
			neigh_logerr("Failed find_pd()");
	}

	/*neigh_logerr("m_pd = %p,  flow_label = %#x, sgid_index=%#x, hop_limit=%#x, traffic_class=%#x",
			m_pd, ((neigh_ib_val *) m_val)->m_ah_attr.grh.flow_label, ((neigh_ib_val *) m_val)->m_ah_attr.grh.sgid_index,
			((neigh_ib_val *) m_val)->m_ah_attr.grh.hop_limit, ((neigh_ib_val *) m_val)->m_ah_attr.grh.traffic_class);
	*/
	if (create_ah())
		return;

	neigh_logdbg("IB broadcast neigh params are : ah=%#x, qkey=%#x, sl=%#x, rate=%#x, port_num = %#x,  qpn=%#x,  dlid=%#x dgid = " IPOIB_HW_ADDR_PRINT_FMT_16,
			((neigh_ib_val *) m_val)->m_ah, ((neigh_ib_val *) m_val)->m_qkey, ((neigh_ib_val *) m_val)->m_ah_attr.sl,
			((neigh_ib_val *) m_val)->m_ah_attr.static_rate,((neigh_ib_val *) m_val)->m_ah_attr.port_num,
			((neigh_ib_val *) m_val)->get_qpn(), ((neigh_ib_val *) m_val)->m_ah_attr.dlid, IPOIB_HW_ADDR_PRINT_ADDR_16(((neigh_ib_val *) m_val)->m_ah_attr.grh.dgid.raw) );


}

bool neigh_ib_broadcast::get_peer_info(neigh_val * p_val)
{
	neigh_logfunc("calling neigh_entry get_peer_info. state = %d", m_state);
	if (p_val == NULL) {
		neigh_logdbg("p_val is NULL, return false");
		return false;
	}

	auto_unlocker lock(m_lock);
	if (m_state) {
		neigh_logdbg("There is a valid val");
		*p_val = *m_val;
		return m_state;
	}

	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int neigh_ib_broadcast::send(neigh_send_info &s_info)
{
	NOT_IN_USE(s_info);
	neigh_logerr("We should not call for this function, something is wrong");
	return false;
}

void neigh_ib_broadcast::send_arp()
{
	neigh_logerr("We should not call for this function, something is wrong");
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
