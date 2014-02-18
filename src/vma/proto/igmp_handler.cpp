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



#include "igmp_handler.h"
#include "vlogger/vlogger.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "vma/dev/wqe_send_handler.h"
#include "vma/dev/wqe_send_ib_handler.h"
#include "vma/util/utils.h"
#include "vma/util/bullseye.h"



#define MODULE_NAME 		"igmp_hdlr"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[%s]:%d:%s() "

#undef	__INFO__
#define __INFO__		this->to_str().c_str()

#define igmp_hdlr_logpanic		__log_info_panic
#define igmp_hdlr_logerr		__log_info_err
#define igmp_hdlr_logwarn		__log_info_warn
#define igmp_hdlr_loginfo		__log_info_info
#define igmp_hdlr_logdbg		__log_info_dbg
#define igmp_hdlr_logfunc		__log_info_func
#define igmp_hdlr_logfuncall		__log_info_funcall

#define RING_KEY 0
#define IGMPV1_MAX_RESPONSE_TIME 100

igmp_handler::igmp_handler(const igmp_key &key, uint8_t	igmp_code) : m_mc_addr (key.get_in_addr()), m_p_ndvl (key.get_net_device_val()),
					   m_ignore_timer(false), m_timer_handle(NULL), m_p_neigh_entry(NULL), m_p_neigh_val(NULL),
					   m_p_ring(NULL), m_igmp_code(igmp_code ? igmp_code : IGMPV1_MAX_RESPONSE_TIME)
{
	memset(&m_sge, 0, sizeof(struct ibv_sge));
	memset(&m_p_send_igmp_wqe, 0, sizeof(vma_ibv_send_wr));
}

igmp_handler::~igmp_handler()
{
	if (m_p_neigh_entry) {
		g_p_neigh_table_mgr->unregister_observer(igmp_key(m_mc_addr, m_p_ndvl),this);
		m_p_neigh_entry = NULL;
	}

	if (m_p_ring) {
		m_p_ndvl->release_ring(RING_KEY);
		m_p_ring = NULL;
	}

	if (m_p_neigh_val) {
		delete m_p_neigh_val;
		m_p_neigh_val = NULL;
	}
}

bool igmp_handler::init(const igmp_key &key)
{
	igmp_hdlr_logfunc("");
	cache_entry_subject<neigh_key, neigh_val*>* p_ces = NULL;
	g_p_neigh_table_mgr->register_observer(key, this, &p_ces);
	m_p_neigh_entry = dynamic_cast<neigh_entry*>(p_ces);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_neigh_entry) {
		igmp_hdlr_logerr("Dynamic casting to neigh_entry has failed");
		return false;
	}

	m_p_neigh_val = new neigh_ib_val;
	if (!m_p_neigh_val) {
		igmp_hdlr_logerr("Failed allocating neigh_val");
		return false;
	}

	m_p_ring = m_p_ndvl->reserve_ring(RING_KEY);
	if (!m_p_ring) {
		igmp_hdlr_logerr("Ring was not reserved");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return true;
}

 // will register timer and later do 'tx_igmp_report(mc_group, ndvl)'
void igmp_handler::handle_query(uint8_t igmp_code)
{
	igmp_hdlr_logdbg("Received igmp query, preparing to send report");

	m_igmp_code = igmp_code ? igmp_code : IGMPV1_MAX_RESPONSE_TIME;

	m_ignore_timer = false;

	priv_register_timer_event(this, ONE_SHOT_TIMER, (void*)IGMP_TIMER_ID);
}

void igmp_handler::priv_register_timer_event(timer_handler* handler, timer_req_type_t req_type, void* user_data)
{
	int duration = 0 ;
	srand(time(NULL));
	duration = (rand() % (m_igmp_code * 100)); // igmp_code (1-255) is in 1/10 sec units

	lock();
	if (!m_timer_handle && g_p_event_handler_manager) {
		igmp_hdlr_logdbg("Register timer (%d msec) for sending igmp report after seen an igmp query for this group", duration);
		m_timer_handle = g_p_event_handler_manager->register_timer_event(duration, handler, req_type, user_data);
	}
	unlock();
}

void igmp_handler::handle_report()
{
	igmp_hdlr_logdbg("Ignoring self timer (%p) after seen an igmp report for this group", m_timer_handle);
	m_ignore_timer = true; // check if was not ignored before ?
}

void igmp_handler::clean_obj()
{
	set_cleaned();
	m_timer_handle = NULL;
	g_p_event_handler_manager->unregister_timers_event_and_delete(this);
}

void igmp_handler::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	igmp_hdlr_logdbg("Timeout expired");
	m_timer_handle = NULL;

	if (m_ignore_timer) {
		igmp_hdlr_logdbg("Ignoring timeout handling due to captured IGMP report");
		return;
	}
	igmp_hdlr_logdbg("Sending igmp report");

	if (!tx_igmp_report()) {
		igmp_hdlr_logdbg("Send igmp report failed, registering new timer");
		priv_register_timer_event(this, ONE_SHOT_TIMER, (void*)IGMP_TIMER_ID);
	}
}

bool igmp_handler::tx_igmp_report()
{

	if (m_p_neigh_entry->get_peer_info(m_p_neigh_val)) {
		igmp_hdlr_logdbg("neigh is valid");
	}
	else {
		igmp_hdlr_logdbg("neigh is not valid");
		return false;
	}

	mem_buf_desc_t* p_mem_buf_desc = m_p_ring->mem_buf_tx_get(false, 1);
	if (unlikely(p_mem_buf_desc == NULL)) {
		igmp_hdlr_logdbg("No free TX buffer, not sending igmp report");
		return false;
	}

	wqe_send_ib_handler wqe_sh;
	wqe_sh.init_wqe(m_p_send_igmp_wqe, &m_sge, 1, ((neigh_ib_val *)m_p_neigh_val)->get_ah(),
			((neigh_ib_val *)m_p_neigh_val)->get_qpn(), ((neigh_ib_val *)m_p_neigh_val)->get_qkey());
	m_header.init();
	m_header.configure_ipoib_headers();
	size_t m_total_l2_hdr_len = m_header.m_total_hdr_len;
	m_header.configure_ip_header(IPPROTO_IGMP, m_p_ndvl->get_local_addr(), m_mc_addr.get_in_addr(),/*ttl for IGMP*/1);
	m_header.copy_l2_ip_hdr((tx_packet_template_t*)p_mem_buf_desc->p_buffer);

	// Override IP header with IGMPV2 specific info
	ip_igmp_tx_hdr_template_t* p_ip_pkt = (ip_igmp_tx_hdr_template_t*)(p_mem_buf_desc->p_buffer + m_header.m_transport_header_tx_offset + m_total_l2_hdr_len);
	set_ip_igmp_hdr(p_ip_pkt);

	m_sge.addr = (uintptr_t)(p_mem_buf_desc->p_buffer + (uint8_t)m_header.m_transport_header_tx_offset);
	m_sge.length = m_header.m_total_hdr_len + sizeof(uint32_t /*m_ip_hdr_ext*/) + sizeof (igmphdr /*m_igmp_hdr*/);
	m_sge.lkey = p_mem_buf_desc->lkey;
	p_mem_buf_desc->p_next_desc = NULL;
	m_p_send_igmp_wqe.wr_id = (uintptr_t)p_mem_buf_desc;

	igmp_hdlr_logdbg("Sending igmp report");
	m_p_ring->send_ring_buffer(&m_p_send_igmp_wqe, false);
	return true;
}

void igmp_handler::set_ip_igmp_hdr(ip_igmp_tx_hdr_template_t* ip_igmp_hdr)
{
	ip_igmp_hdr->m_ip_hdr.ihl = IPV4_IGMP_HDR_LEN_WORDS;
	ip_igmp_hdr->m_ip_hdr.tot_len = htons(IPV4_IGMP_HDR_LEN + sizeof(igmphdr));
	ip_igmp_hdr->m_ip_hdr_ext = htonl(IGMP_IP_HEADER_EXT);
	ip_igmp_hdr->m_ip_hdr.check = 0;
	ip_igmp_hdr->m_ip_hdr.check = csum((unsigned short*)&ip_igmp_hdr->m_ip_hdr, (IPV4_IGMP_HDR_LEN_WORDS) * 2);

	// Create the IGMP header
	ip_igmp_hdr->m_igmp_hdr.type = IGMPV2_HOST_MEMBERSHIP_REPORT;
	ip_igmp_hdr->m_igmp_hdr.code = 0;
	ip_igmp_hdr->m_igmp_hdr.group = m_mc_addr.get_in_addr();
	ip_igmp_hdr->m_igmp_hdr.csum = 0;
	ip_igmp_hdr->m_igmp_hdr.csum = csum((unsigned short*)&ip_igmp_hdr->m_igmp_hdr, IGMP_HDR_LEN_WORDS * 2);
}
