/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#include "vma/proto/neighbour.h"
#include "vma/event/event_handler_manager.h"
#include "vma/event/timer_handler.h"
#include <linux/igmp.h>


#ifndef IGMP_HANDLER_H_
#define IGMP_HANDLER_H_

#define igmp_key neigh_key

#define IGMP_TIMER_ID	0

struct __attribute__ ((packed, aligned)) ip_igmp_tx_hdr_template_t {
	iphdr			m_ip_hdr;
	uint32_t		m_ip_hdr_ext;
	igmphdr			m_igmp_hdr;
};

#define IGMP_IP_HEADER_EXT	0x94040000   // IP header options field: Router alert

class igmp_handler : public timer_handler, public lock_mutex, public cleanable_obj, public cache_observer, public neigh_observer
{
public:
					igmp_handler(const igmp_key &key, uint8_t igmp_code);
	bool 				init(const igmp_key &key);
					~igmp_handler();

	const std::string to_str() const
	{
		return(m_mc_addr.to_str() + " " + m_p_ndvl->to_str());
	}

	virtual transport_type_t 	get_obs_transport_type() const
	{
		return m_p_ndvl->get_transport_type();
	}

	void 				handle_query(uint8_t igmp_code); // handle queries coming from router
	void 				handle_report();  // handle reports coming from other hosts

	virtual void 			clean_obj();
private:

	ip_address 		m_mc_addr;
	net_device_val*		m_p_ndvl;
	ring_allocation_logic_tx m_ring_allocation_logic;
	bool 			m_ignore_timer;
	void* 			m_timer_handle;
	neigh_entry*		m_p_neigh_entry;
	neigh_val*		m_p_neigh_val;
	ring* 			m_p_ring;
	header			m_header;
	ibv_sge 		m_sge;
	vma_ibv_send_wr		m_p_send_igmp_wqe;
	uint8_t			m_igmp_code;
	ring_user_id_t	m_id;

	void 				set_timer(); //called by tx_igmp_report
	void 				unset_timer(); // called if igmp packet is report and not query
	virtual void 			handle_timer_expired(void* user_data);
	void 				priv_register_timer_event(timer_handler* handler, timer_req_type_t req_type, void* user_data);
	bool 				tx_igmp_report();
	void 				set_ip_igmp_hdr(ip_igmp_tx_hdr_template_t* igmp_hdr);

};

#endif
