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


#ifndef DST_ENTRY_H
#define DST_ENTRY_H

#include <unistd.h>
#include <sys/socket.h>
#include "vma/util/if.h"
#include <netinet/in.h>

#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "vma/util/verbs_extra.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/proto/route_entry.h"
#include "vma/proto/route_val.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "vma/dev/net_device_val.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/dev/wqe_send_handler.h"
#include "vma/dev/wqe_send_ib_handler.h"
#include "vma/dev/ring.h"
#include "vma/dev/ring_allocation_logic.h"
#include "vma/infra/sender.h"
#include "header.h"
#include "ip_address.h"

class dst_entry : public cache_observer, public tostr, public neigh_observer
{

public:
	dst_entry(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, int owner_fd);
	virtual ~dst_entry();

	virtual void 	notify_cb();

	virtual bool 	prepare_to_send(bool skip_rules=false, bool is_connect=false);
	virtual ssize_t slow_send(const iovec* p_iov, size_t sz_iov, bool is_dummy, bool b_blocked = true, bool is_rexmit = false, int flags = 0, socket_fd_api* sock = 0, tx_call_t call_type = TX_UNDEF) = 0 ;
	virtual ssize_t fast_send(const struct iovec* p_iov, const ssize_t sz_iov, bool is_dummy, bool b_blocked = true, bool is_rexmit = false, bool dont_inline = false) = 0;

	bool		try_migrate_ring(lock_base& socket_lock);

	bool 		is_offloaded() { return m_b_is_offloaded; }
	void		set_bound_addr(in_addr_t addr);
	void		set_so_bindtodevice_addr(in_addr_t addr);
	in_addr_t	get_dst_addr();
	uint16_t	get_dst_port();
	inline in_addr_t get_src_addr() const {
		return m_pkt_src_ip;
	}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	net_device_val* get_net_dev()
	{
		return m_p_net_dev_val;
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	virtual transport_type_t get_obs_transport_type() const;
	virtual flow_tuple get_flow_tuple() const;

	void	return_buffers_pool();

protected:
	ip_address 		m_dst_ip;
	uint16_t 		m_dst_port;
	uint16_t 		m_src_port;

	in_addr_t		m_bound_ip;
	in_addr_t		m_so_bindtodevice_ip;
	in_addr_t		m_route_src_ip; // source IP used to register in route manager
	in_addr_t		m_pkt_src_ip; // source IP address copied into IP header
	lock_mutex_recursive 	m_slow_path_lock;
	vma_ibv_send_wr 	m_inline_send_wqe;
	vma_ibv_send_wr 	m_not_inline_send_wqe;
	wqe_send_handler*	m_p_send_wqe_handler;
	ibv_sge 		m_sge[MCE_DEFAULT_TX_NUM_SGE];
	uint8_t 		m_num_sge;
	route_entry*		m_p_rt_entry;
	route_val*		m_p_rt_val;
	net_device_entry*	m_p_net_dev_entry;
	net_device_val*		m_p_net_dev_val;
	neigh_entry*		m_p_neigh_entry;
	neigh_val*		m_p_neigh_val;
	bool 			m_b_is_offloaded;
	bool 			m_b_force_os;
	ring*			m_p_ring;
	ring_allocation_logic_tx m_ring_alloc_logic;
	mem_buf_desc_t* 	m_p_tx_mem_buf_desc_list;
	int			m_b_tx_mem_buf_desc_list_pending;
	header 			m_header;
	header 			m_header_neigh;
	uint8_t 		m_ttl;
	uint8_t 		m_tos;
	bool 			m_b_is_initialized;

	vma_ibv_send_wr* 	m_p_send_wqe;
	uint32_t 		m_max_inline;
	ring_user_id_t 	m_id;
	size_t			m_max_ip_payload_size;

	virtual transport_t 	get_transport(sockaddr_in to) = 0;
	virtual uint8_t 	get_protocol_type() const = 0;
	virtual bool 		get_net_dev_val();
	virtual uint32_t 	get_inline_sge_num() = 0;
	virtual ibv_sge*	get_sge_lst_4_inline_send() = 0;
	virtual ibv_sge*	get_sge_lst_4_not_inline_send() = 0;

	virtual bool 		offloaded_according_to_rules();
	virtual void 		init_members();
	virtual bool 		resolve_net_dev(bool is_connect=false);
	virtual void		set_src_addr();
	bool 				update_net_dev_val();
	bool 				update_rt_val();
	virtual bool 		resolve_neigh();
	virtual bool 		resolve_ring();
	virtual bool 		release_ring();
	virtual ssize_t 	pass_buff_to_neigh(const iovec *p_iov, size_t & sz_iov, uint16_t packet_id = 0);
	virtual void 		configure_ip_header(header *h, uint16_t packet_id = 0);
	virtual void 		configure_headers() { conf_hdrs_and_snd_wqe();};
	virtual bool 		conf_hdrs_and_snd_wqe();
	virtual bool 		conf_l2_hdr_and_snd_wqe_eth();
	virtual bool 		conf_l2_hdr_and_snd_wqe_ib();
	virtual void 		init_sge() {};
	bool 			alloc_transport_dep_res();
	bool 			alloc_neigh_val(transport_type_t tranport);

	void			do_ring_migration(lock_base& socket_lock);
	inline void		set_tx_buff_list_pending(bool is_pending = true) {m_b_tx_mem_buf_desc_list_pending = is_pending;}

	inline void		send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block, bool b_dummy)
	{
		if (unlikely(b_dummy)) {
			if (m_p_ring->get_hw_dummy_send_support(id, p_send_wqe)) {
				vma_ibv_wr_opcode last_opcode = m_p_send_wqe_handler->set_opcode(*p_send_wqe, VMA_IBV_WR_NOP);
				m_p_ring->send_ring_buffer(id, p_send_wqe, b_block);
				m_p_send_wqe_handler->set_opcode(*p_send_wqe, last_opcode);
			} else {
				/* free the buffer if dummy send is not supported */
				mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
				m_p_ring->mem_buf_tx_release(p_mem_buf_desc, true);
			}
		} else {
			m_p_ring->send_ring_buffer(id, p_send_wqe, b_block);
		}
	}

};


#endif /* DST_ENTRY_H */
