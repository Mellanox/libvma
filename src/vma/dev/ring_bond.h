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

#ifndef RING_BOND_H
#define RING_BOND_H

#include "ring.h"

#include "vma/dev/ring_tap.h"
#include "vma/dev/net_device_table_mgr.h"

typedef std::vector<ring_slave*> ring_slave_vector_t;

struct flow_sink_t {
	flow_tuple flow;
	pkt_rcvr_sink *sink;
};

class ring_bond : public ring {

public:
	ring_bond(int if_index);
	virtual	~ring_bond();

	virtual void print_val();

	virtual int		request_notification(cq_type_t cq_type, uint64_t poll_sn);
	virtual int		poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual void		adapt_cq_moderation();
	virtual bool		reclaim_recv_buffers(descq_t *rx_reuse);
	virtual bool		reclaim_recv_buffers(mem_buf_desc_t* rx_reuse_lst);
	virtual int		drain_and_proccess();
	virtual int		wait_for_notification_and_process_element(int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual int		get_num_resources() const { return m_bond_rings.size(); };
	virtual bool		attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual bool		detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual void		restart();
	virtual mem_buf_desc_t* mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);
	virtual int		mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false);
	virtual void		inc_tx_retransmissions_stats(ring_user_id_t id);
	virtual void		send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void		send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void		mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual bool		is_member(ring_slave* rng);
	virtual bool		is_active_member(ring_slave* rng, ring_user_id_t id);
	virtual ring_user_id_t	generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
	virtual bool 		get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe);
	virtual int		modify_ratelimit(struct vma_rate_limit_t &rate_limit);
        virtual uint32_t	get_max_inline_data();
#ifdef DEFINED_TSO
        virtual uint32_t	get_max_send_sge(void);
        virtual uint32_t	get_max_payload_sz(void);
        virtual uint16_t	get_max_header_sz(void);
	virtual uint32_t        get_tx_lkey(ring_user_id_t id) { return m_bond_rings[id]->get_tx_lkey(id); }
        virtual bool		is_tso(void);
#endif /* DEFINED_TSO */
	int 			socketxtreme_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags);
	virtual void    slave_create(int if_index) = 0;
	virtual void    slave_destroy(int if_index);
protected:
	void			update_cap(ring_slave *slave = NULL);
	void			update_rx_channel_fds();
	void			popup_active_rings();

	ring_slave_vector_t     m_bond_rings;
	std::vector<struct flow_sink_t> m_rx_flows;
        uint32_t    m_max_inline_data;
#ifdef DEFINED_TSO
        uint32_t    m_max_send_sge;
#endif /* DEFINED_TSO */

private:
	void devide_buffers_helper(descq_t *rx_reuse, descq_t *buffer_per_ring);
	int devide_buffers_helper(mem_buf_desc_t *p_mem_buf_desc_list, mem_buf_desc_t** buffer_per_ring);

	bool is_socketxtreme(void) { return false; }
	void put_ec(struct ring_ec *ec) { NOT_IN_USE(ec); }
	void del_ec(struct ring_ec *ec) { NOT_IN_USE(ec); }
	struct vma_completion_t *get_comp(void) { return NULL; }

	net_device_val::bond_type m_type;
	net_device_val::bond_xmit_hash_policy m_xmit_hash_policy;
	lock_mutex_recursive	m_lock_ring_rx;
	lock_mutex_recursive	m_lock_ring_tx;
};

class ring_bond_eth : public ring_bond
{
public:
	ring_bond_eth(int if_index):
		ring_bond(if_index) {
		net_device_val* p_ndev =
				g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
		if (p_ndev) {
			const slave_data_vector_t& slaves = p_ndev->get_slave_array();
			update_cap();
			for (size_t i = 0; i < slaves.size(); i++) {
				slave_create(slaves[i]->if_index);
			}
		}
	}

protected:
	virtual void slave_create(int if_index);
};

class ring_bond_ib : public ring_bond
{
public:
	ring_bond_ib(int if_index):
		ring_bond(if_index) {
		net_device_val* p_ndev =
				g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
		if (p_ndev) {
			const slave_data_vector_t& slaves = p_ndev->get_slave_array();
			update_cap();
			for (size_t i = 0; i < slaves.size(); i++) {
				slave_create(slaves[i]->if_index);
			}
		}
	}

protected:
	virtual void slave_create(int if_index);
};

class ring_bond_netvsc : public ring_bond
{
public:
	ring_bond_netvsc(int if_index):
		ring_bond(if_index) {
		net_device_val* p_ndev =
				g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());

		m_vf_ring = NULL;
		m_tap_ring = NULL;
		if (p_ndev) {
			const slave_data_vector_t& slaves = p_ndev->get_slave_array();
			update_cap();
			slave_create(p_ndev->get_if_idx());
			for (size_t i = 0; i < slaves.size(); i++) {
				slave_create(slaves[i]->if_index);
			}

			if (m_tap_ring && m_vf_ring) {
				ring_tap* p_ring_tap = dynamic_cast<ring_tap*>(m_tap_ring);
				if (p_ring_tap) {
					p_ring_tap->set_vf_ring(m_vf_ring);
				}
			}
		}
	}

protected:
	virtual void slave_create(int if_index);

public:
	ring_slave*      m_vf_ring;
	ring_slave*      m_tap_ring;
};

#endif /* RING_BOND_H */
