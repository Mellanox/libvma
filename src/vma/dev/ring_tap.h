/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef RING_TAP_H_
#define RING_TAP_H_

#include "ring_slave.h"
#include "vma/util/agent.h"


class ring_tap : public ring_slave
{
public:
	ring_tap(int if_index, ring* parent);
	virtual ~ring_tap();

	virtual bool is_up() { return (m_vf_ring || m_active); }

	virtual bool attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual bool detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);

	virtual int poll_and_process_element_rx(uint64_t* p_cq_poll_sn,
			void* pv_fd_ready_array = NULL);
	virtual int wait_for_notification_and_process_element(int cq_channel_fd,
			uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual int drain_and_proccess();
	virtual bool reclaim_recv_buffers(descq_t *rx_reuse);
	virtual bool reclaim_recv_buffers(mem_buf_desc_t *buff);
	virtual bool rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array);

	virtual void send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual mem_buf_desc_t* mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);
	virtual int mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false);

	virtual void mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc) {
		NOT_IN_USE(p_rx_wc_buf_desc);
	}
	virtual void mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc) {
		NOT_IN_USE(p_tx_wc_buf_desc);
	}
	virtual void mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc,
			void* pv_fd_ready_array = NULL) {
		NOT_IN_USE(p_mem_buf_desc);
		NOT_IN_USE(pv_fd_ready_array);
	}
	virtual void mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual bool get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe) {
		NOT_IN_USE(id);
		NOT_IN_USE(p_send_wqe);
		return false;
	}

	virtual int request_notification(cq_type_t cq_type, uint64_t poll_sn) {
		NOT_IN_USE(cq_type);
		NOT_IN_USE(poll_sn);
		return 0;
	}
	virtual void adapt_cq_moderation() {}

#ifdef DEFINED_SOCKETXTREME
	virtual int socketxtreme_poll(struct vma_completion_t *vma_completions,
			unsigned int ncompletions, int flags) {
		NOT_IN_USE(vma_completions);
		NOT_IN_USE(ncompletions);
		NOT_IN_USE(flags);
		return 0;
	}
#endif // DEFINED_SOCKETXTREME

	virtual int modify_ratelimit(struct vma_rate_limit_t &rate_limit) {
		NOT_IN_USE(rate_limit);
		return 0;
	}
	virtual bool is_ratelimit_supported(struct vma_rate_limit_t &rate_limit) {
		NOT_IN_USE(rate_limit);
		return false;
	}
	virtual int get_max_tx_inline() { return 0; }

	inline void set_tap_data_available() { m_tap_data_available = true; }
	inline void set_vf_ring(ring_slave *p_ring) { m_vf_ring = p_ring; }
	inline void inc_vf_plugouts() { m_p_ring_stat->tap.n_vf_plugouts++; }
	inline ring_slave* get_vf_ring() { return m_vf_ring; }

private:
	inline void return_to_global_pool();
	void prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action,
			flow_tuple& flow_spec_5t);
	void prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action);
	int process_element_rx(void* pv_fd_ready_array);
	bool request_more_tx_buffers();
	bool request_more_rx_buffers();
	int send_buffer(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	void send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe);
	void flow_udp_del_all();
	void flow_tcp_del_all();
	void tap_create(net_device_val* p_ndev);
	void tap_destroy();

	/* These fields are NETVSC mode specific */
	int m_tap_fd;                    /* file descriptor of tap device */

	ring_slave*      m_vf_ring;
	const uint32_t   m_sysvar_qp_compensation_level;
	descq_t          m_tx_pool;
	descq_t          m_rx_pool;
	bool             m_tap_data_available;
	lock_spin_recursive	m_lock_ring_rx;
	lock_spin_recursive	m_lock_ring_tx;

	bool             m_flow_tag_enabled;
	in_addr_t        m_local_if;
	uint32_t         m_mtu;
	uint16_t         m_partition;
	// For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
	// It means that for every MC group, even if we have sockets with different ports - only one rule in the HW.
	// So the hash map below keeps track of the number of sockets per rule so we know when to call ibv_attach and ibv_detach
	rule_filter_map_t	m_l2_mc_ip_attach_map;
	rule_filter_map_t	m_tcp_dst_port_attach_map;
	flow_spec_tcp_map_t	m_flow_tcp_map;
	flow_spec_udp_map_t	m_flow_udp_mc_map;
	flow_spec_udp_map_t	m_flow_udp_uc_map;
};


#endif /* RING_TAP_H_ */
