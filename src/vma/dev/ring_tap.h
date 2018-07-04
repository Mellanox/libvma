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

	virtual int request_notification(cq_type_t, uint64_t) { return 0; }
	virtual int modify_ratelimit(struct vma_rate_limit_t &) { return 0; }
	virtual int get_max_tx_inline() { return 0; }
	virtual int poll_and_process_element_rx(uint64_t* , void* pv_fd_ready_array = NULL) { return process_element_rx(pv_fd_ready_array); };
	virtual int wait_for_notification_and_process_element(int, uint64_t*, void* pv_fd_ready_array = NULL) { return process_element_rx(pv_fd_ready_array); }
	virtual int drain_and_proccess() { return process_element_rx(NULL); }
	virtual int mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false);
	virtual bool is_ratelimit_supported(struct vma_rate_limit_t &) { return false; }
	virtual bool is_up() { return (m_vf_ring || m_active); }
	virtual bool attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual bool detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual bool reclaim_recv_buffers(descq_t *rx_reuse);
	virtual bool reclaim_recv_buffers(mem_buf_desc_t *buff);
	virtual bool get_hw_dummy_send_support(ring_user_id_t, vma_ibv_send_wr*) { return false; }
	virtual void send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual void inc_cq_moderation(size_t) {}
	virtual void adapt_cq_moderation() {}
	virtual uint32_t get_underly_qpn() { return -1; }
	virtual mem_buf_desc_t* mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);

#ifdef DEFINED_SOCKETXTREME
	virtual int socketxtreme_poll(struct vma_completion_t *, unsigned int, int) { return 0; }
#endif // DEFINED_SOCKETXTREME

	inline void set_tap_data_available() { m_tap_data_available = true; }
	inline void set_vf_ring(ring_slave *p_ring) { m_vf_ring = p_ring; }
	inline void inc_vf_plugouts() { m_p_ring_stat->tap.n_vf_plugouts++; }
	inline ring_slave* get_vf_ring() { return m_vf_ring; }

private:
	inline void return_to_global_pool();
	void prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action, flow_tuple& flow_spec_5t);
	void prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action);
	void send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe);
	void tap_create(net_device_val* p_ndev);
	void tap_destroy();
	int process_element_rx(void* pv_fd_ready_array);
	int send_buffer(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);

	/* These fields are NETVSC mode specific */
	int m_tap_fd;                    /* file descriptor of tap device */
	ring_slave*      m_vf_ring;
	const uint32_t   m_sysvar_qp_compensation_level;
	descq_t          m_rx_pool;
	bool             m_tap_data_available;
};


#endif /* RING_TAP_H_ */
