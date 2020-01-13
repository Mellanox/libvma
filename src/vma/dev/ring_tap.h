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
	virtual int poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual int wait_for_notification_and_process_element(int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual int drain_and_proccess();
	virtual bool reclaim_recv_buffers(descq_t *rx_reuse);
	virtual bool reclaim_recv_buffers(mem_buf_desc_t *buff);
	virtual int reclaim_recv_single_buffer(mem_buf_desc_t* rx_reuse) { NOT_IN_USE(rx_reuse); return -1; }
	virtual void send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual mem_buf_desc_t* mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);
	virtual int mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false);
	virtual bool get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe) { NOT_IN_USE(id); NOT_IN_USE(p_send_wqe); return false; }
	virtual int request_notification(cq_type_t cq_type, uint64_t poll_sn) { NOT_IN_USE(cq_type); NOT_IN_USE(poll_sn); return 0; }
	virtual void adapt_cq_moderation() {}

	virtual int socketxtreme_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags) {
		NOT_IN_USE(vma_completions);
		NOT_IN_USE(ncompletions);
		NOT_IN_USE(flags);
		return 0;
	}

	virtual int modify_ratelimit(struct vma_rate_limit_t &rate_limit) { NOT_IN_USE(rate_limit); return 0; }
	void inc_cq_moderation_stats(size_t sz_data) { NOT_IN_USE(sz_data); }
	virtual uint32_t get_underly_qpn() { return -1; }
        virtual uint32_t get_max_inline_data() { return 0; }
#ifdef DEFINED_TSO
        virtual uint32_t get_max_send_sge(void) { return 1; }
        virtual uint32_t get_max_payload_sz(void) { return 0; }
        virtual uint16_t get_max_header_sz(void) { return 0; }
	virtual uint32_t get_tx_lkey(ring_user_id_t id) { NOT_IN_USE(id); return 0; }
        virtual bool is_tso(void) { return false; }
#endif /* DEFINED_TSO */

	inline void set_tap_data_available() { m_tap_data_available = true; }
	inline void set_vf_ring(ring_slave *p_ring) { m_vf_ring = p_ring; }
	inline void inc_vf_plugouts() { m_p_ring_stat->tap.n_vf_plugouts++; }

private:
	inline void return_to_global_pool();
	int prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action, flow_tuple& flow_spec_5t);
	int prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action);
	int process_element_rx(void* pv_fd_ready_array);
	bool request_more_rx_buffers();
	int send_buffer(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	void send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe);
	void tap_create(net_device_val* p_ndev);
	void tap_destroy();

	bool is_socketxtreme(void) { return false; }
	void put_ec(struct ring_ec *ec) { NOT_IN_USE(ec); }
	void del_ec(struct ring_ec *ec) { NOT_IN_USE(ec); }
	struct vma_completion_t *get_comp(void) { return NULL; }

	/* These fields are NETVSC mode specific */
	int              m_tap_fd; /* file descriptor of tap device */
	ring_slave*      m_vf_ring;
	const uint32_t   m_sysvar_qp_compensation_level;
	descq_t          m_rx_pool;
	bool             m_tap_data_available;
};

#endif /* RING_TAP_H_ */
