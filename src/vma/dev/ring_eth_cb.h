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

#ifndef SRC_VMA_DEV_RING_ETH_CB_H_
#define SRC_VMA_DEV_RING_ETH_CB_H_

#include <dev/ring_simple.h>
#include <dev/allocator.h>

#ifdef HAVE_MP_RQ

#define VMA_MP_RQ_BAD_PACKET		(1 << 31) // last bit

enum mp_loop_result {
	MP_LOOP_DRAINED,
	MP_LOOP_LIMIT,
	MP_LOOP_RETURN_TO_APP,
};

enum RING_CB_UMR_ALLOC_IDX {
	CB_UMR_HDR = 0,
	CB_UMR_PAYLOAD,
	CB_UMR_LAST
};

class cq_mgr_mp;

class ring_eth_cb : public ring_eth
{
public:
	ring_eth_cb(int if_index,
		    vma_cyclic_buffer_ring_attr *mp_ring, iovec *mem_sec = NULL,
		    ring *parent = NULL);
	virtual		~ring_eth_cb();
	ibv_exp_res_domain* get_res_domain() const {return m_res_domain;};
	uint32_t	get_wq_count() const {return m_wq_count;};
	uint8_t		get_single_wqe_log_num_of_strides() const {return m_single_wqe_log_num_of_strides;};
	uint32_t	get_strides_num() const {return m_strides_num;};
	uint8_t		get_single_stride_log_num_of_bytes() const {return m_single_stride_log_num_of_bytes;};
	uint32_t	get_stride_size() const {return m_stride_size;};
	uint32_t	get_mem_lkey(ib_ctx_handler* ib_ctx) const {return m_alloc.find_lkey_by_ib_ctx(ib_ctx);}
	virtual int	drain_and_proccess();
	virtual int	poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	int		get_mem_info(ibv_sge &mem_info);
	int		cyclic_buffer_read(vma_completion_cb_t &completion,
					   size_t min, size_t max, int flags);
	void*		allocate_memory(iovec *mem_desc, size_t buffer_size);
protected:
	virtual		qp_mgr* create_qp_mgr(const ib_ctx_handler* ib_ctx,
					      uint8_t port_num,
					      struct ibv_comp_channel* p_rx_comp_event_channel);
private:
	uint32_t			m_curr_wqe_used_strides;
	size_t				m_curr_packets;
	uint32_t			m_padd_mode_used_strides;
	uint16_t			m_packet_size;
	// These members are used to store intermediate results before
	// returning from the user's call to get the data.
	uint32_t			m_strides_num;
	uint32_t			m_stride_size;
	uint32_t			m_all_wqes_used_strides;
	uint8_t				m_single_wqe_log_num_of_strides;
	uint8_t				m_single_stride_log_num_of_bytes;
	vma_cb_packet_rec_mode		m_packet_receive_mode;
	uint16_t			m_wq_count;
	uint16_t			m_curr_wq;
	void*				m_curr_payload_addr;
	void*				m_curr_hdr_ptr;
	uint64_t			m_sge_ptrs[CB_UMR_LAST];
	uint16_t			m_hdr_len; // calculate user header offset in buffer
	uint16_t			m_payload_len; // calculate payload offset in buffer
	ibv_sge				m_buff_data;
	struct timespec			m_curr_hw_timestamp;
	vma_allocator			m_alloc;
	vma_allocator			m_dump_mr;
	struct ibv_exp_send_wr		m_umr_wr;
	struct ibv_exp_res_domain*	m_res_domain;
	struct ibv_mr*			m_p_umr_mr;
	bool				m_external_mem;
	inline mp_loop_result		mp_loop(size_t limit);
	inline mp_loop_result		mp_loop_padded(size_t limit);
	inline bool			reload_wq();
	int				allocate_umr_mem(vma_cyclic_buffer_ring_attr *cb_ring,
							 iovec *mem_desc, uint16_t net_len);
	void				remove_umr_res();
};

#endif /* HAVE_MP_RQ */
#endif /* SRC_VMA_DEV_RING_ETH_CB_H_ */
