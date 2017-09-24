/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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
#define MAX_MP_WQES			20 // limit max used memory
#define MIN_MP_WQES			2

enum mp_loop_result {
	MP_LOOP_DRAINED,
	MP_LOOP_LIMIT,
	MP_LOOP_RETURN_TO_APP,
};

class cq_mgr_mp;

class ring_eth_cb : public ring_eth
{
public:
	ring_eth_cb(in_addr_t local_if,
		    ring_resource_creation_info_t *p_ring_info, int count,
		    bool active, uint16_t vlan, uint32_t mtu,
		    vma_cyclic_buffer_ring_attr *mp_ring, ring *parent = NULL);
	virtual		~ring_eth_cb();
	ibv_exp_res_domain* get_res_domain() const {return m_res_domain;};
	uint32_t	get_wq_count() const {return m_wq_count;};
	void*		get_mem_block() const {return m_alloc.get_ptr();};
	uint8_t		get_single_wqe_log_num_of_strides() const {return m_single_wqe_log_num_of_strides;};
	uint32_t	get_strides_num() const {return m_strides_num;};
	uint8_t		get_single_stride_log_num_of_bytes() const {return m_single_stride_log_num_of_bytes;};
	uint32_t	get_stride_size() const {return m_stride_size;};
	uint32_t	get_mem_lkey(ib_ctx_handler* ib_ctx) const {return m_alloc.find_lkey_by_ib_ctx(ib_ctx);}
	virtual int	drain_and_proccess(cq_type_t cq_type);
	virtual int	poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	int		cyclic_buffer_read(vma_completion_cb_t &completion,
					   size_t min, size_t max, int flags);
protected:
	void		create_resources(ring_resource_creation_info_t* p_ring_info,
					 bool active);
	virtual		qp_mgr* create_qp_mgr(const ib_ctx_handler* ib_ctx,
					      uint8_t port_num,
					      struct ibv_comp_channel* p_rx_comp_event_channel);
private:
	vma_cyclic_buffer_ring_attr	m_cb_ring;
	vma_allocator			m_alloc;
	uint8_t				m_single_wqe_log_num_of_strides;
	uint8_t				m_single_stride_log_num_of_bytes;
	uint32_t			m_stride_size;
	uint32_t			m_strides_num;
	struct ibv_exp_res_domain*	m_res_domain;
	size_t				m_buffer_size;
	uint32_t			m_wq_count;
	uint32_t			m_curr_wqe_used_strides;
	uint32_t			m_all_wqes_used_strides;
	uint32_t			m_curr_batch_starting_stride;
	uint64_t			m_p_buffer_ptr;
	// These members are used to store intermediate results before
	// returning from the user's call to get the data.
	int				m_curr_wq;
	void*				m_curr_d_addr;
	void*				m_curr_h_ptr;
	size_t				m_curr_packets;
	struct timespec			m_curr_hw_timestamp;
	inline mp_loop_result		mp_loop(size_t limit);
	inline bool			reload_wq();
};

#endif /* HAVE_MP_RQ */
#endif /* SRC_VMA_DEV_RING_ETH_CB_H_ */
