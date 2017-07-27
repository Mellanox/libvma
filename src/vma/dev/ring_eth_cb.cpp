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

#include <dev/ring_eth_cb.h>
#include <dev/qp_mgr_mp.h>
#include <dev/cq_mgr_mp.h>

#undef  MODULE_NAME
#define MODULE_NAME		"ring_eth_cb"
#undef  MODULE_HDR
#define MODULE_HDR		MODULE_NAME "%d:%s() "


#ifdef HAVE_MP_RQ

ring_eth_cb::ring_eth_cb(in_addr_t local_if,
			 ring_resource_creation_info_t *p_ring_info, int count,
			 bool active, uint16_t vlan, uint32_t mtu,
			 vma_cyclic_buffer_ring_attr *cb_ring, ring *parent) throw (vma_error) :
			 ring_eth(local_if, p_ring_info, count, active, vlan,
				  mtu, parent, false)
			,m_cb_ring(*cb_ring)
			,m_res_domain(NULL)
			,m_curr_wqe_used_strides(0)
			,m_all_wqes_used_strides(0)
			,m_curr_batch_starting_stride(0)
			,m_curr_wq(0)
			,m_curr_d_addr(NULL)
			,m_curr_h_ptr(NULL)
			,m_curr_packets(0)
{
	// call function from derived not base
	create_resources(p_ring_info, active);
}

void ring_eth_cb::create_resources(ring_resource_creation_info_t *p_ring_info,
				   bool active) throw (vma_error)
{
	struct ibv_exp_res_domain_init_attr res_domain_attr;

	// check MP capabilities currently all caps are 0 due to a buf
	vma_ibv_device_attr& r_ibv_dev_attr =
			p_ring_info->p_ib_ctx->get_ibv_device_attr();

	if (!r_ibv_dev_attr.max_ctx_res_domain) {
		ring_logdbg("device doesn't support resource domain");
		throw_vma_exception("device doesn't support resource domain");
	}

	struct ibv_exp_mp_rq_caps *mp_rq_caps = &r_ibv_dev_attr.mp_rq_caps;
	if (!(mp_rq_caps->supported_qps & IBV_EXP_QPT_RAW_PACKET)) {
		ring_logdbg("mp_rq is not supported");
		throw_vma_exception("device doesn't support RC QP");
	}

	res_domain_attr.comp_mask = IBV_EXP_RES_DOMAIN_THREAD_MODEL |
				    IBV_EXP_RES_DOMAIN_MSG_MODEL;

	// driver is in charge of locks
	res_domain_attr.thread_model = IBV_EXP_THREAD_SAFE;

	// currently have no affect
	res_domain_attr.msg_model = IBV_EXP_MSG_HIGH_BW;

	m_res_domain = ibv_exp_create_res_domain(
				p_ring_info->p_ib_ctx->get_ibv_context(),
				&res_domain_attr);
	if (!m_res_domain) {
		ring_logdbg("could not create resource domain");
		throw_vma_exception("failed creating resource domain");
	}
	// stride size is headers + user payload aligned to power of 2
	m_single_stride_log_num_of_bytes = ilog_2(align32pow2(
			m_cb_ring.stride_bytes +
			ETH_HDR_LEN + sizeof(struct iphdr) + sizeof(struct udphdr)));
	if (m_single_stride_log_num_of_bytes < mp_rq_caps->min_single_stride_log_num_of_bytes) {
		m_single_stride_log_num_of_bytes = mp_rq_caps->min_single_stride_log_num_of_bytes;
	}
	if (m_single_stride_log_num_of_bytes > mp_rq_caps->max_single_stride_log_num_of_bytes) {
		m_single_stride_log_num_of_bytes = mp_rq_caps->max_single_stride_log_num_of_bytes;
	}
	m_stride_size = 1 << m_single_stride_log_num_of_bytes;
	uint32_t max_wqe_size = 1 << mp_rq_caps->max_single_wqe_log_num_of_strides;
	uint32_t user_req_wq = m_cb_ring.num / max_wqe_size;
	if (user_req_wq > 2) {
		m_wq_count = min<uint32_t>(user_req_wq, MAX_MP_WQES);
		m_single_wqe_log_num_of_strides = mp_rq_caps->max_single_wqe_log_num_of_strides;
	} else {
		m_wq_count = MIN_MP_WQES;
		m_single_wqe_log_num_of_strides = ilog_2(align32pow2(m_cb_ring.num) / m_wq_count);
		if (m_single_wqe_log_num_of_strides < mp_rq_caps->min_single_wqe_log_num_of_strides) {
			m_single_wqe_log_num_of_strides = mp_rq_caps->min_single_wqe_log_num_of_strides;
		}
	}
	m_strides_num = 1 << m_single_wqe_log_num_of_strides;
	m_buffer_size = m_stride_size * m_strides_num * m_wq_count;
	if (m_buffer_size == 0) {
		ring_logerr("problem with buffer parameters, m_buffer_size %zd "
			    "strides_num %d stride size %d",
			    m_buffer_size, m_strides_num, m_stride_size);
		throw_vma_exception("bad cyclic buffer parameters");
	}
	memset(&m_curr_hw_timestamp, 0, sizeof(m_curr_hw_timestamp));

	// create cyclic buffer get exception on failure
	m_p_buffer_ptr = (uint64_t)(uintptr_t)m_alloc.alloc_and_reg_mr(m_buffer_size, p_ring_info->p_ib_ctx);
	ring_simple::create_resources(p_ring_info, active);
	m_is_mp_ring = true;
	ring_logdbg("use buffer parameters, m_buffer_size %zd "
		    "strides_num %d stride size %d",
		    m_buffer_size, m_strides_num, m_stride_size);
}

qp_mgr* ring_eth_cb::create_qp_mgr(const ib_ctx_handler *ib_ctx,
				   uint8_t port_num,
				   struct ibv_comp_channel *p_rx_comp_event_channel) throw (vma_error)
{
	return new qp_mgr_mp(this, ib_ctx, port_num, p_rx_comp_event_channel,
			get_tx_num_wr(), get_partition());
}

int ring_eth_cb::drain_and_proccess(cq_type_t cq_type)
{
	NOT_IN_USE(cq_type);
	return 0;
}

int ring_eth_cb::poll_and_process_element_rx(uint64_t* p_cq_poll_sn,
					     void* pv_fd_ready_array)
{
	NOT_IN_USE(p_cq_poll_sn);
	NOT_IN_USE(pv_fd_ready_array);
	return 0;
}

/**
 * loop poll_cq
 * @param limit
 * @return TBD about -1 on error,
 * 	0 if cq is empty
 * 	1 if done looping
 * 	2 if need to return due to WQ or filler
 */
inline mp_loop_result ring_eth_cb::mp_loop(size_t limit)
{
	volatile struct mlx5_cqe64 *cqe64;
	uint16_t size = 0;
	uint32_t flags = 0;

	while (m_curr_packets < limit) {
		int ret = ((cq_mgr_mp *)m_p_cq_mgr_rx)->poll_mp_cq(size, m_curr_wqe_used_strides,
								   flags, cqe64);
		if (size == 0) {
			ring_logfine("no packet found");
			return MP_LOOP_DRAINED;
		}
		if (unlikely(ret == -1)) {
			ring_logdbg("poll_mp_cq failed with errno %m", errno);
			return MP_LOOP_RETURN_TO_APP;
		}

		if (unlikely(flags & VMA_MP_RQ_BAD_PACKET)) {
			if (m_curr_wqe_used_strides >= m_strides_num) {
				reload_wq();
			}
			return MP_LOOP_RETURN_TO_APP;
		}
		m_p_ring_stat->n_rx_pkt_count++;
		m_p_ring_stat->n_rx_byte_count += size;
		++m_curr_packets;
		if (unlikely(m_curr_wqe_used_strides >= m_strides_num)) {
			if (reload_wq()) {
				return MP_LOOP_RETURN_TO_APP;
			}
		}
	}
	ring_logfine("mp_loop finished all iterations");
	return MP_LOOP_LIMIT;
}

/*
 *  all WQE are contagious in memory so we need to return to the user
 *  true if last WQE was posted so we're at the end of the buffer
 *
 */
inline bool ring_eth_cb::reload_wq()
{
	// in current implementation after each WQe is used by the HW
	// the ring reloads it to the HW again that why 1 is used
	((cq_mgr_mp *)m_p_cq_mgr_rx)->update_dbell();
	((qp_mgr_mp *)m_p_qp_mgr)->post_recv(m_curr_wq, 1);
	m_curr_wq = (m_curr_wq + 1) % m_wq_count;
	m_curr_wqe_used_strides = 0;
	if (m_curr_wq == 0) {
		m_all_wqes_used_strides = 0;
		return true;
	}
	m_all_wqes_used_strides += m_strides_num;
	return false;
}

int ring_eth_cb::cyclic_buffer_read(vma_completion_cb_t &completion,
				    size_t min, size_t max, int flags)
{
	uint32_t poll_flags = 0;
	uint16_t size;
	volatile struct mlx5_cqe64 *cqe64;

	// sanity check
	if (unlikely(min > max || max == 0 || flags != MSG_DONTWAIT)) {
		errno = EINVAL;
		ring_logdbg("Illegal values, got min: %d, max: %d, flags %d",
			    min, max, flags);
		if (flags != MSG_DONTWAIT) {
			ring_logdbg("only %d flag is currently supported",
				    MSG_DONTWAIT);
		}
		return -1;
	}
	if (!m_curr_batch_starting_stride) {
		m_curr_batch_starting_stride = m_curr_wqe_used_strides;
	}
	int ret = ((cq_mgr_mp *)m_p_cq_mgr_rx)->poll_mp_cq(size,
					m_curr_wqe_used_strides, poll_flags, cqe64);
	// empty
	if (size == 0) {
		return 0;
	}
	if (unlikely(ret == -1)) {
		m_curr_batch_starting_stride = 0;
		ring_logdbg("poll_mp_cq failed with errno %m", errno);
		return -1;
	}
	m_p_ring_stat->n_rx_pkt_count++;
	m_p_ring_stat->n_rx_byte_count += size;
	// set it here because we might not have min packets avail in this run
	if (likely(!(poll_flags & VMA_MP_RQ_BAD_PACKET))) {
		if (unlikely(m_curr_d_addr == 0)) {
			// user data is located at:
			// (the beginning of allocated memory +
			// stride_size * (number of strides in preceding WQE (e.g. first WQe that was already reposted) +
			//                number of used strides in current WQE before the poll_mp_cq call)
			m_curr_d_addr = (void *)(m_p_buffer_ptr +
					m_stride_size * (m_all_wqes_used_strides + m_curr_batch_starting_stride));
			if (completion.comp_mask & VMA_MP_MASK_TIMESTAMP) {
				convert_hw_time_to_system_time(ntohll(cqe64->timestamp),
							       &m_curr_hw_timestamp);
			}
			// When UMR will be added this will be different
			m_curr_h_ptr = m_curr_d_addr;
			m_curr_packets = 1;
		} else {
			m_curr_packets++;
		}
		bool return_to_app = false;
		if (unlikely(m_curr_wqe_used_strides >= m_strides_num)) {
			return_to_app = reload_wq();
		}
		if (!return_to_app) {
			ret = mp_loop(min);
			if (ret == MP_LOOP_LIMIT) { // there might be more to drain
				mp_loop(max);
			} else if (ret == MP_LOOP_DRAINED) { // no packets left
				((cq_mgr_mp *)m_p_cq_mgr_rx)->update_max_drain(m_curr_packets);
				return 0;
			}
		}
	}
	((cq_mgr_mp *)m_p_cq_mgr_rx)->update_max_drain(m_curr_packets);
	m_curr_batch_starting_stride = m_curr_wqe_used_strides - m_curr_batch_starting_stride;
	completion.payload_ptr = m_curr_d_addr;
	completion.payload_length = m_curr_batch_starting_stride * m_stride_size;
	completion.packets = m_curr_packets;
	if (completion.comp_mask & VMA_MP_MASK_HDR_PTR) {
		completion.headers_ptr = m_curr_h_ptr;
		completion.headers_ptr_length = completion.payload_length;
	}
	// hw_timestamp of first packet in batch
	completion.hw_timestamp = m_curr_hw_timestamp;
	m_curr_d_addr = 0;
	m_curr_batch_starting_stride = 0;
	ring_logdbg("Returning completion, buffer ptr %p, data size %zd, "
		    "number of packets %zd WQ index %d",
		    completion.payload_ptr, completion.payload_length,
		    m_curr_packets, m_curr_wq);
	return 0;
}

ring_eth_cb::~ring_eth_cb()
{
	struct ibv_exp_destroy_res_domain_attr attr;

	memset(&attr, 0, sizeof(attr));
	int res = ibv_exp_destroy_res_domain(
			m_p_qp_mgr->get_ib_ctx_handler()->get_ibv_context(),
			m_res_domain,
			&attr);
	if (res)
		ring_logdbg("call to ibv_exp_destroy_res_domain returned %d", res);
	m_lock_ring_rx.lock();
	flow_udp_uc_del_all();
	flow_udp_mc_del_all();
	flow_tcp_del_all();
	m_lock_ring_rx.unlock();

	// explicitly destroy the qp and cq before this destructor finshes
	// since it will release the memory allocated
	delete m_p_qp_mgr;
	m_p_qp_mgr = NULL;

}
#endif /* HAVE_MP_RQ */

