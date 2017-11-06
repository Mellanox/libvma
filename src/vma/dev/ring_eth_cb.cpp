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
			 vma_cyclic_buffer_ring_attr *cb_ring, ring *parent):
			 ring_eth(local_if, p_ring_info, count, active, vlan,
				  mtu, parent, false)
			,m_cb_ring(*cb_ring)
			,m_res_domain(NULL)
			,m_curr_wqe_used_strides(0)
			,m_all_wqes_used_strides(0)
			,m_curr_wq(0)
			,m_curr_payload_addr(NULL)
			,m_curr_hdr_ptr(NULL)
			,m_curr_packets(0)
{
	// call function from derived not base
	memset(m_sge_ptrs, 0, sizeof(m_sge_ptrs));
	create_resources(p_ring_info, active);
}

void ring_eth_cb::create_resources(ring_resource_creation_info_t *p_ring_info,
				   bool active)
{
	struct ibv_exp_res_domain_init_attr res_domain_attr;

	// check MP capabilities currently all caps are 0 due to a buf
	vma_ibv_device_attr* r_ibv_dev_attr = m_p_ib_ctx->get_ibv_device_attr();

	if (!r_ibv_dev_attr->max_ctx_res_domain) {
		ring_logdbg("device doesn't support resource domain");
		throw_vma_exception("device doesn't support resource domain");
	}

	struct ibv_exp_mp_rq_caps *mp_rq_caps = &r_ibv_dev_attr->mp_rq_caps;
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

	m_res_domain = ibv_exp_create_res_domain(m_p_ib_ctx->get_ibv_context(),
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
	memset(&m_curr_hw_timestamp, 0, sizeof(m_curr_hw_timestamp));
	if (allocate_umr_mem()) {
		ring_logerr("failed creating UMR QP");
		throw_vma_exception("failed creating UMR QP");
	}
	ring_simple::create_resources(p_ring_info, active);
	m_is_mp_ring = true;
}

qp_mgr* ring_eth_cb::create_qp_mgr(const ib_ctx_handler *ib_ctx,
				   uint8_t port_num,
				   struct ibv_comp_channel *p_rx_comp_event_channel)
{
	return new qp_mgr_mp(this, ib_ctx, port_num, p_rx_comp_event_channel,
			get_tx_num_wr(), get_partition(), m_p_umr_mr);
}

/**
 * allocate and set UMR addresses
 * @return 0 on success -1 on failure
 * @note when using UMR memory appears in VMA as follows
 * +----------------------------+
 * |	WQE0 network headers	|
 * |	WQE1 network headers	|
 * |	...			|
 * |	WQE0 user headers	|
 * |	WQE1 user headers	|
 * |	...			|
 * |	WQE0 payload		|
 * |	WQE1 payload		|
 * |	...			|
 * |	WQE0 padding		|
 * |	WQE1 padding		|
 * |	...			|
 * +----------------------------+
 */
int ring_eth_cb::allocate_umr_mem()
{
	ibv_exp_create_mr_in mrin;
	ibv_mr* mr = NULL;
	size_t curr_data_len = 0, packet_len, pad_len, net_len, buffer_size;
	size_t packets_num = m_strides_num * m_wq_count;
	uint64_t base_ptr, prev_addr;
	int index = 0, count = 1, pack_written_size;
	const int ndim = 1; // we only use one dimension see UMR docs

	// the min mr is two one for padding and one for data
	m_umr_blocks = 2;
	if ((m_cb_ring.comp_mask & VMA_CB_HDR_BYTE) && m_cb_ring.hdr_bytes &&
	    m_cb_ring.packet_receive_mode == RAW_PACKET) {
		ring_logwarn("bad parameters!, you cannot choose "
			     "RAW_PACKET and define user header "
			     "the header\n");
		return -1;
	}

	if (m_cb_ring.packet_receive_mode != RAW_PACKET) {
		m_umr_blocks++; // add user_hd\netwrok_hdr
		if ((m_cb_ring.comp_mask & VMA_CB_HDR_BYTE) &&
		    m_cb_ring.hdr_bytes && m_cb_ring.packet_receive_mode == STRIP_NETWORK_HDRS) {
			m_umr_blocks++; // strip network hdr
		}
	}

	m_p_mem_rep_list = new ibv_exp_mem_repeat_block[m_umr_blocks];
	if (!m_p_mem_rep_list) {
		ring_logdbg("Failed to allocate rep_list\n");
		return -1;
	}

	for (int i = 0; i < m_umr_blocks; i++) {
		m_p_mem_rep_list[i].byte_count = new size_t[ndim];
		if (!m_p_mem_rep_list[i].byte_count) {
			ring_logdbg("Failed to allocate byte_count\n");
			goto cleanup;
		}
		m_p_mem_rep_list[i].stride = new size_t[ndim];
		if (!m_p_mem_rep_list[i].stride) {
			ring_logdbg("Failed to allocate stride\n");
			goto cleanup;
		}

	}
	m_p_rpt_cnt = new size_t[ndim];
	if (!m_p_rpt_cnt) {
		ring_logdbg("Failed to allocate rpt_cnt\n");
		goto cleanup;
	}

	m_p_rpt_cnt[ndim - 1] = packets_num;
	if (get_partition()) {
		net_len = ETH_VLAN_HDR_LEN + sizeof(struct iphdr) + sizeof(struct udphdr);
	} else {
		net_len = ETH_HDR_LEN + sizeof(struct iphdr) + sizeof(struct udphdr);
	}

	m_payload_len = m_cb_ring.stride_bytes;
	m_hdr_len = m_cb_ring.hdr_bytes;
	// in case stride smaller then packet size
	while ((m_stride_size * count) <= m_payload_len) {
		++count;
	}

	pad_len = (m_stride_size * count) - net_len - m_hdr_len - m_payload_len;
	// no need to allocate all padding add one so starting address will be valid
	pack_written_size = (m_stride_size * count) - pad_len + 1;
	// allocate buffer
	buffer_size = pack_written_size * packets_num;
	base_ptr = (uint64_t)m_alloc.alloc_and_reg_mr(buffer_size, m_p_ib_ctx);
	ring_logdbg("use buffer parameters, buffer_size %zd "
		    "strides_num %d stride size %d",
		    buffer_size, m_strides_num, m_stride_size);
	prev_addr = base_ptr;
	mr = m_alloc.find_ibv_mr_by_ib_ctx(m_p_ib_ctx);
	if (unlikely(mr == NULL)) {
		ring_logerr("could not find mr");
		return -1;
	}
	packet_len = net_len;
	switch (m_cb_ring.packet_receive_mode) {
		case RAW_PACKET:
			packet_len += m_payload_len;
			// for size calculation in read_cyclic
			m_payload_len = packet_len;
			m_sge_ptrs[CB_UMR_PAYLOAD] = base_ptr;
			m_p_mem_rep_list[index].base_addr = base_ptr;
			m_p_mem_rep_list[index].byte_count[0] = packet_len;
			m_p_mem_rep_list[index].stride[0] = packet_len;
			m_p_mem_rep_list[index].mr = mr;
			curr_data_len = packets_num * packet_len;
			prev_addr += curr_data_len;
			index++;
		break;
		case STRIP_NETWORK_HDRS:
			// network not accessible to application
			m_p_mem_rep_list[index].base_addr = base_ptr;
			m_p_mem_rep_list[index].byte_count[0] = net_len;
			// optimize write header to the same place
			m_p_mem_rep_list[index].stride[0] = 0;
			m_p_mem_rep_list[index].mr = mr;
			curr_data_len = packets_num * net_len;
			prev_addr += curr_data_len;
			index++;
			if (m_hdr_len) {
				m_p_mem_rep_list[index].base_addr = prev_addr;
				m_p_mem_rep_list[index].byte_count[0] = m_hdr_len;
				m_p_mem_rep_list[index].stride[0] = m_hdr_len;
				m_p_mem_rep_list[index].mr = mr;
				m_sge_ptrs[CB_UMR_HDR] = prev_addr;
				curr_data_len = packets_num * m_hdr_len;
				prev_addr += curr_data_len;
				index++;
			}
			m_p_mem_rep_list[index].base_addr = prev_addr;
			m_p_mem_rep_list[index].byte_count[0] = m_payload_len;
			m_p_mem_rep_list[index].stride[0] = m_payload_len;
			m_p_mem_rep_list[index].mr = mr;
			m_sge_ptrs[CB_UMR_PAYLOAD] = prev_addr;
			curr_data_len = packets_num * m_payload_len;
			prev_addr += curr_data_len;
			index++;
		break;
		case SEPERATE_NETWORK_HDRS:
			if (m_hdr_len) {
				packet_len += m_hdr_len;
				// for size calculation in read_cyclic
				m_hdr_len = packet_len;
			} else {
				m_hdr_len = net_len;
			}
			m_p_mem_rep_list[index].base_addr = base_ptr;
			m_p_mem_rep_list[index].byte_count[0] = packet_len;
			m_p_mem_rep_list[index].stride[0] = packet_len;
			m_p_mem_rep_list[index].mr = mr;
			m_sge_ptrs[CB_UMR_HDR] = base_ptr;
			curr_data_len = packets_num * packet_len;
			prev_addr += curr_data_len;
			index++;
			m_p_mem_rep_list[index].base_addr = prev_addr;
			m_p_mem_rep_list[index].byte_count[0] = m_payload_len;
			m_p_mem_rep_list[index].stride[0] = m_payload_len;
			m_p_mem_rep_list[index].mr = mr;
			m_sge_ptrs[CB_UMR_PAYLOAD] = prev_addr;
			curr_data_len = packets_num * m_payload_len;
			prev_addr += curr_data_len;
			index++;
			break;
		default:
			ring_logpanic("bad packet_receive_mode\n");
	}

	m_p_mem_rep_list[index].base_addr = prev_addr;
	m_p_mem_rep_list[index].byte_count[0] = pad_len;
	m_p_mem_rep_list[index].stride[0] = pad_len;
	m_p_mem_rep_list[index].mr = mr;

	// allocate empty lkey
	memset(&mrin, 0, sizeof(mrin));
	mrin.pd = m_p_ib_ctx->get_ibv_pd();
	mrin.attr.create_flags = IBV_EXP_MR_INDIRECT_KLMS;
	mrin.attr.exp_access_flags = IBV_EXP_ACCESS_LOCAL_WRITE;
	mrin.attr.max_klm_list_size = m_umr_blocks;
	m_p_umr_mr = ibv_exp_create_mr(&mrin);
	if (!m_p_umr_mr) {
		ring_logdbg("Failed creating mr %m", errno);
		goto cleanup;
	}

	memset(&m_umr_wr, 0, sizeof(m_umr_wr));
	m_umr_wr.ext_op.umr.umr_type = IBV_EXP_UMR_REPEAT;
	m_umr_wr.ext_op.umr.mem_list.rb.mem_repeat_block_list = m_p_mem_rep_list;
	m_umr_wr.ext_op.umr.mem_list.rb.stride_dim = ndim;
	m_umr_wr.ext_op.umr.mem_list.rb.repeat_count = m_p_rpt_cnt;
	m_umr_wr.exp_send_flags = IBV_EXP_SEND_INLINE;
	m_umr_wr.ext_op.umr.exp_access = IBV_EXP_ACCESS_LOCAL_WRITE;
	m_umr_wr.ext_op.umr.modified_mr = m_p_umr_mr;
	m_umr_wr.ext_op.umr.base_addr = (uint64_t)mr->addr;
	m_umr_wr.ext_op.umr.num_mrs = m_umr_blocks;
	m_umr_wr.exp_send_flags |= IBV_EXP_SEND_SIGNALED;
	m_umr_wr.exp_opcode = IBV_EXP_WR_UMR_FILL;

	if (!m_p_ib_ctx->post_umr_wr(m_umr_wr)) {
		ring_logerr("Failed in ibv_exp_post_send IBV_EXP_WR_UMR_FILL\n");
		goto cleanup;
	}

	// redmine.mellanox.com/issues/396761/
	m_p_umr_mr->addr = (void *)m_umr_wr.ext_op.umr.base_addr;
	return 0;
cleanup:
	if (m_umr_wr.exp_opcode == IBV_EXP_WR_UMR_FILL) {
		m_umr_wr.exp_opcode = IBV_EXP_WR_UMR_INVALIDATE;
		m_p_ib_ctx->post_umr_wr(m_umr_wr);
	}

	if (m_p_umr_mr) {
		ibv_dereg_mr(m_p_umr_mr);
		m_p_umr_mr = NULL;
	}

	if (m_p_rpt_cnt) {
		delete[] m_p_rpt_cnt;
		m_p_rpt_cnt = NULL;
	}

	for (int i = 0; i < m_umr_blocks; i++) {
		if (m_p_mem_rep_list[i].stride) {
			delete[] m_p_mem_rep_list[i].stride;
			m_p_mem_rep_list[i].stride = NULL;
		}
		if (m_p_mem_rep_list[i].byte_count) {
			delete[] m_p_mem_rep_list[i].byte_count;
			m_p_mem_rep_list[i].byte_count = NULL;
		}
	}

	delete[] m_p_mem_rep_list;
	m_p_mem_rep_list = NULL;
	return -1;
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
	uint32_t used_strides = m_curr_wqe_used_strides;
	int ret = ((cq_mgr_mp *)m_p_cq_mgr_rx)->poll_mp_cq(size,
					m_curr_wqe_used_strides, poll_flags, cqe64);
	// empty
	if (size == 0) {
		return 0;
	}
	if (unlikely(ret == -1)) {
		ring_logdbg("poll_mp_cq failed with errno %m", errno);
		return -1;
	}
	// set it here because we might not have min packets avail in this run
	if (likely(!(poll_flags & VMA_MP_RQ_BAD_PACKET))) {
		m_p_ring_stat->n_rx_pkt_count++;
		m_p_ring_stat->n_rx_byte_count += size;
		if (unlikely(m_curr_payload_addr == 0)) {
			// data is in calculated UMR location array +
			// number of strides in old WQEs (e.g. first WQE that was already consumed) +
			// number of used strides in current WQE
			used_strides += m_all_wqes_used_strides;
			m_curr_payload_addr = (void *)(m_sge_ptrs[CB_UMR_PAYLOAD] +
						m_payload_len * used_strides);
			m_curr_hdr_ptr = (void *)(m_sge_ptrs[CB_UMR_HDR] +
						m_hdr_len * used_strides);
			if (completion.comp_mask & VMA_CB_MASK_TIMESTAMP) {
				convert_hw_time_to_system_time(ntohll(cqe64->timestamp),
							       &m_curr_hw_timestamp);
			}
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
	completion.payload_ptr = m_curr_payload_addr;
	completion.payload_length = m_payload_len * m_curr_packets;
	completion.packets = m_curr_packets;
	completion.usr_hdr_ptr = m_curr_hdr_ptr;
	completion.usr_hdr_ptr_length = m_hdr_len * m_curr_packets;
	// hw_timestamp of first packet in batch
	completion.hw_timestamp = m_curr_hw_timestamp;
	m_curr_payload_addr = 0;
	ring_logdbg("Returning completion, buffer ptr %p, data size %zd, "
		    "usr hdr ptr %p usr hdr size %zd, number of packets %zd curr wqe idx %d",
		    completion.payload_ptr, completion.payload_length,
		    completion.usr_hdr_ptr, completion.usr_hdr_ptr_length,
		    m_curr_packets, m_curr_wq);
	return 0;
}

ring_eth_cb::~ring_eth_cb()
{
	struct ibv_exp_destroy_res_domain_attr attr;

	m_lock_ring_rx.lock();
	flow_udp_uc_del_all();
	flow_udp_mc_del_all();
	flow_tcp_del_all();
	m_lock_ring_rx.unlock();

	memset(&attr, 0, sizeof(attr));
	int res = ibv_exp_destroy_res_domain(m_p_ib_ctx->get_ibv_context(),
					     m_res_domain, &attr);
	if (res) {
		ring_logdbg("call to ibv_exp_destroy_res_domain returned %d", res);
	}

	// explicitly destroy the qp and cq before this destructor finshes
	// since it will release the memory allocated
	delete m_p_qp_mgr;
	m_p_qp_mgr = NULL;

	if (m_p_umr_mr) {
		m_umr_wr.exp_opcode = IBV_EXP_WR_UMR_INVALIDATE;
		m_p_ib_ctx->post_umr_wr(m_umr_wr);
		ring_logdbg("Releasing UMR failed\n");
		ibv_dereg_mr(m_p_umr_mr);
	}
	if (m_p_rpt_cnt) {
		delete[] m_p_rpt_cnt;
		m_p_rpt_cnt = NULL;
	}

	if (m_p_mem_rep_list) {
		for (int i = 0; i < m_umr_blocks; i++) {
			if (m_p_mem_rep_list[i].stride) {
				delete[] m_p_mem_rep_list[i].stride;
				m_p_mem_rep_list[i].stride = NULL;
			}
			if (m_p_mem_rep_list[i].byte_count) {
				delete[] m_p_mem_rep_list[i].byte_count;
				m_p_mem_rep_list[i].byte_count = NULL;
			}
		}
		delete[] m_p_mem_rep_list;
		m_p_mem_rep_list = NULL;
	}
}
#endif /* HAVE_MP_RQ */

