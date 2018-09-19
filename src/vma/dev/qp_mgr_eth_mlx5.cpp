/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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
#include "qp_mgr_eth_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)

#include <sys/mman.h>
#include "cq_mgr_mlx5.h"
#include "vma/util/utils.h"
#include "vlogger/vlogger.h"
#include "ring_simple.h"

#undef  MODULE_NAME
#define MODULE_NAME 	"qpm_mlx5"
#define qp_logpanic 	__log_info_panic
#define qp_logerr	__log_info_err
#define qp_logwarn	__log_info_warn
#define qp_loginfo	__log_info_info
#define qp_logdbg	__log_info_dbg
#define qp_logfunc	__log_info_func
#define qp_logfuncall	__log_info_funcall

#if !defined(MLX5_ETH_INLINE_HEADER_SIZE)
#define MLX5_ETH_INLINE_HEADER_SIZE 18
#endif

#define OCTOWORD	16
#define WQEBB		64


//#define DBG_DUMP_WQE	1

#ifdef DBG_DUMP_WQE
#define dbg_dump_wqe(_addr, _size) { \
	uint32_t* _wqe = _addr; \
	qp_logfunc("Dumping %d bytes from %p", _size, _wqe); \
	for (int i = 0; i < (int)_size / 4 + 1; i += 4) { \
		qp_logfunc("%08x %08x %08x %08x", ntohl(_wqe[i+0]), ntohl(_wqe[i+1]), ntohl(_wqe[i+2]), ntohl(_wqe[i+3])); \
	} \
}
#else
#define dbg_dump_wqe(_addr, _size)
#endif

static inline uint64_t align_to_octoword_up(uint64_t val)
{
	return ((val+16-1)>>4)<<4;
}

static inline uint64_t align_to_WQEBB_up(uint64_t val)
{
	return ((val+4-1)>>2)<<2;
}

static bool is_bf(struct ibv_context *ib_ctx)
{
#define VMA_MLX5_MMAP_GET_WC_PAGES_CMD  2 // Corresponding to MLX5_MMAP_GET_WC_PAGES_CMD
#define VMA_MLX5_IB_MMAP_CMD_SHIFT      8 // Corresponding to MLX5_IB_MMAP_CMD_SHIFT

	/*
	 * The following logic was taken from libmlx5 library and its purpose is to check whether
	 * the use of BF is supported for the device.
	 */
	static int page_size = sysconf(_SC_PAGESIZE);
	static off_t offset = VMA_MLX5_MMAP_GET_WC_PAGES_CMD << VMA_MLX5_IB_MMAP_CMD_SHIFT;
	void *addr = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED,
			ib_ctx->cmd_fd, page_size * offset);
	if (addr != MAP_FAILED) {
		(void)munmap(addr, page_size);
		return true;
	}
	return false;
}

qp_mgr_eth_mlx5::qp_mgr_eth_mlx5(const ring_simple* p_ring,
                const ib_ctx_handler* p_context, const uint8_t port_num,
                struct ibv_comp_channel* p_rx_comp_event_channel,
                const uint32_t tx_num_wr, const uint16_t vlan, bool call_configure):
        qp_mgr_eth(p_ring, p_context, port_num, p_rx_comp_event_channel, tx_num_wr, vlan, false)
        ,m_sq_wqe_idx_to_wrid(NULL)
        ,m_sq_wqes(NULL)
        ,m_sq_wqe_hot(NULL)
        ,m_sq_wqes_end(NULL)
        ,m_sq_wqe_hot_index(0)
        ,m_sq_wqe_counter(0)
        ,m_dm_enabled(0)
{
	if (call_configure && configure(p_rx_comp_event_channel)) {
		throw_vma_exception("failed creating qp_mgr_eth");
	}

	memset(&m_mlx5_qp, 0, sizeof(m_mlx5_qp));
	m_db_method = (is_bf(((ib_ctx_handler*)p_context)->get_ibv_context()) ? MLX5_DB_METHOD_BF : MLX5_DB_METHOD_DB);

	qp_logdbg("m_db_method=%d", m_db_method);
}

//
void qp_mgr_eth_mlx5::init_sq()
{
	if (0 != vma_ib_mlx5_get_qp(m_qp, &m_mlx5_qp)) {
		qp_logpanic("vma_ib_mlx5_get_qp failed (errno=%d %m)", errno);
	}

	m_sq_wqes	 = (struct mlx5_wqe64 (*)[])(uintptr_t)m_mlx5_qp.sq.buf;
	m_sq_wqe_hot	 = &(*m_sq_wqes)[0];
	m_sq_wqes_end	 = (uint8_t*)((uintptr_t)m_mlx5_qp.sq.buf + m_mlx5_qp.sq.wqe_cnt * m_mlx5_qp.sq.stride);
	m_sq_wqe_counter = 0;

	m_sq_wqe_hot_index = 0;

	m_tx_num_wr = (m_sq_wqes_end-(uint8_t *)m_sq_wqe_hot)/WQEBB;
	/* Maximum BF inlining consists of:
	 * - CTRL:
	 *   - 1st WQEBB is mostly used for CTRL and ETH segment (where ETH header is inlined)
	 *   - 4 bytes for size of inline data
	 * - DATA:
	 *   - 1 OCTOWORD from 1st WQEBB is used for data inlining, except for
	 *     the 4 bytes used for stating the inline data size
	 *   - 3 WQEBB are fully availabie for data inlining
	 */
	m_max_inline_data = OCTOWORD-4 + 3*WQEBB;

	if (m_sq_wqe_idx_to_wrid == NULL) {
		m_sq_wqe_idx_to_wrid = (uint64_t*)mmap(NULL, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_wrid),
			PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (m_sq_wqe_idx_to_wrid == MAP_FAILED) {
			qp_logerr("Failed allocating m_sq_wqe_idx_to_wrid (errno=%d %m)", errno);
			return;
		}
	}

	qp_logfunc("m_tx_num_wr=%d m_max_inline_data: %d m_sq_wqe_idx_to_wrid=%p",
		    m_tx_num_wr, m_max_inline_data, m_sq_wqe_idx_to_wrid);

	memset((void *)(uintptr_t)m_sq_wqe_hot, 0, sizeof(struct mlx5_wqe64));
	m_sq_wqe_hot->ctrl.data[0] = htonl(MLX5_OPCODE_SEND);
	m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | 4);
	m_sq_wqe_hot->ctrl.data[2] = 0;
	m_sq_wqe_hot->eseg.inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);
	m_sq_wqe_hot->eseg.cs_flags = VMA_TX_PACKET_L3_CSUM | VMA_TX_PACKET_L4_CSUM;

	qp_logfunc("%p allocated for %d QPs sq_wqes:%p sq_wqes_end: %p and configured %d WRs BlueFlame: %p buf_size: %d offset: %d",
			m_qp, m_mlx5_qp.qpn, m_sq_wqes, m_sq_wqes_end,  m_tx_num_wr, m_mlx5_qp.bf.reg, m_mlx5_qp.bf.size, m_mlx5_qp.bf.offset);
}

void qp_mgr_eth_mlx5::up()
{
	init_sq();
	qp_mgr::up();

	m_dm_enabled = m_dm_mgr.allocate_resources(m_p_ib_ctx_handler, m_p_ring->m_p_ring_stat);
}

void qp_mgr_eth_mlx5::down()
{
	m_dm_mgr.release_resources();

	qp_mgr::down();
}

//! Cleanup resources QP itself will be freed by base class DTOR
qp_mgr_eth_mlx5::~qp_mgr_eth_mlx5()
{
	if (m_rq_wqe_idx_to_wrid) {
		if (0 != munmap(m_rq_wqe_idx_to_wrid, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid))) {
			qp_logerr("Failed deallocating memory with munmap m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
		}

		m_rq_wqe_idx_to_wrid = NULL;
	}
	if (m_sq_wqe_idx_to_wrid) {
		if (0 != munmap(m_sq_wqe_idx_to_wrid, m_tx_num_wr * sizeof(*m_sq_wqe_idx_to_wrid))) {
			qp_logerr("Failed deallocating memory with munmap m_sq_wqe_idx_to_wrid (errno=%d %m)", errno);
		}

		m_sq_wqe_idx_to_wrid = NULL;
	}
}

void qp_mgr_eth_mlx5::post_recv_buffer(mem_buf_desc_t* p_mem_buf_desc)
{
	if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
		if (m_p_prev_rx_desc_pushed)
			m_p_prev_rx_desc_pushed->p_prev_desc = p_mem_buf_desc;
		m_p_prev_rx_desc_pushed = p_mem_buf_desc;
	}

	m_ibv_rx_wr_array[m_curr_rx_wr].wr_id  = (uintptr_t)p_mem_buf_desc;
	m_ibv_rx_sg_array[m_curr_rx_wr].addr   = (uintptr_t)p_mem_buf_desc->p_buffer;
	m_ibv_rx_sg_array[m_curr_rx_wr].length = p_mem_buf_desc->sz_buffer;
	m_ibv_rx_sg_array[m_curr_rx_wr].lkey   = p_mem_buf_desc->lkey;

	if (m_rq_wqe_idx_to_wrid) {
		uint32_t index = m_rq_wqe_counter & (m_rx_num_wr - 1);
		m_rq_wqe_idx_to_wrid[index] = (uintptr_t)p_mem_buf_desc;
		++m_rq_wqe_counter;
	}

	if (m_curr_rx_wr == m_n_sysvar_rx_num_wr_to_post_recv - 1) {

		m_last_posted_rx_wr_id = (uintptr_t)p_mem_buf_desc;

		m_p_prev_rx_desc_pushed = NULL;
		p_mem_buf_desc->p_prev_desc = NULL;

		m_curr_rx_wr = 0;
		struct ibv_recv_wr *bad_wr = NULL;
		IF_VERBS_FAILURE(vma_ib_mlx5_post_recv(&m_mlx5_qp, &m_ibv_rx_wr_array[0], &bad_wr)) {
			uint32_t n_pos_bad_rx_wr = ((uint8_t*)bad_wr - (uint8_t*)m_ibv_rx_wr_array) / sizeof(struct ibv_recv_wr);
			qp_logerr("failed posting list (errno=%d %m)", errno);
			qp_logerr("bad_wr is %d in submitted list (bad_wr=%p, m_ibv_rx_wr_array=%p, size=%d)", n_pos_bad_rx_wr, bad_wr, m_ibv_rx_wr_array, sizeof(struct ibv_recv_wr));
			qp_logerr("bad_wr info: wr_id=%#x, next=%p, addr=%#x, length=%d, lkey=%#x", bad_wr[0].wr_id, bad_wr[0].next, bad_wr[0].sg_list[0].addr, bad_wr[0].sg_list[0].length, bad_wr[0].sg_list[0].lkey);
			qp_logerr("QP current state: %d", priv_ibv_query_qp_state(m_qp));

			// Fix broken linked list of rx_wr
			if (n_pos_bad_rx_wr != (m_n_sysvar_rx_num_wr_to_post_recv - 1)) {
				m_ibv_rx_wr_array[n_pos_bad_rx_wr].next = &m_ibv_rx_wr_array[n_pos_bad_rx_wr+1];
			}
			throw;
		} ENDIF_VERBS_FAILURE;
		qp_logfunc("Successful ibv_post_recv");
	}
	else {
		m_curr_rx_wr++;
	}
}

cq_mgr* qp_mgr_eth_mlx5::init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel)
{
	m_rx_num_wr = align32pow2(m_rx_num_wr);

	m_rq_wqe_idx_to_wrid = (uint64_t*)mmap(NULL, m_rx_num_wr * sizeof(*m_rq_wqe_idx_to_wrid), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (m_rq_wqe_idx_to_wrid == MAP_FAILED) {
		qp_logerr("Failed allocating m_rq_wqe_idx_to_wrid (errno=%d %m)", errno);
		return NULL;
	}

#ifdef DEFINED_SOCKETXTREME
	return new cq_mgr(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr, p_rx_comp_event_channel, true);
#else
	return new cq_mgr_mlx5(m_p_ring, m_p_ib_ctx_handler, m_rx_num_wr, p_rx_comp_event_channel, true);
#endif
}

cq_mgr* qp_mgr_eth_mlx5::init_tx_cq_mgr()
{
	m_tx_num_wr = align32pow2(m_tx_num_wr);
	return new cq_mgr_mlx5(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr, m_p_ring->get_tx_comp_event_channel(), false);
}

inline void qp_mgr_eth_mlx5::set_signal_in_next_send_wqe()
{
	volatile struct mlx5_wqe64 *wqe = &(*m_sq_wqes)[m_sq_wqe_counter & (m_tx_num_wr - 1)];
	wqe->ctrl.data[2] = htonl(8);
}

inline void qp_mgr_eth_mlx5::ring_doorbell(uint64_t* wqe, int num_wqebb, int num_wqebb_top)
{
	uint64_t* dst = (uint64_t*)((uint8_t*)m_mlx5_qp.bf.reg + m_mlx5_qp.bf.offset);
	uint64_t* src = wqe;

	m_sq_wqe_counter = (m_sq_wqe_counter + num_wqebb + num_wqebb_top) & 0xFFFF;

	// Make sure that descriptors are written before
	// updating doorbell record and ringing the doorbell
	wmb();
	*m_mlx5_qp.sq.dbrec = htonl(m_sq_wqe_counter);

	// This wc_wmb ensures ordering between DB record and BF copy */
	wc_wmb();
	if (likely(m_db_method == MLX5_DB_METHOD_BF)) {
		/* Copying src to BlueFlame register buffer by Write Combining cnt WQEBBs
		 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
		 * implementations may use move-string-buffer assembler instructions,
		 * which do not guarantee order of copying.
		 */
		while (num_wqebb--) {
			COPY_64B_NT(dst, src);
		}
		src = (uint64_t*)m_sq_wqes;
		while (num_wqebb_top--) {
			COPY_64B_NT(dst, src);
		}
	} else {
		*dst = *src;
	}

	/* Use wc_wmb() to ensure write combining buffers are flushed out
	 * of the running CPU.
	 * sfence instruction affects only the WC buffers of the CPU that executes it
	 */
	wc_wmb();
	m_mlx5_qp.bf.offset ^= m_mlx5_qp.bf.size;
}

inline int qp_mgr_eth_mlx5::fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t* data_addr,
			     int max_inline_len, int inline_len)
{
	int wqe_inline_size = 0;
	while ((data_addr!=NULL) && inline_len) {
		dbg_dump_wqe((uint32_t*)data_addr, inline_len);
		memcpy(cur_seg, data_addr, inline_len);
		wqe_inline_size += inline_len;
		cur_seg += inline_len;
		inline_len = max_inline_len-wqe_inline_size;
		data_addr = sga.get_data(&inline_len);
		qp_logfunc("data_addr:%p cur_seg: %p inline_len: %d wqe_inline_size: %d",
			  data_addr, cur_seg, inline_len, wqe_inline_size);

	}
	return wqe_inline_size;
}

inline int qp_mgr_eth_mlx5::fill_ptr_segment(sg_array &sga, struct mlx5_wqe_data_seg* dp_seg, uint8_t* data_addr,
			     int data_len, mem_buf_desc_t* buffer)
{
	int wqe_seg_size = 0;
	int len = data_len;

	// Currently, a maximum of 2 data pointer segments are utilized by
	// VMA. This is enforced by the dst layer during l2 header
	// configuration.
	while ((data_addr!=NULL) && data_len) {
		wqe_seg_size += sizeof(struct mlx5_wqe_data_seg);
		data_addr = sga.get_data(&len);
		dp_seg->byte_count = htonl(len);

		// Try to copy data to On Device Memory
		if (!(m_dm_enabled && m_dm_mgr.copy_data(dp_seg, data_addr, data_len, buffer))) {
			// Use the registered buffer if copying did not succeed
			dp_seg->lkey = htonl(sga.get_current_lkey());
			dp_seg->addr = htonll((uint64_t)data_addr);
		}

		data_len -= len;
		qp_logfunc("data_addr:%llx data_len: %d len: %d lkey: %x", dp_seg->addr, data_len, len, dp_seg->lkey);
		dp_seg++;
	}
	return wqe_seg_size;
}

//! Fill WQE dynamically, based on amount of free WQEBB in SQ
inline int qp_mgr_eth_mlx5::fill_wqe(vma_ibv_send_wr *pswr)
{
	// control segment is mostly filled by preset after previous packet
	// we always inline ETH header
	sg_array sga(pswr->sg_list, pswr->num_sge);
	int      inline_len = MLX5_ETH_INLINE_HEADER_SIZE;
	int      data_len   = sga.length()-inline_len;
	int      max_inline_len = m_max_inline_data;
	int      wqe_size = sizeof(struct mlx5_wqe_ctrl_seg)/OCTOWORD + sizeof(struct mlx5_wqe_eth_seg)/OCTOWORD;

	uint8_t* cur_seg = (uint8_t*)m_sq_wqe_hot+sizeof(struct mlx5_wqe_ctrl_seg);
	uint8_t* data_addr = sga.get_data(&inline_len); // data for inlining in ETH header

	qp_logfunc("wqe_hot:%p num_sge: %d data_addr: %p data_len: %d max_inline_len: %d inline_len$ %d",
		m_sq_wqe_hot, pswr->num_sge, data_addr, data_len, max_inline_len, inline_len);

	// Fill Ethernet segment with header inline, static data
	// were populated in preset after previous packet send
	memcpy(cur_seg+offsetof(struct mlx5_wqe_eth_seg, inline_hdr_start), data_addr, MLX5_ETH_INLINE_HEADER_SIZE);
	data_addr  += MLX5_ETH_INLINE_HEADER_SIZE;
	cur_seg += sizeof(struct mlx5_wqe_eth_seg);

	if (likely(data_len <= max_inline_len)) {
		max_inline_len = data_len;
		// Filling inline data segment
		// size of BlueFlame buffer is 4*WQEBBs, 3*OCTOWORDS of the first
		// was allocated for control and ethernet segment so we have 3*WQEBB+16-4
		int rest_space = std::min((int)(m_sq_wqes_end-cur_seg-4), (3*WQEBB+OCTOWORD-4));
		// Filling till the end of inline WQE segment or
		// to end of WQEs
		if (likely(max_inline_len <= rest_space)) {
			inline_len = max_inline_len;
			qp_logfunc("NO WRAP data_addr:%p cur_seg: %p rest_space: %d inline_len: %d wqe_size: %d",
					data_addr, cur_seg, rest_space, inline_len, wqe_size);
			//bypass inline size and fill inline data segment
			data_addr = sga.get_data(&inline_len);
			inline_len = fill_inl_segment(sga, cur_seg+4, data_addr, max_inline_len, inline_len);

			// store inline data size and mark the data as inlined
			*(uint32_t*)((uint8_t*)m_sq_wqe_hot+sizeof(struct mlx5_wqe_ctrl_seg)+sizeof(struct mlx5_wqe_eth_seg))
					= htonl(0x80000000|inline_len);
			rest_space = align_to_octoword_up(inline_len+4); // align to OCTOWORDs
			wqe_size += rest_space/OCTOWORD;
			//assert((data_len-inline_len)==0);
			// configuring control
			m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);
			rest_space = align_to_WQEBB_up(wqe_size)/4;
			qp_logfunc("data_len: %d inline_len: %d wqe_size: %d wqebbs: %d",
				data_len-inline_len, inline_len, wqe_size, rest_space);
			ring_doorbell((uint64_t *)m_sq_wqe_hot, rest_space);
			dbg_dump_wqe((uint32_t *)m_sq_wqe_hot, wqe_size*16);
			return rest_space;
		} else {
			// wrap around case, first filling till the end of m_sq_wqes
			int wrap_up_size = max_inline_len-rest_space;
			inline_len = rest_space;
			qp_logfunc("WRAP_UP_SIZE: %d data_addr:%p cur_seg: %p rest_space: %d inline_len: %d wqe_size: %d",
				wrap_up_size, data_addr, cur_seg, rest_space, inline_len, wqe_size);

			data_addr  = sga.get_data(&inline_len);
			inline_len = fill_inl_segment(sga, cur_seg+4, data_addr, rest_space, inline_len);
			data_len  -= inline_len;
			rest_space = align_to_octoword_up(inline_len+4);
			wqe_size  += rest_space/OCTOWORD;
			rest_space = align_to_WQEBB_up(rest_space/OCTOWORD)/4;// size of 1st chunk at the end

			qp_logfunc("END chunk data_addr: %p data_len: %d inline_len: %d wqe_size: %d wqebbs: %d",
				data_addr, data_len, inline_len, wqe_size, rest_space);
			// Wrap around
			//
			cur_seg = (uint8_t*)m_sq_wqes;
			data_addr  = sga.get_data(&wrap_up_size);

			wrap_up_size = fill_inl_segment(sga, cur_seg, data_addr, data_len, wrap_up_size);
			inline_len    += wrap_up_size;
			max_inline_len = align_to_octoword_up(wrap_up_size);
			wqe_size      += max_inline_len/OCTOWORD;
			max_inline_len = align_to_WQEBB_up(max_inline_len/OCTOWORD)/4;
			// store inline data size
			*(uint32_t*)((uint8_t* )m_sq_wqe_hot+sizeof(struct mlx5_wqe_ctrl_seg)+sizeof(struct mlx5_wqe_eth_seg))
					= htonl(0x80000000|inline_len);
			qp_logfunc("BEGIN_CHUNK data_addr: %p data_len: %d wqe_size: %d inline_len: %d end_wqebbs: %d wqebbs: %d",
				data_addr, data_len-wrap_up_size, wqe_size, inline_len+wrap_up_size, rest_space, max_inline_len);
			//assert((data_len-wrap_up_size)==0);
			// configuring control
			m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);

			dbg_dump_wqe((uint32_t*)m_sq_wqe_hot, rest_space*4*16);
			dbg_dump_wqe((uint32_t*)m_sq_wqes, max_inline_len*4*16);

			ring_doorbell((uint64_t*)m_sq_wqe_hot, rest_space, max_inline_len);
			return rest_space+max_inline_len;
		}
	} else {
		// data is bigger than max to inline we inlined only ETH header + uint from IP (18 bytes)
		// the rest will be in data pointer segment
		// adding data seg with pointer if there still data to transfer
		inline_len = fill_ptr_segment(sga, (struct mlx5_wqe_data_seg*)cur_seg, data_addr, data_len, (mem_buf_desc_t *)pswr->wr_id);
		wqe_size  += inline_len/OCTOWORD;
		qp_logfunc("data_addr: %p data_len: %d rest_space: %d wqe_size: %d",
			data_addr, data_len, inline_len, wqe_size);
		// configuring control
		m_sq_wqe_hot->ctrl.data[1] = htonl((m_mlx5_qp.qpn << 8) | wqe_size);
		inline_len = align_to_WQEBB_up(wqe_size)/4;
		ring_doorbell((uint64_t*)m_sq_wqe_hot, inline_len);
		dbg_dump_wqe((uint32_t *)m_sq_wqe_hot, wqe_size*16);
	}
	return 1;
}

//! Maps vma_ibv_wr_opcode to real MLX5 opcode.
//
static inline uint32_t get_mlx5_opcode(vma_ibv_wr_opcode verbs_opcode)
{
	switch (verbs_opcode) {
	case VMA_IBV_WR_NOP:
		return MLX5_OPCODE_NOP;

	case VMA_IBV_WR_SEND:
	default:
		return MLX5_OPCODE_SEND;

	}
}

//! Send one RAW packet by MLX5 BlueFlame
//
int qp_mgr_eth_mlx5::send_to_wire(vma_ibv_send_wr *p_send_wqe, vma_wr_tx_packet_attr attr, bool request_comp)
{
	// Set current WQE's ethernet segment checksum flags
	struct mlx5_wqe_eth_seg* eth_seg = (struct mlx5_wqe_eth_seg*)((uint8_t*)m_sq_wqe_hot+sizeof(struct mlx5_wqe_ctrl_seg));
	eth_seg->cs_flags = (uint8_t)(attr & (VMA_TX_PACKET_L3_CSUM | VMA_TX_PACKET_L4_CSUM) & 0xff);

	m_sq_wqe_hot->ctrl.data[0] = htonl((m_sq_wqe_counter << 8) | (get_mlx5_opcode(vma_send_wr_opcode(*p_send_wqe)) & 0xff) );
	m_sq_wqe_hot->ctrl.data[2] =  request_comp ? htonl(8) : 0 ;

	fill_wqe(p_send_wqe);
	m_sq_wqe_idx_to_wrid[m_sq_wqe_hot_index] = (uintptr_t)p_send_wqe->wr_id;

	// Preparing next WQE and index
	m_sq_wqe_hot = &(*m_sq_wqes)[m_sq_wqe_counter & (m_tx_num_wr - 1)];
	qp_logfunc("m_sq_wqe_hot: %p m_sq_wqe_hot_index: %d wqe_counter: %d new_hot_index: %d wr_id: %llx",
		   m_sq_wqe_hot, m_sq_wqe_hot_index, m_sq_wqe_counter, (m_sq_wqe_counter&(m_tx_num_wr-1)), p_send_wqe->wr_id);
	m_sq_wqe_hot_index = m_sq_wqe_counter & (m_tx_num_wr - 1);

	memset((void*)(uintptr_t)m_sq_wqe_hot, 0, sizeof(struct mlx5_wqe64));

	// Fill Ethernet segment with header inline
	eth_seg = (struct mlx5_wqe_eth_seg*)((uint8_t*)m_sq_wqe_hot+sizeof(struct mlx5_wqe_ctrl_seg));
	eth_seg->inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);

	return 0;
}

//! Handle releasing of Tx buffers
// Single post send with SIGNAL of a dummy packet
// NOTE: Since the QP is in ERROR state no packets will be sent on the wire!
// So we can post_send anything we want :)
void qp_mgr_eth_mlx5::trigger_completion_for_all_sent_packets()
{
	qp_logfunc("unsignaled count=%d, last=%p", m_n_unsignaled_count, m_p_last_tx_mem_buf_desc);

	if (m_p_last_tx_mem_buf_desc) { // Meaning that there is at least one post_send in the QP mem_buf_desc that wasn't signaled for completion
		qp_logdbg("Need to send closing tx wr...");
		// Allocate new send buffer
		mem_buf_desc_t* p_mem_buf_desc = m_p_ring->mem_buf_tx_get(0, true);
		m_p_ring->m_missing_buf_ref_count--; // Align Tx buffer accounting since we will be bypassing the normal send calls
		if (!p_mem_buf_desc) {
			qp_logerr("no buffer in pool");
			return;
		}
		p_mem_buf_desc->p_next_desc = m_p_last_tx_mem_buf_desc;

		// Prepare dummy packet: zeroed payload ('0000').
		// For ETH it replaces the MAC header!! (Nothing is going on the wire, QP in error state)
		/* need to send at least eth+ip, since libmlx5 will drop just eth header */
		ethhdr* p_buffer_ethhdr = (ethhdr *)p_mem_buf_desc->p_buffer;
		memset(p_buffer_ethhdr, 0, sizeof(*p_buffer_ethhdr));
		p_buffer_ethhdr->h_proto = htons(ETH_P_IP);
		iphdr* p_buffer_iphdr = (iphdr *)(p_mem_buf_desc->p_buffer + sizeof(*p_buffer_ethhdr));
		memset(p_buffer_iphdr, 0, sizeof(*p_buffer_iphdr));

		ibv_sge sge[1];
		sge[0].length = sizeof(ethhdr) + sizeof(iphdr);
		sge[0].addr = (uintptr_t)(p_mem_buf_desc->p_buffer);
		sge[0].lkey = m_p_ring->m_tx_lkey;

		// Prepare send wr for (does not care if it is UD/IB or RAW/ETH)
		// UD requires AH+qkey, RAW requires minimal payload instead of MAC header.
		vma_ibv_send_wr send_wr;

		memset(&send_wr, 0, sizeof(send_wr));
		send_wr.wr_id = (uintptr_t)p_mem_buf_desc;
		send_wr.wr.ud.ah = NULL;
		send_wr.sg_list = sge;
		send_wr.num_sge = 1;
		send_wr.next = NULL;
		vma_send_wr_opcode(send_wr) = VMA_IBV_WR_SEND;

		// Close the Tx unsignaled send list
		set_unsignaled_count();
		m_p_last_tx_mem_buf_desc = NULL;

		if (!m_p_ring->m_tx_num_wr_free) {
			qp_logdbg("failed to trigger completion for all packets due to no available wr");
			return;
		}
		m_p_ring->m_tx_num_wr_free--;

		set_signal_in_next_send_wqe();
		send_to_wire(&send_wr, (vma_wr_tx_packet_attr)(VMA_TX_PACKET_L3_CSUM|VMA_TX_PACKET_L4_CSUM), true);
	}
}

#endif /* DEFINED_DIRECT_VERBS */

