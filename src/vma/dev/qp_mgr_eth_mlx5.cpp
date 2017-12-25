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
#include "qp_mgr_eth_mlx5.h"

#if defined(HAVE_INFINIBAND_MLX5_HW_H)

#include <sys/mman.h>
#include "vma/hw/mlx5/wqe.h"
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

//#define DBG_DUMP_WQE	1

#ifdef DBG_DUMP_WQE
#define dbg_dump_wqe(addr, size) { \
	uint32_t* wqe = addr; \
	int sz_= size; \
	qp_logfunc("Dumping %d bytes from %p", size, wqe); \
	for (int i=0; i<sz_/4+1; i+=4) { \
		qp_logfunc("%08x %08x %08x %08x", ntohl(wqe[i+0]), ntohl(wqe[i+1]), ntohl(wqe[i+2]), ntohl(wqe[i+3])); \
	} \
}
#else
#define dbg_dump_wqe(addr, size)
#endif

static inline uint64_t align_to_octoword_up(uint64_t val)
{
	return ((val+16-1)>>4)<<4;
}

static inline uint64_t align_to_WQEBB_up(uint64_t val)
{
	return ((val+4-1)>>2)<<2;
}

//
void qp_mgr_eth_mlx5::init_sq()
{
	struct ibv_mlx5_qp_info qpi;
	if (!ibv_mlx5_exp_get_qp_info(m_qp, &qpi)) {
		qp_logfunc("QPN: %d dbrec: %p QP.info.SQ. buf: %p wqe_cnt: %d stride: %d bf.reg: %p bf.need_lock: %d",
			qpi.qpn, qpi.dbrec, qpi.sq.buf, qpi.sq.wqe_cnt, qpi.sq.stride, qpi.bf.reg, qpi.bf.need_lock);
	}

	struct verbs_qp *vqp = (struct verbs_qp *)m_qp;
	m_hw_qp = (struct mlx5_qp*)container_of(vqp, struct mlx5_qp, verbs_qp);
	m_qp_num	 = m_hw_qp->ctrl_seg.qp_num;
	m_sq_wqes	 = (struct mlx5_wqe64 (*)[])(uintptr_t)m_hw_qp->gen_data.sqstart;
	m_sq_wqe_hot	 = &(*m_sq_wqes)[0];
	m_sq_wqes_end	 = (uint8_t*)m_hw_qp->gen_data.sqend;
	m_sq_wqe_counter = 0;

	m_sq_db		 = &m_hw_qp->gen_data.db[MLX5_SND_DBR];
	m_sq_bf_reg	 = m_hw_qp->gen_data.bf->reg;
	m_sq_bf_buf_size = m_hw_qp->gen_data.bf->buf_size;

	m_sq_wqe_hot_index = 0;
	m_sq_bf_offset	 = m_hw_qp->gen_data.bf->offset;

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
	m_sq_wqe_hot->ctrl.data[1] = htonl((m_qp_num << 8) | 4);
	m_sq_wqe_hot->ctrl.data[2] = 0;
	m_sq_wqe_hot->eseg.inline_hdr_sz = htons(MLX5_ETH_INLINE_HEADER_SIZE);
	m_sq_wqe_hot->eseg.cs_flags = VMA_TX_PACKET_L3_CSUM | VMA_TX_PACKET_L4_CSUM;

	qp_logfunc("%p allocated for %d QPs sq_wqes:%p sq_wqes_end: %p and configured %d WRs BlueFlame: %p buf_size: %d offset: %d",
			m_qp, m_qp_num, m_sq_wqes, m_sq_wqes_end,  m_tx_num_wr, m_sq_bf_reg, m_sq_bf_buf_size, m_sq_bf_offset);
}

qp_mgr_eth_mlx5::qp_mgr_eth_mlx5(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num,
		struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t vlan):
	qp_mgr_eth(p_ring, p_context, port_num, p_rx_comp_event_channel, tx_num_wr, vlan, false)
	,m_hw_qp(NULL)
	,m_sq_wqe_idx_to_wrid(NULL)
	,m_sq_wqes(NULL)
	,m_sq_wqe_hot(NULL)
	,m_sq_wqes_end(NULL)
	,m_sq_db(NULL)
	,m_sq_bf_reg(NULL)
	,m_qp_num(0)
	,m_sq_wqe_hot_index(0)
	,m_sq_bf_offset(0)
	,m_sq_bf_buf_size(0)
	,m_sq_wqe_counter(0)
	,m_dm_enabled(0)
{
	if(configure(p_rx_comp_event_channel)) {
		throw_vma_exception("failed creating qp_mgr_eth");
	}

	qp_logfunc("m_p_cq_mgr_tx= %p", m_p_cq_mgr_tx);
}

void qp_mgr_eth_mlx5::up()
{
	init_sq();
	qp_mgr::up();

	m_dm_enabled = m_dm_context.dm_allocate_resources(m_p_ib_ctx_handler, m_p_ring->m_p_ring_stat);
}

void qp_mgr_eth_mlx5::down()
{
	m_dm_context.dm_release_resources();

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
	return new cq_mgr_mlx5(m_p_ring, m_p_ib_ctx_handler, m_tx_num_wr, m_p_ring->get_tx_comp_event_channel(), false);
}

inline void qp_mgr_eth_mlx5::set_signal_in_next_send_wqe()
{
	volatile struct mlx5_wqe64 *wqe = &(*m_sq_wqes)[m_sq_wqe_counter & (m_tx_num_wr - 1)];
	wqe->ctrl.data[2] = htonl(8);
}

//! Copying src to BlueFlame register buffer by Write Combining cnt WQEBBs
static inline void copy_bf(uint64_t *bf_dst, uint64_t *src, int cnt)
{
	// Avoid using memcpy() to copy to BlueFlame page, since memcpy()
	// implementations may use move-string-buffer assembler instructions,
	// which do not guarantee order of copying.
	while (cnt--) {
		COPY_64B_NT(bf_dst, src);
	}
}

//! Copying two data chunks in wrap around case to BlueFlame register buffer
//  by Write Combining
static inline void copy_bf2(uint64_t* bf_dst, uint64_t* src_bottom, uint64_t* src_top, int cnt_bottom, int cnt_top)
{
	while (cnt_bottom--) {
		COPY_64B_NT(bf_dst, src_bottom);
	}
	while (cnt_top--) {
		COPY_64B_NT(bf_dst, src_top);
	}
}

inline void qp_mgr_eth_mlx5::send_by_bf(uint64_t* addr, int num_wqebb)
{
	m_sq_wqe_counter = (m_sq_wqe_counter + num_wqebb) & 0xFFFF;

	// Make sure that descriptors are written before
	// updating doorbell record and ringing the doorbell
	wmb();
	*m_sq_db = htonl(m_sq_wqe_counter);
	// This wc_wmb ensures ordering between DB record and BF copy
	wc_wmb();

	copy_bf((uint64_t*)((uint8_t*)m_sq_bf_reg + m_sq_bf_offset), addr, num_wqebb);
	dbg_dump_wqe((uint32_t*)addr, num_wqebb*WQEBB);

	/* Use wc_wmb() to ensure write combining buffers are flushed out
	 * of the running CPU.
	 * sfence instruction affects only the WC buffers of the CPU that executes it
	 */
	wc_wmb();
	m_sq_bf_offset ^= m_sq_bf_buf_size;
}

inline void qp_mgr_eth_mlx5::send_by_bf_wrap_up(uint64_t* bottom_addr, int num_wqebb_bottom, int num_wqebb_top)
{
	m_sq_wqe_counter = (m_sq_wqe_counter + num_wqebb_bottom + num_wqebb_top) & 0xFFFF;
	// Make sure that descriptors are written before
	// updating doorbell record and ringing the doorbell
	wmb();
	*m_sq_db = htonl(m_sq_wqe_counter);

	// This wc_wmb ensures ordering between DB record and BF copy */
	wc_wmb();
	// Copying two times for wrap-up, first at the end of SQ and second from the start
	copy_bf2((uint64_t*)((uint8_t*)m_sq_bf_reg+m_sq_bf_offset), bottom_addr, (uint64_t*)m_sq_wqes, num_wqebb_bottom, num_wqebb_top);

	/* Use wc_wmb() to ensure write combining buffers are flushed out
	 * of the running CPU.
	 * sfence instruction affects only the WC buffers of the CPU that executes it
	 */
	wc_wmb();
	m_sq_bf_offset ^= m_sq_bf_buf_size;
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
		if (!(m_dm_enabled && m_dm_context.dm_copy_data(dp_seg, data_addr, data_len, buffer))) {
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

	// assume packet is full inline
	if (likely(data_len <= max_inline_len)) {
		max_inline_len = data_len;
		// Filling inline data segment
		// size of BlueFlame buffer is 4*WQEBBs, 3*OCTOWORDS of the first
		// was allocated for control and ethernet segment so we have 3*WQEBB+16-4
		int rest_space = min((int)(m_sq_wqes_end-cur_seg-4), (3*WQEBB+OCTOWORD-4));
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
			m_sq_wqe_hot->ctrl.data[1] = htonl((m_qp_num << 8) | wqe_size);
			rest_space = align_to_WQEBB_up(wqe_size)/4;
			qp_logfunc("data_len: %d inline_len: %d wqe_size: %d wqebbs: %d",
				data_len-inline_len, inline_len, wqe_size, rest_space);
			send_by_bf((uint64_t *)m_sq_wqe_hot, rest_space);
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
			m_sq_wqe_hot->ctrl.data[1] = htonl((m_qp_num << 8) | wqe_size);

			dbg_dump_wqe((uint32_t*)m_sq_wqe_hot, rest_space*4*16);
			dbg_dump_wqe((uint32_t*)m_sq_wqes, max_inline_len*4*16);

			send_by_bf_wrap_up((uint64_t*)m_sq_wqe_hot, rest_space, max_inline_len);
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
		m_sq_wqe_hot->ctrl.data[1] = htonl((m_qp_num << 8) | wqe_size);
		inline_len = align_to_WQEBB_up(wqe_size)/4;
		send_by_bf((uint64_t*)m_sq_wqe_hot, inline_len);
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

#endif

