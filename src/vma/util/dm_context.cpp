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

#include "vlogger/vlogger.h"
#include "vma/util/dm_context.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/dev/ib_ctx_handler.h"

#define DM_MEMORY_MASK_4  3
#define DM_MEMORY_MASK_64 63
#define DM_ALIGN_SIZE(size, mask) ((size + mask) & (~mask))

#undef  MODULE_NAME
#define MODULE_NAME 		"dmc"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define dmc_logerr	__log_info_err
#define dmc_logwarn	__log_info_warn
#define dmc_logdbg	__log_info_dbg
#define dmc_logfunc	__log_info_func

dm_context::dm_context() :
	m_p_dm_mr(NULL),
	m_p_mlx5_dm(NULL),
	m_p_ring_stat(NULL),
	m_allocation_size(0),
	m_used_bytes(0),
	m_head_index(0),
	m_onair(0)
{};

dm_context::~dm_context()
{
#ifdef DEFINED_IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE
	// Free MEMIC data
	if (m_p_dm_mr) {
		if (ibv_dereg_mr(m_p_dm_mr))
			dmc_logerr("ibv_dereg_mr failed, %d %m", errno);
		dmc_logdbg("ibv_dereg_mr success");
	}

	if (m_p_mlx5_dm) {
		if (ibv_exp_free_dm((vma_ibv_dm *) m_p_mlx5_dm))
			dmc_logerr("ibv_free_dm failed %d %m", errno);
		dmc_logdbg("ibv_free_dm success");
	}

#endif
}


size_t dm_context::dm_allocate_resources(ib_ctx_handler* ib_ctx, ring_stats_t* ring_stats)
{
	NOT_IN_USE(ib_ctx);
	m_p_ring_stat = ring_stats;

#ifdef DEFINED_IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE
	size_t allocation_size = DM_ALIGN_SIZE(safe_mce_sys().ring_dev_mem_tx, DM_MEMORY_MASK_64);
	struct ibv_exp_alloc_dm_attr dm_attr = {allocation_size, 0};
	struct ibv_mr_attr mr_attr;
	vma_ibv_dm *ibv_dm;

	if (!allocation_size) {
		// Memic was disabled by the user
		return 0;
	}

	if (!ib_ctx->get_device_memory_size()) {
		// Memic is not supported bt the device
		return 0;
	}

	// Init mr_attr obj
	bzero(&mr_attr, sizeof(mr_attr));
	mr_attr.type = IBV_DEV_MEM;
	mr_attr.length = allocation_size;
	mr_attr.access = IBV_ACCESS_LOCAL_WRITE;
	mr_attr.mem_type.dev_mem.dm = NULL;
	mr_attr.mem_type.dev_mem.offset = 0;
	mr_attr.comp_mask = 0;

	// Allocate MEMIC data
	ibv_dm = ibv_exp_alloc_dm(ib_ctx->get_ibv_context(), &dm_attr);
	if (!ibv_dm) {
		dmc_logerr("Dev mem allocation failed, %d %m", errno);
		return 0;
	}

	// Register Memic MR
	mr_attr.mem_type.dev_mem.dm = ibv_dm;
	m_p_dm_mr = ibv_reg_mr_ex(ib_ctx->get_ibv_pd(), &mr_attr);
	if (!m_p_dm_mr) {
		ibv_exp_free_dm(ibv_dm);
		dmc_logerr("dm_mr registration failed, %d %m", errno);
		return 0;
	}

	m_allocation_size = allocation_size;
	m_p_mlx5_dm = reinterpret_cast<struct vma_mlx5_dm *> (ibv_dm);
	dmc_logdbg("allocated device memory completed! bytes[%zu] dm_mr handle[0x%.8x] dm_mr lkey[%d] start_addr[%p]",
			dm_attr.length, m_p_dm_mr->handle, m_p_dm_mr->lkey, m_p_mlx5_dm->start_va);

	m_p_ring_stat->n_tx_dev_mem_allocated = m_allocation_size;
#endif

	return m_allocation_size;
}

void dm_context::dm_release_data(mem_buf_desc_t* buff)
{
	m_used_bytes -= buff->tx.memic_length;
	buff->tx.memic_length = 0;
	--m_onair;
	dmc_logfunc("Release! buffer[%p] memic_length[%zu] head_index[%zu] used_bytes[%zu], m_onair[%d]",
			buff, buff->tx.memic_length, m_head_index, m_used_bytes, m_onair);

}

bool dm_context::dm_copy_data(struct mlx5_wqe_data_seg* seg, uint8_t* src, uint32_t length, mem_buf_desc_t* buff)
{
	uint32_t length_aligned_4 = DM_ALIGN_SIZE(length, DM_MEMORY_MASK_4);
	size_t continuous_size_left = 0;
	size_t &buffer_memic_length = buff->tx.memic_length = 0;

	// Check if memic buffer is full
	if (m_used_bytes >= m_allocation_size) {
		goto memic_failed;
	}

	if (m_head_index >= m_used_bytes) {
		if ((continuous_size_left = m_allocation_size - m_head_index) < length_aligned_4) {
			if (m_head_index - m_used_bytes >= length_aligned_4) {
				// There is enough space at the beginning of the buffer.
				m_head_index  = 0;
				buffer_memic_length = continuous_size_left;
			} else {
				goto memic_failed;
			}
		}
	} else if ((continuous_size_left = (m_allocation_size - (m_used_bytes - m_head_index)) - m_head_index) < length_aligned_4) {
		goto memic_failed;
	}

	// Currently, there is a bug in the hardware that we can't write unaligned to 4 byte data.
	memcpy(m_p_mlx5_dm->start_va + m_head_index, src, length_aligned_4);

	// Update sge values
	seg->lkey = htonl(m_p_dm_mr->lkey);
	seg->addr = htonll(m_head_index);

	// Update another values
	m_head_index = (m_head_index + length_aligned_4) % m_allocation_size;
	buffer_memic_length += length_aligned_4;
	m_used_bytes += buffer_memic_length;

	m_p_ring_stat->n_tx_dev_mem_pkt_count++;
	m_p_ring_stat->n_tx_dev_mem_byte_count += length;

	m_onair++;

	dmc_logfunc("Send! Buffer[%p] length[%d] length_aligned_4[%d] continuous_size_left[%zu] head_index[%zu] used_bytes[%zu] m_onair[%d]",
			buff, length, length_aligned_4, continuous_size_left, m_head_index, m_used_bytes, m_onair);

	return true;

	memic_failed:
	dmc_logfunc("Send! Buffer[%p] length[%d] length_aligned_4[%d] continuous_size_left[%zu] head_index[%zu] used_bytes[%zu] m_onair[%d]",
			buff, length, length_aligned_4, continuous_size_left, m_head_index, m_used_bytes, m_onair);

	m_p_ring_stat->n_tx_dev_mem_oob++;

	return false;
}
