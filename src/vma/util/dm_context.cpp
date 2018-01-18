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

#if defined(HAVE_INFINIBAND_MLX5_HW_H)
#if defined(HAVE_IBV_DM)

#define DM_MEMORY_MASK_8  7
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
	m_allocation(0),
	m_used(0),
	m_head(0)
{};

/*
 * Allocate dev_mem resources
 */
bool dm_context::dm_allocate_resources(ib_ctx_handler* ib_ctx, ring_stats_t* ring_stats)
{
	size_t allocation_size = DM_ALIGN_SIZE(safe_mce_sys().ring_dev_mem_tx, DM_MEMORY_MASK_64);
	struct ibv_exp_alloc_dm_attr dm_attr = {allocation_size, 0};
	struct ibv_exp_reg_mr_in mr_in;
	struct ibv_exp_dm *ibv_dm;
	m_p_ring_stat = ring_stats;
	if (!allocation_size) {
		// On Device Memory usage was disabled by the user
		return false;
	}

	if (!ib_ctx->get_on_device_memory_size()) {
		// On Device Memory usage is not supported
		return false;
	}

	// Allocate on device memory buffer
	ibv_dm = ibv_exp_alloc_dm(ib_ctx->get_ibv_context(), &dm_attr);
	if (!ibv_dm) {
		// Memory allocation can fail if we have already allocated the maximum possible.
		dmc_logdbg("ibv_exp_alloc_dm() error - On Device Memory allocation failed, %d %m", errno);
		errno = 0;
		return false;
	}

	// Initialize MR attributes
	memset(&mr_in, 0, sizeof(mr_in));
	mr_in.pd = ib_ctx->get_ibv_pd();
	mr_in.comp_mask = IBV_EXP_REG_MR_DM;
	mr_in.length = allocation_size;
	mr_in.dm = ibv_dm;

	// Register On Device Memory MR
	m_p_dm_mr = ibv_exp_reg_mr(&mr_in);
	if (!m_p_dm_mr) {
		ibv_exp_free_dm(ibv_dm);
		dmc_logerr("ibv_exp_free_dm error - dm_mr registration failed, %d %m", errno);
		return false;
	}

	m_allocation = allocation_size;
	m_p_mlx5_dm = reinterpret_cast<struct vma_mlx5_dm *> (ibv_dm);
	m_p_ring_stat->simple.n_tx_dev_mem_allocated = m_allocation;

	dmc_logdbg("Device memory allocation completed successfully! device[%s] bytes[%zu] dm_mr handle[%d] dm_mr lkey[%d]",
			ib_ctx->get_ibv_device()->name, dm_attr.length, m_p_dm_mr->handle, m_p_dm_mr->lkey);

	return true;
}

/*
 * Release dev_mem resources
 */
void dm_context::dm_release_resources()
{
	if (m_p_dm_mr) {
		if (ibv_dereg_mr(m_p_dm_mr)) {
			dmc_logerr("ibv_dereg_mr failed, %d %m", errno);
		} else {
			dmc_logdbg("ibv_dereg_mr success");
		}
		m_p_dm_mr = NULL;
	}

	if (m_p_mlx5_dm) {
		if (ibv_exp_free_dm((struct ibv_exp_dm*) m_p_mlx5_dm)) {
			dmc_logerr("ibv_free_dm failed %d %m", errno);
		} else {
			dmc_logdbg("ibv_free_dm success");
		}
		m_p_mlx5_dm = NULL;
	}

	m_p_ring_stat = NULL;

	dmc_logdbg("Device memory release completed!");
}

/*
 * Copy data into the On Device Memory buffer.
 *
 * On Device Memory buffer is implemented in a cycle way using two variables :
 * m_head - index of the next offset to be written.
 * m_used - amount of used bytes within the On Device Memory buffer (which also used to calculate the tail of the buffer).
 *
 * In order to maintain a proper order of allocation and release, we must distinguish between three possible cases:
 *
 * First case:
 *   Free space exists in the beginning and in the end of the array.
 *
 *   |-------------------------------------------|
 *   |    |XXXXXXXXXX|                           |
 *   |-------------------------------------------|
 *       tail     head
 *
 * Second case:
 *   There is not enough free space at the end of the array.
 *   |-------------------------------------------|
 *   |                             |XXXXXXXXXX|  |
 *   |-------------------------------------------|
 *                                tail     head
 *
 *   In the case above, we will move the head to the beginning of the array.
 *   |-------------------------------------------|
 *   |                             |XXXXXXXXXXXXX|
 *   |-------------------------------------------|
 *   head                         tail
 *
 * Third case:
 *   Free space exists in the middle of the array
 *   |-------------------------------------------|
 *   |XXXXXXXXXXXXXX|                     |XXXXXX|
 *   |-------------------------------------------|
 *                 head                 tail
 *
 * Due to hardware limitations:
 * 1. Data should be written to 4bytes aligned addresses.
 * 2. Data length should be aligned to 4bytes.
 *
 * Due to performance reasons:
 *  1. Data should be written to a continuous memory area.
 *  2. Data will be written to 8bytes aligned addresses.
 */
bool dm_context::dm_copy_data(struct mlx5_wqe_data_seg* seg, uint8_t* src, uint32_t length, mem_buf_desc_t* buff)
{
	uint32_t length_aligned_8 = DM_ALIGN_SIZE(length, DM_MEMORY_MASK_8);
	uint32_t offset = 0;
	uint64_t data_64 = 0;
	size_t continuous_left = 0;
	size_t &dev_mem_length = buff->tx.dev_mem_length = 0;

	// Check if On Device Memory buffer is full
	if (m_used >= m_allocation) {
		goto dev_mem_oob;
	}

	// Check for a continuous space to write
	if (m_head >= m_used) {	// First case
		if ((continuous_left = m_allocation - m_head) < length_aligned_8) {	// Second case
			if (m_head - m_used >= length_aligned_8) {
				// There is enough space at the beginning of the buffer.
				m_head  = 0;
				dev_mem_length = continuous_left;
			} else {
				// There no enough space at the beginning of the buffer.
				goto dev_mem_oob;
			}
		}
	} else if ((continuous_left = m_allocation - m_used) < length_aligned_8) {	// Third case
		goto dev_mem_oob;
	}

	/* Copy data into the On Device Memory buffer.
	 * The copy is done using a volatile pointer (and not using memcpy of the whole buffer) to prevent any
	 * optimizations which can lead to unaligned writes.
	 * The first memcpy is to support architectures without unaligned access support - this should be optimized
	 * out for architectures with unaligned access.
	 */
	while (offset < length_aligned_8) {
		memcpy(&data_64, src + offset, sizeof(data_64));
		*((volatile typeof(data_64) *)(m_p_mlx5_dm->start_va + m_head + offset)) = data_64;
		offset += sizeof(data_64);
	};

	// Update values
	seg->lkey = htonl(m_p_dm_mr->lkey);
	seg->addr = htonll(m_head);
	m_head = (m_head + length_aligned_8) % m_allocation;
	dev_mem_length += length_aligned_8;
	m_used += dev_mem_length;

	// Update On Device Memory statistics
	m_p_ring_stat->simple.n_tx_dev_mem_pkt_count++;
	m_p_ring_stat->simple.n_tx_dev_mem_byte_count += length;

	dmc_logfunc("Send completed successfully! Buffer[%p] length[%d] length_aligned_8[%d] continuous_left[%zu] head[%zu] used[%zu]",
			buff, length, length_aligned_8, continuous_left, m_head, m_used);

	return true;

dev_mem_oob:
	dmc_logfunc("Send OOB! Buffer[%p] length[%d] length_aligned_8[%d] continuous_left[%zu] head[%zu] used[%zu]",
			buff, length, length_aligned_8, continuous_left, m_head, m_used);

	m_p_ring_stat->simple.n_tx_dev_mem_oob++;

	return false;
}

/*
 * Release On Device Memory buffer.
 * This method should be called after completion was received.
 */
void dm_context::dm_release_data(mem_buf_desc_t* buff)
{
	m_used -= buff->tx.dev_mem_length;
	buff->tx.dev_mem_length = 0;

	dmc_logfunc("Device memory release! buffer[%p] buffer_dev_mem_length[%zu] head[%zu] used[%zu]",
			buff, buff->tx.dev_mem_length, m_head, m_used);

}

#endif /* HAVE_IBV_DM */
#endif /* HAVE_INFINIBAND_MLX5_HW_H */
