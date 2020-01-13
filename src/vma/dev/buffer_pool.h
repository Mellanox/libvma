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


#ifndef BUFFER_POOL_H
#define BUFFER_POOL_H

#include "utils/lock_wrapper.h"
#include "vma/util/vma_stats.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/dev/allocator.h"

inline static void free_lwip_pbuf(struct pbuf_custom *pbuf_custom)
{
	pbuf_custom->pbuf.flags = 0;
	pbuf_custom->pbuf.ref = 0;
}

/**
 * A buffer pool which internally sorts the buffers.
 */
class buffer_pool
{
public:
	buffer_pool(size_t buffer_count, size_t size, pbuf_free_custom_fn custom_free_function);
	~buffer_pool();

	void register_memory(ib_ctx_handler *p_ib_ctx_h);
	void print_val_tbl();

	uint32_t	find_lkey_by_ib_ctx_thread_safe(ib_ctx_handler* p_ib_ctx_h);

	/**
	 * Get buffers from the pool - thread safe
	 * @parma pDeque List to put the buffers.
	 * @param desc_owner The new owner of the buffers.
	 * @param count Number of buffers required.
	 * @param lkey The registered memory lkey.
	 * @return False if no buffers are available, else True.
	 */
	bool get_buffers_thread_safe(descq_t &pDeque, ring_slave* desc_owner, size_t count, uint32_t lkey);

	/**
	 * Return buffers to the pool.
	 */
	void		put_buffers(descq_t *buffers, size_t count);
	void		put_buffers_thread_safe(descq_t *buffers, size_t count);
	void		put_buffers(mem_buf_desc_t *buff_list);
	void		put_buffers_thread_safe(mem_buf_desc_t *buff_list);
	static void	free_rx_lwip_pbuf_custom(struct pbuf *p_buff);
	static void	free_tx_lwip_pbuf_custom(struct pbuf *p_buff);

	/**
	 * Assume locked owner!!! Return buffers to the pool with ref_count check.
	 */
	void		put_buffers_after_deref_thread_safe(descq_t *pDeque);

	/**
	 * @return Number of free buffers in the pool.
	 */
	size_t		get_free_count();

	void		set_RX_TX_for_stats(bool rx);

private:
	lock_spin	m_lock_spin;
	// XXX-dummy buffer list head and count
	// to be replaced with a bucket-sorted array

	size_t		m_size; /* pool size in bytes */
	size_t		m_n_buffers;
	size_t		m_n_buffers_created;
	mem_buf_desc_t *m_p_head;

	bpool_stats_t*	m_p_bpool_stat;
	bpool_stats_t	m_bpool_stat_static;
	vma_allocator	m_allocator;
	/**
	 * Add a buffer to the pool
	 */
	inline void	put_buffer_helper(mem_buf_desc_t *buff);

	void		buffersPanic();

	/**
	 * dtor
	 */
	inline void	free_bpool_resources();
};

extern buffer_pool* g_buffer_pool_rx;
extern buffer_pool* g_buffer_pool_tx;


#endif
