/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef BUFFER_POOL_H
#define BUFFER_POOL_H

#include <deque>
#include "vma/util/verbs_extra.h"
#include "vma/util/vma_stats.h"
#include "vma/util/lock_wrapper.h"
#include "vma/proto/mem_buf_desc.h"

class mem_buf_desc_owner;
class ib_ctx_handler;

inline static void free_lwip_pbuf(struct pbuf_custom *pbuf_custom)
{
	pbuf_custom->pbuf.flags = 0;
	pbuf_custom->pbuf.ref = 0;
}


class net_device;

/**
 * A buffer pool which internally sorts the buffers.
 */
class buffer_pool
{
public:
	buffer_pool(size_t buffer_count, size_t size, mem_buf_desc_owner *owner, pbuf_free_custom_fn custom_free_function);
	~buffer_pool();

	/**
	 * Get buffers from the pool
	 * @param count Number of buffers required.
	 * @return List of buffers, or NULL if don't have enough buffers.
	 */
	mem_buf_desc_t*	get_buffers(size_t count, const ib_ctx_handler *p_ib_ctx_h);

	/**
	 * Return buffers to the pool.
	 */
	void 		put_buffers(descq_t *buffers, size_t count);
	int 		put_buffers(mem_buf_desc_t *buff_list);

	/**
	 * @returns the matching memory region for specific device
	 */
	uint32_t get_lkey_by_ctx(const ib_ctx_handler* ctx);

	void		set_RX_TX_for_stats(bool rx = true);
	size_t		get_free_count();

private:
	size_t          m_n_buffers;
	size_t          m_n_buffers_created;

	// pointer to data block
	void		*m_data_block;

    // contiguous pages allocation indicator
    bool m_is_contig_alloc;

	// Shared memory ID, if allocated in hugetlb
	int		m_shmid;

	// map of device to memory region
	ibv_mr** m_p_mr_arr;
	size_t m_mr_arr_size;
	
	// XXX-dummy buffer list head and count
	// to be replaced with a bucket-sorted array
	mem_buf_desc_t *m_p_head;

	bpool_stats_t* 	m_p_bpool_stat;
	bpool_stats_t 	m_bpool_stat_static;

	/**
	 * Allocate data block in hugetlb memory
	 */
	bool 		hugetlb_alloc(size_t sz_bytes);

	/**
	 * Register memory
	 */
	bool	register_memory(size_t size, uint64_t access);

	/**
	 * Add a buffer to the pool
	 */
	inline void 	put_buffer_helper(mem_buf_desc_t *buff);

	void 		buffersPanic();

	void		free_bpool_resources();
};

#endif
