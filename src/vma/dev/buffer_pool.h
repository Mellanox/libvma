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
#include "vma/util/lock_wrapper.h"
#include "vma/util/verbs_extra.h"
#include "vma/proto/mem_buf_desc.h"


class net_device;
class mem_buf_desc_owner;
class ib_ctx_handler;

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
	buffer_pool(size_t buffer_count, size_t size, ib_ctx_handler *p_ib_ctx_h, mem_buf_desc_owner *owner, pbuf_free_custom_fn custom_free_function);
	virtual ~buffer_pool();

	/**
	 * Set a specific ib_ctx (default lkey) if buffer pool was created without one
	 * @return new default lkey relevant for the requested context
	 * This will make the get_buffers() more efficient
	 */
	uint32_t 	set_default_lkey(const ib_ctx_handler* p_ib_ctx_h);
	uint32_t 	set_default_lkey_thread_safe(const ib_ctx_handler* p_ib_ctx_h);
	uint32_t 	find_lkey_by_ib_ctx_thread_safe(const ib_ctx_handler* p_ib_ctx_h);

	/**
	 * Get buffers from the pool
	 * @param count Number of buffers required.
	 * @return List of buffers, or NULL if don't have enough buffers.
	 */
	mem_buf_desc_t*	get_buffers(size_t count, ib_ctx_handler *p_ib_ctx_h = NULL);
	mem_buf_desc_t *get_buffers(size_t count, uint32_t lkey);
	mem_buf_desc_t*	get_buffers_thread_safe(size_t count, ib_ctx_handler *p_ib_ctx_h = NULL);
	mem_buf_desc_t *get_buffers_thread_safe(size_t count, uint32_t lkey);

	/**
	 * Return buffers to the pool.
	 */
	void 		put_buffers(std::deque<mem_buf_desc_t*> *buffers, size_t count);
	void 		put_buffers_thread_safe(std::deque<mem_buf_desc_t*> *buffers, size_t count);
	int 		put_buffers(mem_buf_desc_t *buff_list);
	int 		put_buffers_thread_safe(mem_buf_desc_t *buff_list);
	static void 	free_rx_lwip_pbuf_custom(struct pbuf *p_buff);
	static void 	free_tx_lwip_pbuf_custom(struct pbuf *p_buff);

	/**
	 * Assume locked owner!!! Return buffers to the pool with ref_count check.
	 */
	void 		put_buffers_after_deref(descq_t *pDeque);
	void 		put_buffers_after_deref_thread_safe(descq_t *pDeque);

	/**
	 * @return Number of free buffers in the pool.
	 */
	size_t		get_free_count();

	/**
	 * @returns list of memory regions
	 */
	std::deque<ibv_mr*> get_memory_regions();

	void 		buffersPanic();

private:

	lock_spin	m_lock_spin;

	// pointer to data block
	void		*m_data_block;
	
        // contiguous pages allocation indicator
        bool m_is_contig_alloc;

	// Shared memory ID, if allocated in hugetlb
	int		m_shmid;

	// List of memory regions
	std::deque<ibv_mr*> m_mrs;
	
	// If the pool was given a specific device, this is the registered memory lkey
	uint32_t	m_lkey;

	ib_ctx_handler* m_p_ib_ctx_h;

	// XXX-dummy buffer list head and count
	// to be replaced with a bucket-sorted array
	mem_buf_desc_t *m_p_head;
	size_t		m_n_buffers;
	size_t		m_n_buffers_created;

	/**
	 * Allocate data block in hugetlb memory
	 */
	bool 		hugetlb_alloc(size_t sz_bytes);
	
	/**
	 * Register memory
	 */
	bool	register_memory(size_t size, ib_ctx_handler *p_ib_ctx_h, uint64_t access);

	/**
	 * Add a buffer to the pool
	 */
	inline void 	put_buffer_helper(mem_buf_desc_t *buff);

	uint32_t 	find_lkey_by_ib_ctx(ib_ctx_handler* p_ib_ctx_h);
};

extern buffer_pool* g_buffer_pool_rx;
extern buffer_pool* g_buffer_pool_tx;


#endif
