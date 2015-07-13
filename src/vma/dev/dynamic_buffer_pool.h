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


#ifndef DYNAMIC_BUFFER_POOL_H
#define DYNAMIC_BUFFER_POOL_H

#include "vma/dev/buffer_pool.h"
#include "vma/event/timer_handler.h"
#include <deque>

class dynamic_buffer_pool;

class dynamic_bpool_timer_handler : public timer_handler
{
public:
	dynamic_bpool_timer_handler(dynamic_buffer_pool *pool_obj): m_p_pool_obj(pool_obj) {};
	virtual void handle_timer_expired(void* a);

private:
	dynamic_buffer_pool *m_p_pool_obj;
};

/**
 * A buffer pool with option to dynamically grow when a minimal threshold of free buffers is left.
 * It starts with a single buffer_pool and provides an option to grow dynamically by allocating new buffer_pools once a minimal threshold of free buffers is reached.
 * The user provides a callback to be called once the minimum free buffers threshold is reached and accordingly to decide what context and when to allocate additional buffers.
 * The calls to get_buffers is never blocked on waiting for new buffers but returns with failure in case of lack of buffers.
  */
class dynamic_buffer_pool
{
	friend class dynamic_bpool_timer_handler;

public:
	dynamic_buffer_pool(size_t init_buffers_count, size_t buffer_size, size_t quanta_buffers_count, size_t max_buffers, size_t free_buffers_min_threshold,
			bool is_rx, pbuf_free_custom_fn custom_free_function);
	~dynamic_buffer_pool();

	/**
	 * Get buffers from the pool
	 * @param count Number of buffers required.
	 * @return List of buffers, or NULL if don't have enough buffers.
	 */
	mem_buf_desc_t*	get_buffers(size_t count, uint32_t lkey);

	/**
	 * Return buffers to the pool.
	 */
	void 		put_buffers(descq_t *buffers, size_t count);
	int 		put_buffers(mem_buf_desc_t *buff_list);

	static void 	free_rx_lwip_pbuf_custom(struct pbuf *p_buff);
	static void 	free_tx_lwip_pbuf_custom(struct pbuf *p_buff);

	int put_buffers_thread_safe(mem_buf_desc_t *buff_list);
	void put_buffers_thread_safe(descq_t *buffers, size_t count);
	void put_buffers_after_deref(descq_t *pDeque);
	void put_buffers_after_deref_thread_safe(descq_t *pDeque);

	size_t get_free_count();
	size_t get_curr_free_count();

	mem_buf_desc_t *get_buffers_thread_safe(size_t count, ib_ctx_handler *p_ib_ctx_h);
	mem_buf_desc_t *get_buffers_thread_safe(size_t count, uint32_t lkey);
	dynamic_bpool_timer_handler *get_timer_handler();

private:
	lock_spin       m_lock_spin;

	size_t          m_n_dyn_buffers;
	size_t          m_n_dyn_buffers_created;

	const size_t m_buffer_size;
	const size_t m_quanta_buffers_count;
	const size_t m_max_buffers;
	const size_t m_min_threshold;
	const pbuf_free_custom_fn m_custom_free_function;

	std::deque<buffer_pool*> m_bpools_dque;
	buffer_pool* m_curr_bpool;
	bool m_need_alloc;
	bool m_curr_bp_is_max;
	bool m_rx_stat;

	bpool_stats_t* 	m_p_bpool_stat;
	bpool_stats_t 	m_bpool_stat_static;

	dynamic_bpool_timer_handler *m_p_timer_handler;

	void 		update_max_free_bpool();
	int allocate_addtional_buffers(size_t count);
	bool get_need_alloc() { return m_need_alloc; }
};

extern dynamic_buffer_pool* g_buffer_pool_rx;
extern dynamic_buffer_pool* g_buffer_pool_tx;

#endif
