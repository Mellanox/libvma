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
#include <map>

class dynamic_buffer_pool;

/**
 * A buffer pool with option to be dynamically growth when a minimal threshold of free buffers are left.
 * It starts with single buffer_pool and provides option to growth dynamically by allocating new buffer_pools once a minimal threshold of free buffers is reached.
 * The user provides a callback to be called once the minimum free buffers threshold is reached and accordingly to decide what context and when to allocate additional buffers.
 * The calls to get_buffers is never blocked on waiting for new buffers but returns with failure in case of lack of buffers.
  */
class dynamic_buffer_pool
{
public:
	dynamic_buffer_pool(size_t init_buffers_count, size_t buffer_size, size_t max_buffers, size_t free_buffers_min_threshold,
			pbuf_free_custom_fn custom_free_function);
	virtual ~dynamic_buffer_pool();

	/**
	 * Get buffers from the pool
	 * @param count Number of buffers required.
	 * @return List of buffers, or NULL if don't have enough buffers.
	 */
	virtual mem_buf_desc_t*	get_buffers(size_t count, const ib_ctx_handler *p_ib_ctx_h);

	/**
	 * Return buffers to the pool.
	 */
	virtual void 		put_buffers(descq_t *buffers, size_t count);
	virtual int 		put_buffers(mem_buf_desc_t *buff_list);

	int allocate_addtional_buffers(size_t count);

	static void 	free_rx_lwip_pbuf_custom(struct pbuf *p_buff);
	static void 	free_tx_lwip_pbuf_custom(struct pbuf *p_buff);

	virtual void	set_RX_TX_for_stats(bool rx = true);

	/*
	 * returns TRUE if minimum threshold was reached and allocate_addtional_buffers() was't called yet or FALSE otherwise
	 */
	bool get_need_alloc() { return m_need_alloc; }

	int put_buffers_thread_safe(mem_buf_desc_t *buff_list);
	void put_buffers_thread_safe(descq_t *buffers, size_t count);


	void put_buffers_after_deref(descq_t *pDeque);

	void put_buffers_after_deref_thread_safe(descq_t *pDeque);

	size_t get_free_count();
	size_t get_curr_free_count();

	mem_buf_desc_t *get_buffers_thread_safe(size_t count, const ib_ctx_handler *p_ib_ctx_h);

private:
	lock_spin       m_lock_spin;
	size_t          m_n_dyn_buffers;
	size_t          m_n_dyn_buffers_created;

	const size_t m_buffer_size;
	const size_t m_max_buffers;
	const size_t m_min_threshold;
	const pbuf_free_custom_fn m_custom_free_function;

	std::deque<buffer_pool*> m_bpools_dque;
	buffer_pool* m_curr_bpool;
	bool m_need_alloc;
	bool m_curr_bp_is_max;
	bool m_rx_stat;
	bool m_tx_stat;

	void 		update_max_free_bpool();
};

extern dynamic_buffer_pool* g_buffer_pool_rx;
extern dynamic_buffer_pool* g_buffer_pool_tx;

class dynamic_bpool_timer_handler : public timer_handler
{
public:
	dynamic_bpool_timer_handler(size_t alloc_count): m_alloc_count(alloc_count) {};
	virtual void handle_timer_expired(void* a);

private:
	size_t m_alloc_count;

};

#endif
