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


#include "dynamic_buffer_pool.h"
#include "vlogger/vlogger.h"

dynamic_buffer_pool *g_buffer_pool_rx = NULL;
dynamic_buffer_pool *g_buffer_pool_tx = NULL;

dynamic_buffer_pool::dynamic_buffer_pool(size_t init_buffers_count, size_t buffer_size, size_t max_buffers, size_t free_buffers_min_threshold,
		pbuf_free_custom_fn custom_free_function):
		m_lock_spin("dynamic_buffer_pool"),
		m_n_dyn_buffers(0), m_n_dyn_buffers_created(0),
		m_buffer_size(buffer_size), m_max_buffers(max_buffers), m_min_threshold(free_buffers_min_threshold),
		m_custom_free_function(custom_free_function), m_need_alloc(false),
		m_rx_stat(false), m_tx_stat(false)
{
	allocate_addtional_buffers(init_buffers_count);
}

dynamic_buffer_pool::~dynamic_buffer_pool()
{
	// update current buffer pools
	std::deque<buffer_pool*>::iterator iter_bps;
	buffer_pool* bp;
	for (iter_bps = m_bpools_dque.begin(); iter_bps != m_bpools_dque.end(); ++iter_bps) {
		bp = (*iter_bps);
		delete bp;
	}
	m_bpools_dque.clear();
}

mem_buf_desc_t *dynamic_buffer_pool::get_buffers(size_t count, const ib_ctx_handler *p_ib_ctx_h)
{
	mem_buf_desc_t * desc=NULL;

	// if not enough buffers and buffers were returned to a bpool then we need to update curr bp to be the bp with max free buffs
	if ((count > m_curr_bpool->get_free_count()) && (!m_curr_bp_is_max)) {
		update_max_free_bpool();
	}

	desc = m_curr_bpool->get_buffers(count, p_ib_ctx_h);
	if (desc) {
		m_n_dyn_buffers -= count;
	}
	// printf("dynamic buffers=%d cur pool buffers=%d\n", (int)m_n_dyn_buffers, (int)m_curr_bpool->get_free_count());

	// call free buffers threshold callback when reaching the threshold only if still not waiting for new buffers from previous call
	if ( (!m_need_alloc) && ((m_n_dyn_buffers < m_min_threshold) || (!desc)) ) {
		m_need_alloc=true;
	}

	return desc;
}

void dynamic_buffer_pool::put_buffers(descq_t *buffers, size_t count)
{
	mem_buf_desc_t *buff_list;
	while (count > 0 && !buffers->empty()) {
		buff_list = buffers->back();
		buffers->pop_back();
		put_buffers(buff_list);
		--count;
	}
}

int dynamic_buffer_pool::put_buffers(mem_buf_desc_t *buff_list)
{
	mem_buf_desc_t *curr, *next;
	buffer_pool* bpool;
	int count=0;

	if (!buff_list)
		return 0;

	// return buffers lists belonging to the same bpool
	while (buff_list) {
		curr=buff_list;
		bpool=buff_list->p_bpool;
		next=curr->p_next_desc;
		while ((next) && (next->p_bpool == bpool)) {
			curr=next;
			next=next->p_next_desc;
		}
		curr->p_next_desc=NULL;
		if (next)
			next->p_prev_desc=NULL;

		count+=bpool->put_buffers(buff_list);
		buff_list=next;
	}

	if (m_curr_bp_is_max)
		m_curr_bp_is_max=false;

	m_n_dyn_buffers += count;

	return count;
}

int dynamic_buffer_pool::allocate_addtional_buffers(size_t count)
{
	auto_unlocker lock(m_lock_spin);
	m_need_alloc=false;

	if (count + m_n_dyn_buffers_created > m_max_buffers) {
		vlog_printf(VLOG_DEBUG, "Cannot allocate additional %d buffers. Maximum limit=%d , total buffers=%d, free buffers=%d\n", count, m_max_buffers, m_n_dyn_buffers_created, m_n_dyn_buffers);
		return -1;
	}
	m_curr_bpool = new buffer_pool(count, m_buffer_size, NULL, m_custom_free_function);

	if (m_rx_stat)
		m_curr_bpool->set_RX_TX_for_stats(true);
	if (m_tx_stat)
		m_curr_bpool->set_RX_TX_for_stats(false);
	m_bpools_dque.push_back(m_curr_bpool);

	m_n_dyn_buffers_created += count;
	m_n_dyn_buffers += count;

	update_max_free_bpool();

	vlog_printf(VLOG_INFO, "Allocated %d buffers. Maximum limit=%d , total buffers=%d, free buffers=%d\n", count, m_max_buffers, m_n_dyn_buffers_created, m_n_dyn_buffers);

	return 0;
}

void dynamic_buffer_pool::update_max_free_bpool()
{
	std::deque<buffer_pool*>::iterator iter_bps;
	buffer_pool* p_bp;
	for (iter_bps = m_bpools_dque.begin(); iter_bps != m_bpools_dque.end(); ++iter_bps) {
		p_bp=(*iter_bps);
		if (p_bp->get_free_count()> m_curr_bpool->get_free_count()) {
			m_curr_bpool = p_bp;
		}
	}

	m_curr_bp_is_max=true;
}


/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * pbuf_free. */
void dynamic_buffer_pool::free_rx_lwip_pbuf_custom(struct pbuf *p_buff)
{
	g_buffer_pool_rx->put_buffers_thread_safe((mem_buf_desc_t *)p_buff);
}

void dynamic_buffer_pool::free_tx_lwip_pbuf_custom(struct pbuf *p_buff)
{
	g_buffer_pool_tx->put_buffers_thread_safe((mem_buf_desc_t *)p_buff);
}

void dynamic_buffer_pool::set_RX_TX_for_stats(bool rx /*= true*/)
{
	// update for future buffer pools
	if (rx)
		m_rx_stat = true;
	else
		m_tx_stat = true;

	// update current buffer pools
	std::deque<buffer_pool*>::iterator iter_bps;
	for (iter_bps = m_bpools_dque.begin(); iter_bps != m_bpools_dque.end(); ++iter_bps) {
		(*iter_bps)->set_RX_TX_for_stats(rx);
	}
}

void dynamic_bpool_timer_handler::handle_timer_expired(void* a) {
	NOT_IN_USE(a);
	vlog_printf(VLOG_INFO, "handle_timer_expired: dyn_rx_n_buffers=%d cur_rx_buffers=%d\n", g_buffer_pool_rx->get_free_count(), g_buffer_pool_rx->get_curr_free_count());
	if ((g_buffer_pool_rx) && (g_buffer_pool_rx->get_need_alloc())) {
		g_buffer_pool_rx->allocate_addtional_buffers(m_alloc_count);
		vlog_printf(VLOG_INFO, "handle_timer_expired ---> allocating for RX\n");
	}
	if ((g_buffer_pool_tx) && (g_buffer_pool_tx->get_need_alloc())) {
		g_buffer_pool_tx->allocate_addtional_buffers(m_alloc_count);
		vlog_printf(VLOG_INFO, "handle_timer_expired ---> allocating for TX\n");
	}
}

int dynamic_buffer_pool::put_buffers_thread_safe(mem_buf_desc_t *buff_list)
{
	auto_unlocker lock(m_lock_spin);
	return put_buffers(buff_list);
}

void dynamic_buffer_pool::put_buffers_thread_safe(descq_t *buffers, size_t count)
{
	auto_unlocker lock(m_lock_spin);
	put_buffers(buffers, count);
}


void dynamic_buffer_pool::put_buffers_after_deref(descq_t *pDeque)
{
	// Assume locked owner!!!
	while (!pDeque->empty()) {
		mem_buf_desc_t * list = pDeque->front();
		pDeque->pop_front();
		if (list->dec_ref_count() <= 1 && (list->lwip_pbuf.pbuf.ref-- <= 1)) {
			put_buffers(list);
		}
	}
}

void dynamic_buffer_pool::put_buffers_after_deref_thread_safe(descq_t *pDeque)
{
	m_lock_spin.lock();
	put_buffers_after_deref(pDeque);
	m_lock_spin.unlock();
}

size_t dynamic_buffer_pool::get_free_count()
{
	return m_n_dyn_buffers;
}

size_t dynamic_buffer_pool::get_curr_free_count()
{
	return m_curr_bpool->get_free_count();
}

mem_buf_desc_t *dynamic_buffer_pool::get_buffers_thread_safe(size_t count, const ib_ctx_handler *p_ib_ctx_h)
{
       mem_buf_desc_t *ret;

       m_lock_spin.lock();
       ret = get_buffers(count, p_ib_ctx_h);
       m_lock_spin.unlock();

       return ret;
}

