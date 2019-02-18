/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#include "buffer_pool.h"

#include <stdlib.h>
#include <sys/param.h> // for MIN

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/util/sys_vars.h"
#include "vma/proto/mem_buf_desc.h"
#include "ib_ctx_handler_collection.h"

#define MODULE_NAME 	"bpool"

buffer_pool *g_buffer_pool_rx = NULL;
buffer_pool *g_buffer_pool_tx = NULL;

// inlining a function only help in case it come before using it...
inline void buffer_pool::put_buffer_helper(mem_buf_desc_t *buff)
{
#if VLIST_DEBUG
	if (buff->buffer_node.is_list_member()) {
		__log_info_warn("Buffer is already a member in a list! id=[%s]", buff->buffer_node.list_id());
	}
#endif
	buff->p_next_desc = m_p_head;
	free_lwip_pbuf(&buff->lwip_pbuf);
	m_p_head = buff;
	m_n_buffers++;
	m_p_bpool_stat->n_buffer_pool_size++;
}

/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * pbuf_free. */
void buffer_pool::free_rx_lwip_pbuf_custom(struct pbuf *p_buff)
{
	g_buffer_pool_rx->put_buffers_thread_safe((mem_buf_desc_t *)p_buff);
}

void buffer_pool::free_tx_lwip_pbuf_custom(struct pbuf *p_buff)
{
	g_buffer_pool_tx->put_buffers_thread_safe((mem_buf_desc_t *)p_buff);
}

buffer_pool::buffer_pool(size_t buffer_count, size_t buf_size, pbuf_free_custom_fn custom_free_function) :
			m_lock_spin("buffer_pool"),
			m_n_buffers(0),
			m_n_buffers_created(buffer_count),
			m_p_head(NULL)
{
	size_t sz_aligned_element = 0;
	uint8_t *ptr_buff, *ptr_desc;

	__log_info_func("count = %d", buffer_count);

	m_p_bpool_stat = &m_bpool_stat_static;
	memset(m_p_bpool_stat , 0, sizeof(*m_p_bpool_stat));
	vma_stats_instance_create_bpool_block(m_p_bpool_stat);

	if (buffer_count) {
		sz_aligned_element = (buf_size + MCE_ALIGNMENT) & (~MCE_ALIGNMENT);
		m_size = (sizeof(mem_buf_desc_t) + sz_aligned_element) * buffer_count + MCE_ALIGNMENT;
	} else {
		m_size = buf_size;
	}
	void *data_block = m_allocator.alloc_and_reg_mr(m_size, NULL);


	if (!buffer_count) return;

	// Align pointers
	ptr_buff = (uint8_t *)((unsigned long)((char*)data_block + MCE_ALIGNMENT) & (~MCE_ALIGNMENT));
	ptr_desc = ptr_buff + sz_aligned_element * buffer_count;

	// Split the block to buffers
	for (size_t i = 0; i < buffer_count; ++i) {
		mem_buf_desc_t *desc = new (ptr_desc) mem_buf_desc_t(ptr_buff, buf_size, custom_free_function);
		put_buffer_helper(desc);

		ptr_buff += sz_aligned_element;
		ptr_desc += sizeof(mem_buf_desc_t);
	}

	print_val_tbl();

	__log_info_func("done");
}

buffer_pool::~buffer_pool()
{
	free_bpool_resources();
}

void buffer_pool::free_bpool_resources()
{
	if (m_n_buffers == m_n_buffers_created) {
		__log_info_func("count %lu, missing %lu", m_n_buffers,
				m_n_buffers_created-m_n_buffers);
	}
	else {
		__log_info_dbg("count %lu, missing %lu", m_n_buffers,
				m_n_buffers_created - m_n_buffers);
	}

	vma_stats_instance_remove_bpool_block(m_p_bpool_stat);

	__log_info_func("done");
}

void buffer_pool::register_memory(ib_ctx_handler *p_ib_ctx_h)
{
	m_allocator.register_memory(m_size, p_ib_ctx_h, VMA_IBV_ACCESS_LOCAL_WRITE);
}

void buffer_pool::print_val_tbl()
{
	__log_info_dbg("pool 0x%X size: %ld buffers: %lu", this, m_size, m_n_buffers);
}

bool buffer_pool::get_buffers_thread_safe(descq_t &pDeque, ring_slave* desc_owner, size_t count, uint32_t lkey)
{
	auto_unlocker lock(m_lock_spin);

	mem_buf_desc_t *head;

	__log_info_funcall("requested %lu, present %lu, created %lu", count, m_n_buffers, m_n_buffers_created);

	if (unlikely(m_n_buffers < count)) {
		VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_DEBUG, VLOG_FUNC, "ERROR! not enough buffers in the pool (requested: %lu, have: %lu, created: %lu, Buffer pool type: %s)",
				count, m_n_buffers, m_n_buffers_created, m_p_bpool_stat->is_rx ? "Rx" : "Tx");

		m_p_bpool_stat->n_buffer_pool_no_bufs++;
		return false;
	}

	// pop buffers from the list
	m_n_buffers -= count;
	m_p_bpool_stat->n_buffer_pool_size -= count;
	while (count-- > 0) {
		// Remove from list
		head = m_p_head;
		m_p_head = m_p_head->p_next_desc;
		head->p_next_desc = NULL;

		// Init
		head->lkey = lkey;
		head->p_desc_owner = desc_owner;

		// Push to queue
		pDeque.push_back(head);
	}

	return true;
}

uint32_t buffer_pool::find_lkey_by_ib_ctx_thread_safe(ib_ctx_handler* p_ib_ctx_h)
{
	auto_unlocker lock(m_lock_spin);
	return m_allocator.find_lkey_by_ib_ctx(p_ib_ctx_h);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

/*
 * this function is minimal C version of Floyd's cycle-finding algorithm
 * just for determining whether a circle exists or not.
 * Complexity is O(n)
 * see: http://en.wikipedia.org/wiki/Cycle_detection#Tortoise_and_hare
 */
bool isCircle (mem_buf_desc_t *pNode) {
	if (!pNode) return false;

	mem_buf_desc_t *p1 = pNode;
	mem_buf_desc_t *p2 = pNode;

	while (p2->p_next_desc && p2->p_next_desc->p_next_desc)
	{
		p1 = p1->p_next_desc;
		p2 = p2->p_next_desc->p_next_desc;
		if (p1 == p2)
			return true;
	}
	return false;
}

typedef mem_buf_desc_t* Node;

static inline Node f(Node x) {
	// NOTE: after we determined we have a circle, no need to check for nullity
	return x->p_next_desc;
}

// full version of Floyd's cycle-finding algorithm
// see: http://en.wikipedia.org/wiki/Cycle_detection#Tortoise_and_hare
void Floyd_LogCircleInfo(Node x0) {

	// The main phase of the algorithm, finding a repetition x_mu = x_2mu
	// The hare moves twice as quickly as the tortoise
	Node tortoise = f(x0); // f(x0) is the element/node next to x0.
	Node hare = f(f(x0));
	while (tortoise != hare) {
		tortoise = f(tortoise);
		hare = f(f(hare));
	}

	// at this point tortoise position is equvi-distant from x0
	// and current hare position (which is the same as tortoise position).  This is
	// true because tortoise moved exactly half of the hare way.
	// so hare (set to tortoise-current position and move at tortoise speed) moving in
	// circle and tortoise (set to x0 ) moving towards circle, must meet at
	// current hare position (== current turtle position).  Realize that they move
	// in same speed, the first intersection will be the beginning of the circle.
	//

	// Find the position of the first repetition of length mu
	// The hare and tortoise move at the same speeds
	int mu = 0; // first index that starts the circle
	hare = tortoise;
	tortoise = x0;
	const int MAX_STEPS = 1 << 24; // = 16M
	while (tortoise != hare) {
		tortoise = f(tortoise);
		hare = f(hare);
		mu++;
		if (mu > MAX_STEPS) break;  // extra safety; not really needed
	}

	// Find the length of the shortest cycle starting from x_mu
	// The hare moves while the tortoise stays still
	int lambda = 1; //circle length
	hare = f(tortoise);
	while (tortoise != hare) {
		hare = f(hare);
		lambda++;
		if (lambda > MAX_STEPS) break;  // extra safety; not really needed
	}
	vlog_printf (VLOG_ERROR, "circle first index (mu) = %d, circle length (lambda) = %d", mu, lambda);
}

void buffer_pool::buffersPanic()
{
	if (isCircle(m_p_head))
	{
		__log_info_err("Circle was found in buffer_pool");

		// print mu & lambda of circle
		Floyd_LogCircleInfo(m_p_head);
	}
	else
	{
		__log_info_info("no circle was found in buffer_pool");
	}

	// log backtrace
	const int MAX_BACKTRACE = 25;
	char **symbols;
	void *addresses[MAX_BACKTRACE];
	int count = backtrace(addresses, MAX_BACKTRACE);
	symbols = backtrace_symbols(addresses, count);
	for (int i = 0; i < count; ++i) {
		vlog_printf(VLOG_ERROR, "   %2d  %s\n", i, symbols[i]);
	}

	__log_info_panic("m_n_buffers(%lu) > m_n_buffers_created(%lu)", m_n_buffers, m_n_buffers_created);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

inline void buffer_pool::put_buffers(mem_buf_desc_t *buff_list)
{
	mem_buf_desc_t *next;
	__log_info_funcall("returning list, present %lu, created %lu", m_n_buffers, m_n_buffers_created);
	while (buff_list) {
		next = buff_list->p_next_desc;
		put_buffer_helper(buff_list);
		buff_list = next;
	}

	if (unlikely(m_n_buffers > m_n_buffers_created)) {
		buffersPanic();
	}
}

void buffer_pool::put_buffers_thread_safe(mem_buf_desc_t *buff_list)
{
	auto_unlocker lock(m_lock_spin);
	put_buffers(buff_list);
}

void buffer_pool::put_buffers(descq_t *buffers, size_t count)
{
	mem_buf_desc_t *buff_list, *next;
	size_t amount;
	__log_info_funcall("returning %lu, present %lu, created %lu", count, m_n_buffers, m_n_buffers_created);
	for (amount = MIN(count, buffers->size()); amount > 0 ; amount--) {
		buff_list = buffers->get_and_pop_back();
		while (buff_list) {
			next = buff_list->p_next_desc;
			put_buffer_helper(buff_list);
			buff_list = next;
		}
	}

	if (unlikely(m_n_buffers > m_n_buffers_created)) {
		buffersPanic();
	}
}

void buffer_pool::put_buffers_thread_safe(descq_t *buffers, size_t count)
{
	auto_unlocker lock(m_lock_spin);
	put_buffers(buffers, count);
}

void buffer_pool::put_buffers_after_deref_thread_safe(descq_t *pDeque)
{
	auto_unlocker lock(m_lock_spin);
	while (!pDeque->empty()) {
		mem_buf_desc_t * list = pDeque->get_and_pop_front();
		if (list->dec_ref_count() <= 1 && (list->lwip_pbuf.pbuf.ref-- <= 1)) {
			put_buffers(list);
		}
	}
}

size_t buffer_pool::get_free_count()
{
	return m_n_buffers;
}

void buffer_pool::set_RX_TX_for_stats(bool rx)
{
	if (rx)
		m_p_bpool_stat->is_rx = true;
	else
		m_p_bpool_stat->is_tx = true;
}

