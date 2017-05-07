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

#ifndef CHUNK_LIST_H_
#define CHUNK_LIST_H_

#include <stdlib.h>
#include "vma/util/vma_list.h"

#define CHUNK_LIST_BUFFER_SIZE        64    // Amount of T elements of each chunk.
#define CHUNK_LIST_BUFFER_AMOUNT       4    // Initial number of chunks.
#define CHUNK_LIST_BUFFER_THRESHOLD   15    // Maximum number of chunks before free.

// debugging macros
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         "clist[%p]:%d:%s() "

#undef  __INFO__
#define __INFO__                this

#define clist_logerr               __log_info_err
#define clist_logwarn              __log_info_warn
#define clist_logdbg               __log_info_dbg

template <typename T>
class chunk_list_t {

	struct chunk {
		static inline size_t node_offset(void) {return NODE_OFFSET(chunk, m_node);}
		list_node<chunk, chunk::node_offset> m_node;
		T*	m_p_buffer;

		chunk(T* buffer) : m_p_buffer(buffer) {}

		~chunk() {
			free(m_p_buffer);
		}
	};

	typedef vma_list_t<chunk, chunk::node_offset> chunk_list;

private:

	chunk_list    m_free_chunks;   // Contains available chunks.
	chunk_list    m_used_chunks;   // Contains used chunks.
	size_t        m_size;          // The amount of T element in the list.
	int           m_front;         // Index of the first element.
	int           m_back;          // Index of the last element.

	size_t allocate_chunks(int chunks = 1) {
		clist_logdbg("Allocating %d chunks of %d bytes each", chunks, CHUNK_LIST_BUFFER_SIZE * sizeof(T));

		chunk* cont;
		for (int i = 0 ; i < chunks ; i++) {
			T* data = (T*)calloc(CHUNK_LIST_BUFFER_SIZE, sizeof(T));
			if (!data || !(cont  = new chunk(data))) {
				clist_logerr("Failed to allocate memory");
				goto out;
			}
			m_free_chunks.push_back(cont);
		}

	out:
		return m_free_chunks.size();
	}

	void initialize() {
		m_free_chunks.set_id("chunk_list_t (%p), m_free_chunks", this);
		m_used_chunks.set_id("chunk_list_t (%p), m_used_chunks", this);

		m_front = 0;
		m_back = -1;
		m_size = 0;

		allocate_chunks(CHUNK_LIST_BUFFER_AMOUNT);
		m_used_chunks.push_back(m_free_chunks.get_and_pop_front());
	}

public:

	chunk_list_t() {
		clist_logdbg("Constructor has been called");
		initialize();
	}

	chunk_list_t(const chunk_list_t &other) {
		clist_logwarn("Copy constructor is not supported! other=%p", &other);
		initialize();
	}

	~chunk_list_t() {
		clist_logdbg("Destructor has been called! m_free_chunks=%zu, m_used_chunks=%zu", m_free_chunks.size(), m_used_chunks.size());

		if (!empty()) {
			clist_logwarn("Not all buffers were freed. size=%zu\n", m_size);
		}

		while (!m_used_chunks.empty()) {
			delete(m_used_chunks.get_and_pop_back());
		}

		while (!m_free_chunks.empty()) {
			delete(m_free_chunks.get_and_pop_back());
		}
	}

	inline bool empty() const {
		return m_size == 0;
	}

	inline size_t size() const {
		return m_size;
	}

	inline T front() const {
		// Check if the list is empty.
		if (unlikely(empty()))
				return NULL;
		return m_used_chunks.front()->m_p_buffer[m_front];
	}

	inline void pop_front() {
		// Check if the list is empty.
		if (unlikely(empty())) {
			clist_logwarn("List is empty - ignoring.\n");
			return;
		}

		// Container is empty, move it to the free list or delete it if necessary.
		if (unlikely(++m_front == CHUNK_LIST_BUFFER_SIZE)) {
			m_front = 0;
			chunk* cont = m_used_chunks.get_and_pop_front();
			unlikely(m_free_chunks.size() > CHUNK_LIST_BUFFER_THRESHOLD) ? delete(cont) : m_free_chunks.push_back(cont);
		}

		m_size--;
	}

	inline T get_and_pop_front() {
		T list_front = front();
		pop_front();
		return list_front;
	}

	inline void push_back(T obj) {
		// Container is full, request a free one or chunk if necessary.
		if (unlikely(++m_back == CHUNK_LIST_BUFFER_SIZE)) {
			if (unlikely(m_free_chunks.empty()) && !allocate_chunks()) {
				clist_logerr("Failed to push back obj %p", obj);
				return;
			}
			m_back = 0;
			m_used_chunks.push_back(m_free_chunks.get_and_pop_back());
		}

		m_used_chunks.back()->m_p_buffer[m_back] = obj;
		m_size++;
	}
};

#endif /* CHUNK_LIST_H_ */
