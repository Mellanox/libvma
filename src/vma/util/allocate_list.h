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

#ifndef ALLOCATE_LIST_H_
#define ALLOCATE_LIST_H_

#include <stdlib.h>
#include "vma/util/vma_list.h"

#define ALLOCATE_LIST_BUFFER_CHUNK_SIZE        64    // Amount of T elements for each chunk.
#define ALLOCATE_LIST_BUFFER_CHUNK_AMOUNT       4    // Initial number of chunks.
#define ALLOCATE_LIST_BUFFER_CHUNK_THRESHOLD   15    // Maximum number of chunk before free

// debugging macros
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         "alist[%p]:%d:%s() "

#undef  __INFO__
#define __INFO__                this

#define alist_logerr               __log_info_err
#define alist_logwarn              __log_info_warn
#define alist_logdbg               __log_info_dbg

template <typename T>
class allocate_list_t {

	struct allocate_list_container {
		static inline size_t container_node_offset(void) {return NODE_OFFSET(allocate_list_container, container_node);}
		list_node<allocate_list_container, allocate_list_container::container_node_offset> container_node;
		T*	p_buffer;

		allocate_list_container(T* buffer) : p_buffer(buffer) {}

		~allocate_list_container() {
			free(p_buffer);
		}
	};

	typedef vma_list_t<allocate_list_container, allocate_list_container::container_node_offset> containers_list;

private:

	containers_list    m_free_buffers_list;  // Contains available buffers.
	containers_list    m_used_buffers_list;  // Contains used buffers.
	size_t             m_size;               // The amount of T element in the list.
	int                m_front;              // Index of the first element.
	int                m_back;               // Index of the last element.

	size_t allocate_chunks(int chunks = 1) {
		alist_logdbg("Allocating %d chunks of %d bytes each", chunks, ALLOCATE_LIST_BUFFER_CHUNK_SIZE * sizeof(T));

		allocate_list_container* cont;
		for (int i = 0 ; i < chunks ; i++) {
			T* data = (T*)calloc(ALLOCATE_LIST_BUFFER_CHUNK_SIZE, sizeof(T));
			if (!data || !(cont  = new allocate_list_container(data))) {
				alist_logerr("Failed to allocate memory");
				goto out;
			}
			m_free_buffers_list.push_back(cont);
		}

	out:
		return m_free_buffers_list.size();
	}

	void initialize() {
		m_free_buffers_list.set_id("allocate_list_t (%p), m_free_buffers_list", this);
		m_used_buffers_list.set_id("allocate_list_t (%p), m_used_buffers_list", this);

		m_front = 0;
		m_back = -1;
		m_size = 0;

		allocate_chunks(ALLOCATE_LIST_BUFFER_CHUNK_AMOUNT);
		m_used_buffers_list.push_back(m_free_buffers_list.get_and_pop_front());
	}

public:

	allocate_list_t() {
		alist_logdbg("Constructor has been called");
		initialize();
	}

	allocate_list_t(const allocate_list_t &other) {
		alist_logwarn("Copy constructor is not supported! other=%p", &other);
		initialize();
	}

	~allocate_list_t() {
		alist_logdbg("Destructor has been called! m_free_buffers_list=%zu, m_used_buffers_list=%zu", m_free_buffers_list.size(), m_used_buffers_list.size());

		if (!empty()) {
			alist_logwarn("Not all buffers were freed. size=%zu\n", m_size);
		}

		while (!m_used_buffers_list.empty()) {
			delete(m_used_buffers_list.get_and_pop_back());
		}

		while (!m_free_buffers_list.empty()) {
			delete(m_free_buffers_list.get_and_pop_back());
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
		return m_used_buffers_list.front()->p_buffer[m_front];
	}

	inline void pop_front() {
		// Check if the list is empty.
		if (unlikely(empty())) {
			alist_logwarn("List is empty - ignoring.\n");
			return;
		}

		// Container is empty, move it to the free list or delete it if necessary.
		if (unlikely(++m_front == ALLOCATE_LIST_BUFFER_CHUNK_SIZE)) {
			m_front = 0;
			allocate_list_container* cont = m_used_buffers_list.get_and_pop_front();
			unlikely(m_free_buffers_list.size() > ALLOCATE_LIST_BUFFER_CHUNK_THRESHOLD) ? delete(cont) : m_free_buffers_list.push_back(cont);
		}

		m_size--;
	}

	inline T get_and_pop_front() {
		T list_front = front();
		pop_front();
		return list_front;
	}

	inline void push_back(T obj) {
		// Container is full, request a free one or allocate if necessary.
		if (unlikely(++m_back == ALLOCATE_LIST_BUFFER_CHUNK_SIZE)) {
			if (unlikely(m_free_buffers_list.empty()) && !allocate_chunks()) {
				alist_logerr("Failed to push back obj %p", obj);
				return;
			}
			m_back = 0;
			m_used_buffers_list.push_back(m_free_buffers_list.get_and_pop_back());
		}

		m_used_buffers_list.back()->p_buffer[m_back] = obj;
		m_size++;
	}
};

#endif /* ALLOCATE_LIST_H_ */
