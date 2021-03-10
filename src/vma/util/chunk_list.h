/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#define CHUNK_LIST_CONTAINER_SIZE        64    // Amount of T elements of each container.
#define CHUNK_LIST_CONTAINER_INIT         4    // Initial number of containers.
#define CHUNK_LIST_CONTIANER_THRESHOLD   15    // Maximum number of containers before free.

#define clist_logfunc(log_fmt, log_args...)    vlog_printf(VLOG_FUNC,    "clist[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__, ##log_args)
#define clist_logwarn(log_fmt, log_args...)    vlog_printf(VLOG_WARNING, "clist[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__, ##log_args)
#define clist_logerr(log_fmt, log_args...)     vlog_printf(VLOG_ERROR,   "clist[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__, ##log_args)

template <typename T>
class chunk_list_t {

	struct container {
		static inline size_t node_offset(void) {return NODE_OFFSET(container, m_node);}
		list_node<container, container::node_offset> m_node;
		T*	m_p_buffer;

		container(T* buffer) : m_p_buffer(buffer) {}

		~container() {
			free(m_p_buffer);
			m_p_buffer = NULL;
		}
	};

	typedef vma_list_t<container, container::node_offset> container_list;

private:

	container_list    m_free_containers;   // Contains available containers.
	container_list    m_used_containers;   // Contains used containers.
	size_t            m_size;              // The amount of T element in the list.
	int               m_front;             // Index of the first element.
	int               m_back;              // Index of the last element.

	size_t allocate(int containers = 1) {
		clist_logfunc("Allocating %d containers of %zu bytes each", containers, CHUNK_LIST_CONTAINER_SIZE * sizeof(T));

		container* cont;
		T* data;
		for (int i = 0 ; i < containers ; i++) {
			data = (T*)calloc(CHUNK_LIST_CONTAINER_SIZE, sizeof(T));
			if (!data || !(cont  = new container(data))) {
				// Memory allocation error
				if (data) free(data);
				clist_logerr("Failed to allocate memory");
				goto out;
			}
			m_free_containers.push_back(cont);
		}

	out:
		return m_free_containers.size();
	}

	void initialize() {
		m_free_containers.set_id("chunk_list_t (%p), m_free_containers", this);
		m_used_containers.set_id("chunk_list_t (%p), m_used_containers", this);

		m_front = 0;
		m_back = -1;
		m_size = 0;

		if (allocate(CHUNK_LIST_CONTAINER_INIT)) {
			m_used_containers.push_back(m_free_containers.get_and_pop_front());
		}
	}

public:

	chunk_list_t() {
		clist_logfunc("Constructor has been called");
		initialize();
	}

	chunk_list_t(const chunk_list_t &other) {
		clist_logwarn("Copy constructor is not supported! other=%p", &other);
		initialize();
	}

	~chunk_list_t() {
		clist_logfunc("Destructor has been called! m_size=%zu, m_free_containers=%zu, m_used_containers=%zu", m_size, m_free_containers.size(), m_used_containers.size());

		if (empty()) {
			while (!m_used_containers.empty()) {
				delete(m_used_containers.get_and_pop_back());
			}
		} else {
			clist_logwarn("Not all buffers were freed. size=%zu\n", m_size);
		}

		while (!m_free_containers.empty()) {
			delete(m_free_containers.get_and_pop_back());
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
		return m_used_containers.front()->m_p_buffer[m_front];
	}

	inline void pop_front() {
		// Check if the list is empty.
		if (unlikely(empty())) {
			return;
		}

		// Container is empty, move it to the free list or delete it if necessary.
		if (unlikely(++m_front == CHUNK_LIST_CONTAINER_SIZE)) {
			m_front = 0;
			container* cont = m_used_containers.get_and_pop_front();
			unlikely(m_free_containers.size() > CHUNK_LIST_CONTIANER_THRESHOLD) ? delete(cont) : m_free_containers.push_back(cont);
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
		if (unlikely(++m_back == CHUNK_LIST_CONTAINER_SIZE)) {
			if (unlikely(m_free_containers.empty()) && !allocate()) {
				clist_logerr("Failed to push back obj %p", obj);
				return;
			}
			m_back = 0;
			m_used_containers.push_back(m_free_containers.get_and_pop_back());
		}

		m_used_containers.back()->m_p_buffer[m_back] = obj;
		m_size++;
	}
};

#endif /* CHUNK_LIST_H_ */
