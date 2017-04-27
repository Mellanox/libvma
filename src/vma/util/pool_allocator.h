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

#ifndef POOL_ALLOCATOR_H_
#define POOL_ALLOCATOR_H_

#include <stdlib.h>

#include "vlogger/vlogger.h"
#include "utils/types.h"
#include "vma/util/vma_list.h"

#define POOL_ALLOCATOR_BUFFER_CHUNK_SIZE        128
#define POOL_ALLOCATOR_READY_CONTAINERS_AMOUNT  256
#define POOL_ALLOCATOR_USED_CONTAINERS_AMOUNT   10

// Set the amount of bytes of each deque's allocate() call.
// See stl_deque.h for more info.
// This definition MUST locate before we include the deque header file.
#define _GLIBCXX_DEQUE_BUF_SIZE                 POOL_ALLOCATOR_BUFFER_CHUNK_SIZE

#include <deque>

// debugging macros
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         "pa[%p]:%d:%s() "

#undef  __INFO__
#define __INFO__                this

#define pa_logerr               __log_info_err
#define pa_logwarn              __log_info_warn
#define pa_logdbg               __log_info_dbg
#define pa_logfunc              __log_info_func

template <typename T>
class pool_allocator_t {

	struct container {
		static inline size_t container_node_offset(void) {return NODE_OFFSET(container, container_node);}
		list_node<container, container::container_node_offset> container_node;
		T*	p_buffer;

		container(T* buffer) : p_buffer(buffer) {}

		container() : p_buffer(NULL) {}

		~container() {
			free(p_buffer);
		}
	};

private:
	vma_list_t<container, container::container_node_offset> m_ready_containers;
	vma_list_t<container, container::container_node_offset> m_used_containers;

	size_t allocate_chunks() {
		pa_logdbg("Allocating %d chunks with %d bytes each", POOL_ALLOCATOR_READY_CONTAINERS_AMOUNT, POOL_ALLOCATOR_BUFFER_CHUNK_SIZE);

		container* cont;
		for (int i = 0 ; i < POOL_ALLOCATOR_READY_CONTAINERS_AMOUNT ; i++) {
			T* data = (T*)calloc(POOL_ALLOCATOR_BUFFER_CHUNK_SIZE, 1);
			if (!data || !(cont  = new container(data))) {
				pa_logerr("Failed to allocate memory");
				goto out;
			}
			m_ready_containers.push_back(cont);
		}
	out:
		return m_ready_containers.size();
	}

	void initialize() {
		pa_logdbg("Initialize has been called");
		m_ready_containers.set_id("pool_allocator_t (%p), m_ready_containers", this);
		m_used_containers.set_id("pool_allocator_t (%p), m_used_containers", this);

		allocate_chunks();

		container* cont;
		for (int i = 0 ; i < POOL_ALLOCATOR_USED_CONTAINERS_AMOUNT ; i++) {
			if (!(cont  = new container())) {
				pa_logerr("Failed to allocate memory");
				return;
			}
			m_used_containers.push_back(cont);
		}
	}

public:

	typedef T value_type;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;
	typedef value_type& reference;
	typedef const value_type& const_reference;
	typedef size_t size_type;
	typedef std::ptrdiff_t difference_type;

	template<typename _Tp1>
	struct rebind {
		typedef pool_allocator_t<_Tp1> other;
	};

	pool_allocator_t() throw() {
		initialize();
	}

	pool_allocator_t(const pool_allocator_t &other) throw() {
		pa_logdbg("Copy constructor is not supported! other=%p", &other);
		initialize();
	}

	template <class U>
	pool_allocator_t(const pool_allocator_t<U> &other) throw() {
		pa_logdbg("Copy constructor is not supported! other=%p", &other);
		initialize();
	}

	~pool_allocator_t() throw() {
		pa_logdbg("Destructor has been called! m_ready_containers=%zu, m_used_containers=%zu", m_ready_containers.size(), m_used_containers.size());

		while (!m_used_containers.empty()) {
			delete(m_used_containers.get_and_pop_back());
		}

		while (!m_ready_containers.empty()) {
			delete(m_ready_containers.get_and_pop_back());
		}
	}

	inline void construct(pointer p, const value_type& t) {
		*p = t;
	};

	inline void destroy(pointer &) {};

	pointer allocate(size_t n) {
		pa_logfunc("Allocating chunk of %d items", n);

		size_type requested = n * sizeof(size_type);
		container* cont;
		pointer chunk;

		if (unlikely(requested > POOL_ALLOCATOR_BUFFER_CHUNK_SIZE)) {
			pa_logerr("Allocation is not supported for more than %d bytes (requested %d)", POOL_ALLOCATOR_BUFFER_CHUNK_SIZE, requested);
			return NULL;
		}

		if (unlikely(m_ready_containers.empty()) && !allocate_chunks()) {
			pa_logerr("Failed to allocate data (requested %d)", requested);
			return NULL;
		}

		cont = m_ready_containers.get_and_pop_back();
		chunk = cont->p_buffer;
		cont->p_buffer = NULL;
		m_used_containers.push_back(cont);

		pa_logfunc("Completed to allocate chunk %p for %d items successfully", chunk, n);

		return chunk;
	}

	void deallocate(pointer p, size_type n) {
		pa_logfunc("Deallocating chunk %p for %d items", p, n);

		size_type requested = n * sizeof(size_type);
		container* cont;

		if (unlikely(requested > POOL_ALLOCATOR_BUFFER_CHUNK_SIZE)) {
			pa_logerr("Deallocation is not supported for more than %d bytes (requested %d)", POOL_ALLOCATOR_BUFFER_CHUNK_SIZE, requested);
			return;
		}

		if (unlikely(m_used_containers.empty())) {
			pa_logdbg("Used containers list is empty! allocating new container");
			if (!(cont  = new container(p))) {
				pa_logerr("Failed to allocate memory");
				free(p);
				return;
			}
		} else {
			cont = m_used_containers.get_and_pop_back();
			cont->p_buffer = p;
		}

		m_ready_containers.push_back(cont);

		pa_logfunc("Completed to deallocate chunk %p for %d items successfully", p, n);
	}
};

#endif /* POOL_ALLOCATOR_H_ */
