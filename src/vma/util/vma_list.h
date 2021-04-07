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

#ifndef VMA_LIST_H
#define VMA_LIST_H

#include "vma/util/list.h"
#include "vlogger/vlogger.h"

#define VLIST_DEBUG        0
#define VLIST_ID_SIZE    200

#define vlist_logwarn(log_fmt, log_args...)     vlog_printf(VLOG_WARNING, "vlist[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__, ##log_args)
#define vlist_logerr(log_fmt, log_args...)      vlog_printf(VLOG_ERROR,   "vlist[%p]:%d:%s() " log_fmt "\n", this, __LINE__, __FUNCTION__, ##log_args)

#if VLIST_DEBUG
template <class T, size_t offset(void)>
class vma_list_t;
#define VLIST_DEBUG_PRINT_ERROR_IS_MEMBER          vlist_logerr("Buff is already a member in a list! parent.id=[%s], this.id=[%s]", node_obj->list_id(), this->list_id())
#define VLIST_DEBUG_SET_PARENT(node_obj, val)      node_obj->parent = val
#else
#define VLIST_DEBUG_PRINT_ERROR_IS_MEMBER          vlist_logerr("Buff is already a member in a list!")
#define VLIST_DEBUG_SET_PARENT(node_obj, val)
#endif

#define NODE_OFFSET(_obj_type, _node_name) \
		((size_t)(&(char &)(((_obj_type *) 1)->_node_name)) - 1)
#define GET_NODE(_obj, _obj_type, _offset_func) \
		((list_node<_obj_type, _offset_func> *) ((size_t)(_obj) + (size_t)(_offset_func())))

template <class T, size_t offset(void)>
class list_node {
public :

	/* head must be the first field! */
	struct list_head head;
	T *obj_ptr;

#if VLIST_DEBUG
	vma_list_t<T, offset> * parent;

	char* list_id() {
		return this->parent->list_id();
	}

#endif

	list_node() : obj_ptr(NULL) {
		this->head.next = &this->head;
		this->head.prev = &this->head;
		VLIST_DEBUG_SET_PARENT(this, NULL);
	}

	/* is_list_member - check if the node is already a member in a list. */
	bool is_list_member() {
		return this->head.next != &this->head || this->head.prev != &this->head;
	}
};

template<typename T, size_t offset(void)>
/* coverity[missing_move_assignment] */
class list_iterator_t : public std::iterator<std::random_access_iterator_tag, T, std::ptrdiff_t, T*, T&>
{
public:

	list_iterator_t(T* ptr = NULL) : m_ptr(ptr) {}

	list_iterator_t(const list_iterator_t<T, offset>& iter) : m_ptr(iter.m_ptr) {}

	~list_iterator_t() {}

	list_iterator_t<T, offset>& operator=(T* ptr) {
		m_ptr = ptr;
		return (*this);
	}

	list_iterator_t<T, offset>& operator=(const list_iterator_t<T, offset>& iter) {
		m_ptr = iter.m_ptr;
		return (*this);
	}

	operator bool() const {
		return m_ptr ? true : false;
	}

	bool operator==(const list_iterator_t<T, offset>& iter) const {
		return m_ptr == iter.getConstPtr();
	}

	bool operator!=(const list_iterator_t<T, offset>& iter) const {
		return m_ptr != iter.getConstPtr();
	}

	list_iterator_t<T, offset> operator++(int) {
		list_iterator_t<T, offset> iter(*this);
		increment_ptr();
		return iter;
	}

	list_iterator_t<T, offset>& operator++() {
		increment_ptr();
		return *this;
	}

	list_iterator_t<T, offset> operator--(int) {
		list_iterator_t<T, offset> iter(*this);
		decrement_ptr();
		return iter;
	}

	list_iterator_t<T, offset>& operator--() {
		decrement_ptr();
		return *this;
	}

	T* operator*() {
		return m_ptr;
	}

	const T* operator*() const {
		return m_ptr;
	}

	T* operator->() {
		return m_ptr;
	}

	T* getPtr() const {
		return m_ptr;
	}

	const T* getConstPtr() const {
		return m_ptr;
	}

private:

	T*	m_ptr;

	inline void increment_ptr() {
		m_ptr = ((list_node<T, offset> *)GET_NODE(m_ptr, T, offset)->head.next)->obj_ptr;
	}

	inline void decrement_ptr() {
		m_ptr = ((list_node<T, offset> *)GET_NODE(m_ptr, T, offset)->head.prev)->obj_ptr;
	}

};

template <class T, size_t offset(void)>
class  vma_list_t
{
public:
	typedef list_iterator_t<T, offset> iterator;
	vma_list_t() {
		init_list();
	}

	void set_id(const char *format, ...) {
		if (format) {
	#if VLIST_DEBUG
			va_list arg;
			va_start (arg, format);
			vsnprintf (id, sizeof(id) ,format, arg);
			va_end (arg);
	#endif
		}
	}

	~vma_list_t() {
		if (!empty()) {
			vlist_logwarn("Destructor is not supported for non-empty list! size=%zu", m_size);
		}
	}

	vma_list_t<T, offset> (const vma_list_t<T, offset>& other) {
		if (!other.empty())
			vlist_logwarn("Copy constructor is not supported for non-empty list! other.size=%zu", other.m_size);
		init_list();
	}

	vma_list_t<T, offset>& operator=(const vma_list_t<T, offset>& other) {
		if (!empty() || !other.empty())
			vlist_logwarn("Operator= is not supported for non-empty list! size=%zu, other.size=%zu", m_size, other.m_size);
		if (this != &other) {
			init_list();
		}
		return *this;
	}

	T* operator[](size_t idx) const {
		return get(idx);
	}

	inline bool empty() const {
		return m_size == 0;
	}

	inline size_t size() const {
		return m_size;
	}

	inline T* front() const {
		if (unlikely(empty()))
			return NULL;
		return ((list_node<T, offset> *)m_list.head.next)->obj_ptr;
	}

	inline T* back() const {
		if (unlikely(empty()))
			return NULL;
/* clang analyzer reports:
 * Use of memory after it is freed
 * This issue comes from ~chunk_list_t() 
 * Root cause is unknown.
 * TODO: Fix based on root cause instead of supressing
 */
#ifndef __clang_analyzer__
                return ((list_node<T, offset> *)m_list.head.prev)->obj_ptr;
#endif
	}

	inline void pop_front() {
		erase(front());
	}

	inline void pop_back() {
		erase(back());
	}

	inline T* get_and_pop_front() {
		T* list_front = front();
		pop_front();
		return list_front;
	}

	inline T* get_and_pop_back() {
		T* list_back = back();
		pop_back();
		return list_back;
	}

	void erase(T* obj) {
		if (unlikely(!obj)) {
			vlist_logwarn("Got NULL object - ignoring");
			return;
		}

		list_node<T, offset> *node_obj = GET_NODE(obj, T, offset);
		VLIST_DEBUG_SET_PARENT(node_obj, NULL);
		list_del_init(&node_obj->head);
		m_size--;
	}

	/**
	 * Clear content
	 * Removes all elements from the list container (which are NOT destroyed), and leaving the container with a size of 0.
	 *
	 * NOTE: we don't expect calling this method in normal situations (it is workaround at application shutdown); Hence, there is no cleanup of node.parent
	 */
	void clear_without_cleanup() {
		init_list();
	}

	void push_back(T* obj) {
		if (unlikely(!obj)) {
			vlist_logwarn("Got NULL object - ignoring");
			return;
		}

		list_node<T, offset> *node_obj = GET_NODE(obj, T, offset);
		if (unlikely(node_obj->is_list_member())) {
			VLIST_DEBUG_PRINT_ERROR_IS_MEMBER;
		}

		VLIST_DEBUG_SET_PARENT(node_obj, this);
		node_obj->obj_ptr = obj;
		list_add_tail(&node_obj->head, &m_list.head);
		m_size++;
	}

	void push_front(T* obj) {
		if (unlikely(!obj)) {
			vlist_logwarn("Got NULL object - ignoring");
			return;
		}

		list_node<T, offset> *node_obj = GET_NODE(obj, T, offset);
		if (unlikely(node_obj->is_list_member())) {
			VLIST_DEBUG_PRINT_ERROR_IS_MEMBER;
		}

		VLIST_DEBUG_SET_PARENT(node_obj, this);
		node_obj->obj_ptr = obj;
		list_add(&node_obj->head, &m_list.head);
		m_size++;
	}

	T* get(size_t index) const {
		if (m_size <= index) {
			return NULL;
		} else {
			list_head* ans = m_list.head.next;
			for (size_t i = 0 ; i < index ; i++) {
				ans = ans->next;
			}
			return ((list_node<T, offset> *)ans)->obj_ptr;
		}
	}

	// concatenate 'from' at the head of this list
	void splice_head(vma_list_t<T, offset>& from) {

		this->m_size += from.m_size;
		list_splice(&from.m_list.head, &this->m_list.head);
		from.init_list();
		// TODO: in case VLIST_DEBUG, this invalidates parent list of all nodes in the list
	}

	// concatenate 'from' at the tail of this list
	void splice_tail(vma_list_t<T, offset>& from) {
		this->m_size += from.m_size;
		list_splice_tail(&from.m_list.head, &this->m_list.head);
		from.init_list();
		// TODO: in case VLIST_DEBUG, this invalidates parent list of all nodes in the list
	}

	/**
	 * Swap content
	 * Exchanges the content of the container by the content of x, which is another list of the same type. Sizes may differ.
	 *
	 * After the call to this member function, the elements in this container are those which were in x before the call, and
	 * the elements of x are those which were in this. All iterators, references and pointers remain valid for the swapped objects.
	 */
	void swap (vma_list_t<T, offset>& x) {
		vma_list_t<T, offset> temp_list;
		this->move_to_empty(temp_list);
		x.move_to_empty(*this);
		temp_list.move_to_empty(x);
	}

	list_iterator_t<T, offset> begin() {
		return list_iterator_t<T, offset>(front());
	}

	list_iterator_t<T,offset> end() {
		return list_iterator_t<T, offset>(NULL);
	}

#if VLIST_DEBUG
	char* list_id() {
		return (char*)&id;
	}
#endif

private:

	list_node<T, offset> m_list;
	size_t m_size;

#if VLIST_DEBUG
	char id[VLIST_ID_SIZE];
#endif

	void move_to_empty(vma_list_t<T, offset>& to) {
		assert(to.empty());
		to.m_size   = this->m_size;
		list_splice_tail(&this->m_list.head, &to.m_list.head);
		this->init_list();
		// TODO: in case VLIST_DEBUG, this invalidates parent list of all nodes in the list
	}

	void init_list() {
		m_size = 0;
		INIT_LIST_HEAD(&m_list.head);
	#if VLIST_DEBUG
		id[0] = '\0';
	#endif
	}
};

#endif /* VMA_LIST_H */
