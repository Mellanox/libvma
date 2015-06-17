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

#ifndef VMA_LIST
#define VMA_LIST

#include "vma/util/list.h"
#include "vlogger/vlogger.h"

#define _VMA_LIST_DEBUG 0
#define ID_MAX_SIZE 200

#if _VMA_LIST_DEBUG
template <class T>
class vma_list_t;

#endif

template <class T>
class list_node {
public :

	/* head must be the first field! */
	struct list_head head;
	T *obj_ptr;

#if _VMA_LIST_DEBUG
	vma_list_t<T>* list;

	char* list_id(){
		return this->list->list_id();
	}

#endif

	list_node() {
		this->head.next = &this->head;
		this->head.prev = &this->head;
		this->obj_ptr = NULL;

	#if _VMA_LIST_DEBUG
		list = NULL;
	#endif
	}

	/* is_list_member - check if the node is already a member in a list. */
	bool is_list_member(){
		return this->head.next != &this->head || this->head.prev != &this->head;
	}

};

template<typename T>
class list_iterator_t : public std::iterator<std::random_access_iterator_tag, T, ptrdiff_t, T*, T&>
{
public:

    list_iterator_t(T* ptr = NULL){m_ptr = ptr;}
    list_iterator_t(const list_iterator_t<T>& iterator){m_ptr = iterator.m_ptr;}
    ~list_iterator_t(){}

    list_iterator_t<T>&                  operator=(T* ptr){m_ptr = ptr;return (*this);}

    operator	bool()const {
        if(m_ptr)
            return true;
        else
            return false;
    }

    bool	operator==(const list_iterator_t<T>& iterator)const{return (m_ptr == iterator.getConstPtr());}
    bool	operator!=(const list_iterator_t<T>& iterator)const{return (m_ptr != iterator.getConstPtr());}

    list_iterator_t<T> operator++(int){
    	list_iterator_t<T> tmp(*this);
    	increment_ptr();
    	return tmp;
    }

    list_iterator_t<T>& operator++(){
    	increment_ptr();
    	return *this;
    }

    list_iterator_t<T> operator--(int){
     	list_iterator_t<T> tmp(*this);
     	decrement_ptr();
     	return tmp;
     }

    list_iterator_t<T>& operator--(){
    	decrement_ptr();
    	return *this;
    }

    T*	operator*(){return m_ptr;}
    const T*	operator*()const{return m_ptr;}
    T*	operator->(){return m_ptr;}

    T*	getPtr()const{return m_ptr;}
    const T*	getConstPtr()const{return m_ptr;}

private:

    T*	m_ptr;

    void increment_ptr() {
    	m_ptr =  ((list_node<T> *)m_ptr->node.head.next)->obj_ptr;
    }

    void decrement_ptr(){
    	m_ptr = ((list_node<T> *)m_ptr->node.head.prev)->obj_ptr;
    }
};

template <class T>
class  vma_list_t
{
public:

	vma_list_t() {
		init_list();
	}

	void set_id(const char *format, ...){
		if (format) {
	#if _VMA_LIST_DEBUG
			va_list arg;
			va_start (arg, format);
			vsnprintf (id, sizeof(id) ,format, arg);
			va_end (arg);
	#endif
		}
	}

	vma_list_t(const vma_list_t& obj) {
		vlog_printf(VLOG_WARNING,"vma_list_t copy constructor is not supported, initialize an empty list.\n");
		list_counter = obj.list_counter;
		init_list();
	}

	vma_list_t& operator=(const vma_list_t& other) {
		vlog_printf(VLOG_WARNING,"vma_list_t operator= is not supported, initialize an empty list.\n");
	    if (this != &other) {
	    	init_list();
	    }
	    return *this;
	}

	T* operator[](size_t idx) {
		return get(idx);
	}

	inline bool empty(){
		return list_empty(&list_t.head);
	}

	inline size_t size(){
		return list_counter;
	}

	inline T* front() {
		if (this->empty())
			return NULL;
		return ((list_node<T> *)list_t.head.next)->obj_ptr;
	}

	inline T* back() {
		if (this->empty())
			return NULL;
		return ((list_node<T> *)list_t.head.prev)->obj_ptr;
	}

	inline void erase(T* obj){
		if (!obj) {
			vlog_printf(VLOG_WARNING,"vma_list_t.erase() got NULL object - ignoring.\n");
			return;
		}
	#if _VMA_LIST_DEBUG
		obj->node.list = NULL;
	#endif
		list_del_init(&obj->node.head);
		list_counter--;
	}

	inline void pop_front(){
		erase(this->front());
	}

	inline void pop_back(){
		erase(this->back());
	}

	inline void push_back(T* obj){
		if (!obj) {
			vlog_printf(VLOG_WARNING,"vma_list_t.push_back() got NULL object - ignoring.\n");
			return;
		}
		if (obj->node.is_list_member()) {
		#if _VMA_LIST_DEBUG
			vlog_printf(VLOG_ERROR,"vma_list_t.push_back() - buff is already a member in a list (list id = %s), (this.id = %s)\n", obj->node.list_id(), this->list_id());
		#else
			vlog_printf(VLOG_ERROR,"vma_list_t.push_back() - buff is already a member in a list.\n");
		#endif
		}
	#if _VMA_LIST_DEBUG
		obj->node.list = this;
	#endif

		obj->node.obj_ptr = obj;
		list_add_tail(&obj->node.head, &list_t.head);
		list_counter++;
	}

	inline void push_front(T* obj){
		if (!obj) {
			vlog_printf(VLOG_WARNING,"vma_list_t.push_front() got NULL object - ignoring.\n");
			return;
		}
		if (obj->node.is_list_member()) {
		#if _VMA_LIST_DEBUG
			vlog_printf(VLOG_ERROR,"vma_list_t.push_front() - buff is already a member in a list (list id = %s), (this.id = %s)\n", obj->node.list_id(), this->list_id());
		#else
			vlog_printf(VLOG_ERROR,"vma_list_t.push_front() - buff is already a member in a list.\n");
		#endif
		}

	#if _VMA_LIST_DEBUG
		obj->node.list = this;
	#endif
		obj->node.obj_ptr = obj;
		list_add(&obj->node.head, &list_t.head);
		list_counter++;
	}

	inline T* get(size_t index) {
		if (list_counter <= index) {
			return NULL;
		} else {
			list_head* ans = list_t.head.next;
			for (size_t i = 0 ; i < index ; i++){
				ans = ans->next;
			}
			return ((list_node<T> *)ans)->obj_ptr;
		}
	}

	inline list_iterator_t<T> begin(){
		return list_iterator_t<T>(front());
	}

	inline list_iterator_t<T> end(){
		return list_iterator_t<T>(NULL);
	}

#if _VMA_LIST_DEBUG
	char* list_id(){
		return (char*)&id;
	}
#endif

private:

	list_node<T> list_t;
	size_t list_counter;

#if _VMA_LIST_DEBUG
	char id[ID_MAX_SIZE];
#endif

	void init_list(){
		list_counter = 0;
		INIT_LIST_HEAD(&list_t.head);
	#if _VMA_LIST_DEBUG
		id[0] = '\0';
	#endif
	}

};

#endif /* VMA_LIST */
