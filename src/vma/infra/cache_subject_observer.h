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


#ifndef CACHE_SUBJECT_OBSERVER_H
#define CACHE_SUBJECT_OBSERVER_H

#include <stdio.h>
#include <tr1/unordered_map>
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "vma/util/vtypes.h"
#include "vma/infra/subject_observer.h"
#include "vma/sock/cleanable_obj.h"
#include "vma/event/timer_handler.h"
#include "vma/event/event_handler_manager.h"

#ifndef MODULE_NAME
#define MODULE_NAME	"cache_subject_observer:"
#endif

typedef uint64_t ticks_t;

class cache_observer : public observer
{
public:
	cache_observer() : m_last_access_time(0), m_is_valid(false) {};
	virtual 		~cache_observer() {};

	inline bool 		is_valid() { return m_is_valid; };
	inline void 		notify_cb(event * ev) { NOT_IN_USE(ev); set_state(false); };

protected:
	inline void		set_state(IN bool state) { m_is_valid = state; };

private:
	ticks_t 		m_last_access_time;
	bool 			m_is_valid; // is my entry valid

	cache_observer(const cache_observer &);  // block copy constructor
};


template <typename Key, typename Val>
class cache_entry_subject : public subject, public tostr, public cleanable_obj
{
public:
	cache_entry_subject(Key, const char* lock_name = "lock(cache_entry_subject)");
	virtual 		~cache_entry_subject() {};

	// We want to return copy of the Val and not the pointer to it
	virtual  bool 		get_val(INOUT Val & val) = 0;

protected:
	// cache_collection now can access cash_entry private and protected members
	//typename cannot shadow the class's typename
	template <typename Key_, typename Val_> friend class 	cache_table_mgr;

	// coverity[member_decl]
	Val 			m_val;

	inline Key		get_key() const { return m_key; };

	inline void 		set_val(IN Val & val)
	{
		auto_unlocker lock(m_lock);
		m_val = val;
	};

	/* This function should return true if cache_entry can be deleted */
	virtual bool		is_deletable() { return true; };

	int 			get_observers_count();

private:
	const Key		m_key;

	cache_entry_subject(const cache_entry_subject <Key, Val> &); // block copy constructor
};

template <typename Key, typename Val>
class cache_table_mgr : public tostr, public timer_handler
{
public:
	cache_table_mgr(const char* lock_name = "lock(cache_table_mgr)") : m_lock(lock_name), m_timer_handle(NULL) {};
	virtual 			~cache_table_mgr();

	/* Returns pointer to the subject */
	bool  				register_observer(IN Key, IN const cache_observer *, OUT cache_entry_subject<Key, Val> **);
	bool 				unregister_observer(IN Key, IN const cache_observer *);
	void 				print_tbl();
	cache_entry_subject<Key, Val>*  get_entry(IN Key);
	int				get_cache_tbl_size() { return m_cache_tbl.size(); };

protected:
	// stats - Need to define structure for statistics

	std::tr1::unordered_map<Key, cache_entry_subject<Key, Val> *> m_cache_tbl;

	lock_mutex_recursive		m_lock;

	virtual cache_entry_subject<Key, Val>* create_new_entry(Key, const observer* ) = 0;

	// This function removes cache entries that are obsolete or number of observers is 0 + entry is deletable
	virtual void 			run_garbage_collector();
	virtual void			start_garbage_collector(int);
	virtual void			stop_garbage_collector();
	virtual void 			handle_timer_expired(void *);

private:
	cache_table_mgr(const cache_table_mgr<Key, Val> & ); // block copy constructor

	void 				try_to_remove_cache_entry(IN typename std::tr1::unordered_map<Key, cache_entry_subject<Key, Val> *>::iterator &);
	void *				m_timer_handle;
};

// ########################################################################################## //
// ##################################### implementation ##################################### //
// ########################################################################################## //

/********************************* cache_entry_subject ********************************/

template <typename Key, typename Val>
cache_entry_subject<Key, Val>::cache_entry_subject(Key key, const char* lock_name /*="lock(cache_entry_subject)"*/) : subject(lock_name), m_key(key)
{

}

template <typename Key, typename Val>
int cache_entry_subject<Key, Val>::get_observers_count()
{
	auto_unlocker lock(m_lock);
	return (m_observers.size());
}

/*********************************cache_collection_mgr ********************************/
//template <typename Key, typename Val>
//cache_entry_subject<Key, Val>*  cache_collection_mgr <Key, Val>::create_new_entry(Key key)
//{
//	return(new cache_entry_subject<Key, Val>(key));
//}


template <typename Key, typename Val>
cache_table_mgr <Key, Val>::~cache_table_mgr()
{
	print_tbl();
}

//This function should be called under lock
template <typename Key, typename Val>
void cache_table_mgr <Key, Val>::try_to_remove_cache_entry(IN typename std::tr1::unordered_map<Key, cache_entry_subject<Key, Val> *>::iterator & itr)
{
	cache_entry_subject<Key, Val> * cache_entry = itr->second;
	Key key = itr->first;
	if (!cache_entry->get_observers_count() && cache_entry->is_deletable()){
		__log_dbg("Deleting cache_entry %s", cache_entry->to_str().c_str());
		m_cache_tbl.erase(key);
		cache_entry->clean_obj();
	}
	else {
		__log_dbg("Cache_entry %s is not deletable", itr->second->to_str().c_str());
	}
}

template <typename Key, typename Val>
void cache_table_mgr<Key, Val>::run_garbage_collector()
{
	__log_dbg("");
	typename std::tr1::unordered_map<Key, cache_entry_subject<Key, Val> *>::iterator cache_itr, cache_itr_tmp;
	auto_unlocker lock(m_lock);
	for (cache_itr = m_cache_tbl.begin(); cache_itr != m_cache_tbl.end(); ) {
		cache_itr_tmp = cache_itr;
		cache_itr_tmp++;
		try_to_remove_cache_entry(cache_itr);
		cache_itr = cache_itr_tmp;
	}
}

template <typename Key, typename Val>
void cache_table_mgr<Key, Val>::start_garbage_collector(int timeout_msec)
{
	stop_garbage_collector();

	m_timer_handle = g_p_event_handler_manager->register_timer_event(timeout_msec, this, PERIODIC_TIMER, NULL);
	if(m_timer_handle == NULL) {
		__log_warn("Failed to start garbage_collector");
	}

}

template <typename Key, typename Val>
void cache_table_mgr<Key, Val>::stop_garbage_collector()
{
	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
}

template <typename Key, typename Val>
void cache_table_mgr<Key, Val>::handle_timer_expired(void *user_data)
{
	NOT_IN_USE(user_data);
	run_garbage_collector();
}

template <typename Key, typename Val>
bool cache_table_mgr<Key, Val>::register_observer(IN Key key, IN const cache_observer* new_observer, OUT cache_entry_subject<Key, Val>** cache_entry)
{
	if (new_observer == NULL) {
		__log_dbg("new_observer == NULL");
		return false;
	}

	cache_entry_subject<Key, Val>* my_cache_entry;

	auto_unlocker lock(m_lock);
	if (!m_cache_tbl.count(key)) {
		// Create new entry and insert it to the table
		my_cache_entry = create_new_entry(key, new_observer);
		if (!my_cache_entry) {
			__log_dbg("Failed to allocate new cache_entry_subject with Key = %s", key.to_str().c_str());
			return false;
		}
		m_cache_tbl[key] = my_cache_entry;
		__log_dbg("Created new cache_entry Key = %s", key.to_str().c_str());
	}
	else {
		my_cache_entry = m_cache_tbl[key];
	}

	my_cache_entry->register_observer(new_observer);
	*cache_entry = my_cache_entry;
	return true;
}

template <typename Key, typename Val>
bool cache_table_mgr <Key, Val>::unregister_observer(IN Key key, IN const cache_observer* old_observer)
{
	__log_dbg("");
	if (old_observer == NULL) {
		__log_dbg("old_observer == NULL");
		return false;
	}

	auto_unlocker lock(m_lock);

	typename std::tr1::unordered_map<Key, cache_entry_subject<Key, Val> *>::iterator cache_itr = m_cache_tbl.find(key);
	if (cache_itr == m_cache_tbl.end()) {
		__log_dbg("Couldn't unregister observer, the cache_entry (Key = %s) doesn't exist", key.to_str().c_str());
		return false;
	}

	cache_itr->second->unregister_observer(old_observer);

	// If number of observers == 0 and cache_entry is deletable need to delete this entry
	try_to_remove_cache_entry(cache_itr);
	return true;
}

template <typename Key, typename Val>
cache_entry_subject<Key, Val>*  cache_table_mgr <Key, Val>::get_entry(Key key)
{
	cache_entry_subject<Key, Val>* ret_entry = NULL;

	if (m_cache_tbl.count(key))
		ret_entry = m_cache_tbl.find(key)->second;
	return ret_entry;
}

template <typename Key, typename Val>
void cache_table_mgr <Key, Val>::print_tbl()
{
	auto_unlocker lock(m_lock);
	typename std::tr1::unordered_map<Key, cache_entry_subject<Key, Val> *>::iterator cache_itr = m_cache_tbl.begin();
	if (cache_itr != m_cache_tbl.end()) {
		__log_dbg("%s contains:", to_str().c_str());
		for (; cache_itr != m_cache_tbl.end(); cache_itr++)
			__log_dbg(" %s", cache_itr->second->to_str().c_str());
	}
	else {
		__log_dbg("%s empty", to_str().c_str());
	}
}


#undef MODULE_NAME

#endif /* SUBJECT_OBSERVER_TEMPLATE_H */
