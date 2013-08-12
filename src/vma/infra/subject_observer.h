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


/* This class implements subject observer design pattern  */

#ifndef SUBJECT_OBSERVER_H
#define SUBJECT_OBSERVER_H

#include <tr1/unordered_set>
#include "vma/util/vtypes.h"
#include "vma/util/to_str.h"
#include "vma/util/lock_wrapper.h"
#include "vma/event/event.h"

class observer
{
public:
	virtual 		~observer() {};
	virtual void 		notify_cb() { return; };
	virtual void 		notify_cb(event * ev) { NOT_IN_USE(ev); notify_cb(); };
};

typedef std::tr1::unordered_set<observer *> observers_t;

class subject
{
public:
				subject(const char* lock_name = "lock(subject)") : m_lock(lock_name) {};
	virtual         	~subject() {};
	bool 			register_observer(IN const observer* const new_observer);
	bool 			unregister_observer(IN const observer* const old_observer);
	void 	  		notify_observers(event * ev = NULL);

protected:
	lock_mutex_recursive    m_lock;
	observers_t             m_observers;  // list of pointers of all observers (using stl::set for uniqueness - preventing duplicates)
};

#endif /* SUBJECT_OBSERVER_H */
