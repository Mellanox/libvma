/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


/* This class implements subject observer design pattern  */

#ifndef SUBJECT_OBSERVER_H
#define SUBJECT_OBSERVER_H

#include <unordered_set>
#include "utils/lock_wrapper.h"
#include "vma/util/vtypes.h"
#include "vma/util/to_str.h"
#include "vma/event/event.h"

class observer
{
public:
	virtual 		~observer() {};
	virtual void 		notify_cb() { return; };
	virtual void 		notify_cb(event * ev) { NOT_IN_USE(ev); notify_cb(); };
};

typedef std::unordered_set<observer *> observers_t;

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
