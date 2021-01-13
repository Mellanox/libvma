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


/* This class implements subject observer design pattern  */

#ifndef SUBJECT_OBSERVER_H
#define SUBJECT_OBSERVER_H

#include <tr1/unordered_set>
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
