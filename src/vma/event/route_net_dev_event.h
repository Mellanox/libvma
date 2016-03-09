/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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



#ifndef ROUTE_NET_DEV_EVENT_H_
#define ROUTE_NET_DEV_EVENT_H_

//code coverage
#if 0

#include "vma/event/event.h"
#include <string.h>

class route_net_dev_event: public event
{
public:
	typedef enum {
		EVENT_UNKNOWN	= -1,
		ADDR_CHANGE	= 0,
		IF_DOWN,
		IF_UP
	} event_type_t;

	route_net_dev_event(void* notifier, int if_index_down, event_type_t event_type);
	virtual ~route_net_dev_event();

	virtual  const std::string to_str() const;

	int get_if_index_down() const { return m_if_index_down; };
	int get_event_type() 	const { return m_event_type; };

private:
	event_type_t m_event_type;
	int m_if_index_down;
};

#endif //code coverage

#endif /* ROUTE_NET_DEV_EVENT_H_ */
