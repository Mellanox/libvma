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
