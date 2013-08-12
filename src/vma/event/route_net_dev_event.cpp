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


//code coverage
#if 0

#define STR_SIZE 255
#define IF_NAMESIZE 255

#include <net/if.h>

#include "route_net_dev_event.h"
#include "vma/util/utils.h"

route_net_dev_event::route_net_dev_event(void* notifier, int if_index_down, event_type_t event_type) : event(notifier)
{
	m_if_index_down = if_index_down;
	m_event_type = event_type;
}

route_net_dev_event::~route_net_dev_event()
{

}

const std::string route_net_dev_event::to_str() const
{
	char outstr[STR_SIZE];
	char if_name[IF_NAMESIZE];
	if_indextoname(m_if_index_down, if_name);
	sprintf(outstr, "interface %s [index %d] is down", if_name, m_if_index_down);
	return std::string(outstr);
}

#endif //code coverage
