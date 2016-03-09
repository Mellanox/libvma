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


//code coverage
#if 0

#define STR_SIZE 255

#include "vma/util/if.h"

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
	char if_name[IFNAMSIZ];
	if_indextoname(m_if_index_down, if_name);
	sprintf(outstr, "interface %s [index %d] is down", if_name, m_if_index_down);
	return std::string(outstr);
}

#endif //code coverage
