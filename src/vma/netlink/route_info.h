/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef NETLINK_ROUTE_INFO_H_
#define NETLINK_ROUTE_INFO_H_

#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include <iostream>

#include "vma/proto/route_val.h"

class netlink_route_info
{
public:

	netlink_route_info(struct rtnl_route* nl_route_obj);
	~netlink_route_info();
	
	route_val*	get_route_val()	{ return m_route_val; };

private:
	// fill all attributes using the provided netlink original route
	void fill(struct rtnl_route* nl_route_obj);
	
	route_val* m_route_val;
};

#endif /* NETLINK_ROUTE_INFO_H_ */
