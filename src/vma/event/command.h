/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 * 
 * command.h
 */

#ifndef COMMAND_H_
#define COMMAND_H_

#include "vma/netlink/netlink_wrapper.h"
#include "vma/util/to_str.h"
#include "vma/event/timer_handler.h"

class command : public tostr
{
public:
	command(){};
	virtual ~command(){};
	virtual void execute() = 0;
private:
	//block copy ctor
	command(const command &command);
};

class command_netlink: public command , public timer_handler
{
public:
	command_netlink(netlink_wrapper *executer): m_ntl_executer(executer) {};

	virtual void execute() {
		if (m_ntl_executer) {
			m_ntl_executer->handle_events();
		}
	}

	const std::string to_str() const
	{
		return(string("command_netlink"));
	}

	virtual void handle_timer_expired(void* a) {
		NOT_IN_USE(a);
		m_ntl_executer->neigh_timer_expired();
	}


private:
	netlink_wrapper *m_ntl_executer;

};

#endif /* COMMAND_H_ */
