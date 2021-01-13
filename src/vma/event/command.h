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
 *
 * command.h
 *
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
