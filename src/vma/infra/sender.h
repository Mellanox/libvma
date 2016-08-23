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


#ifndef SEND_INFO
#define SEND_INFO

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/util/to_str.h"
#include "vma/util/utils.h"
#include "vma/event/event.h"
#include "vma/proto/header.h"

class event;


class send_info : tostr
{
public:
	send_info(): m_p_iov(NULL),m_sz_iov(0){};
	virtual ~send_info(){};

	iovec  *m_p_iov;
	size_t m_sz_iov;
};

class neigh_send_info : public send_info
{
public:
	neigh_send_info(): send_info(), m_p_header(NULL), m_protocol(0){};

	header  *m_p_header;
	uint8_t m_protocol;
};

class send_data
{
public:
	send_data(){};
	send_data(const send_info *si);
	virtual ~send_data();

	iovec m_iov;
};

class neigh_send_data : public send_data
{
public:
	neigh_send_data(): m_header(NULL){};

	neigh_send_data(const neigh_send_info *nsi): send_data((const send_info*)nsi), m_protocol(nsi->m_protocol)
	{
		m_header = new header(*(nsi->m_p_header));
	};

	virtual ~neigh_send_data()
	{
		if(m_header) {
			delete m_header;
		}
	};

	header  *m_header;
	uint8_t m_protocol;
};

class send_event : public event
{
public:
	send_event(send_info s_info): m_send_info(s_info) { m_type = SEND_EVENT; };

	send_info m_send_info;

};

#endif /* SEND_INFO */
