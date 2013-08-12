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


#ifndef SEND_INFO
#define SEND_INFO

#include "vma/util/to_str.h"
#include "vma/event/event.h"
#include "vma/proto/header.h"
#include "vma/util/bullseye.h"
#include "vma/util/utils.h"
#include "vlogger/vlogger.h"

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
