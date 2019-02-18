/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef FLOW_TUPLE_H
#define FLOW_TUPLE_H


#include <list>
#include <netinet/in.h>
#include "vma/util/libvma.h"
#include "vma/util/sock_addr.h"

#define STR_MAX_LENGTH	100

// Looks at the packet in the ingress flow (in regards to dst and src)
// Practically a 'five tuple' key
class flow_tuple
{
public:
	flow_tuple();
	flow_tuple(sock_addr& dst, sock_addr& src, in_protocol_t protocol);
	flow_tuple(in_addr_t dst_ip, in_port_t dst_port, in_addr_t src_ip, in_port_t src_port, in_protocol_t protocol);
	flow_tuple(const flow_tuple &ft); // Copy Constructor
	virtual ~flow_tuple() { };

	in_addr_t	get_dst_ip() { return m_dst_ip; }
	in_addr_t	get_src_ip() { return m_src_ip; }
	in_port_t	get_dst_port() { return m_dst_port; }
	in_port_t	get_src_port() { return m_src_port; }
	in_protocol_t 	get_protocol() { return m_protocol; }

	bool		is_tcp();
	bool		is_udp_uc();
	bool		is_udp_mc();
	bool		is_local_loopback();
	bool 		is_5_tuple();
	bool 		is_3_tuple();

	flow_tuple&	operator=(const flow_tuple &ft);

	virtual bool operator==(flow_tuple const& other) const
	{
		return 	(m_dst_port == other.m_dst_port) &&
			(m_dst_ip == other.m_dst_ip) &&
			(m_src_port == other.m_src_port) &&
			(m_src_ip == other.m_src_ip) &&
			(m_protocol == other.m_protocol);
	}

	virtual bool operator <(flow_tuple const& other) const
	{
		if (m_dst_port != other.m_dst_port)
			return m_dst_port < other.m_dst_port;
		if (m_dst_ip != other.m_dst_ip)
			return m_dst_ip < other.m_dst_ip;
		if (m_src_port != other.m_src_port)
			return m_src_port < other.m_src_port;
		if (m_src_ip != other.m_src_ip)
			return m_src_ip < other.m_src_ip;
		return m_protocol < other.m_protocol;
	}

	virtual size_t hash(void)
	{
		uint8_t csum = 0;
		uint8_t* pval = (uint8_t*)this;
		for (size_t i = 0; i < (sizeof(flow_tuple) - sizeof(m_str)); ++i, ++pval) { csum ^= *pval; }
		return csum;
	}

	const char*	to_str() { return m_str; };

protected:
	in_addr_t	m_dst_ip;
	in_addr_t	m_src_ip;
	in_port_t	m_dst_port;
	in_port_t	m_src_port;
	in_protocol_t 	m_protocol;

	char		m_str[STR_MAX_LENGTH];
	virtual void 	set_str();
};

typedef std::list<flow_tuple> flow_tuple_list_t;


// Adding the 'six tuple' element of local_if
// Required by sockinfo when handling MC groups attach/detach
class flow_tuple_with_local_if : public flow_tuple
{
public:
	flow_tuple_with_local_if(sock_addr& dst, sock_addr& src, in_protocol_t protocol, in_addr_t local_if) :
		flow_tuple(dst, src, protocol), m_local_if(local_if) { set_str(); };
	flow_tuple_with_local_if(in_addr_t dst_ip, in_port_t dst_port, in_addr_t src_ip, in_port_t src_port, in_protocol_t protocol, in_addr_t local_if) :
		flow_tuple(dst_ip, dst_port, src_ip, src_port, protocol), m_local_if(local_if) { set_str(); };

	in_addr_t	get_local_if() { return m_local_if; }

	virtual bool 	operator==(flow_tuple_with_local_if const& other) const
	{
		return ((m_local_if == other.m_local_if) &&
			(*((flow_tuple*)this) == ((flow_tuple)other)));
	}

	virtual bool 	operator <(flow_tuple_with_local_if const& other) const
	{
		if (m_local_if != other.m_local_if)
			return m_local_if < other.m_local_if;
		return (*((flow_tuple*)this) < ((flow_tuple)other));
	}

	virtual size_t 	hash(void)
	{
		uint8_t csum = 0;
		uint8_t* pval = (uint8_t*)this;
		for (size_t i = 0; i < (sizeof(flow_tuple_with_local_if) - sizeof(m_str)); ++i, ++pval) { csum ^= *pval; }
		return csum;
	}

protected:
	in_addr_t	m_local_if;
	virtual void 	set_str();
};


#endif /* FLOW_TUPLE_H */
