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



#include "flow_tuple.h"
#include <vma/util/vtypes.h>
#include <vlogger/vlogger.h>


#define MODULE_NAME "flow_tuple"


flow_tuple::flow_tuple() :
		m_dst_ip(INADDR_ANY), m_src_ip(INADDR_ANY), m_dst_port(INPORT_ANY), m_src_port(INPORT_ANY), m_protocol(PROTO_UNDEFINED)
{
	m_str[0] = '\0';
}

flow_tuple::flow_tuple(sock_addr& dst, sock_addr& src, in_protocol_t protocol)
{
	m_protocol = protocol;
	m_dst_ip = dst.get_in_addr();
	m_dst_port = dst.get_in_port();
	m_src_ip = src.get_in_addr();
	m_src_port = src.get_in_port();
	set_str();
}

flow_tuple::flow_tuple(in_addr_t dst_ip, in_port_t dst_port, in_addr_t src_ip, in_port_t src_port, in_protocol_t protocol)
{
	m_protocol = protocol;
	m_dst_ip = dst_ip;
	m_dst_port = dst_port;
	m_src_ip = src_ip;
	m_src_port = src_port;
	set_str();
}

flow_tuple::flow_tuple(const flow_tuple &ft)
{
	m_protocol = ft.m_protocol;
	m_dst_ip = ft.m_dst_ip;
	m_dst_port = ft.m_dst_port;
	m_src_ip = ft.m_src_ip;
	m_src_port = ft.m_src_port;
	set_str();
}

flow_tuple& flow_tuple::operator=(const flow_tuple &ft)
{
	m_protocol = ft.m_protocol;
	m_dst_ip = ft.m_dst_ip;
	m_dst_port = ft.m_dst_port;
	m_src_ip = ft.m_src_ip;
	m_src_port = ft.m_src_port;
	memcpy(m_str, ft.m_str, sizeof(m_str));

	return *this;
}

/*
void flow_tuple::set_dst_ip(in_addr_t dst_ip)
{
	m_flow_tuple.local_if = m_dst_ip = dst_ip;
	set_str();
}

void flow_tuple::set_src_ip(in_addr_t src_ip)
{
	m_flow_tuple.peer_ip = m_src_ip = src_ip;
	set_str();
}

void flow_tuple::set_dst_port(in_port_t dst_port)
{
	m_flow_tuple.local_port = m_dst_port = dst_port;
	set_str();
}

void flow_tuple::set_src_port(in_port_t src_port)
{
	m_flow_tuple.peer_port = m_src_port = src_port;
	set_str();
}

void flow_tuple::set_protocol(in_protocol_t protocol)
{
	m_protocol = protocol;
	set_str();
}
*/

bool flow_tuple::is_tcp()
{
	return (m_protocol == PROTO_TCP);
}

bool flow_tuple::is_udp_uc()
{
	return ((m_protocol == PROTO_UDP) && !(IN_MULTICAST_N(m_dst_ip)));
}

bool flow_tuple::is_udp_mc()
{
	return ((m_protocol == PROTO_UDP) && (IN_MULTICAST_N(m_dst_ip)));
}

bool flow_tuple::is_local_loopback()
{
	return (LOOPBACK_N(m_dst_ip));
}

bool flow_tuple::is_5_tuple()
{
	return (m_src_ip != INADDR_ANY && m_src_port != INPORT_ANY);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

bool flow_tuple::is_3_tuple()
{
	return (m_src_ip == INADDR_ANY && m_src_port == INPORT_ANY);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void flow_tuple::set_str()
{
	/* cppcheck-suppress wrongPrintfScanfArgNum */
	snprintf(m_str, STR_MAX_LENGTH, "dst:%d.%d.%d.%d:%d, src:%d.%d.%d.%d:%d, protocol:%s",
			NIPQUAD(m_dst_ip), ntohs(m_dst_port),
			NIPQUAD(m_src_ip), ntohs(m_src_port),
			__vma_get_protocol_str(m_protocol));
}





void flow_tuple_with_local_if::set_str()
{
	/* cppcheck-suppress wrongPrintfScanfArgNum */
	snprintf(m_str, STR_MAX_LENGTH, "dst:%d.%d.%d.%d:%d, src:%d.%d.%d.%d:%d, protocol:%s, local if:%d.%d.%d.%d",
			NIPQUAD(m_dst_ip), ntohs(m_dst_port),
			NIPQUAD(m_src_ip), ntohs(m_src_port),
			__vma_get_protocol_str(m_protocol), NIPQUAD(m_local_if));
};
