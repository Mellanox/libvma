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
	memcpy(m_str, ft.m_str, STR_MAX_LENGTH);

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
//*/

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
	snprintf(m_str, STR_MAX_LENGTH, "dst:%d.%d.%d.%d:%d, src:%d.%d.%d.%d:%d, protocol:%s",
			NIPQUAD(m_dst_ip), ntohs(m_dst_port),
			NIPQUAD(m_src_ip), ntohs(m_src_port),
			__vma_get_protocol_str(m_protocol));
}





void flow_tuple_with_local_if::set_str()
{
	snprintf(m_str, STR_MAX_LENGTH, "dst:%d.%d.%d.%d:%d, src:%d.%d.%d.%d:%d, protocol:%s, local if:%d.%d.%d.%d",
			NIPQUAD(m_dst_ip), ntohs(m_dst_port),
			NIPQUAD(m_src_ip), ntohs(m_src_port),
			__vma_get_protocol_str(m_protocol), NIPQUAD(m_local_if));
};
