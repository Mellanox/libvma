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
 */


#ifndef SOCK_ADDR_H
#define SOCK_ADDR_H

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "vma/util/vtypes.h"

class sock_addr
{
public:
	sock_addr() : m_p_sa_in((struct sockaddr_in*)&m_sa) { memset(m_p_sa_in, 0, get_socklen()); m_str[0]='\0'; m_str_in_addr[0]='\0'; m_str_in_port[0]='\0';  };

	// coverity[uninit_member]
	sock_addr(const struct sockaddr* other) : m_sa(*other), m_p_sa_in((struct sockaddr_in*)&m_sa) { m_str[0]='\0'; };
	sock_addr(sa_family_t f, in_addr_t a, in_port_t p) : m_p_sa_in((struct sockaddr_in*)&m_sa)
		{ memset(m_p_sa_in, 0, get_socklen()); set_sa_family(f); set_in_addr(a); set_in_port(p); m_str[0]='\0'; m_str_in_addr[0]='\0'; m_str_in_port[0]='\0'; };
	~sock_addr() {};

	struct sockaddr* get_p_sa() { return &m_sa; }
	void 		get_sa(struct sockaddr* p_sa, size_t size) { memcpy(p_sa, &m_sa, std::min<size_t>(get_socklen(), size)); }
	void 		get_sa(struct sockaddr_in& r_sa_in) { memcpy(&r_sa_in, &m_sa, get_socklen()); }

	sa_family_t 	get_sa_family() { struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa; return p_sa_in->sin_family; }
	in_addr_t 	get_in_addr() { struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa; return p_sa_in->sin_addr.s_addr; }
	in_port_t 	get_in_port() { struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa; return p_sa_in->sin_port; }
	socklen_t 	get_socklen() {return sizeof(struct sockaddr); };

	bool 		is_anyaddr() { return (INADDR_ANY == m_p_sa_in->sin_addr.s_addr); };
	bool 		is_mc() { return (IN_MULTICAST_N(m_p_sa_in->sin_addr.s_addr)); };

	void 		set(struct sockaddr& sa) { m_sa = sa; }
	void 		set_sa_family(sa_family_t family) { m_sa_in.sin_family = family; }
	void 		set_in_addr(in_addr_t in_addr) { m_sa_in.sin_addr.s_addr = in_addr;}
	void 		set_in_port(in_port_t in_port) { m_sa_in.sin_port = in_port;}

	sock_addr& operator=(const sock_addr& other) {
		m_sa = other.m_sa;
		m_p_sa_in = (struct sockaddr_in*)&m_sa;
		m_str[0]='\0';
		m_str_in_addr[0]='\0';
		m_str_in_port[0]='\0';
		return *this;
	}

	bool operator==(sock_addr const& other) const
	{
		struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa;
		struct sockaddr_in* p_sa_in_other = (struct sockaddr_in*)&other.m_sa;

		return 	(p_sa_in->sin_port == p_sa_in_other->sin_port) &&
			(p_sa_in->sin_addr.s_addr == p_sa_in_other->sin_addr.s_addr) &&
			(p_sa_in->sin_family == p_sa_in_other->sin_family);
	}

	size_t hash(void)
	{
		uint8_t csum = 0;
		uint8_t* pval = (uint8_t*)this;
		for (size_t i = 0; i < (sizeof(struct sockaddr)); ++i, ++pval) { csum ^= *pval; }
			return csum;
	}

	char*		to_str_in_addr() { set_str_in_addr(); return m_str_in_addr; };
	char*		to_str_in_port() { set_str_in_port(); return m_str_in_port; };
	char*		to_str()         { set_str_in_addr(); set_str_in_port(); set_str(); return m_str; };

private:
	union  {
		struct sockaddr 	m_sa;
		struct sockaddr_in 	m_sa_in;
	};

	struct sockaddr_in* 	m_p_sa_in;

	char			m_str_in_addr[16];
	char			m_str_in_port[6];
	char			m_str[22];

	/* cppcheck-suppress wrongPrintfScanfArgNum */
	void 		set_str_in_addr() { sprintf(m_str_in_addr, "%d.%d.%d.%d", NIPQUAD(get_in_addr())); set_str(); }
	void 		set_str_in_port() { sprintf(m_str_in_port, "%d", ntohs(get_in_port())); set_str(); }
	/* cppcheck-suppress wrongPrintfScanfArgNum */
	void            set_str() { sprintf(m_str, "%d.%d.%d.%d:%d", NIPQUAD(get_in_addr()), ntohs(get_in_port())); };
};

static inline sa_family_t get_sa_family(const struct sockaddr* addr)
{
   	return ((struct sockaddr_in*)addr)->sin_family;
}

static inline in_addr_t get_sa_ipv4_addr(const struct sockaddr* addr)
{
   	return ((struct sockaddr_in*)addr)->sin_addr.s_addr;
}

static inline in_addr_t get_sa_ipv4_addr(const struct sockaddr& addr)
{
   	return ((struct sockaddr_in*)&addr)->sin_addr.s_addr;
}

static inline in_port_t get_sa_port(const struct sockaddr* addr)
{
   	return ((struct sockaddr_in*)addr)->sin_port;
}

#endif /*SOCK_ADDR_H*/
