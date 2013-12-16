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
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	sock_addr(struct sockaddr& other) : m_sa(other), m_p_sa_in((struct sockaddr_in*)&m_sa) { m_str[0]='\0'; m_str_in_addr[0]='\0'; m_str_in_port[0]='\0'; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	// coverity[uninit_member]
	sock_addr(const struct sockaddr* other) : m_sa(*other), m_p_sa_in((struct sockaddr_in*)&m_sa) { m_str[0]='\0'; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	sock_addr(struct sockaddr_in other) : m_sa(*(struct sockaddr*)&other), m_p_sa_in((struct sockaddr_in*)&m_sa) { m_str[0]='\0'; m_str_in_addr[0]='\0'; m_str_in_port[0]='\0'; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	sock_addr(sa_family_t f, in_addr_t a, in_port_t p) : m_p_sa_in((struct sockaddr_in*)&m_sa)
		{ memset(m_p_sa_in, 0, get_socklen()); set_sa_family(f); set_in_addr(a); set_in_port(p); m_str[0]='\0'; m_str_in_addr[0]='\0'; m_str_in_port[0]='\0'; };
	virtual ~sock_addr() {};

	struct sockaddr* get_p_sa() { return &m_sa; }
	void 		get_sa(struct sockaddr* p_sa) { memcpy(p_sa, &m_sa, get_socklen()); }
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	void 		get_sa(struct sockaddr& r_sa) { memcpy(&r_sa, &m_sa, get_socklen()); }
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	void 		get_sa(struct sockaddr_in& r_sa_in) { memcpy(&r_sa_in, &m_sa, get_socklen()); }

	sa_family_t 	get_sa_family() { struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa; return p_sa_in->sin_family; }
	in_addr_t 	get_in_addr() { struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa; return p_sa_in->sin_addr.s_addr; }
	in_port_t 	get_in_port() { struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa; return p_sa_in->sin_port; }
	socklen_t 	get_socklen() {return sizeof(struct sockaddr); };

	bool 		is_anyaddr() { return (INADDR_ANY == m_p_sa_in->sin_addr.s_addr); };
	bool 		is_mc() { return (IN_MULTICAST_N(m_p_sa_in->sin_addr.s_addr)); };

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	bool 		is_bc() { return (IS_BROADCAST_N(m_p_sa_in->sin_addr.s_addr)); };
	bool 		is_local_loopback() { return (LOOPBACK_N(m_p_sa_in->sin_addr.s_addr)); };
	bool 		is_anyport() { return (INPORT_ANY == m_p_sa_in->sin_port); };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif


	void 		set(struct sockaddr& sa) { m_sa = sa; }
	void 		set_sa_family(sa_family_t family) { (*(struct sockaddr_in*)&m_sa).sin_family = family; }
	void 		set_in_addr(in_addr_t in_addr) { (*(struct sockaddr_in*)&m_sa).sin_addr.s_addr = in_addr;}
	void 		set_in_port(in_port_t in_port) { (*(struct sockaddr_in*)&m_sa).sin_port = in_port;}

	virtual bool operator==(sock_addr const& other) const
	{
		struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa;
		struct sockaddr_in* p_sa_in_other = (struct sockaddr_in*)&other.m_sa;

		return 	(p_sa_in->sin_port == p_sa_in_other->sin_port) &&
			(p_sa_in->sin_addr.s_addr == p_sa_in_other->sin_addr.s_addr) &&
			(p_sa_in->sin_family == p_sa_in_other->sin_family);
	}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual bool operator <(sock_addr const& other) const
	{
		struct sockaddr_in* p_sa_in = (struct sockaddr_in*)&m_sa;
		struct sockaddr_in* p_sa_in_other = (struct sockaddr_in*)&other.m_sa;

		if (p_sa_in->sin_port < p_sa_in_other->sin_port)		return true;
		if (p_sa_in->sin_port > p_sa_in_other->sin_port)		return false;
		if (p_sa_in->sin_addr.s_addr < p_sa_in_other->sin_addr.s_addr)	return true;
		if (p_sa_in->sin_addr.s_addr > p_sa_in_other->sin_addr.s_addr)	return false;
		if (p_sa_in->sin_family < p_sa_in_other->sin_family)		return true;
		return false;
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	virtual size_t hash(void)
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
	struct sockaddr 	m_sa;
	struct sockaddr_in* 	m_p_sa_in;

	char			m_str_in_addr[16];
	char			m_str_in_port[6];
	char			m_str[22];

	void 		set_str_in_addr() { sprintf(m_str_in_addr, "%d.%d.%d.%d", NIPQUAD(get_in_addr())); set_str(); }
	void 		set_str_in_port() { sprintf(m_str_in_port, "%d", ntohs(get_in_port())); set_str(); }
	void            set_str() { sprintf(m_str, "%d.%d.%d.%d:%d", NIPQUAD(get_in_addr()), ntohs(get_in_port())); };
};

static inline sa_family_t get_sa_family(const struct sockaddr* addr)
{
   	return ((struct sockaddr_in*)addr)->sin_family;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
static inline sa_family_t get_sa_family(const struct sockaddr& addr)
{
   	return ((struct sockaddr_in*)&addr)->sin_family;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
static inline in_port_t get_sa_port(const struct sockaddr& addr)
{
   	return ((struct sockaddr_in*)&addr)->sin_port;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

#endif /*SOCK_ADDR_H*/
