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


#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include <stdio.h>
#include "vma/util/to_str.h"
#include "vma/util/vtypes.h"
#include <tr1/unordered_map>

class ip_address : public tostr
{
public:
	ip_address(in_addr_t ip): m_ip(ip){};
	~ip_address(){};

	const std::string to_str() const
	{
		char s[20];
		sprintf(s, "%d.%d.%d.%d", NIPQUAD(m_ip));
		return(std::string(s));
	}

	in_addr_t 	get_in_addr() const { return m_ip; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	in_addr_t 	get_actual_key() { return get_in_addr(); };
	bool		is_anyaddr() { return (INADDR_ANY == m_ip); };
	bool 		is_mc() { return (IN_MULTICAST_N(m_ip)); };
	bool 		is_local_loopback() { return (LOOPBACK_N(m_ip)); };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	bool operator==(const ip_address &ip) const { return (m_ip == ip.get_in_addr()); };

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	bool operator<(const ip_address &ip) const { return (m_ip < ip.get_in_addr()); };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

private:
	in_addr_t m_ip;
};

namespace std { namespace tr1 {
template<>
class hash<ip_address>
{
public:
	size_t operator()(const ip_address &key) const
	{
		hash<int>hash;
		return hash(key.get_in_addr());
	}
};
}}


#endif /* IP_ADDRESS_H */
