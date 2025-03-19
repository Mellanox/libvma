/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef ROUTE_RULE_TABLE_KEY_H
#define ROUTE_RULE_TABLE_KEY_H

#include <stdio.h>
#include <string>
#include <cstring>

#include "vma/util/to_str.h"
#include "vma/util/vtypes.h"

/*
* This class is used as key for route and rule table cashed history
* and its consist from destination IP, source IP and TOS.
*/
class route_rule_table_key : public tostr
{
public:
	route_rule_table_key(in_addr_t dst_ip, in_addr_t src_ip, uint8_t tos): m_dst_ip(dst_ip), m_src_ip(src_ip), m_tos(tos){};
	~route_rule_table_key(){};
	
	const std::string to_str() const
	{
		char s[100] = {0};
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		sprintf(s, "Destination IP:%d.%d.%d.%d", NIPQUAD(m_dst_ip));
		if (m_src_ip) {
			char sx[40] = {0};
			/* cppcheck-suppress wrongPrintfScanfArgNum */
			sprintf(sx, " Source IP:%d.%d.%d.%d", NIPQUAD(m_src_ip));
			strcat(s, sx);
		}	
		if (m_tos) {
			char sx[20] = {0};
			sprintf(sx, " TOS:%u", m_tos);
			strcat(s, sx);
		}
			
		return(std::string(s));
	}
	
	in_addr_t	get_dst_ip()	const 	{ return m_dst_ip; };
	in_addr_t	get_src_ip()	const 	{ return m_src_ip; };
	uint8_t		get_tos()		const 	{ return m_tos; };

	bool operator==(const route_rule_table_key &rrk) const { 
	return (m_dst_ip == rrk.get_dst_ip() && m_src_ip == rrk.get_src_ip() && m_tos == rrk.get_tos()); 
	};
	
private:
	in_addr_t	m_dst_ip;
	in_addr_t	m_src_ip;
	uint8_t		m_tos;
};

namespace std {
template<>
class hash<route_rule_table_key>
{
public:
	size_t operator()(const route_rule_table_key &key) const
	{
		hash<uint64_t>_hash;
		uint64_t val;

		val = ((uint64_t)key.get_dst_ip() << 32ULL) |
			((uint64_t)key.get_src_ip() ^
			((uint64_t)key.get_tos() << 24ULL));
		return _hash(val);
	}
};
}


#endif /* ROUTE_RULE_TABLE_KEY_H */
