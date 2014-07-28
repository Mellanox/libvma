/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef RULE_TABLE_KEY_H
#define RULE_TABLE_KEY_H

#include <stdio.h>
#include <string>

#include "vma/util/to_str.h"
#include "vma/util/vtypes.h"
#include <tr1/unordered_map>

/*
* This class is used as key for rule table cashed history
* and its consist from destination IP, source IP and TOS.
*/
class rule_table_key : public tostr
{
public:
	rule_table_key(in_addr_t dst_ip, in_addr_t src_ip, uint8_t tos): m_dst_ip(dst_ip), m_src_ip(src_ip), m_tos(tos){};
	~rule_table_key(){};
	
	const std::string to_str() const
	{
		char s[100];
		sprintf(s, "Destination IP:%d.%d.%d.%d", NIPQUAD(m_dst_ip));
		if (m_src_ip)
			sprintf(s, "%s Source IP:%d.%d.%d.%d", s, NIPQUAD(m_src_ip));	
		if (m_tos)
			sprintf(s, "%s TOS:%u", s, m_tos);
			
		return(std::string(s));
	}
	
	in_addr_t	get_dst_ip()	const 	{ return m_dst_ip; };
	in_addr_t	get_src_ip()	const 	{ return m_src_ip; };
	uint8_t		get_tos()		const 	{ return m_tos; };

	bool operator==(const rule_table_key &rrk) const { 
	return (m_dst_ip == rrk.get_dst_ip() && m_src_ip == rrk.get_src_ip() && m_tos == rrk.get_tos()); 
	};
	
private:
	in_addr_t	m_dst_ip;
	in_addr_t	m_src_ip;
	uint8_t		m_tos;
};

namespace std { namespace tr1 {
template<>
class hash<rule_table_key>
{
public:
	size_t operator()(const rule_table_key &key) const
	{
		hash<string>hash;
		char s[40];
		/*
		Build string from exist parameter (destination IP, source IP, TOS)
		which is unique for different rule entries.
		*/
		sprintf(s, "%d.%d.%d.%d", NIPQUAD(key.get_dst_ip()));
		if (key.get_src_ip())
			sprintf(s, "%s %d.%d.%d.%d", s, NIPQUAD(key.get_src_ip()));	
		if (key.get_tos())
			sprintf(s, "%s %u", s, key.get_tos());		
		return hash(std::string(s));// Use built in hash function for string input.
	}
};
}}


#endif /* RULE_TABLE_KEY_H */
