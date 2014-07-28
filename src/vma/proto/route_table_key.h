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


#ifndef ROUTE_TABLE_KEY_H
#define ROUTE_TABLE_KEY_H

#include <stdio.h>
#include <string>

#include "vma/util/to_str.h"
#include "vma/util/vtypes.h"
#include <tr1/unordered_map>

/*
* This class is used as key for route table cashed history
* and its consist from destination IP and table ID.
*/
class route_table_key : public tostr
{
public:
	route_table_key(in_addr_t ip, unsigned char table_id): m_ip(ip), m_table_id(table_id){};
	~route_table_key(){};
	
	const std::string to_str() const
	{
		char s[40];
		sprintf(s, "Address :%d.%d.%d.%d Table :%u", NIPQUAD(m_ip), m_table_id);
		return(std::string(s));
	}
	
	in_addr_t 	get_in_addr() const 	{ return m_ip; };
	unsigned char 	get_table_id() const 	{ return m_table_id; };

	bool operator==(const route_table_key &rtk) const { 
	return (m_ip == rtk.get_in_addr() && m_table_id == rtk.get_table_id()); 
	};
	
private:
	in_addr_t 		m_ip;
	unsigned char	m_table_id;
};

namespace std { namespace tr1 {
template<>
class hash<route_table_key>
{
public:
	size_t operator()(const route_table_key &key) const
	{
		hash<string>hash;
		char s[25];
		// Build string from both destination IP and table ID which is unique for different route entries.
		sprintf(s, "%d.%d.%d.%d %u", NIPQUAD(key.get_in_addr()),key.get_table_id());
		return hash(std::string(s));// Use built in hash function for string input.
	}
};
}}


#endif /* ROUTE_TABLE_KEY_H */
