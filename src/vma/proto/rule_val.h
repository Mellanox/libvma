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


#ifndef RULE_VAL_H
#define RULE_VAL_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include "vma/util/if.h"
#include "vma/infra/cache_subject_observer.h"

#define BUFF_SIZE 255

/*
This class will contain information for given routing rule entry.
*/
class rule_val : public cache_observer
{
public:
	rule_val();
	virtual ~rule_val() {};

	inline void set_dst_addr(in_addr_t const &dst_addr) 	{ m_dst_addr = dst_addr; };
	inline void set_src_addr(in_addr_t const &src_addr) 	{ m_src_addr = src_addr; };
	inline void set_protocol(unsigned char protocol) 	{ m_protocol = protocol; };
	inline void set_scope(unsigned char scope) 		{ m_scope = scope; };
	inline void set_type(unsigned char type) 		{ m_type = type; };
	inline void set_tos(unsigned char tos) 			{ m_tos = tos; };
	inline void set_table_id(uint32_t table_id) 		{ m_table_id = table_id; };
	inline void set_iif_name(char *iif_name) 		{ memcpy(m_iif_name, iif_name, IFNAMSIZ); };
	inline void set_oif_name(char *oif_name) 		{ memcpy(m_oif_name, oif_name, IFNAMSIZ); };
	inline void set_priority(uint32_t priority) 		{ m_priority = priority; };

	void 	set_str();

	inline in_addr_t	get_dst_addr()	const		{ return m_dst_addr; };
	inline in_addr_t	get_src_addr() const		{ return m_src_addr; };
	inline unsigned char	get_tos() const		   	{ return m_tos; };
	inline uint32_t 	get_table_id() const		{ return m_table_id; };
	inline const char*  	get_iif_name() const		{ return m_iif_name; };
	inline const char*  	get_oif_name() const		{ return m_oif_name; };

	inline void set_state(bool state) 			{ m_is_valid = state; };
	inline bool is_valid() const		 		{ return m_is_valid; };

	void 	print_val();
	char* 	to_str() { return m_str; };

private:

	unsigned char	m_protocol;
	unsigned char	m_scope;
	unsigned char	m_type;
	unsigned char	m_tos;

	union {
		in_addr_t 	m_dst_addr;
		in_addr 	m_dst_addr_in_addr;
	};
	union {
		in_addr_t 	m_src_addr;
		in_addr 	m_src_addr_in_addr;
	};
	char 		m_iif_name[IFNAMSIZ];
	char 		m_oif_name[IFNAMSIZ];
	uint32_t	m_priority;
	uint32_t	m_table_id;
	
	bool 		m_is_valid;
	
	char 		m_str[BUFF_SIZE];
};

#endif /* RULE_VAL_H */
