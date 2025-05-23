/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef ROUTE_VAL_H
#define ROUTE_VAL_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include "utils/bullseye.h"

#define BUFF_SIZE 255

class route_val
{
public:
	route_val();
	virtual ~route_val() {};

	inline void set_dst_addr(in_addr_t const &dst_addr) 	{ m_dst_addr = dst_addr; };
	inline void set_dst_mask(in_addr_t const &dst_mask) 	{ m_dst_mask = dst_mask; };
	inline void set_dst_pref_len(uint8_t dst_pref_len) 	{ m_dst_pref_len = dst_pref_len; };
	inline void set_src_addr(in_addr_t const &src_addr) 	{ m_src_addr = src_addr; };
	inline void set_gw(in_addr_t const &gw) 		{ m_gw = gw; };
	inline void set_protocol(unsigned char protocol) 	{ m_protocol = protocol; };
	inline void set_scope(unsigned char scope) 		{ m_scope = scope; };
	inline void set_type(unsigned char type) 		{ m_type = type; };
	inline void set_table_id(uint32_t table_id)		{ m_table_id = table_id; };
	void set_mtu(uint32_t mtu);
	inline void set_if_index(int if_index)			{ m_if_index = if_index; };
	inline void set_if_name(char *if_name) 			{ memcpy(m_if_name, if_name, IFNAMSIZ); };
	void 	set_str();

	inline in_addr_t 	get_dst_addr()	const		{ return m_dst_addr; };
	inline in_addr_t 	get_dst_mask() const		{ return m_dst_mask; };
	inline uint8_t 		get_dst_pref_len() const	{ return m_dst_pref_len; };
	inline in_addr_t 	get_src_addr() const		{ return m_src_addr; };
	inline in_addr_t 	get_gw_addr() const		{ return m_gw; };
	inline unsigned char 	get_protocol() const		{ return m_protocol; };
	inline unsigned char 	get_scope() const		{ return m_scope; };
	inline unsigned char 	get_type() const		{ return m_type; };
	inline uint32_t 	get_table_id() const		{ return m_table_id; };
	inline int 		get_if_index() const		{ return m_if_index; };
	inline const char* 	get_if_name() const		{ return m_if_name; };
	inline uint32_t		get_mtu() const			{ return m_mtu; };

	inline void set_state(bool state) 			{ m_is_valid = state; };
	inline bool is_valid() const		 		{ return m_is_valid; };

	inline bool is_deleted() const		 		{ return m_b_deleted; };

	inline bool is_if_up() const		 		{ return m_b_if_up; };

	void 	print_val();
	char* 	to_str() { return m_str; };

private:

	union {
		in_addr_t 	m_dst_addr;
		in_addr 	m_dst_addr_in_addr;
	};
	union {
		in_addr_t 	m_dst_mask;
		in_addr 	m_dst_mask_in_addr;
	};
	uint8_t 	m_dst_pref_len;
	union {
		in_addr_t 	m_src_addr;
		in_addr 	m_src_addr_in_addr;
	};
	union {
		in_addr_t 	m_gw;
		in_addr 	m_gw_in_addr;
	};

	unsigned char	m_protocol;
	unsigned char	m_scope;
	unsigned char	m_type;
	uint32_t	m_table_id;

	char 		m_if_name[IFNAMSIZ];
	int 		m_if_index;

	bool 		m_is_valid;
	bool 		m_b_deleted;
	bool 		m_b_if_up;
	uint32_t	m_mtu;
	char 		m_str[BUFF_SIZE]; // Nice str to represent route_val
};

#endif /* ROUTE_VAL_H */
