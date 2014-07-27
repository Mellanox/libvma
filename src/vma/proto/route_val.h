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


#ifndef ROUTE_VAL_H
#define ROUTE_VAL_H

#include <netinet/in.h>
#include <arpa/inet.h>

#include "vma/dev/net_device_val.h"
#include "vma/dev/net_device_table_mgr.h"

#define BUFF_SIZE 255

class route_val : public cache_observer
{
public:
	route_val();
	virtual ~route_val() {};

	inline void set_dst_addr(in_addr_t const &dst_addr) 	{ m_dst_addr = dst_addr; };
	inline void set_dst_mask(in_addr_t const &dst_mask) 	{ m_dst_mask = dst_mask; };
	inline void set_dst_pref_len(uint8_t dst_pref_len) 	{ m_dst_pref_len = dst_pref_len; };
	inline void set_src_addr(in_addr_t const &src_addr) 	{ m_src_addr = src_addr; };
	inline void set_gw(in_addr_t const &gw) 		{ m_gw = gw; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	inline void set_protocol(unsigned char protocol) 	{ m_protocol = protocol; };
	inline void set_scope(unsigned char scope) 		{ m_scope = scope; };
	inline void set_type(unsigned char type) 		{ m_type = type; };
	inline void set_table_id(unsigned char table_id)	{ m_table_id = table_id; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	inline void set_if_index(int if_index)			{ m_if_index = if_index; };
	inline void set_if_name(char *if_name) 			{ memcpy(m_if_name, if_name, IF_NAMESIZE); };
	void 	set_str();

	inline in_addr_t 	get_dst_addr()	const		{ return m_dst_addr; };
	inline in_addr_t 	get_dst_mask() const		{ return m_dst_mask; };
	inline uint8_t 		get_dst_pref_len() const	{ return m_dst_pref_len; };
	inline in_addr_t 	get_src_addr() const		{ return m_src_addr; };
	inline in_addr_t 	get_gw_addr() const		{ return m_gw; };
	inline unsigned char 	get_protocol() const		{ return m_protocol; };
	inline unsigned char 	get_scope() const		{ return m_scope; };
	inline unsigned char 	get_type() const		{ return m_type; };
	inline unsigned char 	get_table_id() const		{ return m_table_id; };
	inline int 		get_if_index() const		{ return m_if_index; };
	inline const char* 	get_if_name() const		{ return m_if_name; };

	inline void set_state(bool state) 			{ m_is_valid = state; };
	inline bool is_valid() const		 		{ return m_is_valid; };

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	inline void set_deleted()			 	{ m_b_deleted = true; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	inline bool is_deleted() const		 		{ return m_b_deleted; };

	inline bool is_if_up() const		 		{ return m_b_if_up; };

	void 	print_val();
	char* 	to_str() { return m_str; };

private:

	in_addr_t 	m_dst_addr;
	in_addr_t 	m_dst_mask;
	uint8_t 	m_dst_pref_len;
	in_addr_t 	m_src_addr;
	in_addr_t 	m_gw;

	unsigned char	m_protocol;
	unsigned char	m_scope;
	unsigned char	m_type;
	unsigned char	m_table_id;

	char 		m_if_name[IF_NAMESIZE];
	int 		m_if_index;

	bool 		m_is_valid;
	bool 		m_b_deleted;
	bool 		m_b_if_up;

	char 		m_str[BUFF_SIZE]; // Nice str to represent route_val
};

#endif /* ROUTE_VAL_H */
