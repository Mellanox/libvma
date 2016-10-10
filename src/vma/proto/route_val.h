/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef ROUTE_VAL_H
#define ROUTE_VAL_H


#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include <list>

#include "vma/dev/net_device_val.h"
#include "vma/dev/net_device_table_mgr.h"

#define BUFF_SIZE 255

struct nh_info_t
{
	uint8_t			weight;
	uint8_t			flags;
	uint32_t		oif_index;
	uint32_t		realm;
	in_addr_t		gw;
};
class route_val: public cache_observer
{
public:
	route_val();
	virtual ~route_val() {};

	inline void set_dst_addr(in_addr_t const &dst_addr)				{ m_dst_addr = dst_addr; };
	inline void set_src_addr(in_addr_t const &src_addr) 			{ m_src_addr = src_addr; };
	inline void set_gw(in_addr_t const &gw) 						{ m_gw = gw; };
	inline void set_pref_src_addr(in_addr_t const &pref_src_addr)	{ m_pref_src_addr = pref_src_addr; };
	
	inline void set_protocol(unsigned char protocol) 	{ m_protocol = protocol; };
	inline void set_scope(unsigned char scope) 			{ m_scope = scope; };
	inline void set_type(unsigned char type) 			{ m_type = type; };
	inline void set_tos(unsigned char tos) 				{ m_tos = tos; };
	inline void set_table_id(unsigned char table_id)	{ m_table_id = table_id; };
	inline void set_flags(unsigned int flags)			{ m_flags = flags; };
	inline void set_dst_len(uint8_t dst_len) 			{ m_dst_len = dst_len; };
	inline void set_src_len(uint8_t src_len)		 	{ m_src_len = src_len; };
	
	inline void set_iif_name(char *iif_name) 			{ memcpy(m_iif_name, iif_name, IFNAMSIZ); };
	inline void set_oif_name(char *oif_name) 			{ memcpy(m_oif_name, oif_name, IFNAMSIZ); };
	inline void set_oif_index(uint32_t oif_index)		{ m_oif_index = oif_index; };
	inline void set_priority(uint32_t priority)			{ m_priority = priority; };
	inline void set_realms(uint32_t realms)				{ m_realms = realms; };
	inline void add_nh(struct nh_info_t *nh)			{ m_nh_list.push_back(nh); };

	inline void set_state(bool state)	{ m_is_valid = state; };

	void 	set_str();
	void 	set_metric(int metric, uint32_t value);

	inline in_addr_t 	get_dst_addr()	const		{ return m_dst_addr; };
	inline in_addr_t 	get_src_addr() const		{ return m_src_addr; };
	inline in_addr_t 	get_gw_addr() const			{ return m_gw; };	
	inline in_addr_t 	get_pref_src_addr() const	{ return m_pref_src_addr; };

	inline unsigned char	get_protocol() const	{ return m_protocol; };
	inline unsigned char 	get_scope() const		{ return m_scope; };
	inline unsigned char 	get_type() const		{ return m_type; };
	inline unsigned char 	get_tos() const			{ return m_tos; };
	inline unsigned char	get_table_id() const	{ return m_table_id; };
	inline unsigned int		get_flags() const		{ return m_flags; };
	inline uint8_t 			get_src_len() const		{ return m_src_len; };
	inline uint8_t 			get_dst_len() const		{ return m_dst_len; };
	
	inline const char* 	get_iif_name() const	{ return m_iif_name; };
	inline const char* 	get_oif_name() const	{ return m_oif_name; };	
	inline uint32_t 	get_oif_index() const	{ return m_oif_index; };
	inline uint32_t 	get_priority() const	{ return m_priority; };
	inline uint32_t 	get_realms() const		{ return m_realms; };

	inline const std::list<struct nh_info_t *>&	get_nl_list() const	{ return m_nh_list; };

	inline bool is_valid() const	{ return m_is_valid; };
	char* 		to_str() 			{ return m_str; };

	uint32_t	get_metric(int metric) const;

	void 	print_val();

private:
	unsigned char	m_protocol;
	unsigned char	m_scope;
	unsigned char	m_type;
	unsigned char	m_tos;
	unsigned char	m_table_id;
	unsigned int	m_flags;
	uint8_t 		m_dst_len;
	uint8_t			m_src_len;

	
	union {
		in_addr_t 	m_dst_addr;
		in_addr 	m_dst_addr_in_addr;
	};
	union {
		in_addr_t 	m_src_addr;
		in_addr 	m_src_addr_in_addr;
	};
	union {
		in_addr_t 	m_gw;
		in_addr 	m_gw_in_addr;
	};
	in_addr_t 	m_pref_src_addr;
	
	char 		m_iif_name[IFNAMSIZ];
	char 		m_oif_name[IFNAMSIZ];	
	uint32_t 	m_oif_index;
	uint32_t	m_priority;
	uint32_t	m_realms;
	uint32_t	m_metrics[RTAX_MAX];
	
	std::list<struct nh_info_t *>	m_nh_list;
	
	bool 		m_is_valid;

	char 		m_str[BUFF_SIZE]; // Nice str to represent route_val

};

#endif /* ROUTE_VAL_H */
