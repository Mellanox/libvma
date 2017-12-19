/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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
#include <linux/netlink.h>

#include "utils/bullseye.h"

// old linux not all metrices supported
#ifndef RTAX_INITRWND
# define RTAX_INITRWND		(14)
# define RTAX_CC_ALGO		(0) // to pass assignment lwip_cc_algo_mod
# define VMA_RT_METRIC_MAX	(RTAX_MAX)
#elif !defined(RTAX_CC_ALGO)
# define RTAX_CC_ALGO		(0)
# define VMA_RT_METRIC_MAX	(RTAX_MAX)
#else
# define VMA_RT_METRIC_MAX	(RTAX_CC_ALGO + 1)
#endif

#define ROUTE_BUFF_SIZE	(512)

/* types of different cc algorithms */
enum cc_algo_mod {
	CC_MOD_LWIP,
	CC_MOD_CUBIC,
	CC_MOD_NONE
};


static inline const char* lwip_cc_algo_str(uint32_t algo)
{
	switch (algo) {
	case CC_MOD_CUBIC:	return "(CUBIC)";
	case CC_MOD_NONE:	return "(NONE)";
	case CC_MOD_LWIP:
	default:		return "(LWIP)";
	}
}

class route_val
{
public:
	route_val();
	virtual ~route_val() {};
	static const char* get_rtax_name(int attr);
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
	inline void set_metric(int attr, uint32_t val)		{ if (attr < VMA_RT_METRIC_MAX) m_metric[attr] = val; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
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
	inline unsigned char 	get_table_id() const		{ return m_table_id; };
	inline int 		get_if_index() const		{ return m_if_index; };
	inline const char* 	get_if_name() const		{ return m_if_name; };
	uint32_t		get_mtu() const;
	uint32_t		get_advmss() const;
	inline uint32_t		get_metric(int attr) const	{ return attr < VMA_RT_METRIC_MAX ? m_metric[attr] : 0; };
	inline bool		is_attr_lock(int attr) const	{ return m_metric[RTAX_LOCK] & (1 << attr); };

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
	unsigned char	m_table_id;

	char 		m_if_name[IFNAMSIZ];
	int 		m_if_index;

	bool 		m_is_valid;
	bool 		m_b_deleted;
	bool 		m_b_if_up;
	uint32_t	m_metric[VMA_RT_METRIC_MAX];
	char 		m_str[ROUTE_BUFF_SIZE]; // Nice str to represent route_val
};

#endif /* ROUTE_VAL_H */
