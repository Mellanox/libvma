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


#ifndef RULE_VAL_H
#define RULE_VAL_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
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
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	inline void set_protocol(unsigned char protocol) 	{ m_protocol = protocol; };
	inline void set_scope(unsigned char scope) 		{ m_scope = scope; };
	inline void set_type(unsigned char type) 		{ m_type = type; };
	inline void set_tos(unsigned char tos) 			{ m_tos = tos; };
	inline void set_table_id(unsigned char table_id) 	{ m_table_id = table_id; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	inline void set_iif_name(char *iif_name) 		{ memcpy(m_iif_name, iif_name, IF_NAMESIZE); };
	inline void set_oif_name(char *oif_name) 		{ memcpy(m_oif_name, oif_name, IF_NAMESIZE); };
	inline void set_priority(uint32_t priority) 		{ m_priority = priority; };

	void 	set_str();

	inline in_addr_t	get_dst_addr()	const		{ return m_dst_addr; };
	inline in_addr_t	get_src_addr() const		{ return m_src_addr; };
	inline unsigned char 	get_protocol() const		{ return m_protocol; };
	inline unsigned char 	get_scope() const		{ return m_scope; };
	inline unsigned char 	get_type() const	   	{ return m_type; };
	inline unsigned char	get_tos() const		   	{ return m_tos; };
	inline unsigned char 	get_table_id() const		{ return m_table_id; };
	inline const char*  	get_iif_name() const		{ return m_iif_name; };
	inline const char*  	get_oif_name() const		{ return m_oif_name; };
	inline uint32_t     	get_priority() const		{ return m_priority; };

	inline void set_state(bool state) 			{ m_is_valid = state; };
	inline bool is_valid() const		 		{ return m_is_valid; };

	void 	print_val();
	char* 	to_str() { return m_str; };

private:

	unsigned char	m_protocol;
	unsigned char	m_scope;
	unsigned char	m_type;
	unsigned char	m_tos;

	in_addr_t 	m_dst_addr;
	in_addr_t 	m_src_addr;
	char 		m_iif_name[IF_NAMESIZE];
	char 		m_oif_name[IF_NAMESIZE];
	uint32_t	m_priority;
	unsigned char	m_table_id;
	
	bool 		m_is_valid;
	
	char 		m_str[BUFF_SIZE];
};

#endif /* RULE_VAL_H */
