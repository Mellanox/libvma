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


#ifndef _IP_FRAG_H
#define _IP_FRAG_H

/**
 * IP reassembly is based on algorithm described in RFC815
 */

#include <map>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/time.h>

#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include <vma/util/vtypes.h>
#include <vma/util/sys_vars.h>
#include <vma/event/timer_handler.h>
#include <vma/dev/buffer_pool.h>

class mem_buf_desc_t;
class event_handler_manager;
class mem_buf_desc_owner;

#define IP_FRAG_FREED		((size_t)-1)

#define IP_FRAG_MAX_DESC	1024 	/* maximum number of preallocated descriptors */
#define IP_FRAG_MAX_HOLES	16000 	/* maximum number of preallocated holes       */
#define IP_FRAG_TTL		2 	/* default unassembled fragment time to live in ticks */
#define IP_FRAG_INF 		0xFFFF
#define IP_FRAG_NINF  		0x0
#define IP_FRAG_SPACE 		60000
#define IP_FRAG_CLEANUP_INT	10

struct ip_frag_key_t {
	uint16_t  ip_id;
	in_addr_t src_ip;
	in_addr_t dst_ip;
	uint8_t	  ipproto;
};


inline bool
operator<( ip_frag_key_t const& a, ip_frag_key_t const& b)
{
	if (a.ip_id < b.ip_id)
		return true;

	if (a.ip_id > b.ip_id)
		return false;

	if (a.src_ip < b.src_ip)
		return true;

	if (a.src_ip > b.src_ip)
		return false;

	if (a.dst_ip < b.dst_ip)
		return true;

	if (a.dst_ip > b.dst_ip)
		return false;

	if (a.ipproto < b.ipproto)
		return true;

	if (a.ipproto > b.ipproto)
		return false;

	return false;
}

struct ip_frag_hole_desc {
	uint16_t			first;
	uint16_t			last;
	mem_buf_desc_t			*data_first;
	mem_buf_desc_t			*data_last;
	struct ip_frag_hole_desc	*next;
};

typedef struct ip_frag_desc {
	uint16_t			ttl;
	uint16_t			pkt_size;
	struct ip_frag_hole_desc 	*hole_list;
	mem_buf_desc_t 			*frag_list;
	int64_t				frag_counter;
	struct ip_frag_desc		*next;
} ip_frag_desc_t;

typedef std::map<ip_frag_key_t, ip_frag_desc_t *, std::less<ip_frag_key_t> > ip_frags_list_t;
typedef std::map<ring_slave*, mem_buf_desc_t*> owner_desc_map_t;

class ip_frag_manager : private lock_spin, public timer_handler
{
public:
	ip_frag_manager();
	~ip_frag_manager();
	/**
	 * add fragment to the list.
	 * Return:
	 * 0 if finished OK
	 * 		- if the packet is complete - put the pointer to the first fragment of the packet in ret.
	 * 		  Rest of the packet fragments are linked in order.
	 * 		- if we need more fragments - put NULL in ret.
	 * -1 if finished with error and this packet needs to be droped
	 */
	int add_frag(iphdr *hdr, mem_buf_desc_t *frag, mem_buf_desc_t **ret);

	uint64_t	m_frag_counter;

private:
	ip_frags_list_t			m_frags;

	// Map of buffers to return, by owner
	owner_desc_map_t		m_return_descs;


	/**
	 * first fragment for given address is detected - setup
	 */
	ip_frag_desc_t*		new_frag_desc(ip_frag_key_t &key);
	void			print_statistics();
	void			return_buffers_to_owners(const owner_desc_map_t &buff_map);
	void			free_frag(mem_buf_desc_t *frag);
	ip_frag_hole_desc* 	alloc_hole_desc();
	void			free_hole_desc(struct ip_frag_hole_desc *p);
	ip_frag_desc_t*		alloc_frag_desc();
	void			free_frag_desc(ip_frag_desc_t *p);
	void			destroy_frag_desc(ip_frag_desc_t *desc);

	virtual void    	handle_timer_expired(void* user_data);

	void			free_frag_resources(void);
};

extern ip_frag_manager * g_p_ip_frag_manager;

#endif
