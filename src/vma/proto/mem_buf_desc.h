/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef MEM_BUF_DESC_H
#define MEM_BUF_DESC_H

#include <netinet/in.h>
#include "utils/atomic.h"
#include "vma/util/vma_list.h"
#include "vma/lwip/pbuf.h"

class ring_slave;

struct timestamps_t
{
	struct timespec sw;
	struct timespec	hw;
};

/**
 * mem_buf_desc_t struct is used as the mapping of the wr_id in the wce to:
 * (1) p_desc_owner - to notify the owner of this mem_buf_desc of a completion of this WR
 *        Transmitting object (sockinfo) - reference counting for TX limit logic on TX completion
 *        Receiving object (ib_conn_mgr) - processing of the incoming ip packet on RX completion
 * (2) p_next_desc is used to link a few mem_buf_desc_t object on a list (free list,
 * 	TX fragment list, TX waiting completion signal list)
 * (3) p_buffer is the data buffer pointer (to be reused for TX or the ready
 * 	received data in TX)
 */
class mem_buf_desc_t {
public:
	mem_buf_desc_t(uint8_t *buffer, size_t size,  pbuf_free_custom_fn custom_free_function) :
		p_buffer(buffer), lkey(0), p_next_desc(0),
		p_prev_desc(0), sz_buffer(size), sz_data(0),
		p_desc_owner(0) {
		memset(&lwip_pbuf, 0, sizeof(lwip_pbuf));
		memset(&rx, 0, sizeof(rx));
		memset(&tx, 0, sizeof(tx));
		reset_ref_count();

		lwip_pbuf.custom_free_function = custom_free_function;
	}

	struct pbuf_custom lwip_pbuf;	//Do not change the location of this field.
	uint8_t* const	p_buffer;

	static inline size_t buffer_node_offset(void) {return NODE_OFFSET(mem_buf_desc_t, buffer_node);}
	list_node<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> buffer_node;

	union {
		struct {
			sockaddr_in	src; // L3 info
			sockaddr_in	dst; // L3 info

			iovec 		frag; // Datagram part base address and length
			size_t		sz_payload; // This is the total amount of data of the packet, if (sz_payload>sz_data) means fragmented packet.
			uint64_t	hw_raw_timestamp;
			timestamps_t	timestamps;
			void* 		context;
			uint32_t	flow_tag_id; // Flow Tag ID of this received packet

			union {
				struct {
					struct iphdr* 	p_ip_h;
					struct tcphdr* 	p_tcp_h;
					size_t		n_transport_header_len;
					bool		gro;
				} tcp;
				struct {
					in_addr_t	local_if; // L3 info
				} udp;
			};

			int8_t		n_frags;	//number of fragments
			bool 		is_vma_thr; 	// specify whether packet drained from VMA internal thread or from user app thread
			bool		is_sw_csum_need; // specify if software checksum is need for this packet
			bool 		socketxtreme_polled;
		} rx;
		struct {
			size_t		dev_mem_length; // Total data aligned to 4 bytes.
			struct		iphdr* 	p_ip_h;
			union {
				struct		udphdr* p_udp_h;
				struct		tcphdr* p_tcp_h;
			};
		} tx;
	};

private:
	atomic_t	n_ref_count;	// number of interested receivers (sockinfo) [can be modified only in cq_mgr context]
public:

	uint32_t	lkey;      	// Buffers lkey for QP access
	mem_buf_desc_t* p_next_desc;	// A general purpose linked list of mem_buf_desc
	mem_buf_desc_t* p_prev_desc;
	size_t const	sz_buffer; 	// this is the size of the buffer
	size_t		sz_data;   	// this is the amount of data inside the buffer (sz_data <= sz_buffer)

	// Tx: qp_mgr owns the mem_buf_desc and the associated data buffer
	// Rx: cq_mgr owns the mem_buf_desc and the associated data buffer
	ring_slave* p_desc_owner;

	inline int get_ref_count() const {return atomic_read(&n_ref_count);}
	inline void  reset_ref_count() {atomic_set(&n_ref_count, 0);}
	inline int inc_ref_count() {return atomic_fetch_and_inc(&n_ref_count);}
	inline int dec_ref_count() {return atomic_fetch_and_dec(&n_ref_count);}

	inline unsigned int lwip_pbuf_inc_ref_count() {return ++lwip_pbuf.pbuf.ref;}
	inline unsigned int lwip_pbuf_dec_ref_count() {if (likely(lwip_pbuf.pbuf.ref)) --lwip_pbuf.pbuf.ref; return lwip_pbuf.pbuf.ref;}
	inline unsigned int lwip_pbuf_get_ref_count() const {return lwip_pbuf.pbuf.ref;}
};

typedef vma_list_t<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> descq_t;

#endif

