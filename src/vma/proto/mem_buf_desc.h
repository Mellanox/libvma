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


#ifndef MEM_BUF_DESC_H
#define MEM_BUF_DESC_H

#include <netinet/in.h>
#include "utils/atomic.h"
#include "vma/util/vtypes.h" // for unlikely
#include "vma/util/vma_list.h"
#include "vma/lwip/pbuf.h"

class mem_buf_desc_t;

class mem_buf_desc_owner
{
public:
	// Call back function
	virtual ~mem_buf_desc_owner() {};
	virtual void mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_mem_buf_desc) = 0;
	virtual void mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_mem_buf_desc) = 0;
	virtual void mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL) = 0;
	virtual void mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc) = 0;
};


struct ibv_send_wr_ud {
	struct ibv_ah*  ah;
	uint32_t        remote_qpn;
	uint32_t        remote_qkey;
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
	mem_buf_desc_t(uint8_t *buffer, size_t size) : p_buffer(buffer), sz_buffer(size) {
		// coverity[uninit_member]
	}

	struct pbuf_custom lwip_pbuf;	//Do not change the location of this field.
	mem_buf_desc_t* p_next_desc;	// A general purpose linked list of mem_buf_desc
	mem_buf_desc_t* p_prev_desc;
	uint8_t* const	p_buffer;
	size_t const	sz_buffer; 	// this is the size of the buffer
	size_t		sz_data;   	// this is the amount of data inside the buffer (sz_data <= sz_buffer)
	uint32_t	lkey;      	// Buffers lkey for QP access
private:
	atomic_t	n_ref_count;	// number of interested receivers (sockinfo) [can be modified only in cq_mgr context]
public:
	inline int get_ref_count() const {return atomic_read(&n_ref_count);}
	inline void  reset_ref_count() {atomic_set(&n_ref_count, 0);}
	inline int inc_ref_count() {return atomic_fetch_and_inc(&n_ref_count);}
	inline int dec_ref_count() {return atomic_fetch_and_dec(&n_ref_count);}

#ifdef DEFINED_VMAPOLL
	inline unsigned int lwip_pbuf_inc_ref_count() {return ++lwip_pbuf.pbuf.ref;}
	inline unsigned int lwip_pbuf_dec_ref_count() {if (likely(lwip_pbuf.pbuf.ref)) --lwip_pbuf.pbuf.ref; return lwip_pbuf.pbuf.ref;}
	inline unsigned int lwip_pbuf_get_ref_count() const {return lwip_pbuf.pbuf.ref;}
#endif // DEFINED_VMAPOLL

	bool		b_is_tx_mc_loop_dis; // if the mc loop on the tx side is disabled (the loop is per interface)
	bool		is_rx_sw_csum_need;
	int8_t		n_frags;	//number of fragments
	size_t		transport_header_len;

	// Tx: qp_mgr owns the mem_buf_desc and the associated data buffer
	// Rx: cq_mgr owns the mem_buf_desc and the associated data buffer
	mem_buf_desc_owner* p_desc_owner;

	union {
		struct {
			struct iphdr* 	p_ip_h;
			struct tcphdr* 	p_tcp_h;
			uint32_t	gro;		// is gro buff
			bool 		is_vma_thr; 	// specify whether packet drained from VMA internal thread or from user app thread
			bool 		is_tcp_ctl;
			// In network byte ordering
			sockaddr_in	src;
			sockaddr_in	dst;
			in_addr_t	local_if;
			uint16_t	vlan;
			uint32_t	qpn;

			// Datagram part base address and length
			iovec 		frag;

			// this is the total amount of data of the datagram 
			// if (sz_payload>sz_data) means fragmented datagram packet )
			size_t		sz_payload;

			struct timespec sw_timestamp;
			union {
				struct timespec	hw_timestamp;
				uint64_t	hw_raw_timestamp;
			};

			void* 		context;
#ifdef DEFINED_VMAPOLL 
			bool 		vma_polled;
#endif // DEFINED_VMAPOLL 			
		} rx;
		struct {
			ibv_send_wr_ud 	wr_ud_info;
			size_t		sz_tx_offset; // Offset of data start from allocated p_buffer

			// We use these pointer when we want to copy the users
			// tx data buffer once into the INLINE area in the SGE
			uint8_t*	p_buffer_header;
			uint8_t*	p_buffer_user;
			size_t		sz_data_header;  // this is the amount of data inside the header buffer
			size_t		sz_data_user;  // this is the amount of data inside the users buffer
			bool		is_signaled; // send signaled or not?
			bool		hwcsum;		// do hardware checksums
		} tx;
	} path;

	int		serial_num;

	static inline size_t buffer_node_offset(void) {return NODE_OFFSET(mem_buf_desc_t, buffer_node);}
	list_node<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> buffer_node;
#ifdef _DEBUG
	uint8_t		n_ref_count_dbg;	// Debug mode following the desc usage
#endif
};

typedef vma_list_t<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> descq_t;

#endif
