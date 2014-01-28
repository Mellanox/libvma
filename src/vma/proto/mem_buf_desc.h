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


#ifndef MEM_BUF_DESC_H
#define MEM_BUF_DESC_H

#include <deque>
#include <netinet/in.h>
#include "vma/util/vtypes.h" // for unlikely

#include "lwip/pbuf.h"

struct mem_buf_desc_t;

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
	int16_t		n_ref_count;	// number of interested receivers (sockinfo) [can be modified only in cq_mgr context]
public:
	inline int16_t get_ref_count() const {return n_ref_count;}
	inline void  reset_ref_count() {n_ref_count = 0;}
	inline int16_t inc_ref_count() {return ++n_ref_count;}
	inline int16_t dec_ref_count() {return --n_ref_count;}

	bool		b_is_tx_mc_loop_dis; // if the mc loop on the tx side is disabled (the loop is per interface)
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

			struct timespec timestamp;

			void* 		context;
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
#ifdef _DEBUG
	uint8_t		n_ref_count_dbg;	// Debug mode following the desc usage
#endif
};


typedef std::deque<mem_buf_desc_t*> descq_t;

inline void move_owned_descs(const mem_buf_desc_owner* p_desc_owner, descq_t *toq, descq_t *fromq)
{
	// Assume locked by owner!!!

	mem_buf_desc_t *temp;
	const size_t size = fromq->size();
	for (size_t i = 0 ; i < size; i++) {
		temp = fromq->front();
		fromq->pop_front();
		if (temp->p_desc_owner == p_desc_owner)
			toq->push_back(temp);
		else
			fromq->push_back(temp);
	}
}

inline void move_not_owned_descs(const mem_buf_desc_owner* p_desc_owner, descq_t *toq, descq_t *fromq)
{
	// Assume locked by owner!!!

	mem_buf_desc_t *temp;
	const size_t size = fromq->size();
	for (size_t i = 0 ; i < size; i++) {
		temp = fromq->front();
		fromq->pop_front();
		if (temp->p_desc_owner == p_desc_owner)
			fromq->push_back(temp);
		else
			toq->push_back(temp);
	}
}


#endif
