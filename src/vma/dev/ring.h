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


#ifndef RING_H
#define RING_H

#include "utils/lock_wrapper.h"
#include "vma/dev/gro_mgr.h"
#include "vma/util/list.h"
#include "vma/util/hash_map.h"
#include "vma/util/verbs_extra.h"
#include "vma/sock/pkt_rcvr_sink.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/flow_tuple.h"
#include "vma/proto/L2_address.h"
#include "vma/infra/sender.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/dev/net_device_val.h"
#include "vma/dev/qp_mgr.h"
#include "vma/sock/socket_fd_api.h"

class rfs;
class cq_mgr;
class L2_address;
class buffer_pool;

#define RING_LOCK_AND_RUN(__lock__, __func_and_params__) 	\
		__lock__.lock(); __func_and_params__; __lock__.unlock();

#define RING_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) 	\
		__lock__.lock(); ret = __func_and_params__; __lock__.unlock();

#define RING_TRY_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) \
		if (!__lock__.trylock()) { ret = __func_and_params__; __lock__.unlock(); } \
		else { errno = EBUSY; }


#define ring_logpanic 		__log_info_panic
#define ring_logerr			__log_info_err
#define ring_logwarn		__log_info_warn
#define ring_loginfo		__log_info_info
#define ring_logdbg			__log_info_dbg
#define ring_logfunc		__log_info_func
#define ring_logfuncall		__log_info_funcall

#define RING_TX_BUFS_COMPENSATE 256

typedef enum {
	CQT_RX,
	CQT_TX
} cq_type_t;

/* udp uc key, only by destination port as we already know the rest */
typedef struct __attribute__((packed)) flow_spec_udp_uc_key_t {
  in_port_t 	dst_port;

  flow_spec_udp_uc_key_t () {
  	flow_spec_udp_uc_key_helper(INPORT_ANY);
  } //Default constructor
  flow_spec_udp_uc_key_t (in_port_t d_port) {
  	flow_spec_udp_uc_key_helper(d_port);
  }//Constructor
  void flow_spec_udp_uc_key_helper(in_addr_t d_port) {
    memset(this, 0, sizeof(*this));// Silencing coverity
    dst_port = d_port;
  };
} flow_spec_udp_uc_key_t;

typedef struct __attribute__((packed)) flow_spec_udp_mc_key_t {
  in_addr_t	dst_ip;
  in_port_t	dst_port;

  flow_spec_udp_mc_key_t () {
    flow_spec_udp_mc_key_helper( INADDR_ANY, INPORT_ANY);
  } //Default constructor
  flow_spec_udp_mc_key_t (in_addr_t d_ip, in_addr_t d_port) {
    flow_spec_udp_mc_key_helper(d_ip, d_port);
  }//Constructor
  void flow_spec_udp_mc_key_helper(in_addr_t d_ip, in_addr_t d_port) {
    memset(this, 0, sizeof(*this));// Silencing coverity
    dst_ip = d_ip;
    dst_port = d_port;
  };
} flow_spec_udp_mc_key_t;

typedef struct __attribute__((packed)) flow_spec_tcp_key_t {
  in_addr_t	src_ip;
  in_port_t	dst_port;
  in_port_t	src_port;

  flow_spec_tcp_key_t () {
  	flow_spec_tcp_key_helper (INADDR_ANY, INPORT_ANY, INPORT_ANY);
  } //Default constructor
  flow_spec_tcp_key_t (in_addr_t s_ip, in_addr_t d_port, in_addr_t s_port) {
  	flow_spec_tcp_key_helper (s_ip, d_port, s_port);
  }//Constructor
  void flow_spec_tcp_key_helper(in_addr_t s_ip, in_addr_t d_port, in_addr_t s_port) {
    memset(this, 0, sizeof(*this));// Silencing coverity
    src_ip = s_ip;
    dst_port = d_port;
    src_port = s_port;
  };
} flow_spec_tcp_key_t;

/* UDP UC flow to rfs object hash map */
inline bool
operator==(flow_spec_udp_uc_key_t const& key1, flow_spec_udp_uc_key_t const& key2)
{
	return (key1.dst_port == key2.dst_port);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator<(flow_spec_udp_uc_key_t const& key1, flow_spec_udp_uc_key_t const& key2)
{
	if (key1.dst_port < key2.dst_port)
		return true;

	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<flow_spec_udp_uc_key_t, rfs*> flow_spec_udp_uc_map_t;


/* UDP MC flow to rfs object hash map */
inline bool
operator==(flow_spec_udp_mc_key_t const& key1, flow_spec_udp_mc_key_t const& key2)
{
	return 	(key1.dst_port == key2.dst_port) &&
		(key1.dst_ip == key2.dst_ip);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator<(flow_spec_udp_mc_key_t const& key1, flow_spec_udp_mc_key_t const& key2)
{
	if (key1.dst_ip < key2.dst_ip)		return true;
	if (key1.dst_ip > key2.dst_ip)		return false;
	if (key1.dst_port < key2.dst_port)	return true;
	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<flow_spec_udp_mc_key_t, rfs*> flow_spec_udp_mc_map_t;


/* TCP flow to rfs object hash map */
inline bool
operator==(flow_spec_tcp_key_t const& key1, flow_spec_tcp_key_t const& key2)
{
	return	(key1.src_port == key2.src_port) &&
		(key1.src_ip == key2.src_ip) &&
		(key1.dst_port == key2.dst_port);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator<(flow_spec_tcp_key_t const& key1, flow_spec_tcp_key_t const& key2)
{
	if (key1.src_ip < key2.src_ip)		return true;
	if (key1.src_ip > key2.src_ip)		return false;
	if (key1.dst_port < key2.dst_port)	return true;
	if (key1.dst_port > key2.dst_port)	return false;
	if (key1.src_port < key2.src_port)	return true;
	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<flow_spec_tcp_key_t, rfs*> flow_spec_tcp_map_t;


typedef struct {
	ib_ctx_handler*	p_ib_ctx;
	uint8_t 	port_num;
	L2_address* 	p_l2_addr;
	bool			active;
} ring_resource_creation_info_t;


struct counter_and_ibv_flows {
	int counter;
	std::vector<vma_ibv_flow*> ibv_flows;
};

typedef std::tr1::unordered_map<uint32_t, struct counter_and_ibv_flows> rule_filter_map_t;


struct cq_moderation_info {
	uint32_t period;
	uint32_t count;
	uint64_t packets;
	uint64_t bytes;
	uint64_t prev_packets;
	uint64_t prev_bytes;
	uint32_t missed_rounds;
};

typedef int ring_user_id_t;

#ifdef DEFINED_VMAPOLL	
/* Ring event completion */
struct ring_ec {
	struct list_head list;
	struct vma_completion_t completion;
	struct vma_buff_t*      last_buff_lst;
};
#endif // DEFINED_VMAPOLL	

/**
 * @class ring
 *
 * Object to manages the QP and CQ operation
 * This object is used for Rx & Tx at the same time
 * Once created it ...
 *
 *
 * NOTE:
 * In the end this object will contain a QP and CQ.
 * In the first stage it will be a part of the qp_mgr object.
 *
 */
class ring : public mem_buf_desc_owner
{

public:
	ring(int count, uint32_t mtu); //todo count can be moved to ring_bond

	virtual ~ring();

	virtual bool		attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink) = 0;
	virtual bool		detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink) = 0;

	virtual void		restart(ring_resource_creation_info_t* p_ring_info) = 0; //todo move to bond ?

	// Funcs taken from qp_mgr.h
	// Get/Release memory buffer descriptor with a linked data memory buffer
	virtual mem_buf_desc_t*	mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1) = 0;
	virtual int		mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false) = 0;
	virtual void		send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block) = 0;
	virtual void		send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block) = 0;

	// Funcs taken from cq_mgr.h
	int			get_num_resources() const { return m_n_num_resources; };
	int*			get_rx_channel_fds() const { return m_p_n_rx_channel_fds; };
	virtual int		get_max_tx_inline() = 0;
	virtual bool 		get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe) = 0;
	virtual int		request_notification(cq_type_t cq_type, uint64_t poll_sn) = 0;
	virtual bool		reclaim_recv_buffers(descq_t *rx_reuse) = 0;
	virtual int		drain_and_proccess(cq_type_t cq_type) = 0;
	virtual int		wait_for_notification_and_process_element(cq_type_t cq_type, int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL) = 0;
	virtual int		poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL) = 0;
	virtual void		adapt_cq_moderation() = 0;
	virtual void		mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc) = 0; // Assume locked...
	// Tx completion handling at the qp_mgr level is just re listing the desc+data buffer in the free lists
	virtual void		mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc) = 0; // Assume locked...
	virtual void		mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL) = 0;
	virtual void		mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc) = 0;
	virtual void		mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc) = 0;

	virtual void		inc_ring_stats(ring_user_id_t id) = 0;
	virtual bool		is_member(mem_buf_desc_owner* rng) = 0;
	virtual bool		is_active_member(mem_buf_desc_owner* rng, ring_user_id_t id) = 0;
	ring*			get_parent() { return m_parent; };
	virtual ring_user_id_t	generate_id() = 0;
	virtual ring_user_id_t	generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) = 0;
	uint32_t		get_mtu() {return m_mtu;};
#ifdef DEFINED_VMAPOLL		
	virtual int		vma_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags) = 0;
	virtual bool		reclaim_recv_buffers_no_lock(mem_buf_desc_t* rx_reuse_lst) {NOT_IN_USE(rx_reuse_lst); return false;}

	virtual int		vma_poll_reclaim_single_recv_buffer(mem_buf_desc_t* rx_reuse_lst) {NOT_IN_USE(rx_reuse_lst); return -1;}
	virtual void		vma_poll_reclaim_recv_buffers(mem_buf_desc_t* rx_reuse_lst) {NOT_IN_USE(rx_reuse_lst); return;}

	inline void set_vma_active(bool flag) {m_vma_active = flag;}
	inline bool get_vma_active(void) {return m_vma_active;}

	inline void put_ec(struct ring_ec *ec)
	{
		m_lock_ec_list.lock();
		list_add_tail(&ec->list, &m_ec_list);
		m_lock_ec_list.unlock();
	}

	inline ring_ec* get_ec(void)
	{
		struct ring_ec *ec = NULL;

		m_lock_ec_list.lock();
		if (!list_empty(&m_ec_list)) {
			ec = list_entry(m_ec_list.next, struct ring_ec, list);
			list_del(&ec->list);
		}
		m_lock_ec_list.unlock();
		return ec;
	}

	inline void clear_ec(struct ring_ec *ec)
	{
		memset(ec, 0, sizeof(*ec));
	}

	struct vma_completion_t *get_comp(void)
	{
		return m_vma_poll_completion;
	}
#endif // DEFINED_VMAPOLL	
protected:
	uint32_t		m_n_num_resources;
	int*			m_p_n_rx_channel_fds;
	ring*			m_parent;

#ifdef DEFINED_VMAPOLL	
	/* queue of event completion elements
	 * this queue is stored events related different sockinfo (sockets)
	 * In current implementation every sockinfo (socket) can have single event
	 * in this queue
	 */
	struct list_head         m_ec_list;

	/* Thread-safity lock for get/put operations under the queue */
	lock_spin                m_lock_ec_list;

	/* This completion is introduced to process events directly w/o
	 * storing them in the queue of event completion elements
	 */
	struct vma_completion_t* m_vma_poll_completion;
#endif // DEFINED_VMAPOLL	

private:
#ifdef DEFINED_VMAPOLL	
	/* This flag is enabled in case vma_poll() call is done */
	bool                     m_vma_active;
#endif // DEFINED_VMAPOLL	
	uint32_t		m_mtu;
};

#endif /* RING_H */
