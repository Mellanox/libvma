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


#ifndef RING_H
#define RING_H

#include "vma/ib/base/verbs_extra.h"
#include "vma/proto/flow_tuple.h"
#include "vma/sock/socket_fd_api.h"

class pkt_rcvr_sink;

#define ring_logpanic 		__log_info_panic
#define ring_logerr			__log_info_err
#define ring_logwarn		__log_info_warn
#define ring_loginfo		__log_info_info
#define ring_logdbg			__log_info_dbg
#define ring_logfunc		__log_info_func
#define ring_logfuncall		__log_info_funcall
#define ring_logfine		__log_info_fine

typedef enum {
	CQT_RX,
	CQT_TX
} cq_type_t;

typedef int ring_user_id_t;

/* Ring event completion */
struct ring_ec {
	struct list_head list;
	struct vma_completion_t completion;
	struct vma_buff_t*      last_buff_lst;

	inline void clear()
	{
		INIT_LIST_HEAD(&list);
		memset(&completion, 0, sizeof(completion));
		last_buff_lst = NULL;
	}
};

class ring
{
public:
	ring();

	virtual ~ring();

	virtual void print_val();

	virtual bool		attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink) = 0;
	virtual bool		detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink) = 0;

	virtual void		restart() = 0;

	// Funcs taken from qp_mgr.h
	// Get/Release memory buffer descriptor with a linked data memory buffer
	virtual mem_buf_desc_t*	mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1) = 0;
	virtual int		mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false) = 0;
	virtual void		send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr) = 0;
	virtual void		send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr) = 0;

	// Funcs taken from cq_mgr.h
	virtual int		get_num_resources() const = 0;
	int*			get_rx_channel_fds() const { return m_p_n_rx_channel_fds; };
	virtual int		get_tx_channel_fd() const { return -1; };
	virtual bool 		get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe) = 0;
	virtual int		request_notification(cq_type_t cq_type, uint64_t poll_sn) = 0;
	virtual bool		reclaim_recv_buffers(descq_t *rx_reuse) = 0;
	virtual bool		reclaim_recv_buffers(mem_buf_desc_t* rx_reuse_lst) = 0;
	virtual int		drain_and_proccess() = 0;
	virtual int		wait_for_notification_and_process_element(int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL) = 0;
	virtual int		poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL) = 0;
	virtual void		adapt_cq_moderation() = 0;
	virtual void		mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc) = 0;

	virtual void		inc_tx_retransmissions_stats(ring_user_id_t id) = 0;
	virtual bool		is_member(ring_slave* rng) = 0;
	virtual bool		is_active_member(ring_slave* rng, ring_user_id_t id) = 0;
	ring*			get_parent() { return m_parent; };
	ring_user_id_t		generate_id() { return 0; };
	virtual ring_user_id_t	generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) = 0;
	virtual int		modify_ratelimit(struct vma_rate_limit_t &rate_limit) = 0;
        virtual uint32_t	get_max_inline_data() = 0;
#ifdef DEFINED_TSO
        virtual uint32_t	get_max_send_sge(void) = 0;
        virtual uint32_t	get_max_payload_sz(void) = 0;
        virtual uint16_t	get_max_header_sz(void) = 0;
	virtual uint32_t	get_tx_lkey(ring_user_id_t id) = 0;
        virtual bool		is_tso(void) = 0;
#endif /* DEFINED_TSO */
	virtual int		reg_mr(void *addr, size_t length, uint32_t &lkey) { NOT_IN_USE(addr); NOT_IN_USE(length); NOT_IN_USE(lkey); return -1;};
	virtual int		dereg_mr(void *addr, size_t length) { NOT_IN_USE(addr);NOT_IN_USE(length); return -1;};

	virtual int		socketxtreme_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags) = 0;

	virtual bool is_socketxtreme(void) = 0;
	virtual void put_ec(struct ring_ec *ec) = 0;
	virtual void del_ec(struct ring_ec *ec) = 0;
	virtual struct vma_completion_t *get_comp(void) = 0;

	inline int get_if_index() { return m_if_index; }

protected:
	inline void set_parent(ring* parent) { m_parent = ( parent ? parent : this); }
	inline void set_if_index(int if_index) { m_if_index = if_index; }

	int*			m_p_n_rx_channel_fds;
	ring*			m_parent;

	int                 m_if_index;     /* Interface index */
};

#endif /* RING_H */
