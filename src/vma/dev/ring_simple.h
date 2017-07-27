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

#ifndef RING_SIMPLE_H
#define RING_SIMPLE_H

#include "ring.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/utils.h"
#include "vma/vma_extra.h"

class ring_simple : public ring
{
public:
	ring_simple(ring_resource_creation_info_t* p_ring_info, in_addr_t local_if, uint16_t partition_sn, int count, transport_type_t transport_type, uint32_t mtu, ring* parent = NULL) throw (vma_error);
	virtual ~ring_simple();

	virtual int		request_notification(cq_type_t cq_type, uint64_t poll_sn);
	virtual int		poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual void		adapt_cq_moderation();
	bool			reclaim_recv_buffers_no_lock(descq_t *rx_reuse); // No locks
	bool			reclaim_recv_buffers_no_lock(mem_buf_desc_t* rx_reuse_lst); // No locks
#ifdef DEFINED_VMAPOLL	
	virtual int 		vma_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags);	
	virtual int		vma_poll_reclaim_single_recv_buffer(mem_buf_desc_t* rx_reuse_lst); // No locks
	virtual void		vma_poll_reclaim_recv_buffers(mem_buf_desc_t* rx_reuse_lst); // No locks
#endif // DEFINED_VMAPOLL
	virtual bool		reclaim_recv_buffers(descq_t *rx_reuse);
	virtual int		drain_and_proccess(cq_type_t cq_type);
	virtual int		wait_for_notification_and_process_element(cq_type_t cq_type, int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual void		mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc); // Assume locked...
	// Tx completion handling at the qp_mgr level is just re listing the desc+data buffer in the free lists
	virtual void		mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc); // Assume locked...
	virtual void		mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL);
	virtual void		mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual int		get_max_tx_inline();
	inline int		send_buffer(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual bool		attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual bool		detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual void		restart(ring_resource_creation_info_t* p_ring_info);
	bool			is_up();
	void			start_active_qp_mgr();
	void			stop_active_qp_mgr();
	virtual mem_buf_desc_t*	mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);
	virtual int		mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false);
	virtual void		inc_tx_retransmissions(ring_user_id_t id);
	virtual void		send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);
	virtual void		send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block);
	virtual void		mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual bool		is_member(mem_buf_desc_owner* rng);
	virtual bool		is_active_member(mem_buf_desc_owner* rng, ring_user_id_t id);
	virtual ring_user_id_t	generate_id();
	virtual ring_user_id_t	generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
	transport_type_t	get_transport_type() const { return m_transport_type; }
	virtual bool 		get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe);
	inline void 		convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) { m_p_cq_mgr_rx->convert_hw_time_to_system_time(hwtime, systime); }
	inline uint32_t		get_qpn() const { return (m_p_l2_addr ? ((IPoIB_addr *)m_p_l2_addr)->get_qpn() : 0); }
	virtual int 		modify_ratelimit(const uint32_t ratelimit_kbps);

	struct ibv_comp_channel* get_tx_comp_event_channel() { return m_p_tx_comp_event_channel; }
	friend class cq_mgr;
	friend class cq_mgr_mlx5;
	friend class qp_mgr;
	friend class qp_mgr_eth_mlx5;
	friend class rfs;
	friend class rfs_uc;
	friend class rfs_uc_tcp_gro;
	friend class rfs_mc;
	friend class ring_bond;

protected:
	virtual qp_mgr*		create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel) = 0;
	virtual void		create_resources(ring_resource_creation_info_t* p_ring_info, bool active) throw (vma_error);
	// Internal functions. No need for locks mechanism.
#ifdef DEFINED_VMAPOLL	
	inline void 		vma_poll_process_recv_buffer(mem_buf_desc_t* p_rx_wc_buf_desc);
#endif // DEFINED_VMAPOLL	
	bool			rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array);
	void			print_flow_to_rfs_udp_uc_map(flow_spec_udp_uc_map_t *p_flow_map);
	void			print_flow_to_rfs_tcp_map(flow_spec_tcp_map_t *p_flow_map);
	//	void	print_ring_flow_to_rfs_map(flow_spec_map_t *p_flow_map);
	void			flow_udp_uc_del_all();
	void			flow_udp_mc_del_all();
	void			flow_tcp_del_all();
	bool			request_more_tx_buffers(uint32_t count);
	uint32_t		get_tx_num_wr() { return m_tx_num_wr; }
	uint16_t		get_partition() { return m_partition; }
	ib_ctx_handler*		m_p_ib_ctx;
	qp_mgr*			m_p_qp_mgr;
	struct cq_moderation_info m_cq_moderation_info;
	cq_mgr*			m_p_cq_mgr_rx;
	lock_spin_recursive	m_lock_ring_rx;
	bool			m_b_is_hypervisor;
	ring_stats_t*		m_p_ring_stat;
private:
	inline void		send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe);
	inline mem_buf_desc_t*	get_tx_buffers(uint32_t n_num_mem_bufs);
	inline int		put_tx_buffers(mem_buf_desc_t* buff_list);
	inline int		put_tx_single_buffer(mem_buf_desc_t* buff);
	bool			is_available_qp_wr(bool b_block);
	void			modify_cq_moderation(uint32_t period, uint32_t count);
	void			save_l2_address(const L2_address* p_l2_addr) { delete_l2_address(); m_p_l2_addr = p_l2_addr->clone(); };
	void			delete_l2_address() { if (m_p_l2_addr) delete m_p_l2_addr; m_p_l2_addr = NULL; };

	lock_spin_recursive	m_lock_ring_tx;
	cq_mgr*			m_p_cq_mgr_tx;
	lock_mutex		m_lock_ring_tx_buf_wait;
	descq_t			m_tx_pool;
	uint32_t		m_tx_num_bufs;
	uint32_t		m_tx_num_wr;
	int32_t			m_tx_num_wr_free;
	bool			m_b_qp_tx_first_flushed_completion_handled;
	uint32_t		m_missing_buf_ref_count;
	const uint32_t		m_tx_lkey; // this is the registered memory lkey for a given specific device for the buffer pool use
	uint16_t		m_partition; //vlan or pkey
	gro_mgr			m_gro_mgr;
	ring_stats_t		m_ring_stat_static;
	bool			m_up;
	struct ibv_comp_channel* m_p_rx_comp_event_channel;
	struct ibv_comp_channel* m_p_tx_comp_event_channel;
	L2_address*		m_p_l2_addr;
	in_addr_t		m_local_if;
	transport_type_t	m_transport_type;
	// For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
	// It means that for every MC group, even if we have sockets with different ports - only one rule in the HW.
	// So the hash map below keeps track of the number of sockets per rule so we know when to call ibv_attach and ibv_detach
	rule_filter_map_t	m_l2_mc_ip_attach_map;
	rule_filter_map_t	m_tcp_dst_port_attach_map;
	flow_spec_tcp_map_t	m_flow_tcp_map;
	flow_spec_udp_mc_map_t	m_flow_udp_mc_map;
	flow_spec_udp_uc_map_t	m_flow_udp_uc_map;
	const bool		m_b_sysvar_eth_mc_l2_only_rules;
	const bool		m_b_sysvar_mc_force_flowtag;
#ifdef DEFINED_VMAPOLL
	mem_buf_desc_t*		m_rx_buffs_rdy_for_free_head;
	mem_buf_desc_t*		m_rx_buffs_rdy_for_free_tail;
#endif // DEFINED_VMAPOLL		
	bool			m_flow_tag_enabled;
};

class ring_eth : public ring_simple
{
public:
	ring_eth(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info,
		 int count, bool active, uint16_t vlan, uint32_t mtu,
		 ring* parent = NULL, bool call_create_res = true) throw (vma_error):
		ring_simple(p_ring_info, local_if, vlan, count, VMA_TRANSPORT_ETH, mtu, parent) {
		if (call_create_res)
			create_resources(p_ring_info, active);
	};
	virtual bool is_ratelimit_supported(uint32_t rate);
protected:
	virtual qp_mgr* create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel) throw (vma_error);
};

class ring_ib : public ring_simple
{
public:
	ring_ib(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, int count, bool active, uint16_t pkey, uint32_t mtu, ring* parent = NULL) throw (vma_error):
		ring_simple(p_ring_info, local_if, pkey, count, VMA_TRANSPORT_IB, mtu, parent) { create_resources(p_ring_info, active); };
	virtual bool is_ratelimit_supported(uint32_t rate);
protected:
	virtual qp_mgr* create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel) throw (vma_error);
};

#endif //RING_SIMPLE_H
