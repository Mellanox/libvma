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

#include "ring.h"

class ring_simple;

class ring_bond : public ring {

public:
	ring_bond(int count, net_device_val::bond_type type, net_device_val::bond_xmit_hash_policy bond_xmit_hash_policy, uint32_t mtu);
	virtual	~ring_bond();
	void			free_ring_bond_resources();
	virtual int		request_notification(cq_type_t cq_type, uint64_t poll_sn);
	virtual int		poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual void		adapt_cq_moderation();
	virtual bool		reclaim_recv_buffers(descq_t *rx_reuse);
	virtual int		drain_and_proccess(cq_type_t cq_type);
	virtual int		wait_for_notification_and_process_element(cq_type_t cq_type, int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual void		mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc); // Assume locked...
	// Tx completion handling at the qp_mgr level is just re listing the desc+data buffer in the free lists
	virtual void		mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc); // Assume locked...
	virtual void		mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL);
	virtual void		mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual int		get_max_tx_inline();
	virtual bool		attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual bool		detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual void		restart(ring_resource_creation_info_t* p_ring_info);
	virtual mem_buf_desc_t* mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);
	virtual int		mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false);
	virtual void		inc_ring_stats(ring_user_id_t id);
	virtual void		send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block);
	virtual void		send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block);
	virtual void		mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual bool		is_member(mem_buf_desc_owner* rng);
	virtual bool		is_active_member(mem_buf_desc_owner* rng, ring_user_id_t id);
	virtual ring_user_id_t	generate_id();
	virtual ring_user_id_t	generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
	virtual bool 		get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe);

#ifdef DEFINED_VMAPOLL		
	virtual int		fast_poll_and_process_element_rx(vma_packets_t *vma_pkts);
	int 			vma_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags);
#endif // DEFINED_VMAPOLL		
protected:
	virtual void		create_slave_list(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, bool active_slaves[], uint16_t partition) = 0;
	void			update_rx_channel_fds();
	void			close_gaps_active_rings();
	ring_simple**		m_bond_rings;
	ring_simple**		m_active_rings;

	int			m_min_devices_tx_inline;

private:
	void			devide_buffers_helper(descq_t *rx_reuse, descq_t *buffer_per_ring);
	void			devide_buffers_helper(mem_buf_desc_t *p_mem_buf_desc_list, mem_buf_desc_t** buffer_per_ring);

	net_device_val::bond_type m_type;
	net_device_val::bond_xmit_hash_policy m_xmit_hash_policy;
	lock_mutex_recursive	m_lock_ring_rx;
	lock_mutex_recursive	m_lock_ring_tx;
	descq_t*		m_buffer_per_ring;
};

class ring_bond_eth : public ring_bond
{
public:
	ring_bond_eth(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, int count, bool active_slaves[], uint16_t vlan, net_device_val::bond_type type, net_device_val::bond_xmit_hash_policy bond_xmit_hash_policy, uint32_t mtu) throw (vma_error):
		ring_bond(count, type, bond_xmit_hash_policy, mtu){
		create_slave_list(local_if, p_ring_info, active_slaves, vlan);
		update_rx_channel_fds();
	};
protected:
	virtual void create_slave_list(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, bool active_slaves[], uint16_t partition) throw (vma_error);
};

class ring_bond_ib : public ring_bond
{
public:
	ring_bond_ib(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, int count, bool active_slaves[], uint16_t pkey, net_device_val::bond_type type, net_device_val::bond_xmit_hash_policy bond_xmit_hash_policy, uint32_t mtu) throw (vma_error):
		ring_bond(count, type, bond_xmit_hash_policy, mtu){
		create_slave_list(local_if, p_ring_info, active_slaves, pkey);
		update_rx_channel_fds();
	};
protected:
	virtual void create_slave_list(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, bool active_slaves[], uint16_t partition) throw (vma_error);
};
