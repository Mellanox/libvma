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

#include "ring_bond.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>

#include "utils/bullseye.h"
#include "vma/util/utils.h"
#include "vma/proto/ip_frag.h"
#include "vma/proto/L2_address.h"
#include "vma/proto/igmp_mgr.h"
#include "vma/sock/sockinfo_tcp.h"
#include "vma/sock/fd_collection.h"
#include "vma/dev/rfs_mc.h"
#include "vma/dev/rfs_uc.h"
#include "vma/dev/rfs_uc_tcp_gro.h"
#include "vma/dev/cq_mgr.h"
#include "ring_simple.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"ring_bond"
#undef  MODULE_HDR
#define MODULE_HDR	 	MODULE_NAME "%d:%s() "

ring_bond::ring_bond(int count, net_device_val::bond_type type, net_device_val::bond_xmit_hash_policy bond_xmit_hash_policy, uint32_t mtu) :
ring(count, mtu), m_lock_ring_rx("ring_bond:lock_rx"), m_lock_ring_tx("ring_bond:lock_tx") {
	m_bond_rings = new ring_simple*[count];
	for (int i = 0; i < count; i++)
		m_bond_rings[i] = NULL;
	m_active_rings = new ring_simple*[count];
	for (int i = 0; i < count; i++)
		m_active_rings[i] = NULL;
	m_buffer_per_ring = new descq_t[m_n_num_resources + 1];
	m_parent = this;
	m_type = type;
	m_xmit_hash_policy = bond_xmit_hash_policy;
	m_min_devices_tx_inline = -1;
}

void ring_bond::free_ring_bond_resources()
{
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		delete m_bond_rings[i];
		m_bond_rings[i] = NULL;
	}

	delete [] m_bond_rings;
	m_bond_rings = NULL;

	delete [] m_active_rings;
	m_active_rings = NULL;

	delete [] m_buffer_per_ring;
	m_buffer_per_ring = NULL;
}

ring_bond::~ring_bond()
{
	free_ring_bond_resources();
}

bool ring_bond::attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink) {
	bool ret = true;
	m_lock_ring_rx.lock();
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		bool step_ret = m_bond_rings[i]->attach_flow(flow_spec_5t, sink);
		ret = ret && step_ret;
	}
	m_lock_ring_rx.unlock();
	return ret;
}

bool ring_bond::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink) {
	bool ret = true;
	auto_unlocker lock(m_lock_ring_rx);
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		bool step_ret = m_bond_rings[i]->detach_flow(flow_spec_5t, sink);
		ret = ret && step_ret;
	}
	return ret;
}

void ring_bond::restart(ring_resource_creation_info_t* p_ring_info) {
	ring_logdbg("*** ring restart! ***");

	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();

	//for active-backup mode
	ring_simple* previously_active = m_active_rings[0];

	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (p_ring_info[i].active) {
			ring_logdbg("ring %d active", i);

			/* TODO: consider avoid using sleep */
			/* coverity[sleep] */
			m_bond_rings[i]->start_active_qp_mgr();
			m_active_rings[i] = m_bond_rings[i];
		} else {
			ring_logdbg("ring %d not active", i);

			/* TODO: consider avoid using sleep */
			/* coverity[sleep] */
			m_bond_rings[i]->stop_active_qp_mgr();
			m_active_rings[i] = NULL;
		}
	}
	close_gaps_active_rings();

	int ret = 0;
	uint64_t poll_sn = cq_mgr::m_n_global_sn;
	ret = request_notification(CQT_RX, poll_sn);
	if (ret < 0) {
		ring_logdbg("failed arming rx cq_mgr (errno=%d %m)", errno);
	}
	ret = request_notification(CQT_TX, poll_sn);
	if (ret < 0) {
		ring_logdbg("failed arming tx cq_mgr (errno=%d %m)", errno);
	}

	if (m_type == net_device_val::ACTIVE_BACKUP) {
		ring_simple* currently_active = m_active_rings[0];;
		if (safe_mce_sys().cq_moderation_enable) {
			currently_active->m_cq_moderation_info.period = previously_active->m_cq_moderation_info.period;
			currently_active->m_cq_moderation_info.count = previously_active->m_cq_moderation_info.count;
			currently_active->modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec, safe_mce_sys().cq_moderation_count);
		}
	}

	m_lock_ring_tx.unlock();
	m_lock_ring_rx.unlock();

	ring_logdbg("*** ring restart done! ***");
}

void ring_bond::adapt_cq_moderation()
{
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (m_bond_rings[i]->is_up())
			m_bond_rings[i]->adapt_cq_moderation();
	}
}

mem_buf_desc_t* ring_bond::mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs /* default = 1 */)
{
	mem_buf_desc_t* ret;
	ring_simple* active_ring = m_active_rings[id];
	if (likely(active_ring)) {
		ret =  active_ring->mem_buf_tx_get(id, b_block, n_num_mem_bufs);
	} else {
		ret = m_bond_rings[id]->mem_buf_tx_get(id, b_block, n_num_mem_bufs);
	}
	return ret;
}

int ring_bond::mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock/*=false*/)
{
	mem_buf_desc_t* buffer_per_ring[m_n_num_resources];
	memset(buffer_per_ring, 0, m_n_num_resources * sizeof(mem_buf_desc_t*));
	devide_buffers_helper(p_mem_buf_desc_list, buffer_per_ring);
	int ret = 0;
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (buffer_per_ring[i])
			ret += m_bond_rings[i]->mem_buf_tx_release(buffer_per_ring[i], b_accounting, trylock);
	}
	return ret;
}

void ring_bond::mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	((ring_simple*)p_mem_buf_desc->p_desc_owner)->mem_buf_desc_return_single_to_owner_tx(p_mem_buf_desc);
}

void ring_bond::send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block)
{
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
	ring_simple* active_ring = m_active_rings[id];

	if (likely(active_ring && p_mem_buf_desc->p_desc_owner == active_ring)) {
		active_ring->send_ring_buffer(id, p_send_wqe, b_block);
	} else {
		ring_logfunc("active ring=%p, silent packet drop (%p), (HA event?)", active_ring, p_mem_buf_desc);
		p_mem_buf_desc->p_next_desc = NULL;
		active_ring = m_bond_rings[id];
		if (likely(p_mem_buf_desc->p_desc_owner == active_ring)) {
			active_ring->mem_buf_tx_release(p_mem_buf_desc, true);
		} else {
			mem_buf_tx_release(p_mem_buf_desc, true);
		}
	}
}

void ring_bond::send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block)
{
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
	ring_simple* active_ring = m_active_rings[id];

	if (likely(active_ring && p_mem_buf_desc->p_desc_owner == active_ring)) {
		active_ring->send_lwip_buffer(id, p_send_wqe, b_block);
	} else {
		ring_logfunc("active ring=%p, silent packet drop (%p), (HA event?)", active_ring, p_mem_buf_desc);
		p_mem_buf_desc->p_next_desc = NULL;
		/* no need to free the buffer here, as for lwip buffers we have 2 ref counts, */
		/* one for caller, and one for completion. for completion, we ref count in    */
		/* send_lwip_buffer(). Since we are not going in, the caller will free the    */
		/* buffer. */
	}
}

bool ring_bond::get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe)
{
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
	ring_simple* active_ring = m_active_rings[id];

	if (likely(active_ring && p_mem_buf_desc->p_desc_owner == active_ring)) {
		return active_ring->get_hw_dummy_send_support(id, p_send_wqe);
	} else {
		active_ring = m_bond_rings[id];
		if (likely(p_mem_buf_desc->p_desc_owner == active_ring)) {
			return active_ring->get_hw_dummy_send_support(id, p_send_wqe);
		} else {
			return false;
		}
	}
}

int ring_bond::get_max_tx_inline()
{
	return m_min_devices_tx_inline;
}

int ring_bond::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/) {
	int ret = 0;
	int temp = 0;
	if (m_lock_ring_rx.trylock()) {
		errno = EBUSY;
		return 0;
	}
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (m_bond_rings[i]->is_up()) {
			//TODO consider returning immediately after finding something, continue next time from next ring
			temp = m_bond_rings[i]->poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array);
			if (temp > 0) {
				ret += temp;
			}
		}
	}
	m_lock_ring_rx.unlock();
	if (ret > 0) {
		return ret;
	} else {
		return temp;
	}
}

int ring_bond::drain_and_proccess(cq_type_t cq_type)
{
	if (likely(CQT_RX == cq_type)) {
		if (m_lock_ring_rx.trylock()) {
			errno = EBUSY;
			return 0;
		}
	} else {
		if (m_lock_ring_tx.trylock()) {
			errno = EBUSY;
			return 0;
		}
	}
	int ret = 0;
	int temp = 0;
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (m_bond_rings[i]->is_up()) {
			temp = m_bond_rings[i]->drain_and_proccess(cq_type);
			if (temp > 0) {
				ret += temp;
			}
		}
	}
	if (likely(CQT_RX == cq_type)) {
		m_lock_ring_rx.unlock();
	} else {
		m_lock_ring_tx.unlock();
	}
	if (ret > 0) {
		return ret;
	} else {
		return temp;
	}
}

int ring_bond::wait_for_notification_and_process_element(cq_type_t cq_type, int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/) {
	int ret = 0;
	int temp = 0;
	if(m_lock_ring_rx.trylock()) {
		errno = EBUSY;
		return -1;
	}
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (m_bond_rings[i]->is_up()) {
			temp = m_bond_rings[i]->wait_for_notification_and_process_element(cq_type, cq_channel_fd, p_cq_poll_sn, pv_fd_ready_array);
			if (temp > 0) {
				ret += temp;
			}
		}
	}
	m_lock_ring_rx.unlock();
	if (ret > 0) {
		return ret;
	} else {
		return temp;
	}
}

int ring_bond::request_notification(cq_type_t cq_type, uint64_t poll_sn)
{
	if (likely(CQT_RX == cq_type)) {
		if (m_lock_ring_rx.trylock()) {
			errno = EBUSY;
			return 1;
		}
	} else {
		if (m_lock_ring_tx.trylock()) {
			errno = EBUSY;
			return 1;
		}
	}
	int ret = 0;
	int temp;
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (m_bond_rings[i]->is_up()) {
			temp = m_bond_rings[i]->request_notification(cq_type, poll_sn);
			if (temp < 0) {
				ret = temp;
				break;
			} else {
				ret += temp;
			}
		}
	}
	if (likely(CQT_RX == cq_type))
		m_lock_ring_rx.unlock();
	else
		m_lock_ring_tx.unlock();
	return ret;
}

void ring_bond::inc_ring_stats(ring_user_id_t id)
{
	ring_simple* active_ring = m_active_rings[id];
	if (likely(active_ring))
		active_ring->inc_ring_stats(id);
}

bool ring_bond::reclaim_recv_buffers(descq_t *rx_reuse)
{
	devide_buffers_helper(rx_reuse, m_buffer_per_ring);
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		if (m_buffer_per_ring[i].size() > 0) {
			if (!m_bond_rings[i]->reclaim_recv_buffers(&m_buffer_per_ring[i])) {
				g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&m_buffer_per_ring[i]);
			}
		}
	}

	if (m_buffer_per_ring[m_n_num_resources].size() > 0)
		g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&m_buffer_per_ring[m_n_num_resources]);

	return true;
}

void ring_bond::devide_buffers_helper(descq_t *rx_reuse, descq_t* buffer_per_ring)
{
	int last_found_index = 0;
	while (!rx_reuse->empty()) {
		mem_buf_desc_t* buff = rx_reuse->front();
		rx_reuse->pop_front();
		uint32_t checked = 0;
		int index = last_found_index;
		while (checked < m_n_num_resources) {
			if (m_bond_rings[index] == buff->p_desc_owner) {
				buffer_per_ring[index].push_back(buff);
				last_found_index = index;
				break;
			}
			checked++;
			index++;
			index = index % m_n_num_resources;
		}
		//no owner
		if (checked == m_n_num_resources) {
			ring_logfunc("No matching ring %p to return buffer", buff->p_desc_owner);
			buffer_per_ring[m_n_num_resources].push_back(buff);
		}
	}
}

void ring_bond::devide_buffers_helper(mem_buf_desc_t *p_mem_buf_desc_list, mem_buf_desc_t **buffer_per_ring)
{
	mem_buf_desc_t* buffers_last[m_n_num_resources];
	memset(buffers_last, 0, m_n_num_resources * sizeof(mem_buf_desc_t*));
	mem_buf_desc_t *head, *current, *temp;
	mem_buf_desc_owner* last_owner;

	head = p_mem_buf_desc_list;
	while (head) {
		last_owner = head->p_desc_owner;
		current = head;
		while(head && head->p_next_desc && head->p_next_desc->p_desc_owner == last_owner) {
			head = head->p_next_desc;
		}
		uint32_t i = 0;
		for (i = 0; i < m_n_num_resources; i++) {
			if (m_bond_rings[i] == last_owner) {
				if (buffers_last[i]) {
					buffers_last[i]->p_next_desc = current;
					buffers_last[i] = head;
				} else {
					buffer_per_ring[i] = current;
					buffers_last[i] = head;
				}
				break;
			}
		}
		temp = head->p_next_desc;
		head->p_next_desc = NULL;
		if (i == m_n_num_resources) {
			//handle no owner
			ring_logdbg("No matching ring %p to return buffer", current->p_desc_owner);
			g_buffer_pool_tx->put_buffers_thread_safe(current);
		}

		head = temp;
	}
}

/* TODO consider only ring_simple to inherit mem_buf_desc_owner */
void ring_bond::mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc)
{
	NOT_IN_USE(p_rx_wc_buf_desc);
	ring_logpanic("programming error, how did we got here?");
}

void ring_bond::mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc)
{
	NOT_IN_USE(p_tx_wc_buf_desc);
	ring_logpanic("programming error, how did we got here?");
}

void ring_bond::mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array /*NULL*/)
{
	NOT_IN_USE(p_mem_buf_desc);
	NOT_IN_USE(pv_fd_ready_array);
	ring_logpanic("programming error, how did we got here?");
}

void ring_bond::mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	NOT_IN_USE(p_mem_buf_desc);
	ring_logpanic("programming error, how did we got here?");
}

void ring_bond_eth::create_slave_list(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, bool active_slaves[], uint16_t vlan) throw (vma_error)
{
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		m_bond_rings[i] = new ring_eth(local_if, &p_ring_info[i], 1, active_slaves[i], vlan, get_mtu(), this);
		if (m_min_devices_tx_inline < 0)
			m_min_devices_tx_inline = m_bond_rings[i]->get_max_tx_inline();
		else
			m_min_devices_tx_inline = min(m_min_devices_tx_inline, m_bond_rings[i]->get_max_tx_inline());
		if (active_slaves[i]) {
			m_active_rings[i] = m_bond_rings[i];
		} else {
			m_active_rings[i] = NULL;
		}
	}
	close_gaps_active_rings();
}

void ring_bond_ib::create_slave_list(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, bool active_slaves[], uint16_t pkey) throw (vma_error)
{
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		m_bond_rings[i] = new ring_ib(local_if, &p_ring_info[i], 1, active_slaves[i], pkey, get_mtu(), this); // get_mtu() reads the MTU from ifconfig when created. Now passing it to its slaves. could have sent 0 here, as the MTU of the bond is already on the bond
		if (m_min_devices_tx_inline < 0)
			m_min_devices_tx_inline = m_bond_rings[i]->get_max_tx_inline();
		else
			m_min_devices_tx_inline = min(m_min_devices_tx_inline, m_bond_rings[i]->get_max_tx_inline());
		if (active_slaves[i]) {
			m_active_rings[i] = m_bond_rings[i];
		} else {
			m_active_rings[i] = NULL;
		}
	}
	close_gaps_active_rings();
}

void ring_bond::close_gaps_active_rings()
{
	ring_simple* curr_active = NULL;
	uint32_t i = 0;
	for (i = 0; i < m_n_num_resources; i++) {
		if (m_active_rings[i]) {
			curr_active = m_active_rings[i];
			break;
		}
	}
	if (!curr_active)
		return;
	uint32_t checked = 1; //already checked 1
	while (checked < m_n_num_resources) {
		if (i == 0) {
			i = m_n_num_resources - 1;
		} else {
			i--;
		}
		if (m_active_rings[i]) {
			curr_active = m_active_rings[i];
		} else {
			m_active_rings[i] = curr_active;
		}
		checked++;
	}
}

void ring_bond::update_rx_channel_fds() {
	m_p_n_rx_channel_fds = new int[m_n_num_resources];
	for (uint32_t i = 0; i < m_n_num_resources; i++) {
		m_p_n_rx_channel_fds[i] = m_bond_rings[i]->get_rx_channel_fds()[0];
	}
}

bool ring_bond::is_active_member(mem_buf_desc_owner* rng, ring_user_id_t id)
{
	return m_active_rings[id] == rng;
}

bool ring_bond::is_member(mem_buf_desc_owner* rng) {
	ring_simple* r = dynamic_cast<ring_simple*>(rng);
	if (r) {
		return r->m_parent == this;
	}
	return false;
}

ring_user_id_t ring_bond::generate_id() {
	return 0;
}

ring_user_id_t ring_bond::generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {

	if (m_type != net_device_val::LAG_8023ad)
		return 0;

	ring_logdbg("generate_id for policy %d from src_mac=" ETH_HW_ADDR_PRINT_FMT ", dst_mac=" ETH_HW_ADDR_PRINT_FMT ", eth_proto=%#x, encap_proto=%#x, src_ip=%d.%d.%d.%d, dst_ip=%d.%d.%d.%d, src_port=%d, dst_port=%d",
			m_xmit_hash_policy, ETH_HW_ADDR_PRINT_ADDR(src_mac), ETH_HW_ADDR_PRINT_ADDR(dst_mac), ntohs(eth_proto), ntohs(encap_proto), NIPQUAD(src_ip), NIPQUAD(dst_ip), ntohs(src_port), ntohs(dst_port));

	uint32_t hash = 0;

	if (m_xmit_hash_policy > net_device_val::XHP_LAYER_2_3 && eth_proto == htons(ETH_P_8021Q)) {
		eth_proto = encap_proto;
	}

	if (eth_proto != htons(ETH_P_IP)) {
		hash = dst_mac[5] ^ src_mac[5] ^ eth_proto;
		return hash % m_n_num_resources;
	}

	switch (m_xmit_hash_policy) {
	case(net_device_val::XHP_LAYER_2):
		hash = dst_mac[5] ^ src_mac[5] ^ eth_proto;
		break;
	case(net_device_val::XHP_LAYER_2_3):
	case(net_device_val::XHP_ENCAP_2_3):
		hash = dst_mac[5] ^ src_mac[5] ^ eth_proto;
		hash ^= dst_ip ^ src_ip;
		hash ^= (hash >> 16);
		hash ^= (hash >> 8);
		break;
	case(net_device_val::XHP_LAYER_3_4):
	case(net_device_val::XHP_ENCAP_3_4):
		hash = src_port | (dst_port << 16);
		hash ^= dst_ip ^ src_ip;
		hash ^= (hash >> 16);
		hash ^= (hash >> 8);
		break;
	default:
		return generate_id();
	}

	return hash % m_n_num_resources;
}

#ifdef DEFINED_VMAPOLL	
int ring_bond::fast_poll_and_process_element_rx(vma_packets_t *vma_pkts)
{
	NOT_IN_USE(vma_pkts);
	return 0;
}

int ring_bond::vma_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags)
{
	NOT_IN_USE(vma_completions);
	NOT_IN_USE(ncompletions);
	NOT_IN_USE(flags);

	return 0;
}
#endif // DEFINED_VMAPOLL	
