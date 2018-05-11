/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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
#include <linux/if_tun.h>

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
#include "vma/dev/ring_slave.h"
#include "vma/dev/ring_simple.h"
#include "vma/dev/ring_tap.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"ring_bond"
#undef  MODULE_HDR
#define MODULE_HDR	 	MODULE_NAME "%d:%s() "

/* Set limitation for number of rings for bonding device */
#define MAX_NUM_RING_RESOURCES 10


ring_bond::ring_bond(int if_index) :
	ring(),
	m_lock_ring_rx("ring_bond:lock_rx"), m_lock_ring_tx("ring_bond:lock_tx")
{
	net_device_val* p_ndev = NULL;

	/* Configure ring() fields */
	set_parent(this);
	set_if_index(if_index);

	/* Sanity check */
	p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	if (NULL == p_ndev) {
		ring_logpanic("Invalid if_index = %d", if_index);
	}

	/* Configure ring_bond() fields */
	m_bond_rings.clear();
	m_type = p_ndev->get_is_bond();
	m_xmit_hash_policy = p_ndev->get_bond_xmit_hash_policy();
	m_min_devices_tx_inline = -1;

	print_val();
}

ring_bond::~ring_bond()
{
	print_val();

	m_rx_flows.clear();

	ring_slave_vector_t::iterator iter = m_bond_rings.begin();
	for (; iter != m_bond_rings.end(); iter++) {
		delete *iter;
	}
	m_bond_rings.clear();

	if (m_p_n_rx_channel_fds) {
		delete[] m_p_n_rx_channel_fds;
	}
}

void ring_bond::print_val()
{
	ring_logdbg("%d: 0x%X: parent 0x%X type %s",
			m_if_index, this,
			((uintptr_t)this == (uintptr_t)m_parent ? 0 : m_parent),
			"bond");
}

bool ring_bond::attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	bool ret = true;
	struct flow_sink_t value = {flow_spec_5t, sink};

	auto_unlocker lock(m_lock_ring_rx);

	/* Map flow in local map */
	m_rx_flows.push_back(value);

	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		bool step_ret = m_bond_rings[i]->attach_flow(flow_spec_5t, sink);
		ret = ret && step_ret;
	}

	return ret;
}

bool ring_bond::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	bool ret = true;
	struct flow_sink_t value = {flow_spec_5t, sink};

	auto_unlocker lock(m_lock_ring_rx);

	std::vector<struct flow_sink_t>::iterator iter;
	for (iter = m_rx_flows.begin(); iter != m_rx_flows.end(); iter++) {
		struct flow_sink_t cur = *iter;
		if ((cur.flow == value.flow) && (cur.sink == value.sink)) {
			m_rx_flows.erase(iter);
			break;
		}
	}

	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		bool step_ret = m_bond_rings[i]->detach_flow(flow_spec_5t, sink);
		ret = ret && step_ret;
	}

	return ret;
}

void ring_bond::restart()
{
	net_device_val* p_ndev =
			g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());

	if (NULL == p_ndev) {
		return;
	}
	const slave_data_vector_t& slaves = p_ndev->get_slave_array();

	ring_logdbg("*** ring restart! ***");

	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();

	if(p_ndev->get_is_bond() == net_device_val::NETVSC) {
		ring_bond_netvsc* p_ring_bond_netvsc = dynamic_cast<ring_bond_netvsc*>(this);
		if (p_ring_bond_netvsc) {
			ring_tap* p_ring_tap = dynamic_cast<ring_tap*>(p_ring_bond_netvsc->m_tap_ring);
			if (p_ring_tap) {
				size_t num_ring_rx_fds = 0;
				int *ring_rx_fds_array = NULL;
				int epfd = -1;
				int fd = -1;
				int rc = 0;
				size_t i, j, k;

				if (slaves.size() == 1) {
					num_ring_rx_fds = p_ring_bond_netvsc->m_vf_ring->get_num_resources();
					ring_rx_fds_array = p_ring_bond_netvsc->m_vf_ring->get_rx_channel_fds();

					for (k = 0; k < num_ring_rx_fds; k++ ) {
						epfd = g_p_net_device_table_mgr->global_ring_epfd_get();
						if (epfd > 0) {
							fd = ring_rx_fds_array[k];
							rc = orig_os_api.epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
							ring_logdbg("Remove fd=%d from epfd=%d rc=%d errno=%d", fd, epfd, rc, errno);
						}
					}
					for (j = 0; j < m_rx_flows.size(); j++) {
						sockinfo* si = static_cast<sockinfo*> (m_rx_flows[j].sink);
						for (k = 0; k < num_ring_rx_fds; k++ ) {
							epfd = si->get_rx_epfd();
							if (epfd > 0) {
								fd = ring_rx_fds_array[k];
								rc = orig_os_api.epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
								ring_logdbg("Remove fd=%d from epfd=%d rc=%d errno=%d", fd, epfd, rc, errno);
							}
							epfd = si->get_epoll_context_fd();
							if (epfd > 0) {
								fd = ring_rx_fds_array[k];
								rc = orig_os_api.epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
								ring_logdbg("Remove fd=%d from epfd=%d rc=%d errno=%d", fd, epfd, rc, errno);
							}
						}
					}

					p_ring_tap->m_active = true;
					p_ring_bond_netvsc->slave_destroy(p_ring_bond_netvsc->m_vf_ring->get_if_index());
					p_ring_bond_netvsc->m_vf_ring = NULL;
					p_ring_tap->set_vf_ring(NULL);
				} else {
					for (i = 0; i < slaves.size(); i++) {
						if (slaves[i]->if_index != p_ndev->get_tap_if_index()) {
							p_ring_tap->m_active = false;
							slave_create(slaves[i]->if_index);
							p_ring_tap->set_vf_ring(p_ring_bond_netvsc->m_vf_ring);

							num_ring_rx_fds = p_ring_bond_netvsc->m_vf_ring->get_num_resources();
							ring_rx_fds_array = p_ring_bond_netvsc->m_vf_ring->get_rx_channel_fds();

							for (k = 0; k < num_ring_rx_fds; k++ ) {
								epfd = g_p_net_device_table_mgr->global_ring_epfd_get();
								if (epfd > 0) {
									epoll_event ev = {0, {0}};
									fd = ring_rx_fds_array[k];
									ev.events = EPOLLIN;
									ev.data.fd = fd;
									rc = orig_os_api.epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
									ring_logdbg("Add fd=%d from epfd=%d rc=%d errno=%d", fd, epfd, rc, errno);
								}
							}
							for (j = 0; j < m_rx_flows.size(); j++) {
								sockinfo* si = static_cast<sockinfo*> (m_rx_flows[j].sink);
								p_ring_bond_netvsc->m_vf_ring->attach_flow(m_rx_flows[j].flow, m_rx_flows[j].sink);
								for (k = 0; k < num_ring_rx_fds; k++ ) {
									epfd = si->get_rx_epfd();
									if (epfd > 0) {
										epoll_event ev = {0, {0}};
										fd = ring_rx_fds_array[k];
										ev.events = EPOLLIN;
										ev.data.fd = fd;
										rc = orig_os_api.epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
										ring_logdbg("Add fd=%d from epfd=%d rc=%d errno=%d", fd, epfd, rc, errno);
									}
									epfd = si->get_epoll_context_fd();
									if (epfd > 0) {
										#define CQ_FD_MARK 0xabcd /* see socket_fd_api */
										epoll_event ev = {0, {0}};
										fd = ring_rx_fds_array[k];
										ev.events = EPOLLIN | EPOLLPRI;
										ev.data.u64 = (((uint64_t)CQ_FD_MARK << 32) | fd);
										rc = orig_os_api.epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
										ring_logdbg("Add fd=%d from epfd=%d rc=%d errno=%d", fd, epfd, rc, errno);
									}
								}
							}
							break;
						}
					}
				}
			}
		}
	} else {
		/* for active-backup mode
		 * It is guaranteed that the first slave is active by popup_active_rings()
		 */
		ring_simple* previously_active = dynamic_cast<ring_simple*>(m_bond_rings[0]);

		for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
			ring_simple* tmp_ring = dynamic_cast<ring_simple*>(m_bond_rings[i]);
			if (!tmp_ring) {
				continue;
			}
			if (slaves[i]->active) {
				ring_logdbg("ring %d active", i);
				tmp_ring->start_active_qp_mgr();
				m_bond_rings[i]->m_active = true;
			} else {
				ring_logdbg("ring %d not active", i);
				tmp_ring->stop_active_qp_mgr();
				m_bond_rings[i]->m_active = false;
			}
		}
		popup_active_rings();

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
			ring_simple* currently_active = dynamic_cast<ring_simple*>(m_bond_rings[0]);
			if (currently_active && safe_mce_sys().cq_moderation_enable) {
				if (likely(previously_active)) {
					currently_active->m_cq_moderation_info.period = previously_active->m_cq_moderation_info.period;
					currently_active->m_cq_moderation_info.count = previously_active->m_cq_moderation_info.count;
				}
				else {
					currently_active->m_cq_moderation_info.period = safe_mce_sys().cq_moderation_period_usec;
					currently_active->m_cq_moderation_info.count = safe_mce_sys().cq_moderation_count;
				}

				currently_active->modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec, safe_mce_sys().cq_moderation_count);
			}
		}
	}

	m_lock_ring_tx.unlock();
	m_lock_ring_rx.unlock();

	ring_logdbg("*** ring restart done! ***");
}

void ring_bond::adapt_cq_moderation()
{
	if (m_lock_ring_rx.trylock()) {
		return ;
	}

	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		if (m_bond_rings[i]->is_up())
			m_bond_rings[i]->adapt_cq_moderation();
	}

	m_lock_ring_rx.unlock();
}

mem_buf_desc_t* ring_bond::mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs /* default = 1 */)
{
	mem_buf_desc_t* ret = NULL;

	auto_unlocker lock(m_lock_ring_tx);
	ret = m_bond_rings[id]->mem_buf_tx_get(id, b_block, n_num_mem_bufs);

	return ret;
}

int ring_bond::mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock/*=false*/)
{
	mem_buf_desc_t* buffer_per_ring[MAX_NUM_RING_RESOURCES];
	int ret = 0;
	uint32_t i = 0;

	auto_unlocker lock(m_lock_ring_tx);

	memset(buffer_per_ring, 0, sizeof(buffer_per_ring));
	ret = devide_buffers_helper(p_mem_buf_desc_list, buffer_per_ring);

	for (i = 0; i < m_bond_rings.size(); i++) {
		if (buffer_per_ring[i]) {
			ret += m_bond_rings[i]->mem_buf_tx_release(buffer_per_ring[i], b_accounting, trylock);
		}
	}
	return ret;
}

void ring_bond::send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);

	auto_unlocker lock(m_lock_ring_tx);
	ring_slave* active_ring = m_bond_rings[id];

	if (is_active_member(p_mem_buf_desc->p_desc_owner, id)) {
		active_ring->send_ring_buffer(id, p_send_wqe, attr);
	} else {
		ring_logfunc("active ring=%p, silent packet drop (%p), (HA event?)", active_ring, p_mem_buf_desc);
		p_mem_buf_desc->p_next_desc = NULL;
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

	auto_unlocker lock(m_lock_ring_tx);
	ring_slave* active_ring = m_bond_rings[id];

	if (is_active_member(p_mem_buf_desc->p_desc_owner, id)) {
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

	auto_unlocker lock(m_lock_ring_tx);
	ring_slave* active_ring = m_bond_rings[id];

	if (is_active_member(p_mem_buf_desc->p_desc_owner, id)) {
		return active_ring->get_hw_dummy_send_support(id, p_send_wqe);
	} else {
		if (likely(p_mem_buf_desc->p_desc_owner == active_ring)) {
			return active_ring->get_hw_dummy_send_support(id, p_send_wqe);
		}
	}

	return false;
}

int ring_bond::get_max_tx_inline()
{
	return m_min_devices_tx_inline;
}

int ring_bond::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/)
{
	if (m_lock_ring_rx.trylock()) {
		errno = EBUSY;
		return 0;
	}

	int temp = 0;
	int ret = 0;
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
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

int ring_bond::drain_and_proccess()
{
	if (m_lock_ring_rx.trylock()) {
		errno = EBUSY;
		return 0;
	}

	int temp = 0;
	int ret = 0;
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		if (m_bond_rings[i]->is_up()) {
			temp = m_bond_rings[i]->drain_and_proccess();
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

int ring_bond::wait_for_notification_and_process_element(int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/) {
	if(m_lock_ring_rx.trylock()) {
		errno = EBUSY;
		return -1;
	}

	int temp = 0;
	int ret = 0;
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		if (m_bond_rings[i]->is_up()) {
			temp = m_bond_rings[i]->wait_for_notification_and_process_element(cq_channel_fd, p_cq_poll_sn, pv_fd_ready_array);
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
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
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

void ring_bond::inc_tx_retransmissions(ring_user_id_t id)
{
	auto_unlocker lock(m_lock_ring_tx);
	ring_slave* active_ring = m_bond_rings[id];
	if (likely(active_ring->m_active)) {
		active_ring->inc_tx_retransmissions(id);
	}
}

bool ring_bond::reclaim_recv_buffers(descq_t *rx_reuse)
{
	/* use this local array to avoid locking mechanizm
	 * for threads synchronization. So every thread should use
	 * own array. Set hardcoded number to meet C++11
	 * VLA is not an official part of C++11.
	 */
	descq_t buffer_per_ring[MAX_NUM_RING_RESOURCES];
	uint32_t i = 0;

	if(m_lock_ring_rx.trylock()) {
		errno = EBUSY;
		return false;
	}

	devide_buffers_helper(rx_reuse, buffer_per_ring);

	for (i = 0; i < m_bond_rings.size(); i++) {
		if (buffer_per_ring[i].size() > 0) {
			if (!m_bond_rings[i]->reclaim_recv_buffers(&buffer_per_ring[i])) {
				g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&buffer_per_ring[i]);
			}
		}
	}

	if (buffer_per_ring[m_bond_rings.size()].size() > 0) {
		g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&buffer_per_ring[m_bond_rings.size()]);
	}

	m_lock_ring_rx.unlock();

	return true;
}

void ring_bond::devide_buffers_helper(descq_t *rx_reuse, descq_t* buffer_per_ring)
{
	int last_found_index = 0;
	while (!rx_reuse->empty()) {
		mem_buf_desc_t* buff = rx_reuse->get_and_pop_front();
		uint32_t checked = 0;
		int index = last_found_index;
		while (checked < m_bond_rings.size()) {
			if (m_bond_rings[index] == buff->p_desc_owner) {
				buffer_per_ring[index].push_back(buff);
				last_found_index = index;
				break;
			}
			checked++;
			index++;
			index = index % m_bond_rings.size();
		}
		//no owner
		if (checked == m_bond_rings.size()) {
			ring_logfunc("No matching ring %p to return buffer", buff->p_desc_owner);
			buffer_per_ring[m_bond_rings.size()].push_back(buff);
		}
	}
}

int ring_bond::devide_buffers_helper(mem_buf_desc_t *p_mem_buf_desc_list, mem_buf_desc_t **buffer_per_ring)
{
	mem_buf_desc_t* buffers_last[MAX_NUM_RING_RESOURCES];
	mem_buf_desc_t *head, *current, *temp;
	mem_buf_desc_owner* last_owner;
	int count = 0;
	int ret = 0;

	memset(buffers_last, 0, sizeof(buffers_last));
	head = p_mem_buf_desc_list;
	while (head) {
		last_owner = head->p_desc_owner;
		current = head;
		count = 1;
		while(head && head->p_next_desc && head->p_next_desc->p_desc_owner == last_owner) {
			head = head->p_next_desc;
			count++;
		}
		uint32_t i = 0;
		for (i = 0; i < m_bond_rings.size(); i++) {
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
		if (i == m_bond_rings.size()) {
			//handle no owner
			ring_logdbg("No matching ring %p to return buffer", current->p_desc_owner);
			g_buffer_pool_tx->put_buffers_thread_safe(current);
			ret += count;
		}

		head = temp;
	}

	return ret;
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

void ring_bond::popup_active_rings()
{
	ring_slave *cur_slave = NULL;
	int i, j;

	for (i = 0; i < (int)m_bond_rings.size(); i++) {
		for (j = i + 1; j < (int)m_bond_rings.size(); j++) {
			if (!m_bond_rings[i]->m_active && m_bond_rings[j]->m_active) {
				cur_slave = m_bond_rings[i];
				m_bond_rings[i] = m_bond_rings[j];
				m_bond_rings[j] = cur_slave;
			}
		}
	}
}

void ring_bond::update_rx_channel_fds()
{
	if (m_p_n_rx_channel_fds) {
		delete[] m_p_n_rx_channel_fds;
	}
	m_p_n_rx_channel_fds = new int[m_bond_rings.size()];
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		m_p_n_rx_channel_fds[i] = m_bond_rings[i]->get_rx_channel_fds()[0];
	}
}

bool ring_bond::is_active_member(mem_buf_desc_owner* rng, ring_user_id_t id)
{
	return (m_bond_rings[id] == rng && m_bond_rings[id]->m_active);
}

bool ring_bond::is_member(mem_buf_desc_owner* rng)
{
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		if (m_bond_rings[i]->is_member(rng)) {
			return true;
		}
	}
	return false;
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
		return hash % m_bond_rings.size();
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
		return ring::generate_id();
	}

	return hash % m_bond_rings.size();
}

int ring_bond::modify_ratelimit(struct vma_rate_limit_t &rate_limit) {
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		if (m_bond_rings[i]) {
			m_bond_rings[i]->modify_ratelimit(rate_limit);
		}
	}
	return 0;
}

bool ring_bond::is_ratelimit_supported(struct vma_rate_limit_t &rate_limit)
{
	for (uint32_t i = 0; i < m_bond_rings.size(); i++) {
		if (m_bond_rings[i] &&
		    !m_bond_rings[i]->is_ratelimit_supported(rate_limit)) {
				return false;
		}
	}
	return true;
}

#ifdef DEFINED_SOCKETXTREME	
int ring_bond::socketxtreme_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags)
{
	NOT_IN_USE(vma_completions);
	NOT_IN_USE(ncompletions);
	NOT_IN_USE(flags);

	return 0;
}
#endif // DEFINED_SOCKETXTREME	

void ring_bond::slave_destroy(int if_index)
{
	ring_slave *cur_slave = NULL;
	ring_slave_vector_t::iterator iter;

	for (iter = m_bond_rings.begin(); iter != m_bond_rings.end(); iter++) {
		cur_slave = *iter;
		if (cur_slave->get_if_index() == if_index) {
			delete cur_slave;
			m_bond_rings.erase(iter);
			update_rx_channel_fds();
			break;
		}
	}
}

void ring_bond_eth::slave_create(int if_index)
{
	ring_slave *cur_slave = NULL;

	cur_slave = new ring_eth(if_index, this);
	if (m_min_devices_tx_inline < 0) {
		m_min_devices_tx_inline = cur_slave->get_max_tx_inline();
	} else {
		m_min_devices_tx_inline = min(m_min_devices_tx_inline, cur_slave->get_max_tx_inline());
	}
	m_bond_rings.push_back(cur_slave);

	if (m_bond_rings.size() > MAX_NUM_RING_RESOURCES) {
		ring_logpanic("Error creating bond ring with more than %d resource", MAX_NUM_RING_RESOURCES);
	}

	popup_active_rings();
	update_rx_channel_fds();
}

void ring_bond_ib::slave_create(int if_index)
{
	ring_slave *cur_slave = NULL;

	cur_slave = new ring_ib(if_index, this);
	if (m_min_devices_tx_inline < 0) {
		m_min_devices_tx_inline = cur_slave->get_max_tx_inline();
	} else {
		m_min_devices_tx_inline = min(m_min_devices_tx_inline, cur_slave->get_max_tx_inline());
	}
	m_bond_rings.push_back(cur_slave);

	if (m_bond_rings.size() > MAX_NUM_RING_RESOURCES) {
		ring_logpanic("Error creating bond ring with more than %d resource", MAX_NUM_RING_RESOURCES);
	}

	popup_active_rings();
	update_rx_channel_fds();
}

void ring_bond_netvsc::slave_create(int if_index)
{
	ring_slave *cur_slave = NULL;
	net_device_val* p_ndev = NULL;

	p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	if (NULL == p_ndev) {
		ring_logpanic("Error creating bond ring");
	}

	if (if_index == p_ndev->get_tap_if_index()) {
		cur_slave = new ring_tap(if_index, this);
		m_tap_ring = cur_slave;
	} else {
		cur_slave = new ring_eth(if_index, this);
		m_vf_ring = cur_slave;
	}
	if (m_min_devices_tx_inline < 0) {
		m_min_devices_tx_inline = cur_slave->get_max_tx_inline();
	} else {
		m_min_devices_tx_inline = min(m_min_devices_tx_inline, cur_slave->get_max_tx_inline());
	}
	m_bond_rings.push_back(cur_slave);

	if (m_bond_rings.size() > 2) {
		ring_logpanic("Error creating bond ring with more than %d resource", 2);
	}

	popup_active_rings();
	update_rx_channel_fds();
}
