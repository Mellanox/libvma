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

#include "ring_tap.h"

#include <linux/if_tun.h>
#include "vma/util/sg_array.h"
#include "vma/sock/fd_collection.h"
#include "vma/dev/net_device_table_mgr.h"

#undef  MODULE_NAME
#define MODULE_NAME "ring_tap"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

ring_tap::ring_tap(int if_index, ring* parent):
	ring_slave(if_index, parent, RING_TAP),
	m_tap_fd(-1),
	m_vf_ring(NULL),
	m_sysvar_qp_compensation_level(safe_mce_sys().qp_compensation_level),
	m_tap_data_available(false)
{
	int rc = 0;
	struct vma_msg_flow data;
	char tap_if_name[IFNAMSIZ] = {0};
	net_device_val* p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());

	/* Create TAP device and update ring class with new if_index */
	tap_create(p_ndev);

	/* Register tap ring to the internal thread */
	m_p_n_rx_channel_fds = new int[1];
	m_p_n_rx_channel_fds[0] = m_tap_fd;

	if (m_tap_fd >= 0) {
		g_p_fd_collection->addtapfd(m_tap_fd, this);
		g_p_event_handler_manager->update_epfd(m_tap_fd,
				EPOLL_CTL_ADD, EPOLLIN | EPOLLPRI | EPOLLONESHOT);
	}

	/* Initialize RX buffer poll */
	request_more_rx_buffers();
	m_rx_pool.set_id("ring_tap (%p) : m_rx_pool", this);

	/* Initialize TX buffer poll */
	request_more_tx_buffers(m_sysvar_qp_compensation_level, 0);

	/* Update ring statistics */
	m_p_ring_stat->tap.n_tap_fd = m_tap_fd;
	if_indextoname(get_if_index(), tap_if_name);
	memcpy(m_p_ring_stat->tap.s_tap_name, tap_if_name, IFNAMSIZ);

	/* create egress rule (redirect traffic from tap device to physical interface) */
	rc = prepare_flow_message(data, VMA_MSG_FLOW_ADD);
	if (rc != 0) {
		ring_logwarn("Add TC rule failed with error=%d", rc);
	}
}

ring_tap::~ring_tap()
{
	m_lock_ring_rx.lock();
	flow_udp_del_all();
	flow_tcp_del_all();
	m_lock_ring_rx.unlock();

	g_p_event_handler_manager->update_epfd(m_tap_fd,
			EPOLL_CTL_DEL, EPOLLIN | EPOLLPRI | EPOLLONESHOT);

	if (g_p_fd_collection) {
		g_p_fd_collection->del_tapfd(m_tap_fd);
	}

	/* Release RX buffer poll */
	g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_pool, m_rx_pool.size());

	delete[] m_p_n_rx_channel_fds;

	/* TAP device release */
	tap_destroy();
}


void ring_tap::tap_create(net_device_val* p_ndev)
{
	#define TAP_NAME_FORMAT "t%x%x" // t<pid7c><fd7c>
	#define TAP_STR_LENGTH	512
	#define TAP_DISABLE_IPV6 "sysctl -w net.ipv6.conf.%s.disable_ipv6=1"

	int rc = 0, tap_if_index = -1, ioctl_sock = -1;
	struct ifreq ifr;
	char command_str[TAP_STR_LENGTH], return_str[TAP_STR_LENGTH], tap_name[IFNAMSIZ];
	unsigned char hw_addr[ETH_ALEN];

	/* Open TAP device */
	if( (m_tap_fd = orig_os_api.open("/dev/net/tun", O_RDWR)) < 0 ) {
		ring_logerr("FAILED to open tap %m");
		rc = -errno;
		goto error;
	}

	/* Tap name */
	rc = snprintf(tap_name, sizeof(tap_name), TAP_NAME_FORMAT, getpid() & 0xFFFFFFF, m_tap_fd & 0xFFFFFFF);
	if (unlikely(((int)sizeof(tap_name) < rc) || (rc < 0))) {
		ring_logerr("FAILED to create tap name %m");
		rc = -errno;
		goto error;
	}

	/* Init ifr */
	memset(&ifr, 0, sizeof(ifr));
	rc = snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
	if (unlikely((IFNAMSIZ < rc) || (rc < 0))) {
		ring_logerr("FAILED to create tap name %m");
		rc = -errno;
		goto error;
	}

	/* Setting TAP attributes */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE;
	if ((rc = orig_os_api.ioctl(m_tap_fd, TUNSETIFF, (void *) &ifr)) < 0) {
		ring_logerr("ioctl failed fd = %d, %d %m", m_tap_fd, rc);
		rc = -errno;
		goto error;
	}

	/* Set TAP fd nonblocking */
	if ((rc = orig_os_api.fcntl(m_tap_fd, F_SETFL, O_NONBLOCK))  < 0) {
		ring_logerr("ioctl failed fd = %d, %d %m", m_tap_fd, rc);
		rc = -errno;
		goto error;
	}

	/* Disable Ipv6 for TAP interface */
	snprintf(command_str, TAP_STR_LENGTH, TAP_DISABLE_IPV6, tap_name);
	if (run_and_retreive_system_command(command_str, return_str, TAP_STR_LENGTH)  < 0) {
		ring_logerr("sysctl ipv6 failed fd = %d, %m", m_tap_fd);
		rc = -errno;
		goto error;
	}

	/* Create socket */
	if ((ioctl_sock = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		ring_logerr("FAILED to open socket");
		rc = -errno;
		goto error;
	}

	/* Set MAC address */
	ifr.ifr_hwaddr.sa_family = AF_LOCAL;
	get_local_ll_addr(p_ndev->get_ifname_link(), hw_addr, ETH_ALEN, false);
	memcpy(ifr.ifr_hwaddr.sa_data, hw_addr, ETH_ALEN);
	if ((rc = orig_os_api.ioctl(ioctl_sock, SIOCSIFHWADDR, &ifr)) < 0) {
		ring_logerr("ioctl SIOCSIFHWADDR failed %d %m, %s", rc, tap_name);
		rc = -errno;
		goto error;
	}

	/* Set link UP */
	ifr.ifr_flags |= (IFF_UP | IFF_SLAVE);
	if ((rc = orig_os_api.ioctl(ioctl_sock, SIOCSIFFLAGS, &ifr)) < 0) {
		ring_logerr("ioctl SIOCGIFFLAGS failed %d %m, %s", rc, tap_name);
		rc = -errno;
		goto error;
	}

	/* Get TAP interface index */
	tap_if_index = if_nametoindex(tap_name);
	if (!tap_if_index) {
		ring_logerr("if_nametoindex failed to get tap index [%s]", tap_name);
		rc = -errno;
		goto error;
	}

	/* Update if_index on ring class */
	set_if_index(tap_if_index);

	orig_os_api.close(ioctl_sock);

	ring_logdbg("Tap device %d: %s [fd=%d] was created successfully",
			tap_if_index, ifr.ifr_name, m_tap_fd);

	return;

error:
	ring_logerr("Tap device creation failed %d, %m", rc);

	if (ioctl_sock >= 0) {
		orig_os_api.close(ioctl_sock);
	}

	if (m_tap_fd >= 0) {
		orig_os_api.close(m_tap_fd);
	}

	m_tap_fd = -1;
}


void ring_tap::tap_destroy()
{
	if (m_tap_fd >= 0) {
		orig_os_api.close(m_tap_fd);

		m_tap_fd = -1;
	}
}

bool ring_tap::attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink *sink)
{
	auto_unlocker lock(m_lock_ring_rx);
	bool ret = ring_slave::attach_flow(flow_spec_5t, sink);

	if (ret && (flow_spec_5t.is_tcp() || flow_spec_5t.is_udp_uc())) {
		int rc = 0;
		struct vma_msg_flow data;
		rc = prepare_flow_message(data, VMA_MSG_FLOW_ADD, flow_spec_5t);
		if (rc != 0) {
			if (!g_b_exit) {
				ring_logwarn("Add TC rule failed with error=%d", rc);
			}
			ring_slave::detach_flow(flow_spec_5t, sink);
			ret = false;
		}
	}

	return ret;
}

bool ring_tap::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	auto_unlocker lock(m_lock_ring_rx);
	bool ret = ring_slave::detach_flow(flow_spec_5t, sink);

	if (flow_spec_5t.is_tcp() || flow_spec_5t.is_udp_uc()) {
		int rc = 0;
		struct vma_msg_flow data;
		rc = prepare_flow_message(data, VMA_MSG_FLOW_DEL, flow_spec_5t);
		if (rc != 0) {
			if (!g_b_exit) {
				ring_logwarn("Del TC rule failed with error=%d", rc);
			}
			ret = false;
		}
	}

	return ret;
}

int ring_tap::poll_and_process_element_rx(uint64_t*, void* pv_fd_ready_array)
{
	return process_element_rx(pv_fd_ready_array);
}

int ring_tap::wait_for_notification_and_process_element(int, uint64_t*, void* pv_fd_ready_array)
{
	return process_element_rx(pv_fd_ready_array);
}

int ring_tap::drain_and_proccess()
{
	return process_element_rx(NULL);
}

bool ring_tap::reclaim_recv_buffers(descq_t *rx_reuse)
{
	while (!rx_reuse->empty()) {
		mem_buf_desc_t* buff = rx_reuse->get_and_pop_front();
		reclaim_recv_buffers(buff);
	}

	if (m_rx_pool.size() >= m_sysvar_qp_compensation_level * 2) {
		int buff_to_rel = m_rx_pool.size() - m_sysvar_qp_compensation_level;

		g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_pool, buff_to_rel);
		m_p_ring_stat->tap.n_rx_buffers = m_rx_pool.size();
	}

	return true;
}

bool ring_tap::reclaim_recv_buffers(mem_buf_desc_t *buff)
{
	if (buff && (buff->dec_ref_count() <= 1)) {
		mem_buf_desc_t* temp = NULL;
		while (buff) {
			if(buff->lwip_pbuf_dec_ref_count() <= 0) {
				temp = buff;
				buff = temp->p_next_desc;
				temp->p_next_desc = NULL;
				temp->p_prev_desc = NULL;
				temp->reset_ref_count();
				temp->rx.tcp.gro = 0;
				temp->rx.is_vma_thr = false;
				temp->rx.socketxtreme_polled = false;
				temp->rx.flow_tag_id = 0;
				temp->rx.tcp.p_ip_h = NULL;
				temp->rx.tcp.p_tcp_h = NULL;
				temp->rx.timestamps.sw.tv_nsec = 0;
				temp->rx.timestamps.sw.tv_sec = 0;
				temp->rx.timestamps.hw.tv_nsec = 0;
				temp->rx.timestamps.hw.tv_sec = 0;
				temp->rx.hw_raw_timestamp = 0;
				free_lwip_pbuf(&temp->lwip_pbuf);
				m_rx_pool.push_back(temp);
			}
			else {
				buff->reset_ref_count();
				buff = buff->p_next_desc;
			}
		}
		m_p_ring_stat->tap.n_rx_buffers = m_rx_pool.size();
		return true;
	}
	return false;
}

void ring_tap::send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	NOT_IN_USE(id);
	compute_tx_checksum((mem_buf_desc_t*)(p_send_wqe->wr_id), attr & VMA_TX_PACKET_L3_CSUM, attr & VMA_TX_PACKET_L4_CSUM);

	auto_unlocker lock(m_lock_ring_tx);
	int ret = send_buffer(p_send_wqe, attr);
	send_status_handler(ret, p_send_wqe);
}

void ring_tap::send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	NOT_IN_USE(id);
	compute_tx_checksum((mem_buf_desc_t*)(p_send_wqe->wr_id), attr & VMA_TX_PACKET_L3_CSUM, attr & VMA_TX_PACKET_L4_CSUM);

	auto_unlocker lock(m_lock_ring_tx);
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
	p_mem_buf_desc->lwip_pbuf.pbuf.ref++;
	int ret = send_buffer(p_send_wqe, attr);
	send_status_handler(ret, p_send_wqe);
}

int ring_tap::prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action,
		flow_tuple& flow_spec_5t)
{
	int rc = 0;

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_FLOW;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();

	data.action = flow_action;
	data.if_id = get_parent()->get_if_index();
	data.tap_id = get_if_index();

	data.flow.dst_ip = flow_spec_5t.get_dst_ip();
	data.flow.dst_port = flow_spec_5t.get_dst_port();

	if (flow_spec_5t.is_3_tuple()) {
		data.type = flow_spec_5t.is_tcp() ? VMA_MSG_FLOW_TCP_3T : VMA_MSG_FLOW_UDP_3T;
	} else {
		data.type = flow_spec_5t.is_tcp() ? VMA_MSG_FLOW_TCP_5T : VMA_MSG_FLOW_UDP_5T;
		data.flow.t5.src_ip = flow_spec_5t.get_src_ip();
		data.flow.t5.src_port = flow_spec_5t.get_src_port();
	}

	rc = g_p_agent->send_msg_flow(&data);

	return rc;
}

int ring_tap::prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action)
{
	int rc = 0;

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_FLOW;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	data.action = flow_action;
	data.if_id = get_parent()->get_if_index();
	data.tap_id = get_if_index();
	data.type = VMA_MSG_FLOW_EGRESS;

	rc = g_p_agent->send_msg_flow(&data);

	return rc;
}

int ring_tap::process_element_rx(void* pv_fd_ready_array)
{
	int ret = 0;

	if(m_tap_data_available) {
		auto_unlocker lock(m_lock_ring_rx);
		if (m_rx_pool.size() || request_more_rx_buffers()) {
			mem_buf_desc_t *buff = m_rx_pool.get_and_pop_front();
			ret = orig_os_api.read(m_tap_fd, buff->p_buffer, buff->sz_buffer);
			if (ret > 0) {
				/* Data was read and processed successfully */
				buff->sz_data = ret;
				buff->rx.is_sw_csum_need = 1;
				if ((ret = rx_process_buffer(buff, pv_fd_ready_array))) {
					m_p_ring_stat->tap.n_rx_buffers--;
				}
			}
			if (ret <= 0){
				/* Unable to read data, return buffer to pool */
				ret = 0;
				m_rx_pool.push_front(buff);
			}

			m_tap_data_available = false;
			g_p_event_handler_manager->update_epfd(m_tap_fd,
					EPOLL_CTL_MOD, EPOLLIN | EPOLLPRI | EPOLLONESHOT);
		}
	}

	return ret;
}

bool ring_tap::request_more_rx_buffers()
{
	ring_logfuncall("Allocating additional %d buffers for internal use",
			m_sysvar_qp_compensation_level);

	bool res = g_buffer_pool_rx->get_buffers_thread_safe(m_rx_pool,
			this, m_sysvar_qp_compensation_level, 0);
	if (!res) {
		ring_logfunc("Out of mem_buf_desc from RX free pool for internal object pool");
		return false;
	}

	m_p_ring_stat->tap.n_rx_buffers = m_rx_pool.size();

	return true;
}

mem_buf_desc_t* ring_tap::mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs)
{
	mem_buf_desc_t* head = NULL;

	NOT_IN_USE(id);
	NOT_IN_USE(b_block);

	ring_logfuncall("n_num_mem_bufs=%d", n_num_mem_bufs);

	m_lock_ring_tx.lock();

	if (unlikely((int)m_tx_pool.size() < n_num_mem_bufs)) {
		request_more_tx_buffers(m_sysvar_qp_compensation_level, 0);

		if (unlikely((int)m_tx_pool.size() < n_num_mem_bufs)) {
			m_lock_ring_tx.unlock();
			return head;
		}
	}

	head = m_tx_pool.get_and_pop_back();
	head->lwip_pbuf.pbuf.ref = 1;
	n_num_mem_bufs--;

	mem_buf_desc_t* next = head;
	while (n_num_mem_bufs) {
		next->p_next_desc = m_tx_pool.get_and_pop_back();
		next = next->p_next_desc;
		next->lwip_pbuf.pbuf.ref = 1;
		n_num_mem_bufs--;
	}

	m_lock_ring_tx.unlock();

	return head;
}

inline void ring_tap::return_to_global_pool()
{
	if (m_tx_pool.size() >= m_sysvar_qp_compensation_level * 2) {
		int return_bufs = m_tx_pool.size() - m_sysvar_qp_compensation_level;
		g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, return_bufs);
	}
}

void ring_tap::mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	auto_unlocker lock(m_lock_ring_tx);

	int count = 0;

	if (likely(p_mem_buf_desc)) {
		//potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp & sockinfo_tcp by tcp lock
		if (likely(p_mem_buf_desc->lwip_pbuf.pbuf.ref))
			p_mem_buf_desc->lwip_pbuf.pbuf.ref--;
		else
			ring_logerr("ref count of %p is already zero, double free??", p_mem_buf_desc);

		if (p_mem_buf_desc->lwip_pbuf.pbuf.ref == 0) {
			p_mem_buf_desc->p_next_desc = NULL;
			free_lwip_pbuf(&p_mem_buf_desc->lwip_pbuf);
			m_tx_pool.push_back(p_mem_buf_desc);
			count++;
		}
	}

	return_to_global_pool();
}

int ring_tap::mem_buf_tx_release(mem_buf_desc_t* buff_list, bool b_accounting, bool trylock)
{
	int count = 0, freed=0;
	mem_buf_desc_t *next;

	NOT_IN_USE(b_accounting);

	if (!trylock) {
		m_lock_ring_tx.lock();
	} else if (m_lock_ring_tx.trylock()) {
		return 0;
	}

	while (buff_list) {
		next = buff_list->p_next_desc;
		buff_list->p_next_desc = NULL;

		//potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp & sockinfo_tcp by tcp lock
		if (likely(buff_list->lwip_pbuf.pbuf.ref)) {
			buff_list->lwip_pbuf.pbuf.ref--;
		} else {
			ring_logerr("ref count of %p is already zero, double free??", buff_list);
		}

		if (buff_list->lwip_pbuf.pbuf.ref == 0) {
			free_lwip_pbuf(&buff_list->lwip_pbuf);
			m_tx_pool.push_back(buff_list);
			freed++;
		}
		count++;
		buff_list = next;
	}
	ring_logfunc("buf_list: %p count: %d freed: %d\n", buff_list, count, freed);

	return_to_global_pool();

	m_lock_ring_tx.unlock();

	return count;
}

int ring_tap::send_buffer(vma_ibv_send_wr* wr, vma_wr_tx_packet_attr attr)
{
	int ret = 0;
	iovec iovec[wr->num_sge];
	NOT_IN_USE(attr);

	for (int i = 0; i < wr->num_sge; i++) {
		iovec[i].iov_base = (void *) wr->sg_list[i].addr;
		iovec[i].iov_len = wr->sg_list[i].length;
	}

	ret = orig_os_api.writev(m_tap_fd, iovec , wr->num_sge);
	if (ret < 0) {
		ring_logdbg("writev: tap_fd %d, errno: %d\n", m_tap_fd, errno);
	}

	return ret;
}

void ring_tap::send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe)
{
	// Pay attention that there is a difference in return values in ring_simple and ring_tap
	// Non positive value of ret means that we are on error flow (unlike for ring_simple).
	if (p_send_wqe) {
		mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);

		if (likely(ret > 0)) {
			// Update TX statistics
			sg_array sga(p_send_wqe->sg_list, p_send_wqe->num_sge);
			m_p_ring_stat->n_tx_byte_count += sga.length();
			++m_p_ring_stat->n_tx_pkt_count;
		}

		mem_buf_tx_release(p_mem_buf_desc, true);
	}
}
