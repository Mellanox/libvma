/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd. All rights reserved.
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
#include "vma/dev/net_device_table_mgr.h"
#include "vma/sock/fd_collection.h"

#undef  MODULE_NAME
#define MODULE_NAME "ring_tap"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "


ring_tap::ring_tap(int if_index, ring* parent):
	ring_slave(if_index, RING_TAP, parent),
	m_sysvar_qp_compensation_level(safe_mce_sys().qp_compensation_level)
{
	char tap_if_name[IFNAMSIZ + 1] = {0};
	net_device_val* p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());

	m_vf_ring = NULL;
	m_tap_data_available = false;
	m_tap_fd = p_ndev->get_tap_fd();

	/* Register tap ring to the internal thread */
	m_p_n_rx_channel_fds = new int[1];
	m_p_n_rx_channel_fds[0] = m_tap_fd;
//	g_p_fd_collection->add_cq_channel_fd(m_p_n_rx_channel_fds[0], this);
	g_p_fd_collection->addtapfd(m_tap_fd, this);
	g_p_event_handler_manager->update_epfd(m_tap_fd,
			EPOLL_CTL_ADD, EPOLLIN | EPOLLPRI | EPOLLONESHOT);

	/* Initialize RX buffer poll */
	request_more_rx_buffers();
	m_rx_pool.set_id("ring_tap (%p) : m_rx_pool", this);

	/* Update ring statistics */
	m_p_ring_stat->p_ring_master = this;
	m_p_ring_stat->n_type = RING_TAP;
	m_p_ring_stat->tap.n_tap_fd = m_tap_fd;
	if_indextoname(get_if_index(), tap_if_name);
	memcpy(m_p_ring_stat->tap.s_tap_name, tap_if_name, IFNAMSIZ);
}

ring_tap::~ring_tap()
{
	g_p_event_handler_manager->update_epfd(m_tap_fd,
			EPOLL_CTL_DEL, EPOLLIN | EPOLLPRI | EPOLLONESHOT);

	if (g_p_fd_collection) {
		g_p_fd_collection->del_tapfd(m_tap_fd);
	}

	/* Release Rx buffer poll */
	g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_pool, m_rx_pool.size());

	delete[] m_p_n_rx_channel_fds;
}

bool ring_tap::attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	ring_logdbg("flow: %s, with sink (%p)",
		    flow_spec_5t.to_str(), sink);

	if( sink == NULL )
		return false;

	if (flow_spec_5t.is_tcp()) {
		int rc = 0;
		struct vma_msg_flow data;
		prepare_flow_message(data, flow_spec_5t, VMA_MSG_FLOW_ADD);

		rc = g_p_agent->send_msg_flow(&data);
		if (rc != 0) {
			ring_logwarn("Add TC rule failed with error=%d", rc);
			return false;
		}
	}

	return true;
}

bool ring_tap::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	ring_logdbg("flow: %s, with sink (%p)",
		    flow_spec_5t.to_str(), sink);

	if( sink == NULL )
		return false;

	if (flow_spec_5t.is_tcp()) {
		int rc = 0;
		struct vma_msg_flow data;
		prepare_flow_message(data, flow_spec_5t, VMA_MSG_FLOW_DEL);

		rc = g_p_agent->send_msg_flow(&data);
		if (rc != 0) {
			ring_logwarn("Del TC rule failed with error=%d", rc);
			return false;
		}
	}

	return true;
}

int ring_tap::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	NOT_IN_USE(p_cq_poll_sn);
	return process_element_rx(pv_fd_ready_array);
}

int ring_tap::wait_for_notification_and_process_element(int cq_channel_fd,
		uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	NOT_IN_USE(cq_channel_fd);
	NOT_IN_USE(p_cq_poll_sn);
	return process_element_rx(pv_fd_ready_array);
}

int ring_tap::drain_and_proccess()
{
	return process_element_rx(NULL);
}

int ring_tap::process_element_rx(void* pv_fd_ready_array)
{
	int ret = 0;

	if(m_tap_data_available) {
		if (m_rx_pool.size() || request_more_rx_buffers()) {
			mem_buf_desc_t *buff = m_rx_pool.get_and_pop_front();
			buff->sz_data = orig_os_api.read(m_tap_fd, buff->p_buffer, buff->sz_buffer);
			if (buff->sz_data > 0) {
				/* Data was read and processed successfully */
				if (m_vf_ring) {
					m_vf_ring->rx_process_buffer(buff, pv_fd_ready_array);
				}
				ret = buff->sz_data;
				m_p_ring_stat->n_rx_byte_count += ret;
				m_p_ring_stat->n_rx_pkt_count++;
				m_p_ring_stat->tap.n_rx_buffers--;
			} else {
				/* Unable to read data, return buffer to pool */
				m_rx_pool.push_front(buff);
			}

			m_tap_data_available = false;
			g_p_event_handler_manager->update_epfd(m_tap_fd,
					EPOLL_CTL_MOD, EPOLLIN | EPOLLPRI | EPOLLONESHOT);
		}
	}

	return ret;
}

void ring_tap::prepare_flow_message(vma_msg_flow& data,
		flow_tuple& flow_spec_5t, msg_flow_t flow_action)
{
	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_FLOW;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	data.action = flow_action;
	data.if_id = get_parent()->get_if_index();
	data.tap_id = get_if_index();
	if (flow_spec_5t.is_3_tuple()) {
		data.type = VMA_MSG_FLOW_TCP_3T;
		data.flow.t3.dst_ip = flow_spec_5t.get_dst_ip();
		data.flow.t3.dst_port = flow_spec_5t.get_dst_port();
	} else {
		data.type = VMA_MSG_FLOW_TCP_5T;
		data.flow.t5.src_ip = flow_spec_5t.get_src_ip();
		data.flow.t5.src_port = flow_spec_5t.get_src_port();
		data.flow.t5.dst_ip = flow_spec_5t.get_dst_ip();
		data.flow.t5.dst_port = flow_spec_5t.get_dst_port();
	}
}

bool ring_tap::request_more_rx_buffers()
{
	ring_logfuncall("Allocating additional %d buffers for internal use",
			m_sysvar_qp_compensation_level);

	bool res = g_buffer_pool_rx->get_buffers_thread_safe(m_rx_pool,
			this, m_sysvar_qp_compensation_level, 0);
	if (!res) {
		ring_logfunc("Out of mem_buf_desc from TX free pool for internal object pool");
		return false;
	}

	m_p_ring_stat->tap.n_rx_buffers = m_rx_pool.size();

	return true;
}
