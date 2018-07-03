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

#include <linux/if_tun.h>
#include "vma/util/sg_array.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/dev/rfs.h"
#include "vma/dev/rfs_mc.h"
#include "vma/dev/rfs_uc.h"
#include "vma/dev/rfs_uc_tcp_gro.h"
#include "vma/proto/ip_frag.h"
#include "vma/sock/fd_collection.h"

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
	request_more_tx_buffers();
	m_tx_pool.set_id("ring_tap (%p) : m_tx_pool", this);

	/* Update ring statistics */
	m_p_ring_stat->tap.n_tap_fd = m_tap_fd;
	if_indextoname(get_if_index(), tap_if_name);
	memcpy(m_p_ring_stat->tap.s_tap_name, tap_if_name, IFNAMSIZ);

	/* create egress rule (redirect traffic from tap device to physical interface) */
	prepare_flow_message(data, VMA_MSG_FLOW_ADD);
	rc = g_p_agent->send_msg_flow(&data);
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

	/* Release TX buffer poll */
	g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, m_tx_pool.size());

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

	if (ring_slave::attach_flow(flow_spec_5t, sink) && (flow_spec_5t.is_tcp() || flow_spec_5t.is_udp_uc())) {
		int rc = 0;
		struct vma_msg_flow data;
		prepare_flow_message(data, VMA_MSG_FLOW_ADD, flow_spec_5t);

		rc = g_p_agent->send_msg_flow(&data);
		if (rc == 0) {
			return true;
		} else {
			if (!g_b_exit) {
				ring_logwarn("Add TC rule failed with error=%d", rc);
			}
			ring_slave::detach_flow(flow_spec_5t, sink);
		}
	}
	return false;
}

bool ring_tap::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	rfs* p_rfs = NULL;

	ring_logdbg("flow: %s, with sink (%p)",
		    flow_spec_5t.to_str(), sink);

	if( sink == NULL )
		return false;

	if (flow_spec_5t.is_tcp() || flow_spec_5t.is_udp_uc()) {
		int rc = 0;
		struct vma_msg_flow data;
		prepare_flow_message(data, VMA_MSG_FLOW_DEL, flow_spec_5t);

		rc = g_p_agent->send_msg_flow(&data);
		if (rc != 0) {
			if (!g_b_exit) {
				ring_logwarn("Del TC rule failed with error=%d", rc);
			}
			return false;
		}
	}

	auto_unlocker lock(m_lock_ring_rx);

	/* Get the appropriate hash map (tcp, uc or mc) from the 5t details */
	if (flow_spec_5t.is_udp_uc()) {
		flow_spec_udp_key_t key_udp_uc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		p_rfs = m_flow_udp_uc_map.get(key_udp_uc, NULL);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (p_rfs == NULL) {
			ring_logdbg("Could not find rfs object to detach!");
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		p_rfs->detach_flow(sink);
		if (p_rfs->get_num_of_sinks() == 0) {
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!(m_flow_udp_uc_map.del(key_udp_uc))) {
				ring_logdbg("Could not find rfs object to delete in ring udp uc hash map!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			delete p_rfs;
		}
	} else if (flow_spec_5t.is_udp_mc()) {
		flow_spec_udp_key_t key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
#if 0 /* useless */
		int keep_in_map = 1;
		if (m_transport_type == VMA_TRANSPORT_IB || m_b_sysvar_eth_mc_l2_only_rules) {
			rule_filter_map_t::iterator l2_mc_iter = m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (l2_mc_iter == m_l2_mc_ip_attach_map.end()) {
				ring_logdbg("Could not find matching counter for the MC group!");
			BULLSEYE_EXCLUDE_BLOCK_END
			} else {
				keep_in_map = m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = MAX(0 , ((l2_mc_iter->second.counter) - 1));
			}
		}
#endif /* useless */
		p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (p_rfs == NULL) {
			ring_logdbg("Could not find rfs object to detach!");
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		p_rfs->detach_flow(sink);
#if 0 /* useless */
		if(!keep_in_map){
			m_l2_mc_ip_attach_map.erase(m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip));
		}
#endif /* useless */
		if (p_rfs->get_num_of_sinks() == 0) {
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!(m_flow_udp_mc_map.del(key_udp_mc))) {
				ring_logdbg("Could not find rfs object to delete in ring udp mc hash map!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			delete p_rfs;
		}
	} else if (flow_spec_5t.is_tcp()) {
		int keep_in_map = 1;
		flow_spec_tcp_key_t key_tcp(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(), flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
		rule_key_t rule_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		if (safe_mce_sys().tcp_3t_rules) {
			rule_filter_map_t::iterator tcp_dst_port_iter = m_tcp_dst_port_attach_map.find(rule_key.key);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (tcp_dst_port_iter == m_tcp_dst_port_attach_map.end()) {
				ring_logdbg("Could not find matching counter for TCP src port!");
				BULLSEYE_EXCLUDE_BLOCK_END
			} else {
				keep_in_map = m_tcp_dst_port_attach_map[rule_key.key].counter = MAX(0 , ((tcp_dst_port_iter->second.counter) - 1));
			}
		}
		p_rfs = m_flow_tcp_map.get(key_tcp, NULL);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (p_rfs == NULL) {
			ring_logdbg("Could not find rfs object to detach!");
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		p_rfs->detach_flow(sink);
		if(!keep_in_map){
			m_tcp_dst_port_attach_map.erase(m_tcp_dst_port_attach_map.find(rule_key.key));
		}
		if (p_rfs->get_num_of_sinks() == 0) {
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!(m_flow_tcp_map.del(key_tcp))) {
				ring_logdbg("Could not find rfs object to delete in ring tcp hash map!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			delete p_rfs;
		}
	BULLSEYE_EXCLUDE_BLOCK_START
	} else {
		ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

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
#ifdef DEFINED_SOCKETXTREME
				temp->rx.socketxtreme_polled = false;
#endif // DEFINED_SOCKETXTREME
				temp->rx.flow_tag_id = 0;
				temp->rx.tcp.p_ip_h = NULL;
				temp->rx.tcp.p_tcp_h = NULL;
				temp->rx.udp.sw_timestamp.tv_nsec = 0;
				temp->rx.udp.sw_timestamp.tv_sec = 0;
				temp->rx.udp.hw_timestamp.tv_nsec = 0;
				temp->rx.udp.hw_timestamp.tv_sec = 0;
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

#if 0 /* useless: m_flow_tag_enabled=false for ring_tap */
// calling sockinfo callback with RFS bypass
static inline bool check_rx_packet(sockinfo *si, mem_buf_desc_t* p_rx_wc_buf_desc, void *fd_ready_array)
{
	// Dispatching: Notify new packet to the FIRST registered receiver ONLY
	p_rx_wc_buf_desc->reset_ref_count();
	p_rx_wc_buf_desc->inc_ref_count();

	si->rx_input_cb(p_rx_wc_buf_desc,fd_ready_array);

	// Check packet ref_count to see the last receiver is interested in this packet
	if (p_rx_wc_buf_desc->dec_ref_count() > 1) {
		// The sink will be responsible to return the buffer to CQ for reuse
		return true;
	}
	// Reuse this data buffer & mem_buf_desc
	return false;
}
#endif /* useless */


bool ring_tap::rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array)
{
	size_t sz_data = 0;
	size_t transport_header_len;
	uint16_t ip_hdr_len = 0;
	uint16_t ip_tot_len = 0;
	uint16_t ip_frag_off = 0;
	uint16_t n_frag_offset = 0;
	struct ethhdr* p_eth_h = (struct ethhdr*)(p_rx_wc_buf_desc->p_buffer);
	struct iphdr* p_ip_h = NULL;
	struct udphdr* p_udp_h = NULL;

	// Validate buffer size
	sz_data = p_rx_wc_buf_desc->sz_data;
	if (unlikely(sz_data > p_rx_wc_buf_desc->sz_buffer)) {
		if (sz_data == IP_FRAG_FREED) {
			ring_logfuncall("Rx buffer dropped - old fragment part");
		} else {
			ring_logwarn("Rx buffer dropped - buffer too small (%d, %d)", sz_data, p_rx_wc_buf_desc->sz_buffer);
		}
		return false;
	}

	m_p_ring_stat->n_rx_byte_count += sz_data;
	++m_p_ring_stat->n_rx_pkt_count;

#if 0 /* useless: m_flow_tag_enabled=false for ring_tap */
	// This is an internal function (within ring and 'friends'). No need for lock mechanism.
	if (likely(m_flow_tag_enabled && p_rx_wc_buf_desc->rx.flow_tag_id &&
		   (p_rx_wc_buf_desc->rx.flow_tag_id != FLOW_TAG_MASK))) {
		sockinfo* si = NULL;
		// trying to get sockinfo per flow_tag_id-1 as it was incremented at attach
		// to allow mapping sockfd=0
		si = static_cast <sockinfo* >(g_p_fd_collection->get_sockfd(p_rx_wc_buf_desc->rx.flow_tag_id-1));

		if (likely((si != NULL) && si->flow_tag_enabled())) {
			// will process packets with set flow_tag_id and enabled for the socket
			if (p_eth_h->h_proto == htons(ETH_P_8021Q)) {
				// Handle VLAN header as next protocol
				transport_header_len = ETH_VLAN_HDR_LEN;
			} else {
				transport_header_len = ETH_HDR_LEN;
			}
			p_ip_h = (struct iphdr*)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
			ip_hdr_len = 20; //(int)(p_ip_h->ihl)*4;
			ip_tot_len = ntohs(p_ip_h->tot_len);

			ring_logfunc("FAST PATH Rx packet info: transport_header_len: %d, IP_header_len: %d L3 proto: %d tcp_5t: %d",
				transport_header_len, p_ip_h->ihl, p_ip_h->protocol, si->tcp_flow_is_5t());

			if (likely(si->tcp_flow_is_5t())) {
				// we have a single 5tuple TCP connected socket, use simpler fast path
				struct tcphdr* p_tcp_h = (struct tcphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

				// Update the L3 and L4 info
				p_rx_wc_buf_desc->rx.src.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.src.sin_port        = p_tcp_h->source;
				p_rx_wc_buf_desc->rx.src.sin_addr.s_addr = p_ip_h->saddr;

				p_rx_wc_buf_desc->rx.dst.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.dst.sin_port        = p_tcp_h->dest;
				p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr = p_ip_h->daddr;
				// Update packet descriptor with datagram base address and length
				p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_tcp_h + sizeof(struct tcphdr);
				p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct tcphdr);
				p_rx_wc_buf_desc->rx.sz_payload    = ip_tot_len - ip_hdr_len - p_tcp_h->doff*4;

				p_rx_wc_buf_desc->rx.tcp.p_ip_h                 = p_ip_h;
				p_rx_wc_buf_desc->rx.tcp.p_tcp_h                = p_tcp_h;
				p_rx_wc_buf_desc->rx.tcp.n_transport_header_len = transport_header_len;
				p_rx_wc_buf_desc->rx.n_frags = 1;

				ring_logfunc("FAST PATH Rx TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
					ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest),
					p_tcp_h->urg?"U":"", p_tcp_h->ack?"A":"", p_tcp_h->psh?"P":"",
					p_tcp_h->rst?"R":"", p_tcp_h->syn?"S":"", p_tcp_h->fin?"F":"",
					ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window),
					p_rx_wc_buf_desc->rx.sz_payload);

				return check_rx_packet(si, p_rx_wc_buf_desc, pv_fd_ready_array);

			} else if (likely(p_ip_h->protocol==IPPROTO_UDP)) {
				// Get the udp header pointer + udp payload size
				p_udp_h = (struct udphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

				// Update the L3 and L4 info
				p_rx_wc_buf_desc->rx.src.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.src.sin_port        = p_udp_h->source;
				p_rx_wc_buf_desc->rx.src.sin_addr.s_addr = p_ip_h->saddr;

				p_rx_wc_buf_desc->rx.dst.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.dst.sin_port        = p_udp_h->dest;
				p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr = p_ip_h->daddr;
				// Update packet descriptor with datagram base address and length
				p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_udp_h + sizeof(struct udphdr);
				p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct udphdr);
				p_rx_wc_buf_desc->rx.sz_payload    = ntohs(p_udp_h->len) - sizeof(struct udphdr);

				p_rx_wc_buf_desc->rx.udp.local_if        = m_local_if;
				p_rx_wc_buf_desc->rx.n_frags = 1;

				ring_logfunc("FAST PATH Rx UDP datagram info: src_port=%d, dst_port=%d, payload_sz=%d, csum=%#x",
					     ntohs(p_udp_h->source), ntohs(p_udp_h->dest), p_rx_wc_buf_desc->rx.sz_payload, p_udp_h->check);

				return check_rx_packet(si, p_rx_wc_buf_desc, pv_fd_ready_array);
			}
		}
	}
#endif /* useless */

	// Validate transport type headers
	switch (m_transport_type) {
#if 0 /* useless: IB is not supported */
	case VMA_TRANSPORT_IB:
	{
		// Get the data buffer start pointer to the ipoib header pointer
		struct ipoibhdr* p_ipoib_h = (struct ipoibhdr*)(p_rx_wc_buf_desc->p_buffer + GRH_HDR_LEN);

		transport_header_len = GRH_HDR_LEN + IPOIB_HDR_LEN;

		// Validate IPoIB header
		if (unlikely(p_ipoib_h->ipoib_header != htonl(IPOIB_HEADER))) {
			ring_logwarn("Rx buffer dropped - Invalid IPOIB Header Type (%#x : %#x)", p_ipoib_h->ipoib_header, htonl(IPOIB_HEADER));
			return false;
		}
	}
	break;
#endif /* useless */
	case VMA_TRANSPORT_ETH:
	{
//		printf("\nring_simple::rx_process_buffer\n");
//		{
//			struct ethhdr* p_eth_h = (struct ethhdr*)(p_rx_wc_buf_desc->p_buffer);
//
//			int i = 0;
//			printf("p_eth_h->h_dest [0]=%d, [1]=%d, [2]=%d, [3]=%d, [4]=%d, [5]=%d\n",
//					(uint8_t)p_eth_h->h_dest[0], (uint8_t)p_eth_h->h_dest[1], (uint8_t)p_eth_h->h_dest[2], (uint8_t)p_eth_h->h_dest[3], (uint8_t)p_eth_h->h_dest[4], (uint8_t)p_eth_h->h_dest[5]);
//			printf("p_eth_h->h_source [0]=%d, [1]=%d, [2]=%d, [3]=%d, [4]=%d, [5]=%d\n",
//					(uint8_t)p_eth_h->h_source[0], (uint8_t)p_eth_h->h_source[1], (uint8_t)p_eth_h->h_source[2], (uint8_t)p_eth_h->h_source[3], (uint8_t)p_eth_h->h_source[4], (uint8_t)p_eth_h->h_source[5]);
//
//			while(i++<62){
//				printf("%d, ", (uint8_t)p_rx_wc_buf_desc->p_buffer[i]);
//			}
//			printf("\n");
//		}

		uint16_t* p_h_proto = &p_eth_h->h_proto;

		ring_logfunc("Rx buffer Ethernet dst=" ETH_HW_ADDR_PRINT_FMT " <- src=" ETH_HW_ADDR_PRINT_FMT " type=%#x",
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_dest),
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_source),
				htons(*p_h_proto));

		// Handle VLAN header as next protocol
		struct vlanhdr* p_vlan_hdr = NULL;
		uint16_t packet_vlan = 0;
		if (*p_h_proto == htons(ETH_P_8021Q)) {
			p_vlan_hdr = (struct vlanhdr*)((uint8_t*)p_eth_h + ETH_HDR_LEN);
			transport_header_len = ETH_VLAN_HDR_LEN;
			p_h_proto = &p_vlan_hdr->h_vlan_encapsulated_proto;
			packet_vlan = (htons(p_vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK);
		} else {
			transport_header_len = ETH_HDR_LEN;
		}

		//TODO: Remove this code when handling vlan in flow steering will be available. Change this code if vlan stripping is performed.
		if((m_partition & VLAN_VID_MASK) != packet_vlan) {
			ring_logfunc("Rx buffer dropped- Mismatched vlan. Packet vlan = %d, Local vlan = %d", packet_vlan, m_partition & VLAN_VID_MASK);
			return false;
		}

		// Validate IP header as next protocol
		if (unlikely(*p_h_proto != htons(ETH_P_IP))) {
			ring_logwarn("Rx buffer dropped - Invalid Ethr Type (%#x : %#x)", p_eth_h->h_proto, htons(ETH_P_IP));
			return false;
		}
	}
	break;
	default:
		ring_logwarn("Rx buffer dropped - Unknown transport type %d", m_transport_type);
		return false;
	}

	// Jump to IP header - Skip IB (GRH and IPoIB) or Ethernet (MAC) header sizes
	sz_data -= transport_header_len;

	// Validate size for IPv4 header
	if (unlikely(sz_data < sizeof(struct iphdr))) {
		ring_logwarn("Rx buffer dropped - buffer too small for IPv4 header (%d, %d)", sz_data, sizeof(struct iphdr));
		return false;
	}

	// Get the ip header pointer
	p_ip_h = (struct iphdr*)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

	// Drop all non IPv4 packets
	if (unlikely(p_ip_h->version != IPV4_VERSION)) {
		ring_logwarn("Rx packet dropped - not IPV4 packet (got version: %#x)", p_ip_h->version);
		return false;
	}

	// Check that received buffer size is not smaller then the ip datagram total size
	ip_tot_len = ntohs(p_ip_h->tot_len);
	if (unlikely(sz_data < ip_tot_len)) {
		ring_logwarn("Rx packet dropped - buffer too small for received datagram (RxBuf:%d IP:%d)", sz_data, ip_tot_len);
		ring_loginfo("Rx packet info (buf->%p, bufsize=%d), id=%d", p_rx_wc_buf_desc->p_buffer, p_rx_wc_buf_desc->sz_data, ntohs(p_ip_h->id));
		vlog_print_buffer(VLOG_INFO, "rx packet data: ", "\n", (const char*)p_rx_wc_buf_desc->p_buffer, min(112, (int)p_rx_wc_buf_desc->sz_data));
		return false;
	} else if (sz_data > ip_tot_len) {
		p_rx_wc_buf_desc->sz_data -= (sz_data - ip_tot_len);
	}

	// Read fragmentation parameters
	ip_frag_off = ntohs(p_ip_h->frag_off);
	n_frag_offset = (ip_frag_off & FRAGMENT_OFFSET) * 8;

	ring_logfunc("Rx ip packet info: dst=%d.%d.%d.%d, src=%d.%d.%d.%d, packet_sz=%d, offset=%d, id=%d, proto=%s[%d] (local if: %d.%d.%d.%d)",
			NIPQUAD(p_ip_h->daddr), NIPQUAD(p_ip_h->saddr),
			(sz_data > ip_tot_len ? ip_tot_len : sz_data), n_frag_offset, ntohs(p_ip_h->id),
			iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol,
			NIPQUAD(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr));

	// Check that the ip datagram has at least the udp header size for the first ip fragment (besides the ip header)
	ip_hdr_len = (int)(p_ip_h->ihl)*4;
	if (unlikely((n_frag_offset == 0) && (ip_tot_len < (ip_hdr_len + sizeof(struct udphdr))))) {
		ring_logwarn("Rx packet dropped - ip packet too small (%d bytes)- udp header cut!", ip_tot_len);
		return false;
	}

	// Handle fragmentation
	p_rx_wc_buf_desc->rx.n_frags = 1;
	if (unlikely((ip_frag_off & MORE_FRAGMENTS_FLAG) || n_frag_offset)) { // Currently we don't expect to receive fragments
		//for disabled fragments handling:
		/*ring_logwarn("Rx packet dropped - VMA doesn't support fragmentation in receive flow!");
		ring_logwarn("packet info: dst=%d.%d.%d.%d, src=%d.%d.%d.%d, packet_sz=%d, frag_offset=%d, id=%d, proto=%s[%d], transport type=%s, (local if: %d.%d.%d.%d)",
				NIPQUAD(p_ip_h->daddr), NIPQUAD(p_ip_h->saddr),
				(sz_data > ip_tot_len ? ip_tot_len : sz_data), n_frag_offset, ntohs(p_ip_h->id),
				iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol, (m_transport_type ? "ETH" : "IB"),
				NIPQUAD(local_addr));
		return false;*/
#if 1 //handle fragments
		// Update fragments descriptor with datagram base address and length
		p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_ip_h + ip_hdr_len;
		p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len;

		// Add ip fragment packet to out fragment manager
		mem_buf_desc_t* new_buf = NULL;
		int ret = -1;
		if (g_p_ip_frag_manager)
			ret = g_p_ip_frag_manager->add_frag(p_ip_h, p_rx_wc_buf_desc, &new_buf);
		if (ret < 0)  // Finished with error
			return false;
		if (!new_buf)  // This is fragment
			return true;

		// Re-calc all ip related values for new ip packet of head fragmentation list
		p_rx_wc_buf_desc = new_buf;
		p_ip_h = (struct iphdr*)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
		ip_hdr_len = (int)(p_ip_h->ihl)*4;
		ip_tot_len = ntohs(p_ip_h->tot_len);

		mem_buf_desc_t *tmp;
		for (tmp = p_rx_wc_buf_desc; tmp; tmp = tmp->p_next_desc) {
			++p_rx_wc_buf_desc->rx.n_frags;
		}
#endif
	}

	if (p_rx_wc_buf_desc->rx.is_sw_csum_need && compute_ip_checksum((unsigned short*)p_ip_h, p_ip_h->ihl * 2)) {
		return false; // false ip checksum
	}

//We want to enable loopback between processes for IB
#if 0
	//AlexV: We don't support Tx MC Loopback today!
	if (p_ip_h->saddr == m_local_if) {
		ring_logfunc("Rx udp datagram discarded - mc loop disabled");
		return false;
	}
#endif
	rfs* p_rfs = NULL;

	// Update the L3 info
	p_rx_wc_buf_desc->rx.src.sin_family      = AF_INET;
	p_rx_wc_buf_desc->rx.src.sin_addr.s_addr = p_ip_h->saddr;
	p_rx_wc_buf_desc->rx.dst.sin_family      = AF_INET;
	p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr = p_ip_h->daddr;

	switch (p_ip_h->protocol) {
	case IPPROTO_UDP:
	{
		// Get the udp header pointer + udp payload size
		p_udp_h = (struct udphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

		// Update packet descriptor with datagram base address and length
		p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_udp_h + sizeof(struct udphdr);
		p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct udphdr);

		if (p_rx_wc_buf_desc->rx.is_sw_csum_need && p_udp_h->check && compute_udp_checksum_rx(p_ip_h, p_udp_h, p_rx_wc_buf_desc)) {
			return false; // false udp checksum
		}

		size_t sz_payload = ntohs(p_udp_h->len) - sizeof(struct udphdr);
		ring_logfunc("Rx udp datagram info: src_port=%d, dst_port=%d, payload_sz=%d, csum=%#x",
				ntohs(p_udp_h->source), ntohs(p_udp_h->dest), sz_payload, p_udp_h->check);

		// Update the L3 info
		p_rx_wc_buf_desc->rx.udp.local_if        = m_local_if;

		// Update the L4 info
		p_rx_wc_buf_desc->rx.src.sin_port        = p_udp_h->source;
		p_rx_wc_buf_desc->rx.dst.sin_port        = p_udp_h->dest;
		p_rx_wc_buf_desc->rx.sz_payload          = sz_payload;

		// Find the relevant hash map and pass the packet to the rfs for dispatching
		if (!(IN_MULTICAST_N(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr))) {      // This is UDP UC packet
			p_rfs = m_flow_udp_uc_map.get(flow_spec_udp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr,
				p_rx_wc_buf_desc->rx.dst.sin_port), NULL);
		} else {        // This is UDP MC packet
			p_rfs = m_flow_udp_mc_map.get(flow_spec_udp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr,
				p_rx_wc_buf_desc->rx.dst.sin_port), NULL);
		}
	}
	break;

	case IPPROTO_TCP:
	{
		// Get the tcp header pointer + tcp payload size
		struct tcphdr* p_tcp_h = (struct tcphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

		if (p_rx_wc_buf_desc->rx.is_sw_csum_need && compute_tcp_checksum(p_ip_h, (unsigned short*) p_tcp_h)) {
			return false; // false tcp checksum
		}

		size_t sz_payload = ip_tot_len - ip_hdr_len - p_tcp_h->doff*4;
		ring_logfunc("Rx TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
				ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest),
				p_tcp_h->urg?"U":"", p_tcp_h->ack?"A":"", p_tcp_h->psh?"P":"",
				p_tcp_h->rst?"R":"", p_tcp_h->syn?"S":"", p_tcp_h->fin?"F":"",
				ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window),
				sz_payload);

		// Update packet descriptor with datagram base address and length
		p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_tcp_h + sizeof(struct tcphdr);
		p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct tcphdr);

		// Update the L4 info
		p_rx_wc_buf_desc->rx.src.sin_port        = p_tcp_h->source;
		p_rx_wc_buf_desc->rx.dst.sin_port        = p_tcp_h->dest;
		p_rx_wc_buf_desc->rx.sz_payload          = sz_payload;

		p_rx_wc_buf_desc->rx.tcp.p_ip_h = p_ip_h;
		p_rx_wc_buf_desc->rx.tcp.p_tcp_h = p_tcp_h;

		// Find the relevant hash map and pass the packet to the rfs for dispatching
		p_rfs = m_flow_tcp_map.get(flow_spec_tcp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr,
				p_rx_wc_buf_desc->rx.src.sin_addr.s_addr, p_rx_wc_buf_desc->rx.dst.sin_port,
				p_rx_wc_buf_desc->rx.src.sin_port), NULL);

		p_rx_wc_buf_desc->rx.tcp.n_transport_header_len = transport_header_len;

		if (unlikely(p_rfs == NULL)) {	// If we didn't find a match for TCP 5T, look for a match with TCP 3T
			p_rfs = m_flow_tcp_map.get(flow_spec_tcp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr, 0, p_rx_wc_buf_desc->rx.dst.sin_port, 0), NULL);
		}
	}
	break;

#if 0 /* useless */
	case IPPROTO_IGMP:
	{
		struct igmp* p_igmp_h= (struct igmp*)((uint8_t*)p_ip_h + ip_hdr_len);
		NOT_IN_USE(p_igmp_h); /* to supress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
		ring_logdbg("Rx IGMP packet info: type=%s (%d), group=%d.%d.%d.%d, code=%d",
				priv_igmp_type_tostr(p_igmp_h->igmp_type), p_igmp_h->igmp_type,
				NIPQUAD(p_igmp_h->igmp_group.s_addr), p_igmp_h->igmp_code);
		if (m_transport_type == VMA_TRANSPORT_IB  || m_b_sysvar_eth_mc_l2_only_rules) {
			ring_logdbg("Transport type is IB (or eth_mc_l2_only_rules), passing igmp packet to igmp_manager to process");
			if(g_p_igmp_mgr) {
				(g_p_igmp_mgr->process_igmp_packet(p_ip_h, m_local_if));
				return false; // we return false in order to free the buffer, although we handled the packet
			}
			ring_logdbg("IGMP packet drop. IGMP manager does not exist.");
			return false;
		}
		ring_logerr("Transport type is ETH, dropping the packet");
		return false;
	}
#endif /* useless */
	break;

	default:
		ring_logwarn("Rx packet dropped - undefined protocol = %d", p_ip_h->protocol);
		return false;
	}

	if (unlikely(p_rfs == NULL)) {
		ring_logdbg("Rx packet dropped - rfs object not found: dst:%d.%d.%d.%d:%d, src%d.%d.%d.%d:%d, proto=%s[%d]",
				NIPQUAD(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr), ntohs(p_rx_wc_buf_desc->rx.dst.sin_port),
				NIPQUAD(p_rx_wc_buf_desc->rx.src.sin_addr.s_addr), ntohs(p_rx_wc_buf_desc->rx.src.sin_port),
				iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol);

		return false;
	}
	return p_rfs->rx_dispatch_packet(p_rx_wc_buf_desc, pv_fd_ready_array);
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

void ring_tap::prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action,
		flow_tuple& flow_spec_5t)
{
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
}

void ring_tap::prepare_flow_message(vma_msg_flow& data, msg_flow_t flow_action)
{
	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_FLOW;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	data.action = flow_action;
	data.if_id = get_parent()->get_if_index();
	data.tap_id = get_if_index();
	data.type = VMA_MSG_FLOW_EGRESS;
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

bool ring_tap::request_more_tx_buffers()
{
	ring_logfuncall("Allocating additional %d buffers for internal use",
			m_sysvar_qp_compensation_level);

	bool res = g_buffer_pool_tx->get_buffers_thread_safe(m_tx_pool,
			this, m_sysvar_qp_compensation_level, 0);
	if (!res) {
		ring_logfunc("Out of mem_buf_desc from TX free pool for internal object pool");
		return false;
	}

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
		request_more_tx_buffers();

		if (unlikely((int)m_tx_pool.size() < n_num_mem_bufs)) {
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
