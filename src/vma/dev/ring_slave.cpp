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

#include "ring_slave.h"

#include "vma/proto/ip_frag.h"
#include "vma/proto/igmp_mgr.h"
#include "vma/dev/rfs_mc.h"
#include "vma/dev/rfs_uc_tcp_gro.h"
#include "vma/sock/fd_collection.h"
#include "vma/sock/sockinfo.h"

#undef  MODULE_NAME
#define MODULE_NAME "ring_slave"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#ifndef IGMP_V3_MEMBERSHIP_REPORT
#define IGMP_V3_MEMBERSHIP_REPORT	0x22	/* V3 version of 0x11 */ /* ALEXR: taken from <linux/igmp.h> */
#endif

// String formating helper function for IGMP
const char* priv_igmp_type_tostr(uint8_t igmptype)
{
	switch (igmptype) {
	case IGMP_HOST_MEMBERSHIP_QUERY:        return "IGMP_QUERY";
	case IGMP_HOST_MEMBERSHIP_REPORT:       return "IGMPV1_REPORT";
	case IGMP_V2_MEMBERSHIP_REPORT:     	return "IGMPV2_REPORT";
	case IGMP_V3_MEMBERSHIP_REPORT:     	return "IGMPV3_REPORT";
	case IGMP_HOST_LEAVE_MESSAGE:           return "IGMP_LEAVE_MESSAGE";
	default:                                return "IGMP type UNKNOWN";
	}
}

ring_slave::ring_slave(int if_index, ring* parent, ring_type_t type):
	ring(),
	m_lock_ring_rx("ring_slave:lock_rx"),
	m_lock_ring_tx("ring_slave:lock_tx"),
	m_partition(0),
	m_flow_tag_enabled(false),
	m_b_sysvar_eth_mc_l2_only_rules(safe_mce_sys().eth_mc_l2_only_rules),
	m_b_sysvar_mc_force_flowtag(safe_mce_sys().mc_force_flowtag),
	m_type(type)
{
	net_device_val* p_ndev = NULL;
	const slave_data_t * p_slave = NULL;

	/* Configure ring() fields */
	set_parent(parent);
	set_if_index(if_index);

	/* Sanity check */
	p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	if (NULL == p_ndev) {
		ring_logpanic("Invalid if_index = %d", if_index);
	}

	p_slave = p_ndev->get_slave(get_if_index());

	/* Configure ring_slave() fields */
	m_transport_type = p_ndev->get_transport_type();
	m_local_if = p_ndev->get_local_addr();

	/* Set the same ring active status as related slave has for all ring types
	 * excluding ring with type RING_TAP that does not have related slave device.
	 * So it is marked as active just in case related netvsc device is absent.
	 */
	m_active = p_slave ?
			p_slave->active :
			p_ndev->get_slave_array().empty();

	// use local copy of stats by default
	m_p_ring_stat = &m_ring_stat;
	memset(m_p_ring_stat, 0, sizeof(*m_p_ring_stat));
	m_p_ring_stat->n_type = m_type;
	if (m_parent != this) {
		m_ring_stat.p_ring_master = m_parent;
	}

	m_tx_pool.set_id("ring_slave (%p) : m_tx_pool", this);

	vma_stats_instance_create_ring_block(m_p_ring_stat);

	print_val();
}

ring_slave::~ring_slave()
{
	print_val();

	if (m_p_ring_stat) {
		vma_stats_instance_remove_ring_block(m_p_ring_stat);
	}

	/* Release TX buffer poll */
	g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, m_tx_pool.size());
}

void ring_slave::print_val()
{
	ring_logdbg("%d: 0x%X: parent 0x%X type %s",
			m_if_index, this,
			((uintptr_t)this == (uintptr_t)m_parent ? 0 : m_parent),
			ring_type_str[m_type]);
}

void ring_slave::restart()
{
	ring_logpanic("Can't restart a slave ring");
}

bool ring_slave::is_active_member(ring_slave* rng, ring_user_id_t)
{
	return (this == rng);
}

bool ring_slave::is_member(ring_slave* rng)
{
	return (this == rng);
}

ring_user_id_t ring_slave::generate_id()
{
	return 0;
}

ring_user_id_t ring_slave::generate_id(const address_t, const address_t,
				uint16_t, uint16_t, uint32_t, uint32_t, uint16_t, uint16_t)
{
	return 0;
}

void ring_slave::inc_tx_retransmissions_stats(ring_user_id_t) {
	m_p_ring_stat->n_tx_retransmits++;
}

bool ring_slave::attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink *sink)
{
	rfs* p_rfs;
	rfs* p_tmp_rfs = NULL;
	sockinfo* si = static_cast<sockinfo*> (sink);

	if (si == NULL)
		return false;

	uint32_t flow_tag_id = si->get_flow_tag_val(); // spec will not be attached to rule
	if (!m_flow_tag_enabled) {
		flow_tag_id = 0;
	}
	ring_logdbg("flow: %s, with sink (%p), flow tag id %d "
		    "m_flow_tag_enabled: %d", flow_spec_5t.to_str(), si,
		    flow_tag_id, m_flow_tag_enabled);

	/*
	 * //auto_unlocker lock(m_lock_ring_rx);
	 * todo instead of locking the whole function which have many "new" calls,
	 * we'll only lock the parts that touch the ring members.
	 * if some of the constructors need the ring locked, we need to modify
	 * and add separate functions for that, which will be called after ctor with ring locked.
	 * currently we assume the ctors does not require the ring to be locked.
	 */
	m_lock_ring_rx.lock();

	/* Get the appropriate hash map (tcp, uc or mc) from the 5t details */
	if (flow_spec_5t.is_udp_uc()) {
		flow_spec_udp_key_t key_udp_uc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		if (flow_tag_id && si->flow_in_reuse()) {
			flow_tag_id = FLOW_TAG_MASK;
			ring_logdbg("UC flow tag for socketinfo=%p is disabled: SO_REUSEADDR or SO_REUSEPORT were enabled", si);
		}
		p_rfs = m_flow_udp_uc_map.get(key_udp_uc, NULL);
		if (p_rfs == NULL) {
			// No rfs object exists so a new one must be created and inserted in the flow map
			m_lock_ring_rx.unlock();
			try {
				p_tmp_rfs = new rfs_uc(&flow_spec_5t, this, NULL, flow_tag_id);
			} catch(vma_exception& e) {
				ring_logerr("%s", e.message);
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_tmp_rfs == NULL) {
				ring_logerr("Failed to allocate rfs!");
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			m_lock_ring_rx.lock();
			p_rfs = m_flow_udp_uc_map.get(key_udp_uc, NULL);
			if (p_rfs) {
				delete p_tmp_rfs;
			} else {
				p_rfs = p_tmp_rfs;
				m_flow_udp_uc_map.set(key_udp_uc, p_rfs);
			}
		}
	} else if (flow_spec_5t.is_udp_mc()) {
		flow_spec_udp_key_t key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());

		if (flow_tag_id) {
			if (m_b_sysvar_mc_force_flowtag || !si->flow_in_reuse()) {
				ring_logdbg("MC flow tag ID=%d for socketinfo=%p is enabled: force_flowtag=%d, SO_REUSEADDR | SO_REUSEPORT=%d",
					flow_tag_id, si, m_b_sysvar_mc_force_flowtag, si->flow_in_reuse());
			} else {
				flow_tag_id = FLOW_TAG_MASK;
				ring_logdbg("MC flow tag for socketinfo=%p is disabled: force_flowtag=0, SO_REUSEADDR or SO_REUSEPORT were enabled", si);
			}
		}
		// Note for CX3:
		// For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
		// It means that for every MC group, even if we have sockets with different ports - only one rule in the HW.
		// So the hash map below keeps track of the number of sockets per rule so we know when to call ibv_attach and ibv_detach
		rfs_rule_filter* l2_mc_ip_filter = NULL;
		if ((m_transport_type == VMA_TRANSPORT_IB && 0 == get_underly_qpn()) || m_b_sysvar_eth_mc_l2_only_rules) {
			rule_filter_map_t::iterator l2_mc_iter = m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip);
			if (l2_mc_iter == m_l2_mc_ip_attach_map.end()) { // It means that this is the first time attach called with this MC ip
				m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = 1;
			} else {
				m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = ((l2_mc_iter->second.counter) + 1);
			}
		}
		p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
		if (p_rfs == NULL) {		// It means that no rfs object exists so I need to create a new one and insert it to the flow map
			m_lock_ring_rx.unlock();
			if ((m_transport_type == VMA_TRANSPORT_IB && 0 == get_underly_qpn()) || m_b_sysvar_eth_mc_l2_only_rules) {
				l2_mc_ip_filter = new rfs_rule_filter(m_l2_mc_ip_attach_map, key_udp_mc.dst_ip, flow_spec_5t);
			}
			try {
				p_tmp_rfs = new rfs_mc(&flow_spec_5t, this, l2_mc_ip_filter, flow_tag_id);
			} catch(vma_exception& e) {
				ring_logerr("%s", e.message);
				return false;
			} catch(const std::bad_alloc &e) {
				NOT_IN_USE(e);
				ring_logerr("Failed to allocate rfs!");
				return false;
			}
			m_lock_ring_rx.lock();
			p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
			if (p_rfs) {
				delete p_tmp_rfs;
			} else {
				p_rfs = p_tmp_rfs;
				m_flow_udp_mc_map.set(key_udp_mc, p_rfs);
			}
		}
	} else if (flow_spec_5t.is_tcp()) {
		flow_spec_tcp_key_t key_tcp(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
				flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
		rule_key_t rule_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		rfs_rule_filter* tcp_dst_port_filter = NULL;
		if (safe_mce_sys().tcp_3t_rules) {
			rule_filter_map_t::iterator tcp_dst_port_iter = m_tcp_dst_port_attach_map.find(rule_key.key);
			if (tcp_dst_port_iter == m_tcp_dst_port_attach_map.end()) {
				m_tcp_dst_port_attach_map[rule_key.key].counter = 1;
			} else {
				m_tcp_dst_port_attach_map[rule_key.key].counter = ((tcp_dst_port_iter->second.counter) + 1);
			}
		}

		p_rfs = m_flow_tcp_map.get(key_tcp, NULL);
		if (p_rfs == NULL) {		// It means that no rfs object exists so I need to create a new one and insert it to the flow map
			m_lock_ring_rx.unlock();
			if (safe_mce_sys().tcp_3t_rules) {
				flow_tuple tcp_3t_only(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port(), 0, 0, flow_spec_5t.get_protocol());
				tcp_dst_port_filter = new rfs_rule_filter(m_tcp_dst_port_attach_map, rule_key.key, tcp_3t_only);
			}
			if(safe_mce_sys().gro_streams_max && flow_spec_5t.is_5_tuple() && is_simple()) {
				// When the gro mechanism is being used, packets must be processed in the rfs
				// layer. This must not be bypassed by using flow tag.
				if (flow_tag_id) {
					flow_tag_id = FLOW_TAG_MASK;
					ring_logdbg("flow_tag_id = %d is disabled to enable TCP GRO socket to be processed on RFS!", flow_tag_id);
				}
				p_tmp_rfs = new (std::nothrow)rfs_uc_tcp_gro(&flow_spec_5t, this, tcp_dst_port_filter, flow_tag_id);
			} else {
				try {
					p_tmp_rfs = new (std::nothrow)rfs_uc(&flow_spec_5t, this, tcp_dst_port_filter, flow_tag_id);
				} catch(vma_exception& e) {
					ring_logerr("%s", e.message);
					return false;
				}
			}
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_tmp_rfs == NULL) {
				ring_logerr("Failed to allocate rfs!");
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_rx.lock();
			p_rfs = m_flow_tcp_map.get(key_tcp, NULL);
			if (p_rfs) {
				delete p_tmp_rfs;
			} else {
				p_rfs = p_tmp_rfs;
				m_flow_tcp_map.set(key_tcp, p_rfs);
			}
		}
	BULLSEYE_EXCLUDE_BLOCK_START
	} else {
		m_lock_ring_rx.unlock();
		ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	bool ret = p_rfs->attach_flow(sink);
	if (ret) {
		if (flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
			// A flow with FlowTag was attached succesfully, check stored rfs for fast path be tag_id
			si->set_flow_tag(flow_tag_id);
			ring_logdbg("flow_tag: %d registration is done!", flow_tag_id);
		}
		if (flow_spec_5t.is_tcp() && !flow_spec_5t.is_3_tuple()) {
			// save the single 5tuple TCP connected socket for improved fast path
			si->set_tcp_flow_is_5t();
			ring_logdbg("single 5T TCP update m_tcp_flow_is_5t m_flow_tag_enabled: %d", m_flow_tag_enabled);
		}
	} else {
		ring_logerr("attach_flow=%d failed!", ret);
	}
	/* coverity[double_unlock] TODO: RM#1049980 */
	m_lock_ring_rx.unlock();
	return ret;
}

bool ring_slave::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	rfs* p_rfs = NULL;

	ring_logdbg("flow: %s, with sink (%p)", flow_spec_5t.to_str(), sink);

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
		int keep_in_map = 1;
		flow_spec_udp_key_t key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
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
		p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (p_rfs == NULL) {
			ring_logdbg("Could not find rfs object to detach!");
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		p_rfs->detach_flow(sink);
		if(!keep_in_map){
			m_l2_mc_ip_attach_map.erase(m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip));
		}
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
		flow_spec_tcp_key_t key_tcp(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
				flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
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

// calling sockinfo callback with RFS bypass
static inline bool check_rx_packet(sockinfo *si, mem_buf_desc_t* p_rx_wc_buf_desc, void *fd_ready_array)
{
	// Dispatching: Notify new packet to the FIRST registered receiver ONLY
#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif //RDTSC_MEASURE_RX_DISPATCH_PACKET

	p_rx_wc_buf_desc->reset_ref_count();
	p_rx_wc_buf_desc->inc_ref_count();

	si->rx_input_cb(p_rx_wc_buf_desc,fd_ready_array);

#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif //RDTSC_MEASURE_RX_DISPATCH_PACKET

	// Check packet ref_count to see the last receiver is interested in this packet
	if (p_rx_wc_buf_desc->dec_ref_count() > 1) {
		// The sink will be responsible to return the buffer to CQ for reuse
		return true;
	}
	// Reuse this data buffer & mem_buf_desc
	return false;
}

// All CQ wce come here for some basic sanity checks and then are distributed to the correct ring handler
// Return values: false = Reuse this data buffer & mem_buf_desc
bool ring_slave::rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array)
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

	inc_cq_moderation_stats(sz_data);

	m_p_ring_stat->n_rx_byte_count += sz_data;
	++m_p_ring_stat->n_rx_pkt_count;

	// This is an internal function (within ring and 'friends'). No need for lock mechanism.
	if (likely(m_flow_tag_enabled && p_rx_wc_buf_desc->rx.flow_tag_id &&
		   p_rx_wc_buf_desc->rx.flow_tag_id != FLOW_TAG_MASK &&
		   !p_rx_wc_buf_desc->rx.is_sw_csum_need)) {
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

	// Validate transport type headers
	switch (m_transport_type) {
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
	case VMA_TRANSPORT_ETH:
	{
//		printf("\nring_slave::rx_process_buffer\n");
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

		uint16_t h_proto = p_eth_h->h_proto;

		ring_logfunc("Rx buffer Ethernet dst=" ETH_HW_ADDR_PRINT_FMT " <- src=" ETH_HW_ADDR_PRINT_FMT " type=%#x",
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_dest),
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_source),
				htons(h_proto));

		// Handle VLAN header as next protocol
		struct vlanhdr* p_vlan_hdr = NULL;
		uint16_t packet_vlan = 0;
		if (h_proto == htons(ETH_P_8021Q)) {
			p_vlan_hdr = (struct vlanhdr*)((uint8_t*)p_eth_h + ETH_HDR_LEN);
			transport_header_len = ETH_VLAN_HDR_LEN;
			h_proto = p_vlan_hdr->h_vlan_encapsulated_proto;
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
		if (unlikely(h_proto != htons(ETH_P_IP))) {
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
			p_rfs = m_flow_tcp_map.get(flow_spec_tcp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr, 0,
					p_rx_wc_buf_desc->rx.dst.sin_port, 0), NULL);
		}
	}
	break;

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

void ring_slave::flow_udp_del_all()
{
	flow_spec_udp_key_t map_key_udp;
	flow_spec_udp_map_t::iterator itr_udp;

	itr_udp = m_flow_udp_uc_map.begin();
	while (itr_udp != m_flow_udp_uc_map.end()) {
		rfs *p_rfs = itr_udp->second;
		map_key_udp = itr_udp->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_udp_uc_map.del(map_key_udp))) {
			ring_logdbg("Could not find rfs object to delete in ring udp uc hash map!");
		}
		itr_udp =  m_flow_udp_uc_map.begin();
	}

	itr_udp = m_flow_udp_mc_map.begin();
	while (itr_udp != m_flow_udp_mc_map.end()) {
		rfs *p_rfs = itr_udp->second;
		map_key_udp = itr_udp->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_udp_mc_map.del(map_key_udp))) {
			ring_logdbg("Could not find rfs object to delete in ring udp mc hash map!");
		}
		itr_udp =  m_flow_udp_mc_map.begin();
	}
}

void ring_slave::flow_tcp_del_all()
{
	flow_spec_tcp_key_t map_key_tcp;
	flow_spec_tcp_map_t::iterator itr_tcp;

	while ((itr_tcp = m_flow_tcp_map.begin()) != m_flow_tcp_map.end()) {
		rfs *p_rfs = itr_tcp->second;
		map_key_tcp = itr_tcp->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_tcp_map.del(map_key_tcp))) {
			ring_logdbg("Could not find rfs object to delete in ring tcp hash map!");
		}
	}
}

bool ring_slave::request_more_tx_buffers(uint32_t count, uint32_t lkey)
{
	ring_logfuncall("Allocating additional %d buffers for internal use", count);

	bool res = g_buffer_pool_tx->get_buffers_thread_safe(m_tx_pool, this, count, lkey);
	if (!res) {
		ring_logfunc("Out of mem_buf_desc from TX free pool for internal object pool");
		return false;
	}

	return true;
}
