/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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

#include "vma/dev/rfs_mc.h"
#include "vma/dev/rfs_uc.h"
#include "vma/dev/rfs_uc_tcp_gro.h"
#include "vma/sock/sockinfo.h"

#undef  MODULE_NAME
#define MODULE_NAME "ring_slave"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "


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

	vma_stats_instance_create_ring_block(m_p_ring_stat);

	print_val();
}

ring_slave::~ring_slave()
{
	print_val();

	if (m_p_ring_stat) {
		vma_stats_instance_remove_ring_block(m_p_ring_stat);
	}
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

bool ring_slave::is_active_member(ring_slave* rng, ring_user_id_t id)
{
	NOT_IN_USE(id);

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

ring_user_id_t ring_slave::generate_id(const address_t src_mac, const address_t dst_mac,
				uint16_t eth_proto, uint16_t encap_proto,
				uint32_t src_ip, uint32_t dst_ip,
				uint16_t src_port, uint16_t dst_port)
{
	NOT_IN_USE(src_mac);
	NOT_IN_USE(dst_mac);
	NOT_IN_USE(eth_proto);
	NOT_IN_USE(encap_proto);
	NOT_IN_USE(src_ip);
	NOT_IN_USE(dst_ip);
	NOT_IN_USE(src_port);
	NOT_IN_USE(dst_port);

	return 0;
}

void ring_slave::inc_tx_retransmissions(ring_user_id_t id) {
	NOT_IN_USE(id);
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
			if(safe_mce_sys().gro_streams_max && flow_spec_5t.is_5_tuple()) {
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
