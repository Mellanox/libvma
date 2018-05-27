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

#include "ring_slave.h"

#include "vma/dev/rfs_mc.h"
#include "vma/dev/rfs_uc.h"
#include "vma/dev/rfs_uc_tcp_gro.h"

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
