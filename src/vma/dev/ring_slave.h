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

#ifndef RING_SLAVE_H_
#define RING_SLAVE_H_

#include "ring.h"
#include "vma/dev/net_device_table_mgr.h"


class rfs;

typedef struct __attribute__((packed)) flow_spec_udp_key_t {
  in_addr_t	dst_ip;
  in_port_t	dst_port;

  flow_spec_udp_key_t () {
    flow_spec_udp_key_helper(INADDR_ANY, INPORT_ANY);
  } //Default constructor
  flow_spec_udp_key_t (in_addr_t d_ip, in_addr_t d_port) {
    flow_spec_udp_key_helper(d_ip, d_port);
  }//Constructor
  void flow_spec_udp_key_helper(in_addr_t d_ip, in_addr_t d_port) {
    memset(this, 0, sizeof(*this));// Silencing coverity
    dst_ip = d_ip;
    dst_port = d_port;
  };
} flow_spec_udp_key_t;

typedef struct __attribute__((packed)) flow_spec_tcp_key_t {
  in_addr_t	src_ip;
  in_port_t	dst_port;
  in_port_t	src_port;

  flow_spec_tcp_key_t () {
  	flow_spec_tcp_key_helper (INADDR_ANY, INPORT_ANY, INPORT_ANY);
  } //Default constructor
  flow_spec_tcp_key_t (in_addr_t s_ip, in_addr_t d_port, in_addr_t s_port) {
  	flow_spec_tcp_key_helper (s_ip, d_port, s_port);
  }//Constructor
  void flow_spec_tcp_key_helper(in_addr_t s_ip, in_addr_t d_port, in_addr_t s_port) {
    memset(this, 0, sizeof(*this));// Silencing coverity
    src_ip = s_ip;
    dst_port = d_port;
    src_port = s_port;
  };
} flow_spec_tcp_key_t;


/* UDP flow to rfs object hash map */
inline bool
operator==(flow_spec_udp_key_t const& key1, flow_spec_udp_key_t const& key2)
{
	return 	(key1.dst_port == key2.dst_port) &&
		(key1.dst_ip == key2.dst_ip);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator<(flow_spec_udp_key_t const& key1, flow_spec_udp_key_t const& key2)
{
	if (key1.dst_ip < key2.dst_ip)		return true;
	if (key1.dst_ip > key2.dst_ip)		return false;
	if (key1.dst_port < key2.dst_port)	return true;
	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<flow_spec_udp_key_t, rfs*> flow_spec_udp_map_t;


/* TCP flow to rfs object hash map */
inline bool
operator==(flow_spec_tcp_key_t const& key1, flow_spec_tcp_key_t const& key2)
{
	return	(key1.src_port == key2.src_port) &&
		(key1.src_ip == key2.src_ip) &&
		(key1.dst_port == key2.dst_port);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator<(flow_spec_tcp_key_t const& key1, flow_spec_tcp_key_t const& key2)
{
	if (key1.src_ip < key2.src_ip)		return true;
	if (key1.src_ip > key2.src_ip)		return false;
	if (key1.dst_port < key2.dst_port)	return true;
	if (key1.dst_port > key2.dst_port)	return false;
	if (key1.src_port < key2.src_port)	return true;
	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<flow_spec_tcp_key_t, rfs*> flow_spec_tcp_map_t;

struct counter_and_ibv_flows {
	int counter;
	std::vector<vma_ibv_flow*> ibv_flows;
};

typedef std::tr1::unordered_map<uint32_t, struct counter_and_ibv_flows> rule_filter_map_t;


class ring_slave : public ring
{
public:
	ring_slave(int if_index, ring* parent, ring_type_t type);
	virtual ~ring_slave();

	virtual void print_val();

	virtual void        restart();

	virtual int         get_num_resources() const { return 1; };
	virtual bool        is_member(mem_buf_desc_owner* rng);
	virtual bool        is_active_member(mem_buf_desc_owner* rng, ring_user_id_t id);
	virtual ring_user_id_t	generate_id();
	virtual ring_user_id_t	generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
	virtual bool        is_up() = 0;
	virtual void        inc_tx_retransmissions(ring_user_id_t id);
	virtual bool        rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array) = 0;

	ring_type_t         get_type() const { return m_type; }
	transport_type_t    get_transport_type() const { return m_transport_type; }


	bool                m_active;         /* State indicator */

protected:
	transport_type_t    m_transport_type; /* transport ETH/IB */
	ring_stats_t*       m_p_ring_stat;

private:
	ring_type_t         m_type;           /* ring type */
	ring_stats_t        m_ring_stat;
};


#endif /* RING_SLAVE_H_ */
