/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef RFS_H
#define RFS_H

#include <vector>

#include "vma/ib/base/verbs_extra.h"
#include "vma/util/vtypes.h"
#include "vma/dev/ring_simple.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/flow_tuple.h"


#define rfs_logpanic 	__log_info_panic
#define rfs_logerr	__log_info_err
#define rfs_logwarn	__log_info_warn
#define rfs_loginfo	__log_info_info
#define rfs_logdbg	__log_info_dbg
#define rfs_logfunc	__log_info_func
#define rfs_logfuncall	__log_info_funcall

#define RFS_SINKS_LIST_DEFAULT_LEN 32

class qp_mgr;
class pkt_rcvr_sink;

/* ETHERNET
 */
typedef struct attach_flow_data_eth_ipv4_tcp_udp_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_eth_ipv4_tcp_udp {
		vma_ibv_flow_attr             attr;
		vma_ibv_flow_spec_eth         eth;
		vma_ibv_flow_spec_ipv4        ipv4;
		vma_ibv_flow_spec_tcp_udp     tcp_udp;
		vma_ibv_flow_spec_action_tag  flow_tag; // must be the last as struct can be used without it		

		ibv_flow_attr_eth_ipv4_tcp_udp(uint8_t port) {
			memset(this, 0, sizeof(*this));
			attr.size = sizeof(struct ibv_flow_attr_eth_ipv4_tcp_udp) - sizeof(flow_tag);			
			attr.num_of_specs = 3;
			attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
			attr.priority = 1; // almost highest priority, 0 is used for 5-tuple later
			attr.port = port;
		}
		inline void add_flow_tag_spec(void) {
			attr.num_of_specs++;
			attr.size += sizeof(flow_tag);
		}
	} ibv_flow_attr;
	attach_flow_data_eth_ipv4_tcp_udp_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}
} attach_flow_data_eth_ipv4_tcp_udp_t;

/* IPOIB (MC)
 */
typedef struct attach_flow_data_ib_v2_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_ib_v2 {
		vma_ibv_flow_attr             attr;
		vma_ibv_flow_spec_ipv4        ipv4;
		vma_ibv_flow_spec_tcp_udp     tcp_udp;

		ibv_flow_attr_ib_v2(uint8_t port) {
			memset(this, 0, sizeof(*this));
			attr.size = sizeof(struct ibv_flow_attr_ib_v2);
			attr.num_of_specs = 2;
			attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
			attr.priority = 1; // almost highest priority, 0 is used for 5-tuple later
			attr.port = port;
		}
	} ibv_flow_attr;
	attach_flow_data_ib_v2_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}

} attach_flow_data_ib_v2_t;

#ifdef DEFINED_IBV_FLOW_SPEC_IB
typedef struct attach_flow_data_ib_v1_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_ib_v1 {
		vma_ibv_flow_attr             attr;
		vma_ibv_flow_spec_ib          ib;

		ibv_flow_attr_ib_v1(uint8_t port) {
			memset(this, 0, sizeof(*this));
			attr.size = sizeof(struct ibv_flow_attr_ib_v1);
			attr.num_of_specs = 1;
			attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
			attr.priority = 1; // almost highest priority, 0 is used for 5-tuple later
			attr.port = port;
		}
	} ibv_flow_attr;
	attach_flow_data_ib_v1_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}

} attach_flow_data_ib_v1_t;
#endif

/* IPOIB (UC)
 */
typedef struct attach_flow_data_ib_ipv4_tcp_udp_v2_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_ib_ipv4_tcp_udp_v2 {

		vma_ibv_flow_attr             attr;
		vma_ibv_flow_spec_ipv4        ipv4;
		vma_ibv_flow_spec_tcp_udp     tcp_udp;

		ibv_flow_attr_ib_ipv4_tcp_udp_v2(uint8_t port) {
			memset(this, 0, sizeof(*this));
			attr.size = sizeof(struct ibv_flow_attr_ib_ipv4_tcp_udp_v2);
			attr.num_of_specs = 2;
			attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
			attr.priority = 1; // almost highest priority, 0 is used for 5-tuple later
			attr.port = port;
		}
	} ibv_flow_attr;
	attach_flow_data_ib_ipv4_tcp_udp_v2_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}
} attach_flow_data_ib_ipv4_tcp_udp_v2_t;

#ifdef DEFINED_IBV_FLOW_SPEC_IB
typedef struct attach_flow_data_ib_ipv4_tcp_udp_v1_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_ib_ipv4_tcp_udp_v1 {

		vma_ibv_flow_attr             attr;
		vma_ibv_flow_spec_ib          ib;
		vma_ibv_flow_spec_ipv4        ipv4;
		vma_ibv_flow_spec_tcp_udp     tcp_udp;

		ibv_flow_attr_ib_ipv4_tcp_udp_v1(uint8_t port) {
			memset(this, 0, sizeof(*this));
			attr.size = sizeof(struct ibv_flow_attr_ib_ipv4_tcp_udp_v1);
			attr.num_of_specs = 3;
			attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
			attr.priority = 1; // almost highest priority, 0 is used for 5-tuple later
			attr.port = port;
		}
	} ibv_flow_attr;
	attach_flow_data_ib_ipv4_tcp_udp_v1_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}
} attach_flow_data_ib_ipv4_tcp_udp_v1_t;
#endif /* DEFINED_IBV_FLOW_SPEC_IB */

typedef struct attach_flow_data_t {
	vma_ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	vma_ibv_flow_attr                    ibv_flow_attr;
} attach_flow_data_t;

typedef std::vector<attach_flow_data_t*> attach_flow_data_vector_t;


class rfs_rule_filter
{
public:
	rfs_rule_filter(rule_filter_map_t& map, uint64_t key, flow_tuple& flow_tuple) : m_map(map), m_key(key), m_flow_tuple(flow_tuple) {}
	rule_filter_map_t& m_map;
	uint64_t m_key;
	flow_tuple m_flow_tuple;
};

/**
 * @class rfs
 *
 * Object to manages the sink list
 * This object is used for maintaining the sink list and dispatching packets
 *
 */


class rfs
{
public:
	rfs(flow_tuple *flow_spec_5t, ring_slave *p_ring,
	    rfs_rule_filter* rule_filter = NULL, uint32_t flow_tag_id = 0);
	virtual ~rfs();

	/**
	 * Register/Unregister a sink with this rfs object
	 * Get notifications about incoming packets using the pkt_rcvr_sink callback api
	 * The rfs will call ibv_attach on the QP once when at least one receiver sink is registered
	 * An ibv_detach is called when the last receiver sink is deleted from the registered list
	 *
	 */
	bool 			attach_flow(pkt_rcvr_sink *sink); // Add a sink. If this is the first sink --> map the sink and attach flow to QP
	bool 			detach_flow(pkt_rcvr_sink *sink); // Delete a sink. If this is the last sink --> delete it and detach flow from QP

	uint32_t 		get_num_of_sinks() const { return m_n_sinks_list_entries; }
	virtual bool 		rx_dispatch_packet(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array) = 0;

protected:
	flow_tuple		m_flow_tuple;
	ring_slave*		m_p_ring;
	rfs_rule_filter*	m_p_rule_filter;
	attach_flow_data_vector_t m_attach_flow_data_vector;
	pkt_rcvr_sink**		m_sinks_list;
	uint32_t 		m_n_sinks_list_entries; // Number of actual sinks in the array (we shrink the array if a sink is removed)
	uint32_t		m_n_sinks_list_max_length;
	uint32_t		m_flow_tag_id; // Associated with this rule, set by attach_flow()
	bool 			m_b_tmp_is_attached; // Only temporary, while ibcm calls attach_flow with no sinks...

	bool 			create_ibv_flow(); // Attach flow to all qps
	bool 			destroy_ibv_flow(); // Detach flow from all qps
	bool 			add_sink(pkt_rcvr_sink* p_sink);
	bool 			del_sink(pkt_rcvr_sink* p_sink);
	virtual bool 		prepare_flow_spec() = 0;

private:
	rfs();		// I don't want anyone to use the default constructor
	inline void 		prepare_filter_attach(int& filter_counter, rule_filter_map_t::iterator& filter_iter);
	inline void 		filter_keep_attached(rule_filter_map_t::iterator& filter_iter);
	inline void 		prepare_filter_detach(int& filter_counter, bool decrease_counter);

};

#endif /* RFS_H */
