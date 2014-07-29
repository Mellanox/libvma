/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef RFS_H
#define RFS_H

#include <vector>

#include "vma/util/vtypes.h"
#include "vma/util/verbs_extra.h"
#include "vma/dev/ring.h"
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

#ifdef DEFINED_IBV_FLOW_SPEC_IB
//for mc
typedef struct __attribute__ ((packed)) ibv_flow_attr_ib {
	vma_ibv_flow_attr             attr;
	vma_ibv_flow_spec_ib          ib;

	ibv_flow_attr_ib(uint8_t port) {
		memset(this, 0, sizeof(struct ibv_flow_attr_ib));
		attr.size = sizeof(struct ibv_flow_attr_ib);
		attr.num_of_specs = 1;
		attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
		attr.priority = 0; // highest priority for all offloaded rules
		attr.port = port;
		attr.flags = VMA_IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK;
	}
} ibv_flow_attr_ib;

//for uc
typedef struct __attribute__ ((packed)) ibv_flow_attr_ib_ipv4_tcp_udp {

	vma_ibv_flow_attr             attr;
	vma_ibv_flow_spec_ib          ib;
	vma_ibv_flow_spec_ipv4        ipv4;
	vma_ibv_flow_spec_tcp_udp     tcp_udp;

	ibv_flow_attr_ib_ipv4_tcp_udp(uint8_t port) {
		memset(this, 0, sizeof(struct ibv_flow_attr_ib_ipv4_tcp_udp));
		attr.size = sizeof(struct ibv_flow_attr_ib_ipv4_tcp_udp);
		attr.num_of_specs = 3;
		attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
		attr.priority = 0; // highest priority for all offloaded rules
		attr.port = port;
		attr.flags = VMA_IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK;
	}
} ibv_flow_attr_ib_ipv4_tcp_udp;
#else
//for uc
typedef struct __attribute__ ((packed)) ibv_flow_attr_ib_ipv4_tcp_udp {

	vma_ibv_flow_attr             attr;
	vma_ibv_flow_spec_ipv4        ipv4;
	vma_ibv_flow_spec_tcp_udp     tcp_udp;

	ibv_flow_attr_ib_ipv4_tcp_udp(uint8_t port) {
		memset(this, 0, sizeof(struct ibv_flow_attr_ib_ipv4_tcp_udp));
		attr.size = sizeof(struct ibv_flow_attr_ib_ipv4_tcp_udp);
		attr.num_of_specs = 2;
		attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
		attr.priority = 0; // highest priority for all offloaded rules
		attr.port = port;
		attr.flags = VMA_IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK;
	}
} ibv_flow_attr_ib_ipv4_tcp_udp;
#endif

typedef struct __attribute__ ((packed)) ibv_flow_attr_eth_ipv4_tcp_udp {
	vma_ibv_flow_attr             attr;
	vma_ibv_flow_spec_eth         eth;
	vma_ibv_flow_spec_ipv4        ipv4;
	vma_ibv_flow_spec_tcp_udp     tcp_udp;

	ibv_flow_attr_eth_ipv4_tcp_udp(uint8_t port) {
		memset(this, 0, sizeof(struct ibv_flow_attr_eth_ipv4_tcp_udp));
		attr.size = sizeof(struct ibv_flow_attr_eth_ipv4_tcp_udp);
		attr.num_of_specs = 3;
		attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
		attr.priority = 0; // highest priority for all offloaded rules
		attr.port = port;
	}
} ibv_flow_attr_eth_ipv4_tcp_udp;

#ifdef DEFINED_IBV_FLOW_SPEC_IB
typedef struct __attribute__ ((packed)) attach_flow_data_ib_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_ib                 ibv_flow_attr;
	attach_flow_data_ib_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}

} attach_flow_data_ib_t;
#endif

typedef struct __attribute__ ((packed)) attach_flow_data_ib_ipv4_tcp_udp_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_ib_ipv4_tcp_udp    ibv_flow_attr;
	attach_flow_data_ib_ipv4_tcp_udp_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}
} attach_flow_data_ib_ipv4_tcp_udp_t;

typedef struct __attribute__ ((packed)) attach_flow_data_eth_ipv4_tcp_udp_t {
	struct ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	struct ibv_flow_attr_eth_ipv4_tcp_udp   ibv_flow_attr;
	attach_flow_data_eth_ipv4_tcp_udp_t(qp_mgr* qp_mgr) :
		ibv_flow(NULL),
		p_qp_mgr(qp_mgr),
		ibv_flow_attr(qp_mgr->get_port_num()) {}
} attach_flow_data_eth_ipv4_tcp_udp_t;

typedef struct __attribute__ ((packed)) attach_flow_data_t {
	vma_ibv_flow *                       ibv_flow;
	qp_mgr*                                 p_qp_mgr;
	vma_ibv_flow_attr                    ibv_flow_attr;
} attach_flow_data_t;

typedef std::vector<attach_flow_data_t*> attach_flow_data_vector_t;


class rfs_rule_filter
{
public:
	rfs_rule_filter(rule_filter_map_t& map, uint32_t key, flow_tuple& flow_tuple) : m_map(map), m_key(key), m_flow_tuple(flow_tuple) {}
	rule_filter_map_t& m_map;
	uint32_t m_key;
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
	rfs(flow_tuple *flow_spec_5t, ring *p_ring, rfs_rule_filter* rule_filter = NULL);
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
	const char*		to_str();

protected:
	flow_tuple		m_flow_tuple;
	ring*			m_p_ring;
	rfs_rule_filter*	m_p_rule_filter;
	attach_flow_data_vector_t m_attach_flow_data_vector;
	pkt_rcvr_sink**		m_sinks_list;
	uint32_t 		m_n_sinks_list_entries; // Number of actual sinks in the array (we shrink the array if a sink is removed)
	uint32_t		m_n_sinks_list_max_length;
	bool 			m_b_tmp_is_attached; // Only temporary, while ibcm calls attach_flow with no sinks...

	bool 			create_ibv_flow(); // Attach flow to all qps
	bool 			destroy_ibv_flow(); // Detach flow from all qps
	bool 			add_sink(pkt_rcvr_sink* p_sink);
	bool 			del_sink(pkt_rcvr_sink* p_sink);
	virtual void 		prepare_flow_spec() = 0;

private:
	rfs();		// I don't want anyone to use the default constructor
	inline void 		prepare_filter_attach(int& filter_counter, rule_filter_map_t::iterator& filter_iter);
	inline void 		filter_keep_attached(rule_filter_map_t::iterator& filter_iter);
	inline void 		prepare_filter_detach(int& filter_counter);

};

#endif /* RFS_H */
