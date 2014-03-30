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


#ifndef RING_H
#define RING_H

#include "vma/dev/gro_mgr.h"
#include "vma/util/hash_map.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/verbs_extra.h"
#include "vma/sock/pkt_rcvr_sink.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/flow_tuple.h"
#include "vma/proto/L2_address.h"
#include "vma/infra/sender.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/dev/net_device_val.h"
#include "vma/dev/qp_mgr.h"

class rfs;
class cq_mgr;
class L2_address;
class buffer_pool;


typedef enum {
	CQT_RX,
	CQT_TX
} cq_type_t;

/* udp uc key, only by destination port as we already know the rest */
typedef struct __attribute__((packed)) {
	in_port_t 	dst_port;
} flow_spec_udp_uc_key_t;

typedef struct __attribute__((packed)) {
	in_addr_t	dst_ip;
	in_port_t	dst_port;
} flow_spec_udp_mc_key_t;

typedef struct __attribute__((packed)) {
	in_addr_t	src_ip;
	in_port_t	dst_port;
	in_port_t	src_port;
} flow_spec_tcp_key_t;


/* UDP UC flow to rfs object hash map */
inline bool
operator==(flow_spec_udp_uc_key_t const& key1, flow_spec_udp_uc_key_t const& key2)
{
	return (key1.dst_port == key2.dst_port);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator<(flow_spec_udp_uc_key_t const& key1, flow_spec_udp_uc_key_t const& key2)
{
	if (key1.dst_port < key2.dst_port)
		return true;

	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<flow_spec_udp_uc_key_t, rfs*> flow_spec_udp_uc_map_t;


/* UDP MC flow to rfs object hash map */
inline bool
operator==(flow_spec_udp_mc_key_t const& key1, flow_spec_udp_mc_key_t const& key2)
{
	return 	(key1.dst_port == key2.dst_port) &&
		(key1.dst_ip == key2.dst_ip);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator<(flow_spec_udp_mc_key_t const& key1, flow_spec_udp_mc_key_t const& key2)
{
	if (key1.dst_ip < key2.dst_ip)		return true;
	if (key1.dst_ip > key2.dst_ip)		return false;
	if (key1.dst_port < key2.dst_port)	return true;
	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<flow_spec_udp_mc_key_t, rfs*> flow_spec_udp_mc_map_t;


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


typedef struct {
	ib_ctx_handler*	p_ib_ctx;
	uint8_t 	port_num;
	L2_address* 	p_l2_addr;
} ring_resource_creation_info_t;


class ring_resource_definition
{
public:
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	ring_resource_definition(const ib_ctx_handler* p_ib_ctx, const uint8_t port_num, const L2_address* p_l2_addr) : m_p_ib_ctx(p_ib_ctx), m_port_num(port_num), m_p_l2_addr(NULL) { save_l2_address(p_l2_addr); };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	ring_resource_definition(const ring_resource_creation_info_t* p_info) : m_p_ib_ctx(p_info-> p_ib_ctx), m_port_num(p_info->port_num), m_p_l2_addr(NULL) { save_l2_address(p_info->p_l2_addr); };
	ring_resource_definition(const ring_resource_creation_info_t& info) : m_p_ib_ctx(info. p_ib_ctx), m_port_num(info.port_num), m_p_l2_addr(NULL) { save_l2_address(info.p_l2_addr); };
	ring_resource_definition(const ring_resource_definition& other) : m_p_ib_ctx(other.get_ib_ctx_handle()), m_port_num(other.get_port_num()), m_p_l2_addr(NULL) { save_l2_address(other.get_l2_addr()); };
	virtual ~ring_resource_definition() { delete_l2_address(); } ;

	const ib_ctx_handler* 	get_ib_ctx_handle() const { return m_p_ib_ctx; };
	uint8_t 		get_port_num() const { return m_port_num; };
	L2_address* 		get_l2_addr() const { return m_p_l2_addr; };

	virtual bool operator==(ring_resource_definition const& other) const
	{
		return 	(m_p_ib_ctx == other.m_p_ib_ctx) &&
			(m_port_num == other.m_port_num);
	}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual bool operator <(ring_resource_definition const& other) const
	{
		if (m_p_ib_ctx < other.m_p_ib_ctx)		return true;
		if (m_p_ib_ctx > other.m_p_ib_ctx)		return false;
		if (m_port_num  < other.m_port_num)		return true;
		return false;
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	virtual size_t 	hash(void)
	{
		uint8_t csum = 0;
		uint8_t* pval = (uint8_t*)this;
		for (size_t i = 0; i < (sizeof(ib_ctx_handler*) + sizeof(uint8_t)); ++i, ++pval) { csum ^= *pval; }
		return csum;
	}

private:
	const ib_ctx_handler*	m_p_ib_ctx;
	const uint8_t 		m_port_num;
	L2_address* 		m_p_l2_addr;

	void	save_l2_address(const L2_address* p_l2_addr) { delete_l2_address(); m_p_l2_addr = p_l2_addr->clone(); };
	void	delete_l2_address() { if (m_p_l2_addr) delete m_p_l2_addr; m_p_l2_addr = NULL; };
};

struct ring_resources_info_t {
	qp_mgr*				m_p_qp_mgr;
	cq_mgr*				m_p_cq_mgr_rx;
	cq_mgr*				m_p_cq_mgr_tx;
	struct ibv_comp_channel*	m_p_rx_comp_event_channel;
};

namespace std { namespace tr1 {
template<>
class hash<ring_resource_definition>
{
public:
	size_t operator()(const ring_resource_definition &key) const
	{
		ring_resource_definition* tmp_key = (ring_resource_definition*)&key;
		return tmp_key->hash();
	}
};
}}
typedef std::tr1::unordered_map<ring_resource_definition, ring_resources_info_t> ring_resources_map_t;


typedef std::tr1::unordered_map<int, ring_resources_map_t::iterator> p_rx_channel_fd_to_ring_resources_t;


struct counter_and_ibv_flows {
	int counter;
	std::vector<vma_ibv_flow*> ibv_flows;
};

typedef std::tr1::unordered_map<uint32_t, struct counter_and_ibv_flows> rule_filter_map_t;


struct cq_moderation_info {
	uint32_t period;
	uint32_t count;
	uint64_t packets;
	uint64_t bytes;
	uint64_t prev_packets;
	uint64_t prev_bytes;
	uint32_t missed_rounds;
};


/**
 * @class ring
 *
 * Object to manages the QP and CQ operation
 * This object is used for Rx & Tx at the same time
 * Once created it ...
 *
 *
 * NOTE:
 * In the end this object will contain a QP and CQ.
 * In the first stage it will be a part of the qp_mgr object.
 *
 */
class ring : public mem_buf_desc_owner
{
public:
	ring(in_addr_t local_if, uint16_t partition_sn, int count, transport_type_t transport_type);
	~ring();

	bool 		attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	bool 		detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);

	void		restart(ring_resource_creation_info_t* p_ring_info);

	// Funcs taken from qp_mgr.h
	// Get/Release memory buffer descriptor with a linked data memory buffer
	mem_buf_desc_t* mem_buf_tx_get(bool b_block, int n_num_mem_bufs = 1);
	int		mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting = false);
	virtual void 	send_ring_buffer(vma_ibv_send_wr* p_send_wqe, bool b_block);
	virtual void 	send_lwip_buffer(vma_ibv_send_wr* p_send_wqe, bool b_block);

	// Funcs taken from cq_mgr.h
	int		get_num_resources() const { return m_n_num_resources; };
	int*		get_rx_channel_fds() const { return m_p_n_rx_channel_fds; };
	int		get_max_tx_inline();
	int		request_notification(cq_type_t cq_type, uint64_t poll_sn);
	int		wait_for_notification_and_process_element(cq_type_t cq_type, int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	int 		poll_and_process_element_tx(uint64_t* p_cq_poll_sn);
	int 		poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	bool		reclaim_recv_buffers(descq_t *rx_reuse);
	bool		reclaim_recv_buffers_no_lock(descq_t *rx_reuse); // No locks
	bool		reclaim_recv_buffers_no_lock(mem_buf_desc_t* rx_reuse_lst); // No locks
	int		drain_and_proccess(cq_type_t cq_type);

	void		adapt_cq_moderation();

	void		mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc); // Assume locked...
	// Tx completion handling at the qp_mgr level is just re listing the desc+data buffer in the free lists
	void		mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc); // Assume locked...
	void		mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL);
	void		mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);

	void		mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);

	friend class cq_mgr;
	friend class qp_mgr;
	friend class rfs;
	friend class rfs_uc;
	friend class rfs_uc_tcp_gro;
	friend class rfs_mc;

protected:
	void 		create_resources(ring_resource_creation_info_t* p_ring_info, int active);
	virtual qp_mgr* create_qp_mgr(ring_resource_definition& key, struct ibv_comp_channel* p_rx_comp_event_channel) = 0;

	in_addr_t 		 		m_local_if;
	transport_type_t 	 		m_transport_type;
	int					m_n_num_resources;
	ring_resources_map_t			m_ring_resources_map;
	ring_resources_map_t::iterator		m_ring_active_resource;
	p_rx_channel_fd_to_ring_resources_t	m_rx_channel_fd_to_ring_resources_map;
	// For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
	// It means that for every MC group, even if we have sockets with different ports - only one rule in the HW.
	// So the hash map below keeps track of the number of sockets per rule so we know when to call ibv_attach and ibv_detach
	rule_filter_map_t			m_l2_mc_ip_attach_map;
	rule_filter_map_t			m_tcp_dst_port_attach_map;
	struct ibv_comp_channel* 		m_p_tx_comp_event_channel;
	flow_spec_tcp_map_t 	 		m_flow_tcp_map;
	flow_spec_udp_mc_map_t 	 		m_flow_udp_mc_map;
	flow_spec_udp_uc_map_t 	 		m_flow_udp_uc_map;
	lock_mutex_recursive			m_lock_ring_rx;
	lock_mutex_recursive			m_lock_ring_tx;
	lock_mutex				m_lock_ring_tx_buf_wait;
	int*					m_p_n_rx_channel_fds;
	descq_t					m_tx_pool;
	uint32_t				m_tx_num_bufs;
	uint32_t 		 		m_tx_num_wr;
	int32_t 		 		m_tx_num_wr_free;
	bool					m_b_qp_tx_first_flushed_completion_handled;
	uint32_t		 		m_missing_buf_ref_count;

	struct cq_moderation_info		m_cq_moderation_info;

	uint32_t				m_tx_lkey; // this is the registered memory lkey for a given specific device for the buffer pool use

	uint16_t 				m_partition; //vlan or pkey

	gro_mgr					m_gro_mgr;

	ring_stats_t*				m_p_ring_stat;
	ring_stats_t				m_ring_stat_static;

	// Internal functions. No need for locks mechanism.
	transport_type_t 	 get_transport_type() { return m_transport_type; }	// TODO ODEDS: move to ctor...
	struct ibv_comp_channel* get_tx_comp_event_channel() { return m_p_tx_comp_event_channel; }
	bool			 rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, transport_type_t m_transport_type, void* pv_fd_ready_array);
	void 			 print_flow_to_rfs_udp_uc_map(flow_spec_udp_uc_map_t *p_flow_map);
	void 			 print_flow_to_rfs_tcp_map(flow_spec_tcp_map_t *p_flow_map);
	//	void	print_ring_flow_to_rfs_map(flow_spec_map_t *p_flow_map);

	void			 flow_udp_uc_del_all();
	void			 flow_udp_mc_del_all();
	void			 flow_tcp_del_all();

private:
	inline void 		 send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe);
	inline bool		 is_available_qp_wr(bool b_block);
	inline bool		 request_more_tx_buffers(uint32_t count);
	inline mem_buf_desc_t*	 get_tx_buffers(uint32_t n_num_mem_bufs);
	inline int		 put_tx_buffers(mem_buf_desc_t* buff_list);
	inline int		 put_tx_single_buffer(mem_buf_desc_t* buff);
	inline int		 send_buffer(vma_ibv_send_wr* p_send_wqe, bool b_block);

	void			 modify_cq_moderation(uint32_t period, uint32_t count);
};

class ring_eth : public ring
{
public:
	ring_eth(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, int count, int active, uint16_t vlan) :
		ring(local_if, vlan, count, VMA_TRANSPORT_ETH) { create_resources(p_ring_info, active); };

protected:
	virtual qp_mgr* create_qp_mgr(ring_resource_definition& key, struct ibv_comp_channel* p_rx_comp_event_channel);
};

class ring_ib : public ring
{
public:
	ring_ib(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, int count, int active, uint16_t pkey) :
		ring(local_if, pkey, count, VMA_TRANSPORT_IB) { create_resources(p_ring_info, active); };

protected:
	virtual qp_mgr* create_qp_mgr(ring_resource_definition& key, struct ibv_comp_channel* p_rx_comp_event_channel);
};

#endif /* RING_H */
