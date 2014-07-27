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


#ifndef DST_ENTRY_H
#define DST_ENTRY_H

#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>

#include "vlogger/vlogger.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/verbs_extra.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/proto/route_entry.h"
#include "vma/proto/route_val.h"
#include "vma/proto/rule_entry.h"
#include "vma/proto/neighbour_table_mgr.h"
#include "vma/dev/net_device_val.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/dev/wqe_send_handler.h"
#include "vma/dev/wqe_send_ib_handler.h"
#include "vma/dev/ring.h"
#include "vma/dev/ring_allocation_logic.h"
#include "vma/infra/sender.h"
#include "header.h"
#include "ip_address.h"
#include "util/lock_wrapper.h"

class dst_entry : public cache_observer, public tostr, public neigh_observer
{

public:
	dst_entry(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, int owner_fd);
	virtual ~dst_entry();

	virtual void 	notify_cb();

	virtual bool 	prepare_to_send(bool skip_rules=false);
	virtual ssize_t slow_send(const iovec* p_iov, size_t sz_iov, bool b_blocked = true, bool is_rexmit = false, int flags = 0, socket_fd_api* sock = 0, tx_call_t call_type = TX_UNDEF) = 0 ;
	virtual ssize_t fast_send(const struct iovec* p_iov, const ssize_t sz_iov, bool b_blocked = true, bool is_rexmit = false, bool dont_inline = false) = 0;

	bool		try_migrate_ring(lock_base& socket_lock);

	bool 		is_offloaded() { return m_b_is_offloaded; }
	void		set_bound_addr(in_addr_t addr);
	void		set_so_bindtodevice_addr(in_addr_t addr);
	in_addr_t	get_src_addr();
	in_addr_t	get_dst_addr();
	uint16_t	get_dst_port();

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	net_device_val* get_net_dev()
	{
		return m_p_net_dev_val;
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	virtual transport_type_t get_obs_transport_type() const;
	virtual flow_tuple get_flow_tuple() const;

protected:
	ip_address 		m_dst_ip;
	uint16_t 		m_dst_port;
	uint16_t 		m_src_port;

	in_addr_t		m_bound_ip;
	in_addr_t		m_so_bindtodevice_ip;

	lock_mutex_recursive 	m_slow_path_lock;
	vma_ibv_send_wr 	m_inline_send_wqe;
	vma_ibv_send_wr 	m_not_inline_send_wqe;
	wqe_send_handler*	m_p_send_wqe_handler;
	ibv_sge 		m_sge[2];
	uint8_t 		m_num_sge;
	rule_entry*		m_p_rr_entry;
	rule_val*		m_p_rr_val;
	route_entry*		m_p_rt_entry;
	route_val*		m_p_rt_val;
	net_device_entry*	m_p_net_dev_entry;
	net_device_val*		m_p_net_dev_val;
	neigh_entry*		m_p_neigh_entry;
	neigh_val*		m_p_neigh_val;
	bool 			m_b_is_offloaded;
	bool 			m_b_force_os;
	ring*			m_p_ring;
	ring_allocation_logic_tx m_ring_alloc_logic;
	mem_buf_desc_t* 	m_p_tx_mem_buf_desc_list;
	header 			m_header;
	uint8_t 		m_ttl;
	uint8_t 		m_tos;
	bool 			m_b_is_initialized;

	vma_ibv_send_wr* 		m_p_send_wqe;
	uint32_t 		m_max_inline;

	virtual transport_t 	get_transport(sockaddr_in to) = 0;
	virtual uint8_t 	get_protocol_type() const = 0;
	virtual bool 		get_net_dev_val();
	virtual uint32_t 	get_inline_sge_num() = 0;
	virtual ibv_sge*	get_sge_lst_4_inline_send() = 0;
	virtual ibv_sge*	get_sge_lst_4_not_inline_send() = 0;

	virtual bool 		offloaded_according_to_rules();
	virtual void 		init_members();
	virtual bool 		resolve_net_dev();
	bool 			update_net_dev_val();
	bool 			update_rt_val();
	virtual bool 		resolve_neigh();
	virtual bool 		resolve_ring();
	virtual bool 		release_ring();
	virtual ssize_t 	pass_buff_to_neigh(const iovec *p_iov, size_t & sz_iov, uint16_t packet_id = 0);
	virtual void 		configure_ip_header(uint16_t packet_id = 0);
	virtual void 		configure_headers() { conf_hdrs_and_snd_wqe();};
	virtual bool 		conf_hdrs_and_snd_wqe();
	virtual bool 		conf_l2_hdr_and_snd_wqe_eth();
	virtual bool 		conf_l2_hdr_and_snd_wqe_ib();
	virtual void 		init_sge() {};
	bool 			alloc_transport_dep_res();
	bool 			alloc_neigh_val(transport_type_t tranport);

	void			do_ring_migration(lock_base& socket_lock);
};


#endif /* DST_ENTRY_H */
