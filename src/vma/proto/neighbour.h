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


#ifndef NEIGHBOUR_H
#define NEIGHBOUR_H

#include <rdma/rdma_cma.h>

#include "state_machine/sm.h"
#include "vma/util/sys_vars.h"
#include "vma/util/to_str.h"
#include "vma/infra/cache_subject_observer.h"
#include "vma/infra/sender.h"
#include "vma/event/event_handler_ibverbs.h"
#include "vma/event/event_handler_rdma_cm.h"
#include "vma/event/event_handler_manager.h"
#include "vma/event/timer_handler.h"
#include "vma/event/netlink_event.h"
#include "vma/proto/ip_address.h"
#include "vma/proto/L2_address.h"

#include "vma/proto/header.h"
#include "vma/dev/ring_allocation_logic.h"
#include "vma/dev/net_device_val.h"
#include "vma/dev/ring.h"
#include "vma/proto/arp.h"

class neigh_key : public tostr
{
public:
	neigh_key(ip_address addr, net_device_val* p_ndvl): m_ip_addrs(addr), m_p_net_dev_val(p_ndvl) {};
	virtual ~neigh_key() {};

	const std::string to_str() const
	{
		return(m_ip_addrs.to_str() + " " + m_p_net_dev_val->to_str());
	}
	in_addr_t 	get_in_addr() const { return m_ip_addrs.get_in_addr(); };
	net_device_val*	get_net_device_val() const { return m_p_net_dev_val; };

	virtual size_t 	hash(void)
	{
		uint8_t csum = 0;
		uint8_t* pval = (uint8_t*)this;
		for (size_t i = 0; i < sizeof(ip_address); ++i, ++pval) { csum ^= *pval; }
		return csum;
	}

	virtual bool operator==(neigh_key const& other) const
	{
		return ((m_ip_addrs == other.m_ip_addrs) && (m_p_net_dev_val == other.m_p_net_dev_val));
	}

private:
	ip_address m_ip_addrs;
	net_device_val* m_p_net_dev_val;
};

namespace std {
template<>
class hash<neigh_key>
{
public:
	size_t operator()(const neigh_key &key) const
	{
		neigh_key* tmp_key = (neigh_key*)&key;
		return tmp_key->hash();
	}
};
}

class neigh_val : public tostr
{
public:
				neigh_val(): m_trans_type(VMA_TRANSPORT_UNKNOWN), m_l2_address(NULL){};
	virtual 		~neigh_val(){};

	virtual void    	zero_all_members()
	{ 				if(m_l2_address)
						delete m_l2_address;
					m_l2_address = NULL;
	};
	const L2_address*	get_l2_address() const { return m_l2_address; };

	virtual neigh_val & operator=(const neigh_val & val)
	{
		if (this != &val) {
			m_l2_address = val.m_l2_address;
			m_trans_type = val.m_trans_type;
		}
		return *this;
	}

protected:
	friend	class		neigh_entry;
	friend  class		neigh_ib;
	friend  class		neigh_eth;
	friend 	class		neigh_ib_broadcast;
	transport_type_t	m_trans_type;
	L2_address*		m_l2_address;
};

class neigh_eth_val : public neigh_val
{
public:
	neigh_eth_val()
	{
		m_trans_type = VMA_TRANSPORT_ETH;
		zero_all_members();
	}

	neigh_val & operator=(const neigh_val & val)
	{
		return neigh_val::operator=(val);
	}

private:
	friend	class 		neigh_eth;
};

class neigh_ib_val : public neigh_val
{
public:
				neigh_ib_val() : m_ah(NULL) { zero_all_members(); };

	ibv_ah* 		get_ah()const		{ return m_ah; };
	ibv_ah_attr 		get_ah_attr() const	{ return m_ah_attr; };
	uint32_t 		get_qkey() const	{ return m_qkey; };
	uint32_t		get_qpn() const
	{
				if (m_l2_address)
					return(((IPoIB_addr *) m_l2_address)->get_qpn());
				else
					return 0;
	}

	neigh_val & operator=(const neigh_val & val);

private:
	friend			class neigh_ib;
	friend 			class neigh_ib_broadcast;

	ibv_ah_attr		m_ah_attr;
	ibv_ah*			m_ah;
	uint32_t		m_qkey;

	void 			zero_all_members()
	{
				memset(&m_ah_attr, 0, sizeof(m_ah_attr));
				//m_ah 	= NULL;
				m_qkey 	= 0;
				neigh_val::zero_all_members();
	}
};

/* neigh_entry inherits from cache_entry_subject where
 * Key = address (peer IP)
 * Val = class neigh_val
 */
typedef std::deque<neigh_send_data *> unsent_queue_t;

class neigh_entry : public cache_entry_subject<neigh_key, neigh_val *>, public event_handler_rdma_cm, public timer_handler
{
public:
	enum type
	{
		UNKNOWN,
		MC,
		UC
	};

	enum state_t
	{
		ST_NOT_ACTIVE = 0,
		ST_INIT = 1,
		ST_INIT_RESOLUTION,
		ST_ADDR_RESOLVED,
		ST_ARP_RESOLVED,
		ST_PATH_RESOLVED,
		ST_READY,
		ST_ERROR,
		ST_LAST
	};

	enum event_t
	{
		EV_KICK_START = 0,
		EV_START_RESOLUTION,
		EV_ARP_RESOLVED,
		EV_ADDR_RESOLVED,
		EV_PATH_RESOLVED,
		EV_ERROR,
		EV_TIMEOUT_EXPIRED, // For IB MC join
		EV_UNHANDLED,
		EV_LAST
	};

	friend 	class		neighbour_table_mgr;

	neigh_entry (neigh_key key, transport_type_t type, bool is_init_resources = true);
	virtual 		~neigh_entry();

	//Overwrite cach_entry virtual function
	virtual bool 		is_deletable();
	virtual void 		clean_obj();

	//Implementation of pure virtual function: Don't use get_val function, instead use get_peer_info
	virtual bool 		get_val(INOUT neigh_val * & val){ NOT_IN_USE(val); return false;};

	virtual bool 		get_peer_info(neigh_val * val);
	// Overriding subject's register_observer
	virtual bool 		register_observer(const observer* const new_observer);
	//Overriding tostr to_str()
	virtual const std::string to_str() const;

	const char* 		event_to_str(event_t event) const;
	const char* 		state_to_str(state_t state) const;

	void    		handle_event_rdma_cm_cb(struct rdma_cm_event* p_event);
	void			handle_neigh_event(neigh_nl_event* nl_ev);

	static void		general_st_entry(const sm_info_t& func_info);
	static void		general_st_leave(const sm_info_t& func_info);
	static void 		print_event_info(int state, int event, void* app_data);
	static void 		dofunc_enter_init(const sm_info_t& func_info);
	static void 		dofunc_enter_init_resolution(const sm_info_t& func_info);
	static void 		dofunc_enter_addr_resolved(const sm_info_t& func_info);
	static void 		dofunc_enter_error(const sm_info_t& func_info);
	static void		dofunc_enter_not_active(const sm_info_t& func_info);
	static void		dofunc_enter_ready(const sm_info_t& func_info);

	//Implementing pure virtual function of sender
	virtual int		send(neigh_send_info &s_info);

protected:
	rdma_cm_id*		m_cma_id;
	sockaddr_in  		m_dst_addr;
	sockaddr_in  		m_src_addr;
	enum rdma_port_space 	m_rdma_port_space;
	state_machine*		m_state_machine;
	type			m_type; // UC  / MC
	transport_type_t	m_trans_type;
	bool			m_state;
	unsent_queue_t 		m_unsent_queue;
	//Counter to sign that KickStart was already generated in ERROR_ST
	uint32_t 		m_err_counter;

	void*			m_timer_handle;
	// members for sending arp
	uint32_t		m_arp_counter;
	net_device_val*		m_p_dev;
	ring* 			m_p_ring;
	vma_ibv_send_wr 	m_send_wqe;
	ibv_sge 		m_sge;
	bool 			m_is_loopback;

	const std::string	m_to_str;
	ring_user_id_t		m_id;

	virtual void 		priv_general_st_entry(const sm_info_t& func_info);
	virtual void 		priv_general_st_leave(const sm_info_t& func_info);
	virtual void		priv_print_event_info(state_t state, event_t event);
	virtual void		priv_kick_start_sm();
	virtual void		priv_enter_not_active();
	virtual void		priv_enter_error();
	virtual int 		priv_enter_init();
	virtual int 		priv_enter_init_resolution();
	virtual int 		priv_enter_addr_resolved();
	virtual int 		priv_enter_ready();

	bool 			priv_get_neigh_state(int & state);
	bool 			priv_get_neigh_l2(address_t & l2_addr);
	bool 			priv_is_reachable(int state) { return state & (NUD_REACHABLE | NUD_PERMANENT); }
	bool 			priv_is_failed(int state) { return state & (NUD_FAILED | NUD_INCOMPLETE); }

	void			event_handler(event_t event, void* p_event_info = NULL);
	void			priv_event_handler_no_locks(event_t event, void* p_event_info = NULL);

	virtual bool 		priv_handle_neigh_is_l2_changed(address_t) { return false; };
	void 			priv_handle_neigh_reachable_event();
	void 			priv_destroy_cma_id();
	virtual void* 		priv_register_timer_event(int timeout_msec, timer_handler* handler, timer_req_type_t req_type, void* user_data);
	void			priv_unregister_timer();

	virtual void 		send_arp();
	virtual bool 		post_send_arp(bool) { return true;};
	virtual bool 		prepare_to_send_packet(header *) {return true;};
	void			handle_timer_expired(void* user_data);

	virtual ring_user_id_t	generate_ring_user_id(header *h = NULL) { NOT_IN_USE(h); return m_p_ring->generate_id(); };

	lock_mutex_recursive    m_sm_lock;

private:
	bool 			m_is_first_send_arp;
	const uint32_t		m_n_sysvar_neigh_wait_till_send_arp_msec;
	const uint32_t		m_n_sysvar_neigh_uc_arp_quata;
	const uint32_t		m_n_sysvar_neigh_num_err_retries;
	ring_allocation_logic_tx m_ring_allocation_logic;
	event_t 		rdma_event_mapping(struct rdma_cm_event* p_event);
	void 			empty_unsent_queue();
	bool 			post_send_packet(neigh_send_data *n_send_data);
	bool			post_send_udp(neigh_send_data *n_send_data);
	bool			post_send_tcp(neigh_send_data *n_send_data);
};

class neigh_ib : public neigh_entry, public event_handler_ibverbs
{
public:
	friend 	class		neighbour_table_mgr;
				neigh_ib(neigh_key key, bool is_init_resources = true);
				~neigh_ib();

	static void		dofunc_enter_arp_resolved(const sm_info_t& func_info);
	static void		dofunc_enter_path_resolved(const sm_info_t& func_info);

protected:
	ibv_pd* 		m_pd;

	int			find_pd();
	int			create_ah();
	int			destroy_ah();
	virtual int 		build_mc_neigh_val(struct rdma_cm_event* event_data, uint32_t & wait_after_join_msec);

private:

	//Implementation of pure virtual functions
	void			handle_event_ibverbs_cb(void* ev_data, void* ctx);
	void			handle_timer_expired(void* user_data);

	// Overriding neigh_entry priv_enter_not_active
	void			priv_enter_not_active();
	void 			priv_enter_error();
	int			priv_enter_arp_resolved();
	int 			priv_enter_path_resolved(struct rdma_cm_event* event_data, uint32_t & wait_after_join_msec);
	virtual bool		priv_handle_neigh_is_l2_changed(address_t);
	// Overriding neigh_entry priv_enter_ready
	int			priv_enter_ready();

	int			handle_enter_arp_resolved_uc();
	int			handle_enter_arp_resolved_mc();
	int 			build_uc_neigh_val(struct rdma_cm_event* event_data, uint32_t & wait_after_join_msec);

	event_t 		ibverbs_event_mapping(void* p_event_info);
	virtual bool 		post_send_arp(bool);
	virtual bool 		prepare_to_send_packet(header *);

	const uint32_t		m_n_sysvar_wait_after_join_msec;
};

class neigh_ib_broadcast : public neigh_ib
{
public:
				neigh_ib_broadcast(neigh_key key);
	virtual int		send(neigh_send_info & s_info);
	virtual bool 		get_peer_info(neigh_val * p_val);
	virtual bool 		is_deletable() { return false; };

private:
	void 			build_mc_neigh_val();
	virtual void 		send_arp();
};

class neigh_eth : public neigh_entry
{
public:
	friend 	class		neighbour_table_mgr;
				neigh_eth(neigh_key key);
				~neigh_eth();
	virtual bool 		get_peer_info(neigh_val * val);
	//Overriding neigh_entry register_observer
	bool 			register_observer(const observer* const new_observer);
	//Overriding neigh_entry is_deletable
	virtual bool 		is_deletable();

protected:
	virtual ring_user_id_t	generate_ring_user_id(header * h = NULL);

private:

	int 			build_mc_neigh_val();
	int			build_uc_neigh_val();
	//Overriding neigh_entry priv_enter_ready
	virtual int 		priv_enter_ready();
	virtual int 		priv_enter_init();
	virtual int 		priv_enter_init_resolution();
	virtual bool 		priv_handle_neigh_is_l2_changed(address_t);
	virtual bool 		post_send_arp(bool is_broadcast);
	virtual bool 		prepare_to_send_packet(header *);
};

#endif /* NEIGHBOUR_H */
