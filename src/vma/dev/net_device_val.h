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


#ifndef NET_DEVICE_VAL_H
#define NET_DEVICE_VAL_H


#include <string>
#include <vector>
#include <tr1/unordered_map>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vma/util/sys_vars.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/verbs_extra.h"
#include "vma/event/event_handler_ibverbs.h"
#include "vma/event/event_handler_rdma_cm.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/proto/neighbour_observer.h"
#include "vma/infra/cache_subject_observer.h"

typedef unsigned long int resource_allocation_key;
class L2_address;
class ring;
class neigh_ib_broadcast;

// each ring has a ref count
typedef std::tr1::unordered_map<resource_allocation_key, std::pair<ring*, int> > rings_hash_map_t;

typedef std::tr1::unordered_map<resource_allocation_key, std::pair<resource_allocation_key, int> > rings_key_redirection_hash_map_t;

#define THE_RING                        ring_iter->second.first
#define GET_THE_RING(key)               m_h_ring_map[key].first
#define RING_REF_CNT                    ring_iter->second.second
#define ADD_RING_REF_CNT        	RING_REF_CNT++
#define DEC_RING_REF_CNT	       	RING_REF_CNT--
#define TEST_REF_CNT_ZERO       	RING_REF_CNT==0


typedef struct {
        char* 		if_name;
        ib_ctx_handler* p_ib_ctx;
        int 		port_num;
        uint16_t	pkey;
        L2_address* 	p_L2_addr;
        bool 		is_active_slave;
} slave_data_t;

typedef std::vector<slave_data_t*> slave_data_vector_t;


/*
 * Represents Offloading capable device such as eth4, ib1, eth3.5, eth5:6
 */
class net_device_val
{
public:
	enum state {
		DOWN,
		UP,
		RUNNING,
		INVALID
	};
public:
	net_device_val(transport_type_t transport_type);
	/* on init:
	 *      get ibv, sys channel handlers from the relevant collections.
	 *      register to ibv_ctx, rdma_cm and sys_net_channel
	 *
	 * */
	virtual ~net_device_val();
	virtual void 		configure(struct ifaddrs* ifa, struct rdma_cm_id* cma_id);

	ring*                   reserve_ring(IN resource_allocation_key); // create if not exists
	bool 			release_ring(IN resource_allocation_key); // delete from hash if ref_cnt == 0
	state                   get_state() const  { return m_state; } // not sure, look at state init at c'tor
	virtual std::string     to_str();
	rdma_cm_id*		get_cma_id() { return m_cma_id; };
	int                     get_mtu() { return m_mtu; }
	int                     get_if_idx() { return m_if_idx; }
	transport_type_t        get_transport_type() const { return m_transport_type; }
	virtual bool            handle_event_rdma_cm(struct rdma_cm_event* p_event);
	bool 			handle_event_ADDR_CHANGE();
	in_addr_t               get_local_addr() {return m_local_addr;};
	in_addr_t               get_netmask() {return m_netmask;};
	bool                    is_valid() { return true; };
	int                     global_ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);
	int                     global_ring_request_notification(uint64_t poll_sn) ;
	int                     ring_drain_and_proccess();
	void			ring_adapt_cq_moderation();
	L2_address*		get_l2_address() { return m_p_L2_addr; };
	L2_address* 		get_br_address() { return m_p_br_addr; };

protected:
	int                     m_if_idx; // not unique: eth4 and eth4:5 has the same idx
	in_addr_t		m_local_addr;
	in_addr_t		m_netmask;
	int                     m_mtu;
	state			m_state;
	L2_address*		m_p_L2_addr;
	L2_address* 		m_p_br_addr;
	transport_type_t	m_transport_type;
	lock_mutex_recursive	m_lock;
	rings_hash_map_t        m_h_ring_map;
	rings_key_redirection_hash_map_t        m_h_ring_key_redirection_map;
        slave_data_vector_t	m_slaves;
	rdma_cm_id*             m_cma_id;
	std::string             m_name;

	virtual ring*		create_ring() = 0;
	virtual void		create_br_address(const char* ifname) = 0;
	virtual L2_address*	create_L2_address(const char* ifname) = 0;
	void 			delete_L2_address();

	resource_allocation_key ring_key_redirection_reserve(IN resource_allocation_key key);
	resource_allocation_key ring_key_redirection_release(IN resource_allocation_key key);
};

class net_device_val_eth : public net_device_val
{
public:
	net_device_val_eth() : net_device_val(VMA_TRANSPORT_ETH), m_vlan(0) {};
	virtual void 		configure(struct ifaddrs* ifa, struct rdma_cm_id* cma_id);
	uint16_t		get_vlan() {return m_vlan;}
	std::string		to_str();

protected:
	virtual ring*		create_ring();
	virtual L2_address*	create_L2_address(const char* ifname);
	virtual void		create_br_address(const char* ifname);

private:
	uint16_t		m_vlan;
};


class net_device_val_ib : public net_device_val,  public neigh_observer, public cache_observer
{
public:
	net_device_val_ib() : net_device_val(VMA_TRANSPORT_IB), m_pkey(0), m_br_neigh(NULL) {};
	~net_device_val_ib();

	virtual void 		configure(struct ifaddrs* ifa, struct rdma_cm_id* cma_id);
	std::string		to_str();
	const neigh_ib_broadcast* get_br_neigh() {return m_br_neigh;}
	virtual transport_type_t get_obs_transport_type() const {return get_transport_type();}

protected:
	ring*			create_ring();
	virtual L2_address*	create_L2_address(const char* ifname);
	virtual void		create_br_address(const char* ifname);

private:
	uint16_t		m_pkey;
	neigh_ib_broadcast*	m_br_neigh;
};


#endif
