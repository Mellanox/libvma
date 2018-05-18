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


#ifndef NET_DEVICE_VAL_H
#define NET_DEVICE_VAL_H


#include <string>
#include <vector>
#include <tr1/unordered_map>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils/lock_wrapper.h"
#include "vma/util/sys_vars.h"
#include "vma/util/verbs_extra.h"
#include "vma/event/event_handler_ibverbs.h"
#include "vma/event/event_handler_rdma_cm.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/proto/neighbour_observer.h"
#include "vma/proto/L2_address.h"
#include "vma/infra/cache_subject_observer.h"


class L2_address;
class ring;
class neigh_ib_broadcast;

#define RING_ALLOC_STR_SIZE	256
class ring_alloc_logic_attr
{
public:
	ring_alloc_logic_attr();
	ring_alloc_logic_attr(ring_logic_t ring_logic);
	ring_alloc_logic_attr(const ring_alloc_logic_attr &other);
	void set_ring_alloc_logic(ring_logic_t logic);
	void set_ring_profile_key(vma_ring_profile_key profile);
	void set_user_id_key(uint64_t user_id_key);
	inline ring_logic_t get_ring_alloc_logic() { return m_ring_alloc_logic;}
	inline vma_ring_profile_key get_ring_profile_key() { return m_ring_profile_key;}
	inline uint64_t get_user_id_key() { return m_user_id_key;}

	bool operator==(const ring_alloc_logic_attr& other) const
	{
		return (m_ring_alloc_logic == other.m_ring_alloc_logic &&
			m_ring_profile_key == other.m_ring_profile_key &&
			m_user_id_key == other.m_user_id_key);
	}

	bool operator!=(const ring_alloc_logic_attr& other) const
	{
		return !(*this == other);
	}

	ring_alloc_logic_attr& operator=(const ring_alloc_logic_attr& other)
	{
		if (this != &other) {
			m_ring_alloc_logic = other.m_ring_alloc_logic;
			m_ring_profile_key = other.m_ring_profile_key;
			m_user_id_key = other.m_user_id_key;
			m_hash = other.m_hash;
			snprintf(m_str, RING_ALLOC_STR_SIZE, "%s", other.m_str);
		}
		return *this;
	}

	const char* to_str() const
	{

		return m_str;
	}

	size_t operator()(const ring_alloc_logic_attr *key) const
	{
		return key->m_hash;
	}

	bool operator()(const ring_alloc_logic_attr *k1, const ring_alloc_logic_attr *k2) const
	{
		return *k1 == *k2;
	}
private:
	size_t			m_hash;
	/* ring allocation logic , per thread per fd ... */
	ring_logic_t		m_ring_alloc_logic;
	/* key in g_p_ring_profile */
	vma_ring_profile_key	m_ring_profile_key;
	/* either user_idx or key as defined in ring_logic_t */
	uint64_t		m_user_id_key;
	char			m_str[RING_ALLOC_STR_SIZE];
	void			init();
};

typedef ring_alloc_logic_attr resource_allocation_key;
// each ring has a ref count
typedef std::tr1::unordered_map<resource_allocation_key *, std::pair<ring*, int>, ring_alloc_logic_attr, ring_alloc_logic_attr> rings_hash_map_t;

typedef std::tr1::unordered_map<resource_allocation_key *, std::pair<resource_allocation_key *, int> ,ring_alloc_logic_attr, ring_alloc_logic_attr> rings_key_redirection_hash_map_t;

#define THE_RING                        ring_iter->second.first
#define GET_THE_RING(key)               m_h_ring_map[key].first
#define RING_REF_CNT                    ring_iter->second.second
#define ADD_RING_REF_CNT        	RING_REF_CNT++
#define DEC_RING_REF_CNT	       	RING_REF_CNT--
#define TEST_REF_CNT_ZERO       	RING_REF_CNT==0

#define MAX_SLAVES 16

typedef struct slave_data {
        int         if_index;
        ib_ctx_handler* p_ib_ctx;
        int 		port_num;
        L2_address* 	p_L2_addr;
        bool 		active;
	slave_data(int _if_index) :
		if_index(_if_index), p_ib_ctx(NULL), port_num(-1), p_L2_addr(NULL), active(false) {}
	~slave_data() {
		delete p_L2_addr;
		p_L2_addr = NULL;
	}
} slave_data_t;

typedef std::vector<slave_data_t*> slave_data_vector_t;

typedef struct ip_data {
	int       flags;
	in_addr_t local_addr;
	in_addr_t netmask;
	ip_data() {
		flags = 0;
		local_addr = 0;
		netmask = 0;
	}
	~ip_data() {
		flags = 0;
		local_addr = 0;
		netmask = 0;
	}
} ip_data_t;

typedef std::vector<ip_data_t*> ip_data_vector_t;


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
	enum bond_type {
		NO_BOND,
		ACTIVE_BACKUP,
		LAG_8023ad,
		NETVSC
	};
	enum bond_xmit_hash_policy {
		XHP_LAYER_2,
		XHP_LAYER_3_4,
		XHP_LAYER_2_3,
		XHP_ENCAP_2_3,
		XHP_ENCAP_3_4
	};
	struct net_device_val_desc {
		struct nlmsghdr *nl_msg;
	};
public:

	net_device_val(struct net_device_val_desc *desc);
	/* on init:
	 *      get ibv, sys channel handlers from the relevant collections.
	 *      register to ibv_ctx, rdma_cm and sys_net_channel
	 *
	 * */
	virtual ~net_device_val();

	inline void set_type(int type) { m_type = type; }
	inline void set_if_idx(int if_idx) { m_if_idx = if_idx; }
	inline void set_flags(int flags) { m_flags = flags; }
	inline void set_mtu(int mtu) { m_mtu = mtu; }
	inline void set_if_link(int if_link) { m_if_link = if_link; }
	inline void set_ifname(char *ifname) {
		m_name = ifname;
		get_base_interface_name(ifname, m_base_name, sizeof(m_base_name));
	}
	inline void set_l2_if_addr(uint8_t *addr, size_t size) {
		memcpy(m_l2_if_addr, addr, std::min(sizeof(m_l2_if_addr), size));
	}
	inline void set_l2_bc_addr(uint8_t *addr, size_t size) {
		memcpy(m_l2_bc_addr, addr, std::min(sizeof(m_l2_bc_addr), size));
	}
	void set_ip_array();

	inline int get_type() { return m_type; }
	inline int get_if_idx() { return m_if_idx; }
	inline int get_flags() { return m_flags; }
	inline int get_mtu() { return m_mtu; }
	inline int get_if_link() { return m_if_link; }
	inline char* get_ifname() { return (char *)m_name.c_str(); }
	inline char* get_ifname_link() { return m_base_name; }
	inline uint8_t* get_l2_if_addr() { return m_l2_if_addr; }
	inline uint8_t* get_l2_bc_addr() { return m_l2_bc_addr; }
	const ip_data_vector_t& get_ip_array() const { return m_ip; }
	const slave_data_vector_t& get_slave_array() const { return m_slaves; }
	const slave_data_t* get_slave(int if_index);

	void set_str();
	void print_val();

	inline int get_tap_if_index() { return m_netvsc.tap_if_index; }
	inline int get_tap_fd() { return m_netvsc.tap_fd; }

	ring*                   reserve_ring(resource_allocation_key*); // create if not exists
	bool 			release_ring(resource_allocation_key*); // delete from m_hash if ref_cnt == 0
	state                   get_state() const  { return m_state; } // not sure, look at state init at c'tor
	virtual std::string     to_str();
	inline void set_transport_type(transport_type_t value) { m_transport_type = value; }
	transport_type_t        get_transport_type() const { return m_transport_type; }
	bool 			update_active_backup_slaves();
	in_addr_t               get_local_addr() { return m_ip[0]->local_addr; } // Valid object must have at least one address
	int                     global_ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);
	int                     global_ring_request_notification(uint64_t poll_sn) ;
	int                     ring_drain_and_proccess();
	void			ring_adapt_cq_moderation();
	L2_address*		get_l2_address() { return m_p_L2_addr; };
	L2_address* 		get_br_address() { return m_p_br_addr; };
	inline bond_type  get_is_bond() { return m_bond; }
	inline bond_xmit_hash_policy get_bond_xmit_hash_policy() { return m_bond_xmit_hash_policy; }
	bool 			update_active_slaves();
	bool 			update_netvsc_slaves();
	void 			register_to_ibverbs_events(event_handler_ibverbs *handler);
	void 			unregister_to_ibverbs_events(event_handler_ibverbs *handler);

protected:

	void set_slave_array();
	virtual ring*		create_ring(resource_allocation_key *key) = 0;
	virtual void		create_br_address(const char* ifname) = 0;
	virtual L2_address*	create_L2_address(const char* ifname) = 0;

	L2_address*		m_p_L2_addr;
	L2_address* 		m_p_br_addr;
	transport_type_t	m_transport_type;
	lock_mutex_recursive	m_lock;
	rings_hash_map_t        m_h_ring_map;
	rings_key_redirection_hash_map_t        m_h_ring_key_redirection_map;

	state            m_state;          /* device current state */
	bond_type        m_bond;           /* type of the device as simple, bond, etc */
	slave_data_vector_t	m_slaves;      /* array of slaves */
	int              m_if_active;      /* ifindex of active slave (only for active-backup) */
	bond_xmit_hash_policy m_bond_xmit_hash_policy;
	int m_bond_fail_over_mac;

private:
	bool 			verify_ipoib_mode();
	void 			verify_bonding_mode();
	bool 			verify_eth_qp_creation(const char* ifname);
	bool 			verify_bond_ipoib_or_eth_qp_creation();
	bool 			verify_ipoib_or_eth_qp_creation(const char* interface_name);
	bool 			verify_enable_ipoib(const char* ifname);

	resource_allocation_key* ring_key_redirection_reserve(resource_allocation_key *key);
	resource_allocation_key* ring_key_redirection_release(resource_allocation_key *key);

	bool get_up_and_active_slaves(bool* up_and_active_slaves, size_t size);
	int netvsc_create();
	void netvsc_destroy();

	/* See: RFC 3549 2.3.3.1. */
	int              m_if_idx;         /* Uniquely identifies interface (not unique: eth4 and eth4:5 has the same idx) */
	int              m_type;           /* This defines the type of the link. */
	int              m_flags;          /* Device Flags (IFF_x).  */
	int              m_mtu;            /* MTU of the device. */
	int              m_if_link;        /* ifindex of link to which this device is bound */
	uint8_t          m_l2_if_addr[20]; /* hardware L2 interface address */
	uint8_t          m_l2_bc_addr[20]; /* hardware L2 broadcast address */

	/* See: RFC 3549 2.3.3.2. */
	ip_data_vector_t m_ip;             /* vector of ip addresses */

	std::string      m_name;           /* container for ifname */
	char             m_str[BUFF_SIZE]; /* detailed information about device */
	char             m_base_name[IFNAMSIZ]; /* base name of device basing ifname */

	/* These fields are NETVSC mode specific */
	struct {
		int tap_if_index;              /* if_index of tap device */
		int tap_fd;                    /* file descriptor of tap device */
	} m_netvsc;
};

class net_device_val_eth : public net_device_val
{
public:
	net_device_val_eth(struct net_device_val_desc *desc) : net_device_val(desc), m_vlan(0) {
		set_transport_type(VMA_TRANSPORT_ETH);
		if (INVALID != get_state()) {
			set_slave_array();
			configure();
		}
	}
	uint16_t		get_vlan() {return m_vlan;}
	std::string		to_str();

protected:
	virtual ring*		create_ring(resource_allocation_key *key);

private:
	void			configure();
	L2_address*		create_L2_address(const char* ifname);
	void			create_br_address(const char* ifname);
	uint16_t		m_vlan;
};


class net_device_val_ib : public net_device_val,  public neigh_observer, public cache_observer
{
public:
	net_device_val_ib(struct net_device_val_desc *desc) : net_device_val(desc), m_pkey(0), m_br_neigh(NULL) {
		set_transport_type(VMA_TRANSPORT_IB);
		if (INVALID != get_state()) {
			set_slave_array();
			configure();
		}
	}
	~net_device_val_ib();

	std::string		to_str();
	uint16_t		get_pkey() { return m_pkey; }
	const neigh_ib_broadcast* get_br_neigh() {return m_br_neigh;}
	virtual transport_type_t get_obs_transport_type() const {return get_transport_type();}

protected:
	ring*			create_ring(resource_allocation_key *key);

private:
	void			configure();
	L2_address*		create_L2_address(const char* ifname);
	void			create_br_address(const char* ifname);
	uint16_t		m_pkey;
	neigh_ib_broadcast*	m_br_neigh;
};


#endif
