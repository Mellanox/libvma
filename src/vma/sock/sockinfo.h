/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <unordered_map>
#include <ifaddrs.h>

#include "config.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "vma/vma_extra.h"
#include "vma/util/data_updater.h"
#include "vma/util/sock_addr.h"
#include "vma/util/vma_stats.h"
#include "vma/util/sys_vars.h"
#include "vma/util/wakeup_pipe.h"
#include "vma/proto/flow_tuple.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/dst_entry.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/dev/ring_simple.h"
#include "vma/dev/ring_allocation_logic.h"

#include "socket_fd_api.h"
#include "pkt_rcvr_sink.h"
#include "pkt_sndr_source.h"
#include "sock-redirect.h"

#ifndef BASE_SOCKINFO_H
#define BASE_SOCKINFO_H

#define SI_RX_EPFD_EVENT_MAX		16
#define BYTE_TO_KB(byte_value)		((byte_value) / 125)
#define KB_TO_BYTE(kbit_value)		((kbit_value) * 125)

#if DEFINED_MISSING_NET_TSTAMP
enum {
	SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
	SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
	SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
	SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
	SOF_TIMESTAMPING_SOFTWARE = (1<<4),
	SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
	SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
	SOF_TIMESTAMPING_MASK =
			(SOF_TIMESTAMPING_RAW_HARDWARE - 1) |
			SOF_TIMESTAMPING_RAW_HARDWARE
};
#else
#include <linux/net_tstamp.h>
#endif

#ifndef SO_TIMESTAMPNS
#define SO_TIMESTAMPNS		35
#endif

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING		37
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT		15
#endif

struct cmsg_state
{
	struct msghdr	*mhdr;
	struct cmsghdr	*cmhdr;
	size_t		cmsg_bytes_consumed;
};

#define NOTIFY_ON_EVENTS(context, events) context->set_events(events)

struct buff_info_t {
		buff_info_t(){
			rx_reuse.set_id("buff_info_t (%p) : rx_reuse", this);
			n_buff_num = 0;
		}

       int     n_buff_num;
       descq_t     rx_reuse;
};

typedef struct {
	net_device_entry* 	p_nde;
	net_device_val* 	p_ndv;
	ring* 			p_ring;
	int 			refcnt;
} net_device_resources_t;

typedef std::unordered_map<in_addr_t, net_device_resources_t> rx_net_device_map_t;

/*
 * Sockinfo setsockopt() return values
 */
#define	SOCKOPT_INTERNAL_VMA_SUPPORT  0    // Internal socket option, should not pass request to OS.
#define	SOCKOPT_NO_VMA_SUPPORT       -1    // Socket option was found but not supported, error should be returned to user.
#define	SOCKOPT_PASS_TO_OS            1	   // Should pass to TCP/UDP level or OS.

namespace std {
template<>
class hash<flow_tuple_with_local_if>
{
public:
	size_t operator()(const flow_tuple_with_local_if &key) const
	{
		flow_tuple_with_local_if* tmp_key = (flow_tuple_with_local_if*)&key;
		return tmp_key->hash();
	}
};
}
typedef std::unordered_map<flow_tuple_with_local_if, ring*> rx_flow_map_t;

typedef struct {
	int 			refcnt;
	buff_info_t 		rx_reuse_info;
} ring_info_t;

typedef std::unordered_map<ring*, ring_info_t*> rx_ring_map_t;

// see route.c in Linux kernel
const uint8_t ip_tos2prio[16] = {
	0, 0, 0, 0,
	2, 2, 2, 2,
	6, 6, 6, 6,
	4, 4, 4, 4
};

class sockinfo : public socket_fd_api, public pkt_rcvr_sink, public pkt_sndr_source, public wakeup_pipe
{
public:
	sockinfo(int fd);
	virtual ~sockinfo();

	enum sockinfo_state {
		SOCKINFO_OPENED,
		SOCKINFO_CLOSING,
		SOCKINFO_CLOSED
	};

	virtual void consider_rings_migration();

	virtual int add_epoll_context(epfd_info *epfd);
	virtual void remove_epoll_context(epfd_info *epfd);

	inline bool set_flow_tag(uint32_t flow_tag_id) {
		if (flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
			m_flow_tag_id = flow_tag_id;
			m_flow_tag_enabled = true;
			return true;
		}
		m_flow_tag_id = FLOW_TAG_MASK;
		return false;
	}
	inline bool flow_tag_enabled(void) { return m_flow_tag_enabled; }
	inline int get_rx_epfd(void) { return m_rx_epfd; }
	
	virtual bool flow_in_reuse(void) { return false;};
	virtual int* get_rings_fds(int &res_length);
	virtual int get_rings_num();
	virtual int get_socket_network_ptr(void *ptr, uint16_t &len);
	virtual bool check_rings() {return m_p_rx_ring ? true: false;}
	virtual void statistics_print(vlog_levels_t log_level = VLOG_DEBUG);
	uint32_t get_flow_tag_val() { return m_flow_tag_id; }
	inline in_protocol_t get_protocol(void) { return m_protocol; }

private:
	int				fcntl_helper(int __cmd, unsigned long int __arg, bool& bexit);

protected:
	bool 			m_b_blocking;
	bool 			m_b_pktinfo;
	bool 			m_b_rcvtstamp;
	bool 			m_b_rcvtstampns;
	uint8_t 		m_n_tsing_flags;
	in_protocol_t		m_protocol;

	lock_spin_recursive	m_lock_rcv;
	lock_mutex		m_lock_snd;
	lock_mutex		m_rx_migration_lock;

	sockinfo_state		m_state; // socket current state
	sock_addr 		m_bound;
	sock_addr 		m_connected;
	dst_entry*		m_p_connected_dst_entry;

	in_addr_t 		m_so_bindtodevice_ip;

	socket_stats_t		m_socket_stats;
	socket_stats_t*		m_p_socket_stats;

	int			m_rx_epfd;
	cache_observer 		m_rx_nd_observer;
	rx_net_device_map_t	m_rx_nd_map;
	rx_flow_map_t		m_rx_flow_map;
	// we either listen on ALL system cqs or bound to the specific cq
	ring*			m_p_rx_ring; //used in TCP/UDP
	buff_info_t		m_rx_reuse_buff; //used in TCP instead of m_rx_ring_map
	bool			m_rx_reuse_buf_pending; //used to periodically return buffers, even if threshold was not reached
	bool			m_rx_reuse_buf_postponed; //used to mark threshold was reached, but free was not done yet
	inline void		set_rx_reuse_pending(bool is_pending = true) {m_rx_reuse_buf_pending = is_pending;}

	rx_ring_map_t		m_rx_ring_map; // CQ map
	lock_mutex_recursive	m_rx_ring_map_lock;
	ring_allocation_logic_rx m_ring_alloc_logic;

	loops_timer             m_loops_timer;

	/**
	 * list of pending ready packet on the Rx,
	 * each element is a pointer to the ib_conn_mgr that holds this ready rx datagram
	 */
	int						m_n_rx_pkt_ready_list_count;
	size_t 					m_rx_pkt_ready_offset;
	size_t					m_rx_ready_byte_count;

	const int				m_n_sysvar_rx_num_buffs_reuse;
	const int32_t				m_n_sysvar_rx_poll_num;
	ring_alloc_logic_attr			m_ring_alloc_log_rx;
	ring_alloc_logic_attr			m_ring_alloc_log_tx;
	uint32_t				m_pcp;

	struct {
		/* Track internal events to return in socketxtreme_poll()
		 * Current design support single event for socket at a particular time
		 */
		struct ring_ec ec;
		struct vma_completion_t* completion;
		struct vma_buff_t*       last_buff_lst;
	} m_socketxtreme;

	// Callback function pointer to support VMA extra API (vma_extra.h)
	vma_recv_callback_t	m_rx_callback;
	void*			m_rx_callback_context; // user context
	struct vma_rate_limit_t m_so_ratelimit;
	void*			m_fd_context; // Context data stored with socket
	uint32_t		m_flow_tag_id;	// Flow Tag for this socket
	bool			m_flow_tag_enabled; // for this socket
	uint8_t			m_n_uc_ttl; // time to live

	int*			m_p_rings_fds;
	virtual void 		set_blocking(bool is_blocked);
	virtual int 		fcntl(int __cmd, unsigned long int __arg);
	virtual int 		fcntl64(int __cmd, unsigned long int __arg);
	virtual int 		ioctl(unsigned long int __request, unsigned long int __arg);
	virtual int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	int setsockopt_kernel(int __level, int __optname, const void *__optval, socklen_t __optlen, int supported, bool allow_priv);
	virtual int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen);

	virtual	mem_buf_desc_t* get_front_m_rx_pkt_ready_list() = 0;
	virtual	size_t get_size_m_rx_pkt_ready_list() = 0;
	virtual	void pop_front_m_rx_pkt_ready_list() = 0;
	virtual	void push_back_m_rx_pkt_ready_list(mem_buf_desc_t* buff) = 0;

	void 			save_stats_rx_os(int bytes);
	void 			save_stats_tx_os(int bytes);
	void 			save_stats_rx_offload(int nbytes);

	virtual int             rx_verify_available_data() = 0;
	virtual void            update_header_field(data_updater *updater) = 0;
	virtual mem_buf_desc_t *get_next_desc (mem_buf_desc_t *p_desc) = 0;
	virtual	mem_buf_desc_t* get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx) = 0;
	virtual timestamps_t* get_socket_timestamps() = 0;
	virtual void          update_socket_timestamps(timestamps_t * ts) = 0;
	virtual void 	post_deqeue (bool release_buff) = 0;
	
	virtual int 	zero_copy_rx (iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags) = 0;
	int 			register_callback(vma_recv_callback_t callback, void *context);

	virtual size_t		handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags, int* p_out_flags);

	bool 			attach_receiver(flow_tuple_with_local_if &flow_key);
	bool 			detach_receiver(flow_tuple_with_local_if &flow_key);
	net_device_resources_t* create_nd_resources(const ip_address ip_local);
	bool                    destroy_nd_resources(const ip_address ip_local);
	void			do_rings_migration(resource_allocation_key &old_key);
	int			set_ring_attr(vma_ring_alloc_logic_attr *attr);
	int			set_ring_attr_helper(ring_alloc_logic_attr *sock_attr, vma_ring_alloc_logic_attr *attr);

	// Attach to all relevant rings for offloading receive flows - always used from slow path
	// According to bounded information we need to attach to all UC relevant flows
	// If local_ip is ANY then we need to attach to all offloaded interfaces OR to the one our connected_ip is routed to
	bool			attach_as_uc_receiver(role_t role, bool skip_rules = false);
	transport_t 		find_target_family(role_t role, struct sockaddr *sock_addr_first, struct sockaddr *sock_addr_second = NULL);

	// This callback will notify that socket is ready to receive and map the cq.
	virtual void		rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring);
	virtual void 		rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring);

	virtual void		lock_rx_q() {m_lock_rcv.lock();}
	virtual void		unlock_rx_q() {m_lock_rcv.unlock();}

	void			shutdown_rx();
	void 			destructor_helper();
	int 			modify_ratelimit(dst_entry* p_dst_entry, struct vma_rate_limit_t &rate_limit);

	void            move_descs(ring* p_ring, descq_t *toq, descq_t *fromq, bool own);
	void            pop_descs_rx_ready(descq_t *cache, ring* p_ring = NULL);
	void            push_descs_rx_ready(descq_t *cache);
	void            reuse_descs(descq_t *reuseq, ring* p_ring = NULL);
	int			set_sockopt_prio(__const void *__optval, socklen_t __optlen);

	virtual void    handle_ip_pktinfo(struct cmsg_state *cm_state) = 0;
	inline  void    handle_recv_timestamping(struct cmsg_state *cm_state);
	void            insert_cmsg(struct cmsg_state *cm_state, int level, int type, void *data, int len);
	void            handle_cmsg(struct msghdr * msg);
	void            process_timestamps(mem_buf_desc_t* p_desc);

	virtual bool try_un_offloading(); // un-offload the socket if possible

	virtual inline void do_wakeup()	{
		if (!is_socketxtreme()) {
			wakeup_pipe::do_wakeup();
		}
	}

	inline bool is_socketxtreme() {
		return (m_p_rx_ring && m_p_rx_ring->is_socketxtreme());
	}

	inline void set_events(uint64_t events) {
		static int enable_socketxtreme = safe_mce_sys().enable_socketxtreme;

		if (enable_socketxtreme && m_state == SOCKINFO_OPENED) {
			/* Collect all events if rx ring is enabled */
			if (is_socketxtreme()) {
				if (m_socketxtreme.completion) {
					if (!m_socketxtreme.completion->events) {
						m_socketxtreme.completion->user_data = (uint64_t)m_fd_context;
					}
					m_socketxtreme.completion->events |= events;
				}
				else {
					if (!m_socketxtreme.ec.completion.events) {
					m_socketxtreme.ec.completion.user_data = (uint64_t)m_fd_context;
					m_p_rx_ring->put_ec(&m_socketxtreme.ec);
					}
					m_socketxtreme.ec.completion.events |= events;
				}
			}
		}

		socket_fd_api::notify_epoll_context((uint32_t)events);
	}

	// This function validates the ipoib's properties
	// Input params:
	// 	1. IF name (can be alias)
	//	2. IF flags
	//	3. general path to ipoib property file (for example: /sys/class/net/%s/mtu)
	//	4. the expected value of the property
	//	5. size of the property
	// Output params:
	//	1. property sysfs filename
	//	2. physical IF name (stripped alias)
	// Return Value
	// Type: INT
	// Val:  -1 Reading from the sys file failed
	// 	 1 Reading succeeded but the actual prop value != expected
	//	 0 Reading succeeded and acutal ptop value == expected one
	//TODO need to copy this function from util
	//int validate_ipoib_prop(char* ifname, unsigned int ifflags, const char param_file[], const char *val, int size, char *filename, char * base_ifname);

	inline void fetch_peer_info(sockaddr_in *p_peer_addr, sockaddr_in *__from, socklen_t *__fromlen)
	{
		*__from = *p_peer_addr;
		*__fromlen = sizeof(sockaddr_in);
	}

	inline int dequeue_packet(iovec *p_iov, ssize_t sz_iov,
		                  sockaddr_in *__from, socklen_t *__fromlen,
		                  int in_flags, int *p_out_flags)
	{
		mem_buf_desc_t *pdesc;
		int total_rx = 0;
		uint32_t nbytes, pos;
		bool relase_buff = true;

		bool is_peek = in_flags & MSG_PEEK;
		int rx_pkt_ready_list_idx = 1;
		int rx_pkt_ready_offset = m_rx_pkt_ready_offset;

		pdesc = get_front_m_rx_pkt_ready_list();
		void *iov_base = (uint8_t*)pdesc->rx.frag.iov_base + m_rx_pkt_ready_offset;
		size_t bytes_left = pdesc->rx.frag.iov_len - m_rx_pkt_ready_offset;
		size_t payload_size = pdesc->rx.sz_payload;

		if (__from && __fromlen)
			fetch_peer_info(&pdesc->rx.src, __from, __fromlen);

		if (in_flags & MSG_VMA_ZCOPY) {
			relase_buff = false;
			total_rx = zero_copy_rx(p_iov, pdesc, p_out_flags);
			if (unlikely(total_rx < 0))
				return -1;
			m_rx_pkt_ready_offset = 0;	
		}
		else {
			for (int i = 0; i < sz_iov && pdesc; i++) {
				pos = 0;
				while (pos < p_iov[i].iov_len && pdesc) {
					nbytes = p_iov[i].iov_len - pos;
					if (nbytes > bytes_left) nbytes = bytes_left;
					memcpy((char *)(p_iov[i].iov_base) + pos, iov_base, nbytes);
					pos += nbytes;
					total_rx += nbytes;
					m_rx_pkt_ready_offset += nbytes;
					bytes_left -= nbytes;
					iov_base = (uint8_t*)iov_base + nbytes;
					if (m_b_rcvtstamp || m_n_tsing_flags) update_socket_timestamps(&pdesc->rx.timestamps);
					if(bytes_left <= 0) {
						if (unlikely(is_peek)) {
							pdesc = get_next_desc_peek(pdesc, rx_pkt_ready_list_idx);
						} else {
							pdesc = get_next_desc(pdesc);
						}
						m_rx_pkt_ready_offset = 0;
						if (pdesc) {
							iov_base = pdesc->rx.frag.iov_base;
							bytes_left = pdesc->rx.frag.iov_len;
						}
					}

				}
			}

		}

		if (unlikely(is_peek)) {
			m_rx_pkt_ready_offset = rx_pkt_ready_offset; //if MSG_PEEK is on, m_rx_pkt_ready_offset must be zero-ed
			//save_stats_rx_offload(total_rx); //TODO??
		}
		else {
			m_rx_ready_byte_count -= total_rx;
			m_p_socket_stats->n_rx_ready_byte_count -= total_rx;
			post_deqeue(relase_buff);
			save_stats_rx_offload(total_rx);
		}

		total_rx = handle_msg_trunc(total_rx, payload_size, in_flags, p_out_flags);

        return total_rx;
    }

    inline void reuse_buffer(mem_buf_desc_t *buff)
    {
    	set_rx_reuse_pending(false);
    	ring* p_ring = buff->p_desc_owner->get_parent();
    	rx_ring_map_t::iterator iter = m_rx_ring_map.find(p_ring);
    	if(likely(iter != m_rx_ring_map.end())){
            descq_t *rx_reuse = &iter->second->rx_reuse_info.rx_reuse;
            int& n_buff_num = iter->second->rx_reuse_info.n_buff_num;
            rx_reuse->push_back(buff);
            n_buff_num += buff->rx.n_frags;
            if(n_buff_num < m_n_sysvar_rx_num_buffs_reuse){
        	    return;
            }
            if(n_buff_num >= 2 * m_n_sysvar_rx_num_buffs_reuse){
                if (p_ring->reclaim_recv_buffers(rx_reuse)) {
                    n_buff_num = 0;
                } else {
                	g_buffer_pool_rx->put_buffers_after_deref_thread_safe(rx_reuse);
                	n_buff_num = 0;
                }
                m_rx_reuse_buf_postponed = false;
            } else {
                m_rx_reuse_buf_postponed = true;
            }
        }
        else{
            // Retuned buffer to global pool when owner can't be found
            // In case ring was deleted while buffers where still queued
            vlog_printf(VLOG_DEBUG, "Buffer owner not found\n");
            // Awareness: these are best efforts: decRef without lock in case no CQ
            if(buff->dec_ref_count() <= 1 && (buff->lwip_pbuf.pbuf.ref-- <= 1))
                g_buffer_pool_rx->put_buffers_thread_safe(buff);

        }
    }

    static const char * setsockopt_so_opt_to_str(int opt)
    {
    	switch (opt) {
    	case SO_REUSEADDR: 		return "SO_REUSEADDR";
    	case SO_REUSEPORT: 		return "SO_REUSEPORT";
    	case SO_BROADCAST:	 	return "SO_BROADCAST";
    	case SO_RCVBUF:			return "SO_RCVBUF";
    	case SO_SNDBUF:			return "SO_SNDBUF";
    	case SO_TIMESTAMP:		return "SO_TIMESTAMP";
    	case SO_TIMESTAMPNS:		return "SO_TIMESTAMPNS";
    	case SO_BINDTODEVICE:		return "SO_BINDTODEVICE";
    	case SO_VMA_RING_ALLOC_LOGIC:	return "SO_VMA_RING_ALLOC_LOGIC";
    	case SO_MAX_PACING_RATE:	return "SO_MAX_PACING_RATE";
    	case SO_VMA_FLOW_TAG:           return "SO_VMA_FLOW_TAG";
    	case SO_VMA_SHUTDOWN_RX:        return "SO_VMA_SHUTDOWN_RX";
    	default:			break;
    	}
    	return "UNKNOWN SO opt";
    }

    int			get_sock_by_L3_L4(in_protocol_t protocol, in_addr_t ip, in_port_t  port);

    //////////////////////////////////////////////////////////////////
    int handle_exception_flow(){
		if (safe_mce_sys().exception_handling.is_suit_un_offloading()) {
			try_un_offloading();
		}
		if (safe_mce_sys().exception_handling == vma_exception_handling::MODE_RETURN_ERROR) {
			errno = EINVAL;
			return -1;
		}
		if (safe_mce_sys().exception_handling == vma_exception_handling::MODE_ABORT) {
			return -2;
		}
		return 0;
    }
    //////////////////////////////////////////////////////////////////
};

#endif /* BASE_SOCKINFO_H */
