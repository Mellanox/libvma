/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef SOCKINFO_H
#define SOCKINFO_H

#include <list>
#include <vector>
#include <tr1/unordered_map>
#include <netinet/in.h>

#include "config.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"

#include "vma/vma_extra.h"
#include "vma/util/chunk_list.h"
#include "vma/util/vma_stats.h"
#include "vma/util/sys_vars.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/dst_entry_udp.h"

#include "pkt_rcvr_sink.h"
#include "pkt_sndr_source.h"
#include "sock-redirect.h"
#include "sockinfo.h"

// Send flow dst_entry map
namespace std {
 namespace tr1 {
  template<>
   class hash<sock_addr>
   {
   public:
	size_t operator()(const sock_addr &key) const
	{
		sock_addr* tmp_key = (sock_addr*)&key;
		return tmp_key->hash();
	}
   };
 }
}
typedef std::tr1::unordered_map<sock_addr, dst_entry*> dst_entry_map_t;


struct mc_pending_pram
{
  struct in_addr imr_multiaddr;
  struct in_addr imr_interface;
  struct in_addr imr_sourceaddr;
  int optname;
};

// Multicast pending list
typedef std::list<struct mc_pending_pram> mc_pram_list_t;
typedef std::tr1::unordered_map<in_addr_t, std::tr1::unordered_map<in_addr_t, int> > mc_memberships_map_t;

/**
 * @class udp sockinfo
 * Represents an udp socket.
 */
class sockinfo_udp : public sockinfo
{
public:
	sockinfo_udp(int fd);
	virtual ~sockinfo_udp();

	void 	setPassthrough() { m_p_socket_stats->b_is_offloaded = m_sock_offload = false;}
	bool 	isPassthrough()  { return ! m_sock_offload;}

	int 	prepare_to_connect(const sockaddr *__to, socklen_t __tolen);

	int	bind(const struct sockaddr *__addr, socklen_t __addrlen);
	int	connect(const struct sockaddr *__to, socklen_t __tolen);
	int	getsockname(struct sockaddr *__name, socklen_t *__namelen);
	int	setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	int	getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen);

	inline void set_reuseaddr(bool reuseaddr) { m_reuseaddr = reuseaddr; }
	inline void set_reuseport(bool reuseport) { m_reuseport = reuseport; }
	virtual bool flow_in_reuse(void) { return m_reuseaddr | m_reuseport; }

	/**
	* Sampling the OS immediately by matching the rx_skip_os counter (m_rx_udp_poll_os_ratio_counter) to the limit (safe_mce_sys().rx_udp_poll_os_ratio)
	*/
	void	set_immediate_os_sample();
	/**
	 * Reseting rx_skip_os counter to prevent sampling OS immediately
	 */
	void	unset_immediate_os_sample();
	/**
	 * Process a Rx request, we might have a ready packet, or we might block until
	 * we have one (if sockinfo::m_b_blocking == true)
	 */
	ssize_t rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags, sockaddr *__from = NULL, socklen_t *__fromlen = NULL, struct msghdr *__msg = NULL);
	/**
	 * Check that a call to this sockinfo rx() will not block
	 * -> meaning, we got an offloaded ready rx datagram
	 * Return 'true' if would not block, 'false' if might block.
	 *
	 * While polling CQ, the fd_array is filled with a list of newly queued packets FD's
	 */
	bool is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_array = NULL);
	/**
	 * Arm the event channel(s) assosiated with this sockinfo
	 * Fill the fd_set (p_rxfds) with the correct fd channel values and the p_nfds with the (max_fd + 1)
	 * Fill the p_cq_mgr_fd_map with the pointer to the cq_mgr asosiated with the fd
	 * Return count of channels (fds) that where mapped
	 */
	int rx_request_notification(uint64_t poll_sn);
	/**
	 * Process a Tx request, handle all that is needed to send the packet, we might block
	 * until the connection info is ready or a tx buffer is releast (if sockinfo::m_b_blocking == true)
	 */
	ssize_t tx(const tx_call_t call_type, const iovec *p_iov, const ssize_t sz_iov, const int flags = 0, const struct sockaddr *__to = NULL, const socklen_t __tolen = 0);
	/**
	 * Check that a call to this sockinof rx() will not block
	 * -> meaning, we got a ready rx packet
	 */
	void rx_add_ring_cb(flow_tuple_with_local_if& flow_key, ring* p_ring, bool is_migration = false);
	void rx_del_ring_cb(flow_tuple_with_local_if& flow_key, ring* p_ring, bool is_migration = false);
	virtual int rx_verify_available_data();

	// This callback will handle ready rx packet notification from any ib_conn_mgr
	/**
	 *	Method sockinfo_udp::rx_process_packet run packet processor
	 *	with inspection, in case packet is OK, completion for SOCKETXTREME mode
	 *	will be filled or in other cases packet go to ready queue.
	 *	If packet to be discarded, packet ref. counter will not be
	 *	incremented and method returns false.
	 *	Normally it is single point from sockinfo to be called from ring level.
	 */
	inline bool rx_input_cb(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array)
	{
		return (this->*m_rx_packet_processor)(p_rx_wc_buf_desc, pv_fd_ready_array);
	}
	inline void set_rx_packet_processor(void);

	// This call will handle all rdma related events (bind->listen->connect_req->accept)
	virtual void statistics_print(vlog_levels_t log_level = VLOG_DEBUG);
	virtual	int free_packets(struct vma_packet_t *pkts, size_t count);
	virtual inline fd_type_t get_type()
	{
		return FD_TYPE_SOCKET;
	}

	virtual bool prepare_to_close(bool process_shutdown = false);
	virtual int get_socket_tx_ring_fd(struct sockaddr *to, socklen_t tolen);
	virtual void update_header_field(data_updater *updater);

private:

	struct port_socket_t {

		int port;
		int fd;

		bool operator== (const int& r_port)
		{
			return port == r_port;
		}
	};

/*	in_addr_t 	m_bound_if;
	in_port_t 	m_bound_port;
	in_addr_t 	m_connected_ip;
	in_port_t 	m_connected_port;
*/
	typedef bool (sockinfo_udp::* udp_rx_packet_processor_t)(mem_buf_desc_t* p_desc, void* pv_fd_ready_array);

	udp_rx_packet_processor_t	m_rx_packet_processor; // to inspect and process incoming packet

	in_addr_t 	m_mc_tx_if;
	bool 		m_b_mc_tx_loop;
	uint8_t 	m_n_mc_ttl;

	int32_t 	m_loops_to_go; // local param for polling loop on this socket
	uint32_t	m_rx_udp_poll_os_ratio_counter; 	// Data member which sets how many offloaded polls on the cq
							// we want to do before doing an OS poll, on this socket
	bool 		m_sock_offload;

	mc_pram_list_t 	m_pending_mreqs;
	mc_memberships_map_t m_mc_memberships_map;
	uint32_t	m_mc_num_grp_with_src_filter;

	lock_spin 	m_port_map_lock;
	std::vector<struct port_socket_t> m_port_map;
	unsigned 	m_port_map_index;

	dst_entry_map_t	m_dst_entry_map;
	dst_entry*	m_p_last_dst_entry;
	sock_addr	m_last_sock_addr;

	chunk_list_t<mem_buf_desc_t *>	m_rx_pkt_ready_list;

	uint8_t		m_tos;

	const uint32_t	m_n_sysvar_rx_poll_yield_loops;
	const uint32_t	m_n_sysvar_rx_udp_poll_os_ratio;
	const uint32_t	m_n_sysvar_rx_ready_byte_min_limit;
	const uint32_t	m_n_sysvar_rx_cq_drain_rate_nsec;
	const uint32_t	m_n_sysvar_rx_delta_tsc_between_cq_polls;

	bool		m_reuseaddr; // to track setsockopt with SO_REUSEADDR
	bool		m_reuseport; // to track setsockopt with SO_REUSEPORT
	bool		m_sockopt_mapped; // setsockopt IPPROTO_UDP UDP_MAP_ADD
	bool		m_is_connected; // to inspect for in_addr.src
	bool		m_multicast; // true when socket set MC rule

	int mc_change_membership(const mc_pending_pram *p_mc_pram);
	int mc_change_membership_start_helper(in_addr_t mc_grp, int optname);
	int mc_change_membership_end_helper(in_addr_t mc_grp, int optname, in_addr_t mc_src = 0);
	int mc_change_pending_mreq(const mc_pending_pram *p_mc_pram);
	int on_sockname_change(struct sockaddr *__name, socklen_t __namelen);
	void handle_pending_mreq();
	void original_os_setsockopt_helper( void* pram, int pram_size, int optname);
	/* helper functions */
	void 		set_blocking(bool is_blocked);

	void 		rx_ready_byte_count_limit_update(size_t n_rx_ready_bytes_limit); // Drop rx ready packets from head of queue

	void 		save_stats_threadid_rx(); // ThreadId will only saved if logger is at least in DEBUG(4) level
	void 		save_stats_threadid_tx(); // ThreadId will only saved if logger is at least in DEBUG(4) level

	void 		save_stats_tx_offload(int bytes, bool is_dummy);

	int 		rx_wait_helper(int &poll_count, bool is_blocking);
	
	inline int 	rx_wait(bool blocking);
	inline int 	poll_os();

	virtual inline void			reuse_buffer(mem_buf_desc_t *buff);
	virtual 	mem_buf_desc_t*	get_next_desc (mem_buf_desc_t *p_desc);
	virtual		mem_buf_desc_t* get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx);
	virtual		timestamps_t* get_socket_timestamps();
	virtual		void update_socket_timestamps(timestamps_t *) {};

    inline void return_reuse_buffers_postponed() {
	    if (!m_rx_reuse_buf_postponed)
		    return;

            //for the parallel reclaim mechanism from internal thread, used for "silent" sockets
	    set_rx_reuse_pending(false);

		m_rx_reuse_buf_postponed = false;

		rx_ring_map_t::iterator iter = m_rx_ring_map.begin();
		while (iter != m_rx_ring_map.end()) {
				descq_t *rx_reuse = &iter->second->rx_reuse_info.rx_reuse;
				int& n_buff_num = iter->second->rx_reuse_info.n_buff_num;
			if (n_buff_num >= m_n_sysvar_rx_num_buffs_reuse) {
				if (iter->first->reclaim_recv_buffers(rx_reuse)) {
					n_buff_num = 0;
				} else {
					m_rx_reuse_buf_postponed = true;
				}
			}
			++iter;
		}
    }

	inline bool	rx_process_udp_packet_full(mem_buf_desc_t* p_desc, void* pv_fd_ready_array);
	inline bool	rx_process_udp_packet_partial(mem_buf_desc_t* p_desc, void* pv_fd_ready_array);
	inline bool	inspect_uc_packet(mem_buf_desc_t* p_desc);
	inline bool	inspect_connected(mem_buf_desc_t* p_desc);
	inline bool	inspect_mc_packet(mem_buf_desc_t* p_desc);
	inline vma_recv_callback_retval_t inspect_by_user_cb(mem_buf_desc_t* p_desc);
	inline void	fill_completion(mem_buf_desc_t* p_desc);
	inline void	update_ready(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array, vma_recv_callback_retval_t cb_ret);

	virtual void 	post_deqeue (bool release_buff);
	virtual int 	zero_copy_rx (iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags);
	virtual size_t	handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags, int* p_out_flags);
	virtual void	handle_ip_pktinfo(struct cmsg_state *cm_state);

	virtual	mem_buf_desc_t* get_front_m_rx_pkt_ready_list();
	virtual	size_t get_size_m_rx_pkt_ready_list();
	virtual	void pop_front_m_rx_pkt_ready_list();
	virtual	void push_back_m_rx_pkt_ready_list(mem_buf_desc_t* buff);
};
#endif
