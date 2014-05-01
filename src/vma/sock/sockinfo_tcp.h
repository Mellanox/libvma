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


#ifndef TCP_SOCKINFO_H
#define TCP_SOCKINFO_H

#include <list>
#include <deque>

#include "vma/util/lock_wrapper.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/dev/buffer_pool.h"
#include "vma/dev/cq_mgr.h"

// LWIP includes
#include <lwip/opt.h>
#include <lwip/init.h>
#include <lwip/sys.h>
#include <lwip/tcp_impl.h>
#include <netif/etharp.h>
#include <lwip/stats.h>
#include <lwip/tcp.h>

#include "sockinfo.h"

/**
 * Tcp socket states: rdma_offload or os_passthrough. in rdma_offload:
 * init --/bind()/ --> bound -- /listen()/ --> accept_ready -- /accept()may go to connected/ --> connected
 * init --(optional: bind()/ -- /connect()|async_connect/--> connected --/close()/--> init
 * may need to handle bind before connect in the future
 */
enum tcp_sock_offload_e {
	TCP_SOCK_PASSTHROUGH = 1, // OS handling this socket connection
//	TCP_SOCK_RDMA_CM,         // Offloaded, uses RDMA CM - SDP like connection
	TCP_SOCK_LWIP             // Offloaded, uses LWIP for wire compatible TCP impl
};

enum tcp_sock_state_e {
	TCP_SOCK_INITED = 1,
	TCP_SOCK_BOUND,
	TCP_SOCK_LISTEN_READY,    // internal state that indicate that prepareListen was called
	TCP_SOCK_ACCEPT_READY,
	TCP_SOCK_CONNECTED_RD,    // ready to rcv
	TCP_SOCK_CONNECTED_WR,    // ready to send
	TCP_SOCK_CONNECTED_RDWR,  // full duplex op
	TCP_SOCK_ASYNC_CONNECT,   // async connect in progress
	TCP_SOCK_ACCEPT_SHUT      // after shutdown on TCP_SOCK_ACCEPT_READY socket
};

/**
 * state machine for the connect() side connection establishment. Taken from VMS
 */
enum tcp_conn_state_e {
	TCP_CONN_INIT = 0,
	TCP_CONN_CONNECTING,
	TCP_CONN_CONNECTED,
	TCP_CONN_FAILED,
	TCP_CONN_TIMEOUT,
	TCP_CONN_ERROR,
	TCP_CONN_RESETED
};

class sockinfo_tcp;

typedef std::map<flow_tuple, tcp_pcb*>	syn_received_map_t;
typedef std::deque<sockinfo_tcp*>	accepted_conns_deque_t;

class sockinfo_tcp : public sockinfo, public timer_handler
{
public:
	sockinfo_tcp(int fd);
	virtual ~sockinfo_tcp();

	virtual void clean_obj();

	void setPassthrough() {m_sock_offload = TCP_SOCK_PASSTHROUGH;}
	bool isPassthrough()  {return m_sock_offload == TCP_SOCK_PASSTHROUGH;}

	int prepareConnect(const sockaddr *__to, socklen_t __tolen);
	int prepareListen();
	int shutdown(int __how);

	//Not always we can close immediately TCP socket: we can do that only after the TCP connection in closed.
	//In this method we just kikstarting the TCP connection termination (empty the unsent/unacked, senf FIN...)
	//Return val: true is the socket is already closable and false otherwise
	virtual bool prepare_to_close(bool process_shutdown = false);
	virtual void force_close();
	void create_dst_entry();
	bool prepare_dst_to_send(bool is_accepted_socket = false);

	virtual int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	virtual int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen);
	virtual int connect(const sockaddr*, socklen_t);
	virtual int bind(const sockaddr *__addr, socklen_t __addrlen);
	virtual int listen(int backlog);
	virtual int accept(struct sockaddr *__addr, socklen_t *__addrlen);
	virtual int accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags);
	virtual int getsockname(sockaddr *__name, socklen_t *__namelen);
	virtual int getpeername(sockaddr *__name, socklen_t *__namelen);

	//Returns the connected pcb, with 5 tuple which matches the input arguments,
	//in state "SYN Received" or NULL if pcb wasn't found

	struct tcp_pcb* get_syn_received_pcb(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port);

	ssize_t tx(const tx_call_t call_type, const struct iovec *p_iov, const ssize_t sz_iov, const int flags = 0, const struct sockaddr *__to = NULL, const socklen_t __tolen = 0);
	ssize_t rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags, sockaddr *__from = NULL, socklen_t *__fromlen = NULL, struct msghdr *__msg = NULL);
	static err_t ip_output(struct pbuf *p, void* v_p_conn, int is_rexmit);
	virtual bool rx_input_cb(mem_buf_desc_t* p_rx_pkt_mem_buf_desc_info, void* pv_fd_ready_array = NULL);
	inline void init_pbuf_custom(mem_buf_desc_t *p_desc);
	static struct pbuf * tcp_tx_pbuf_alloc(void* p_conn);
	static void tcp_tx_pbuf_free(void* p_conn, struct pbuf *p_buff);
	static struct tcp_seg * tcp_seg_alloc(void* p_conn);
	static void tcp_seg_free(void* p_conn, struct tcp_seg * seg);

	bool inline is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_array = NULL);
	bool inline is_writeable();
	bool is_closable() { return m_pcb.state == CLOSED && m_syn_received.empty() && m_accepted_conns.empty(); }
	int rx_request_notification(uint64_t poll_sn);
	bool skip_os_select()
	{
		// calling os select on offloaded TCP sockets makes no sense unless it's a listen socket
		// to make things worse, it returns that os fd is ready...
		return (m_sock_offload == TCP_SOCK_LWIP && !is_server() && m_conn_state != TCP_CONN_INIT);
	}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	bool is_eof()
	{
		return m_sock_state == TCP_SOCK_INITED || m_sock_state == TCP_SOCK_CONNECTED_WR;
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	bool is_connected()
	{
		return m_sock_state == TCP_SOCK_CONNECTED_RDWR;
	}

	inline bool is_rtr()
	{
		return (m_n_rx_pkt_ready_list_count || m_sock_state == TCP_SOCK_CONNECTED_RD || m_sock_state == TCP_SOCK_CONNECTED_RDWR);
	}

	bool is_rts()
	{
		//ready to send
		return m_sock_state == TCP_SOCK_CONNECTED_WR || m_sock_state == TCP_SOCK_CONNECTED_RDWR;
	}

	bool is_server()
	{
		return m_sock_state == TCP_SOCK_ACCEPT_READY || m_sock_state == TCP_SOCK_ACCEPT_SHUT;
	}

	static const int CONNECT_DEFAULT_TIMEOUT_MS = 10000;
	virtual inline fd_type_t get_type()
	{
		return FD_TYPE_SOCKET;
	}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	tcp_pcb *get_pcb()
	{
		return &m_pcb;
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	void handle_timer_expired(void* user_data);

	virtual bool delay_orig_close_to_dtor();

protected:
	virtual void		lock_rx_q();
	virtual void		unlock_rx_q();

private:
	//lwip specific things
	struct tcp_pcb m_pcb;
	tcp_sock_offload_e m_sock_offload;
	tcp_sock_state_e m_sock_state;
	sockinfo_tcp *m_parent;
	/* connection state machine */
	int m_conn_timeout;
	/* RCVBUF acconting */
	int m_rcvbuff_max; // defaults?
	int m_rcvbuff_current;
	int m_rcvbuff_non_tcp_recved;
	lock_mutex_cond m_conn_cond;
	tcp_conn_state_e m_conn_state;
	fd_array_t* m_iomux_ready_fd_array;

	/* local & peer addresses */
/*	struct sockaddr *m_addr_local;
	socklen_t m_local_alen;
	struct sockaddr *m_addr_peer;
	socklen_t m_peer_alen;
*/

	//Relevant only for listen sockets: map connections in syn received state
	//We need this map since for syn received connection no sockinfo is created yet!
	syn_received_map_t m_syn_received;
	uint32_t m_received_syn_num;

	/* pending connections */
	accepted_conns_deque_t m_accepted_conns;
	uint32_t m_ready_conn_cnt;
	int m_backlog;

	void *m_timer_handle;
	lock_spin_recursive m_tcp_con_lock;
	bool m_timer_pending;

	bool report_connected; //used for reporting 'connected' on second non-blocking call to connect.

	int m_call_orig_close_on_dtor;

	int m_error_status;

	struct tcp_seg * m_tcp_seg_list;
	int m_tcp_seg_count;
	int m_tcp_seg_in_use;

	inline void lock_tcp_con();
	inline void unlock_tcp_con();
	void tcp_timer();

	bool prepare_listen_to_close();

	//Builds rfs key
	static void create_flow_tuple_key_from_pcb(flow_tuple &key, struct tcp_pcb *pcb);

	// accept cb func
	static err_t accept_lwip_cb(void *arg, struct tcp_pcb *child_pcb, err_t err);

	//Called when legal syn is received in order to remember the new active pcb which
	//is already created by lwip, but no sockinfo instance is created yet at this stage
	static err_t syn_received_lwip_cb(void *arg, struct tcp_pcb *newpcb, err_t err);

	static err_t syn_received_drop_lwip_cb(void *arg, struct tcp_pcb *newpcb, err_t err);

	static err_t clone_conn_cb(void *arg, struct tcp_pcb **newpcb, err_t err);

	int accept_helper(struct sockaddr *__addr, socklen_t *__addrlen, int __flags = 0);

	// clone socket in accept call
	sockinfo_tcp *accept_clone();
	// connect() helper & callback func
	int wait_for_conn_ready();
	static err_t connect_lwip_cb(void *arg, struct tcp_pcb *tpcb, err_t err);
	//tx
	unsigned tx_wait(int & err, bool is_blocking);

	void abort_connection();
	int handle_child_FIN(sockinfo_tcp* child_conn);

	//rx
	//int rx_wait(int &poll_count, bool is_blocking = true);
	static err_t ack_recvd_lwip_cb(void *arg, struct tcp_pcb *tpcb, u16_t space);
	static err_t rx_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
	static err_t rx_drop_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);

	// Be sure that m_pcb is initialized
	void set_conn_properties_from_pcb();

	//Register to timer
	void register_timer();

	/** Function prototype for tcp error callback functions. Called when the pcb
	 * receives a RST or is unexpectedly closed for any other reason.
	 *
	 * @note The corresponding pcb is already freed when this callback is called!
	 *
	 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
	 * @param err Error code to indicate why the pcb has been closed
	 *            ERR_ABRT: aborted through tcp_abort or by a TCP timer
	 *            ERR_RST: the connection was reset by the remote host
	 */
	static void 	err_lwip_cb(void *arg, err_t err);
	/* (re)alloc sockaddr of desired len. old addr may be freed if new_len != old_len
	 * old_len will be changed to new_len
	 */
	struct sockaddr *sockaddr_realloc(struct sockaddr *old_addr, socklen_t & old_len, socklen_t new_len);
	inline void 	return_rx_buffs(ring *p_ring);
	inline void 	reuse_buffer(mem_buf_desc_t *buff);
	virtual mem_buf_desc_t *get_next_desc(mem_buf_desc_t *p_desc);
	virtual	mem_buf_desc_t* get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx);
	virtual void 	post_deqeue(bool release_buff);
	virtual int 	zero_copy_rx(iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags);
	struct tcp_pcb* get_syn_received_pcb(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr,
            							 in_port_t dest_port, int protocol, in_addr_t local_addr);

	// stats
	uint64_t m_n_pbufs_rcvd;
	uint64_t m_n_pbufs_freed;

	//lock_spin_recursive m_rx_cq_lck;
	/* pick all cqs that match given address */
	int 		rx_wait(int & poll_count, bool is_blocking);
	int 		rx_wait_helper(int & poll_count, bool is_blocking);
	void 		fit_snd_bufs_to_nagle(bool disable_nagle);

	inline struct tcp_seg * get_tcp_seg();
	inline void put_tcp_seg(struct tcp_seg * seg);
};

typedef struct tcp_seg tcp_seg;

class tcp_seg_pool : lock_spin {
public:
	tcp_seg_pool(int size);
	virtual ~tcp_seg_pool();

	tcp_seg * get_tcp_segs(int amount);
	void put_tcp_segs(tcp_seg * seg_list);
	
private:
	tcp_seg *	m_tcp_segs_array;
	tcp_seg *	m_p_head;
};

extern tcp_seg_pool* g_tcp_seg_pool;


class tcp_timers_collection : public timers_group , public cleanable_obj {
public:
	tcp_timers_collection(int period, int resolution);
	virtual ~tcp_timers_collection();

	void clean_obj();

	virtual void handle_timer_expired(void* user_data);

protected:
	// add a new timer
	void add_new_timer(timer_node_t* node, timer_handler* handler, void* user_data);

	// remove timer from list and free it.
	// called for stopping (unregistering) a timer
	void remove_timer(timer_node_t* node);

private:
	int m_n_period;
	int m_n_resolution;
	int m_n_intervals_size;
	timer_node_t** m_p_intervals;
	int m_n_location;
	int m_n_count;
	int m_n_next_insert_bucket;
};

extern tcp_timers_collection* g_tcp_timers_collection;

#endif
