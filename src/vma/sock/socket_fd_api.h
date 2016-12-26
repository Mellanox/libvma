/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef SOCKET_FD_API_H
#define SOCKET_FD_API_H

#include "config.h"
#include <sys/socket.h>
#ifdef DEFINED_VMAPOLL
#include "vma/vmapoll_extra.h"
#else
#include "vma/vma_extra.h"
#endif // DEFINED_VMAPOLL

#include <vma/dev/cq_mgr.h>
#include <vma/dev/buffer_pool.h>
#include <vma/sock/cleanable_obj.h>

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 04000
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif

#define IS_DUMMY_PACKET(flags) (flags & VMA_SND_FLAGS_DUMMY)

class cq_mgr;
class epfd_info;

class mem_buf_desc_t;

typedef enum {
	TX_WRITE = 13, TX_WRITEV, TX_SEND, TX_SENDTO, TX_SENDMSG, TX_UNDEF
} tx_call_t;

typedef enum {
	RX_READ = 23, RX_READV, RX_RECV, RX_RECVFROM, RX_RECVMSG
} rx_call_t;

#define FD_ARRAY_MAX	24
typedef struct {
	// coverity[member_decl]
	int fd_list[FD_ARRAY_MAX]; // Note: An FD might appear twice in the list,
	//  the user of this array will need to handle it correctly
	int fd_max;
	int fd_count;
} fd_array_t;

enum fd_type_t{
	FD_TYPE_SOCKET = 0,
	FD_TYPE_PIPE,
};

typedef vma_list_t<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> vma_desc_list_t;

/**
 *
 * class socket_fd_api
 *
 */

class socket_fd_api: public cleanable_obj
{
public:
	socket_fd_api(int fd);
	virtual ~socket_fd_api();

	virtual void setPassthrough() {}
	virtual bool isPassthrough()  {return false;}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual int prepareConnect(const sockaddr *, socklen_t ) {return 0;}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	virtual int prepareListen()  {return 0;}

	virtual void destructor_helper();

	virtual int shutdown(int __how);

	virtual int listen(int backlog);
	
	virtual int accept(struct sockaddr *__addr, socklen_t *__addrlen);

	virtual int accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags);

	virtual int bind(const sockaddr *__addr, socklen_t __addrlen);

	virtual int connect(const sockaddr *__to, socklen_t __tolen);

	virtual int getsockname(sockaddr *__name, socklen_t *__namelen);
	virtual int getpeername(sockaddr *__name, socklen_t *__namelen);

	virtual int setsockopt(int __level, int __optname,
			       __const void *__optval, socklen_t __optlen) throw (vma_error);

	virtual int getsockopt(int __level, int __optname, void *__optval,
			       socklen_t *__optlen) throw (vma_error);
	virtual int fcntl(int __cmd, unsigned long int __arg) throw (vma_error) = 0;

	virtual int ioctl(unsigned long int __request, unsigned long int __arg) throw (vma_error) = 0;

	virtual ssize_t rx(const rx_call_t call_type, iovec* iov,
			   const ssize_t iovlen, int* p_flags = 0,
			   sockaddr *__from = NULL,
			   socklen_t *__fromlen = NULL,
			   struct msghdr *__msg = NULL) = 0;

	virtual bool is_readable(uint64_t *p_poll_sn, 
				 fd_array_t* p_fd_array = NULL);

	virtual bool is_writeable();

	virtual bool is_errorable(int *errors);

	// Instructing the socket to immediately sample/un-sample the OS in receive flow
	virtual void set_immediate_os_sample();
	virtual void unset_immediate_os_sample();

	virtual bool is_closable(){ return true; }


	//In some cases we need the socket can't be deleted immidiatly
	//(for example STREAME sockets)
	//This prepares the socket for termination and return true if the
	//Return val: true is the socket is already closable and false otherwise
	virtual bool prepare_to_close(bool process_shutdown = false) { NOT_IN_USE(process_shutdown); return is_closable(); }

	// this function is called when you can't go through destructor
	// it should be called only once
	virtual void force_close() {}

	virtual int rx_request_notification(uint64_t poll_sn);

	virtual ssize_t tx(const tx_call_t call_type, const iovec* iov,
			   const ssize_t iovlen, int __flags = 0,
			   __CONST_SOCKADDR_ARG   __to = NULL,
			   const socklen_t __tolen = 0) = 0;

	virtual void statistics_print(vlog_levels_t log_level = VLOG_DEBUG);

	virtual int register_callback(vma_recv_callback_t callback, void *context);
	
	virtual int free_packets(struct vma_packet_t *pkts, size_t count);

#ifdef DEFINED_VMAPOLL
	virtual	int free_buffs(uint16_t len);
#endif // DEFINED_VMAPOLL	

	virtual int get_fd( ) const { return m_fd; };

	// true if fd must be skipped from OS select()
	// If m_n_sysvar_select_poll_os_ratio == 0, it means that user configured VMA not to poll os (i.e. TRUE...)
	virtual bool skip_os_select() { return (!m_n_sysvar_select_poll_os_ratio); };

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	// true if EOF condition is detected on offloaded socket()
	virtual bool is_eof() { return false; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	virtual fd_type_t get_type() = 0;

	virtual void consider_rings_migration() {}

	virtual int add_epoll_context(epfd_info *epfd);
	virtual void remove_epoll_context(epfd_info *epfd);
	int get_epoll_context_fd();

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual bool delay_orig_close_to_dtor() {return false;}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	// Calling OS transmit
	ssize_t tx_os(const tx_call_t call_type, const iovec* p_iov,
		      const ssize_t sz_iov, const int __flags,
		      const sockaddr *__to, const socklen_t __tolen);

	static inline size_t pendig_to_remove_node_offset(void) {return NODE_OFFSET(socket_fd_api, pendig_to_remove_node);}
	list_node<socket_fd_api, socket_fd_api::pendig_to_remove_node_offset> pendig_to_remove_node;

	static inline size_t socket_fd_list_node_offset(void) {return NODE_OFFSET(socket_fd_api, socket_fd_list_node);}
	list_node<socket_fd_api, socket_fd_api::socket_fd_list_node_offset> socket_fd_list_node;

	static inline size_t ep_ready_fd_node_offset(void) {return NODE_OFFSET(socket_fd_api, ep_ready_fd_node);}
	list_node<socket_fd_api, socket_fd_api::ep_ready_fd_node_offset> ep_ready_fd_node;

	uint32_t m_epoll_event_flags;
#ifdef DEFINED_VMAPOLL	
	virtual int get_rings_num() {return 0;}
	virtual bool check_rings() {return false;}
	virtual int* get_rings_fds() {return NULL;}
#endif // DEFINED_VMAPOLL

protected:
	void notify_epoll_context(uint32_t events);
	void notify_epoll_context_add_ring(ring* ring);
	void notify_epoll_context_remove_ring(ring* ring);
	bool notify_epoll_context_verify(epfd_info *epfd);
	void notify_epoll_context_fd_is_offloaded();

	// identification information <socket fd>
	int m_fd;
	const uint32_t	m_n_sysvar_select_poll_os_ratio;

	// Calling OS receive
	ssize_t rx_os(const rx_call_t call_type, iovec* p_iov, ssize_t sz_iov,
		      const int flags, sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg);


private:
	epfd_info *m_econtext;
};
#endif
