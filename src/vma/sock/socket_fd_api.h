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


#ifndef SOCKET_FD_API_H
#define SOCKET_FD_API_H

#include <sys/socket.h>
#include <deque>
#include <vma/vma_extra.h>
#include <vma/dev/cq_mgr.h>
#include <vma/dev/buffer_pool.h>
#include <vma/sock/cleanable_obj.h>

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 04000
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif

class cq_mgr;
class epfd_info;

struct mem_buf_desc_t;

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

typedef std::deque<mem_buf_desc_t*> vma_desc_list_t;

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
			       __const void *__optval, socklen_t __optlen);

	virtual int getsockopt(int __level, int __optname, void *__optval,
			       socklen_t *__optlen);
	virtual int fcntl(int __cmd, unsigned long int __arg) = 0;

	virtual int ioctl(unsigned long int __request, unsigned long int __arg) = 0;

	virtual ssize_t rx(const rx_call_t call_type, iovec* iov,
			   const ssize_t iovlen, int* p_flags = 0,
			   sockaddr *__from = NULL,
			   socklen_t *__fromlen = NULL,
			   struct msghdr *__msg = NULL) = 0;

	virtual bool is_readable(uint64_t *p_poll_sn, 
				 fd_array_t* p_fd_array = NULL);

	virtual bool is_writeable();

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

	virtual void statistics_print();

	virtual int register_callback(vma_recv_callback_t callback, void *context);
	
	virtual int free_datagrams(void **pkt_desc_ids, size_t count);

	virtual int get_fd( ) const { return m_fd; };

	// true if fd must be skipped from OS select()
	// If mce_sys.rx_udp_poll_os_ratio == 0, it means that user configured VMA not to poll os (i.e. TRUE...)
	virtual bool skip_os_select() { return (!(mce_sys.select_poll_os_ratio)); };

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

	virtual void add_epoll_context(epfd_info *epfd);
	virtual void remove_epoll_context(epfd_info *epfd);

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

protected:
	void notify_epoll_context(uint32_t events);
	void notify_epoll_context_add_ring(ring* ring);
	void notify_epoll_context_remove_ring(ring* ring);
	bool notify_epoll_context_verify(epfd_info *epfd);
	void notify_epoll_context_fd_is_offloaded();

	// identification information <socket fd>
	int m_fd;

	// Calling OS receive
	ssize_t rx_os(const rx_call_t call_type, iovec* p_iov, ssize_t sz_iov,
		      int* p_flags, sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg);


private:
	epfd_info *m_econtext;
};

#endif
