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


#include "socket_fd_api.h"
#include "sock-redirect.h"

#include <vma/iomux/epfd_info.h>
#include <vlogger/vlogger.h>
#include <sys/epoll.h>

#define MODULE_NAME 		"sapi"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "[fd=%d]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_fd

socket_fd_api::socket_fd_api(int fd) : m_fd(fd), m_econtext(NULL)
{
}

socket_fd_api::~socket_fd_api()
{
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
void socket_fd_api::destructor_helper()
{
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

int socket_fd_api::shutdown(int __how)
{
	__log_info_func("");
	int ret = orig_os_api.shutdown(m_fd, __how);
	if (ret) {
		__log_info_dbg("shutdown failed (ret=%d %m)", ret);
	}
	return ret;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

int socket_fd_api::bind(const sockaddr *__addr, socklen_t __addrlen)
{
	__log_info_func("");
	int ret = orig_os_api.bind(m_fd, __addr, __addrlen);
	if (ret) {
		__log_info_err("bind failed (ret=%d %m)", ret);
	}
	return ret;
}

int socket_fd_api::connect(const sockaddr *__to, socklen_t __tolen)
{
	__log_info_func("");
	int ret = orig_os_api.connect(m_fd, __to, __tolen);
	if (ret) {
		__log_info_err("connect failed (ret=%d %m)", ret);
	}
	return ret;
}

int socket_fd_api::accept(struct sockaddr *__addr, socklen_t *__addrlen)
{
       __log_info_func("");
       int ret = orig_os_api.accept(m_fd, __addr, __addrlen);
       if (ret < 0) {
               __log_info_err("accept failed (ret=%d %m)", ret);
       }
       return ret;
}

int socket_fd_api::accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags)
{
       __log_info_func("");
       int ret = orig_os_api.accept4(m_fd, __addr, __addrlen, __flags);
       if (ret < 0) {
               __log_info_err("accept4 failed (ret=%d %m)", ret);
       }
       return ret;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

int socket_fd_api::listen(int backlog)
{
       __log_info_func("");
       int ret = orig_os_api.listen(m_fd, backlog);
       if (ret < 0) {
               __log_info_err("listen failed (ret=%d %m)", ret);
       }
       return ret;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

int socket_fd_api::getsockname(sockaddr *__name, socklen_t *__namelen)
{
	__log_info_func("");
	int ret = orig_os_api.getsockname(m_fd, __name, __namelen);
	if (ret) {
		__log_info_err("getsockname failed (ret=%d %m)", ret);
	}
	return ret;
}

int socket_fd_api::getpeername(sockaddr *__name, socklen_t *__namelen)
{
	__log_info_func("");
	int ret = orig_os_api.getpeername(m_fd, __name, __namelen);
	if (ret) {
		__log_info_err("getpeername failed (ret=%d %m)", ret);
	}
	return ret;
}

int socket_fd_api::setsockopt(int __level, int __optname,
			      __const void *__optval, socklen_t __optlen)
{
	__log_info_func("");
	int ret = orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);
	if (ret) {
		__log_info_err("setsockopt failed (ret=%d %m)", ret);
	}
	return ret;
}

int socket_fd_api::getsockopt(int __level, int __optname, void *__optval,
			      socklen_t *__optlen)
{
	__log_info_func("");
	int ret = orig_os_api.getsockopt(m_fd, __level, __optname, __optval, __optlen);
	if (ret) {
		__log_info_err("getsockopt failed (ret=%d %m)", ret);
	}
	return ret;
}


bool socket_fd_api::is_readable(uint64_t *p_poll_sn, fd_array_t* p_fd_array)
{
	NOT_IN_USE(p_poll_sn);
	NOT_IN_USE(p_fd_array);
	__log_info_funcall("");
	return false;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void socket_fd_api::set_immediate_os_sample()
{
	__log_info_funcall("");
	return;
}

void socket_fd_api::unset_immediate_os_sample()
{
	__log_info_funcall("");
	return;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int socket_fd_api::rx_request_notification(uint64_t poll_sn)
{
	NOT_IN_USE(poll_sn);
	__log_info_funcall("");
	return false;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

bool socket_fd_api::is_writeable()
{
	__log_info_funcall("");
	return true;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
void socket_fd_api::statistics_print()
{
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

ssize_t socket_fd_api::rx_os(const rx_call_t call_type, iovec* p_iov,
			     ssize_t sz_iov, int* p_flags, sockaddr *__from,
			     socklen_t *__fromlen, struct msghdr *__msg)
{
	errno = 0;
	switch (call_type) {
	case RX_READ:
		__log_info_func("calling os receive with orig read");
		return orig_os_api.read(m_fd, p_iov[0].iov_base, p_iov[0].iov_len);

	case RX_READV:
		__log_info_func("calling os receive with orig readv");
		return orig_os_api.readv(m_fd, p_iov, sz_iov);

	case RX_RECV:
		__log_info_func("calling os receive with orig recv");
		return orig_os_api.recv(m_fd, p_iov[0].iov_base, p_iov[0].iov_len,
		                        *p_flags);

	case RX_RECVFROM:
		__log_info_func("calling os receive with orig recvfrom");
		return orig_os_api.recvfrom(m_fd, p_iov[0].iov_base, p_iov[0].iov_len,
		                            *p_flags, __from, __fromlen);

	case RX_RECVMSG: {
		__log_info_func("calling os receive with orig recvmsg");
		return orig_os_api.recvmsg(m_fd, __msg, *p_flags);
	}
	}
	return (ssize_t) -1;
}

ssize_t socket_fd_api::tx_os(const tx_call_t call_type,
			     const iovec* p_iov, const ssize_t sz_iov,
			     const int __flags, const sockaddr *__to,
			     const socklen_t __tolen)
{
	errno = 0;
	switch (call_type) {
	case TX_WRITE:
		__log_info_func("calling os transmit with orig write");
		return orig_os_api.write(m_fd, p_iov[0].iov_base, p_iov[0].iov_len);

	case TX_WRITEV:
		__log_info_func("calling os transmit with orig writev");
		return orig_os_api.writev(m_fd, p_iov, sz_iov);

	case TX_SEND:
		__log_info_func("calling os transmit with orig send");
		return orig_os_api.send(m_fd, p_iov[0].iov_base, p_iov[0].iov_len,
		                        __flags);

	case TX_SENDTO:
		__log_info_func("calling os transmit with orig sendto");
		return orig_os_api.sendto(m_fd, p_iov[0].iov_base, p_iov[0].iov_len,
		                          __flags, __to, __tolen);

	case TX_SENDMSG: {
		msghdr __message;
		memset(&__message, 0, sizeof(struct msghdr));
		__message.msg_iov = (iovec*) p_iov;
		__message.msg_iovlen = sz_iov;
		__message.msg_name = (void*) __to;
		__message.msg_namelen = __tolen;

		__log_info_func("calling os transmit with orig sendmsg");
		return orig_os_api.sendmsg(m_fd, &__message, __flags);
		}
	default:
		__log_info_func("calling undefined os call type!");
		break;
	}
	return (ssize_t) -1;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

int socket_fd_api::register_callback(vma_recv_callback_t callback, void *context)
{
	NOT_IN_USE(callback);
	NOT_IN_USE(context);
	return -1;
}

int socket_fd_api::free_datagrams(void **pkt_desc_ids, size_t count)
{
	NOT_IN_USE(pkt_desc_ids);
	NOT_IN_USE(count);
	return -1;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void socket_fd_api::add_epoll_context(epfd_info *epfd)
{
	if(!m_econtext) m_econtext = epfd;
}

void socket_fd_api::remove_epoll_context(epfd_info *epfd)
{
	if (m_econtext == epfd)
		m_econtext = NULL;
}

void socket_fd_api::notify_epoll_context(uint32_t events)
{
	if (m_econtext) {
		m_econtext->insert_epoll_event_cb(m_fd, events);
	}
}

void socket_fd_api::notify_epoll_context_add_ring(ring* ring)
{
	if (m_econtext) {
		m_econtext->increase_ring_ref_count(ring);
	}
}

void socket_fd_api::notify_epoll_context_remove_ring(ring* ring)
{
	if (m_econtext){
		m_econtext->decrease_ring_ref_count(ring);
	}
}

bool socket_fd_api::notify_epoll_context_verify(epfd_info *epfd)
{
	return m_econtext == epfd;
}

void socket_fd_api::notify_epoll_context_fd_is_offloaded()
{
	if (m_econtext) {
		m_econtext->set_fd_as_offloaded_only(m_fd);
	}
}
