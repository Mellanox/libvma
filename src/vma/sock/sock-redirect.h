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


#ifndef SOCK_REDIRECT_H
#define SOCK_REDIRECT_H


//if you need select with more than 1024 sockets - enable this
#ifndef SELECT_BIG_SETSIZE
#define SELECT_BIG_SETSIZE 0
#endif

#if SELECT_BIG_SETSIZE
#include <features.h>
#if  (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 2)
#include <bits/types.h>
#undef __FD_SETSIZE
#define __FD_SETSIZE 32768
#endif
#endif //SELECT_BIG_SETSIZE

#include <stdint.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <features.h>
#include <signal.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <time.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <resolv.h>

#include <vma/util/vtypes.h>
#include <vma/util/vma_stats.h>
#include <vma/util/sys_vars.h>
#include <vma/util/utils.h>

#include <vlogger/vlogger.h>

// Format a fd_set into a string for logging
// Check nfd to know how many 32 bits hexs do we want to sprintf into user buffer
const char* sprintf_fdset(char* buf, int buflen, int __nfds, fd_set *__fds);


/**
 *-----------------------------------------------------------------------------
 *  variables to hold the function-pointers to original functions
 *-----------------------------------------------------------------------------
 */

struct os_api {
	int (*creat) (const char *__pathname, mode_t __mode);
	int (*open) (__const char *__file, int __oflag, ...);
	int (*dup) (int fildes);
	int (*dup2) (int fildes, int fildes2);
	int (*pipe) (int __filedes[2]);
	int (*socket) (int __domain, int __type, int __protocol);
	int (*socketpair) (int __domain, int __type, int __protocol, int __sv[2]);

	int (*close) (int __fd);
	int (*__res_iclose) (res_state statp, bool free_addr);
	int (*shutdown) (int __fd, int __how);

	int (*accept) (int __fd, struct sockaddr *__addr, socklen_t *__addrlen);
	int (*accept4) (int __fd, struct sockaddr *__addr, socklen_t *__addrlen, int __flags);
	int (*bind) (int __fd, const struct sockaddr *__addr, socklen_t __addrlen);
	int (*connect) (int __fd, const struct sockaddr *__to, socklen_t __tolen);
	int (*listen) (int __fd, int __backlog);

	int (*setsockopt) (int __fd, int __level, int __optname, __const void *__optval, socklen_t __optlen);
	int (*getsockopt) (int __fd, int __level, int __optname, void *__optval, socklen_t *__optlen);
	int (*fcntl) (int __fd, int __cmd, ...);
	int (*ioctl) (int __fd, unsigned long int __request, ...);
	int (*getsockname) (int __fd, struct sockaddr *__name,socklen_t *__namelen);
	int (*getpeername) (int __fd, struct sockaddr *__name,socklen_t *__namelen);

	ssize_t (*read) (int __fd, void *__buf, size_t __nbytes);
	ssize_t (*__read_chk) (int __fd, void *__buf, size_t __nbytes, size_t __buflen);
	ssize_t (*readv) (int __fd, const struct iovec *iov, int iovcnt);
	ssize_t (*recv) (int __fd, void *__buf, size_t __n, int __flags);
	ssize_t (*__recv_chk) (int __fd, void *__buf, size_t __n,  size_t __buflen, int __flags);
	ssize_t (*recvmsg) (int __fd, struct msghdr *__message, int __flags);
	int (*recvmmsg) (int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags, const struct timespec *__timeout);

	ssize_t (*recvfrom) (int __fd, void *__restrict __buf, size_t __n, int __flags, struct sockaddr *__from, socklen_t *__fromlen);
	ssize_t (*__recvfrom_chk) (int __fd, void *__restrict __buf, size_t __n, size_t __buflen, int __flags, struct sockaddr *__from, socklen_t *__fromlen);


	ssize_t (*write) (int __fd, __const void *__buf, size_t __n);
	ssize_t (*writev) (int __fd, const struct iovec *iov, int iovcnt);
	ssize_t (*send) (int __fd, __const void *__buf, size_t __n, int __flags);
	ssize_t (*sendmsg) (int __fd, __const struct msghdr *__message, int __flags);
	ssize_t (*sendmmsg) (int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags);
	ssize_t (*sendto) (int __fd, __const void *__buf, size_t __n,int __flags, const struct sockaddr *__to, socklen_t __tolen);

	int (*select) (int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds, struct timeval *__timeout);
	int (*pselect) (int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__errorfds, const struct timespec *__timeout, const sigset_t *__sigmask);

	int (*poll) (struct pollfd *__fds, nfds_t __nfds, int __timeout);
	int (*ppoll) (struct pollfd *__fds, nfds_t __nfds, const struct timespec *__timeout, const sigset_t *__sigmask);
	int (*epoll_create) (int __size);
	int (*epoll_create1) (int __flags);
	int (*epoll_ctl) (int __epfd, int __op, int __fd, struct epoll_event *__event);
	int (*epoll_wait) (int __epfd, struct epoll_event *__events, int __maxevents, int __timeout);
	int (*epoll_pwait) (int __epfd, struct epoll_event *__events, int __maxevents, int __timeout, const sigset_t *sigmask);

	int (*clone) (int (*__fn)(void *), void *__child_stack, int __flags, void *__arg);
	pid_t (*fork) (void);
	pid_t (*vfork) (void);
	int (*daemon) (int __nochdir, int __noclose);

	int (*sigaction) (int signum, const struct sigaction *act, struct sigaction *oldact);
};

/**
 *-----------------------------------------------------------------------------
 *  variables to hold the function-pointers to original functions
 *-----------------------------------------------------------------------------
 */
extern os_api orig_os_api;

extern void get_orig_funcs();

extern iomux_stats_t* g_p_select_stats;
extern iomux_stats_t* g_p_poll_stats;
extern iomux_stats_t* g_p_epoll_stats;

void do_global_ctors();
void handle_close(int fd, bool cleanup = false, bool passthrough = false);

// allow calling our socket(...) implementation safely from within libvma.so
// this is critical in case VMA was loaded using dlopen and not using LD_PRELOAD
// TODO: look for additional such functions/calls
int socket_internal(int __domain, int __type, int __protocol, bool check_offload = false);

#endif  //SOCK_REDIRECT_H


