/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef TOOLS_DAEMON_DAEMON_H_
#define TOOLS_DAEMON_DAEMON_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#ifdef HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#endif

#include "vma/util/agent_def.h"


#define MODULE_NAME             "vmad"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define INVALID_VALUE (-1)
#define STATE_ESTABLISHED	4

#define PID_MAX         499    /**< Default maximum number of processes
                                    per node (should be prime number) */
#define FID_MAX         2203   /**< Default maximum number of sockets
                                    per process (should be prime number) */

#ifndef HAVE_LINUX_LIMITS_H
#define NAME_MAX         255    /**< chars in a file name */
#define PATH_MAX        4096    /**< chars in a path name including null */
#endif

#define log_fatal(fmt, ...) \
	do {                                                        \
		if (daemon_cfg.opt.log_level > 0)                              \
			sys_log(LOG_ALERT, "[FATAL ] " fmt, ##__VA_ARGS__);    \
	} while (0)

#define log_error(fmt, ...) \
	do {                                                        \
		if (daemon_cfg.opt.log_level > 1)                              \
			sys_log(LOG_ERR, "[ERROR ] " fmt, ##__VA_ARGS__);      \
	} while (0)

#define log_warn(fmt, ...) \
	do {                                                         \
		if (daemon_cfg.opt.log_level > 2)                               \
			sys_log(LOG_WARNING, "[WARN  ] " fmt, ##__VA_ARGS__);   \
	} while (0)

#define log_info(fmt, ...) \
	do {                                                         \
		if (daemon_cfg.opt.log_level > 3)                               \
			sys_log(LOG_NOTICE, "[INFO  ] " fmt, ##__VA_ARGS__);    \
	} while (0)

#define log_debug(fmt, ...) \
	do {                                                         \
		if (daemon_cfg.opt.log_level > 4)                               \
			sys_log(LOG_INFO, "[DEBUG ] " fmt, ##__VA_ARGS__);    \
	} while (0)

/**
 * @struct module_cfg
 * @brief Configuration parameters in global values
 */
struct module_cfg {
	struct {
		int mode;                   /**< 0 - daemon, 1 - console */
		int log_level;              /**< 0..5 verbose level */
		int max_pid_num;            /**< maximum number of processes per node */
		int max_fid_num;            /**< maximum number of sockets per process */
		int force_rst;              /**< RST method
	                                     * 0 - only system RST is sent as
	                                     * reaction on spoofed SYN
	                                     * 1 - form and send internal RST
	                                     * based on SeqNo */
	} opt;
	volatile sig_atomic_t sig;
	const char *lock_file;
	int lock_fd;
	const char *sock_file;
	int sock_fd;
	int raw_fd;
	int notify_fd;
	const char *notify_dir;
	hash_t ht;
};

extern struct module_cfg daemon_cfg;

/**
 * @struct store_pid
 * @brief Describe process using pid as unique key
 */
struct store_pid {
	pid_t          pid;         /**< Process id */
	hash_t         ht;          /**< Handle to socket store */
	uint32_t       lib_ver;     /**< Library version that the process uses */
	struct timeval t_start;     /**< Start time of the process */
};

/**
 * @struct store_fid
 * @brief Describe socket using fid as unique key
 */
struct store_fid {
	int            fid;         /**< Socket id */
	uint32_t       src_ip;      /**< Source IP address */
	uint32_t       dst_ip;      /**< Destination IP address */
	uint16_t       src_port;    /**< Source port number */
	uint16_t       dst_port;    /**< Destination port number */
	uint8_t        type;        /**< Connection type */
	uint8_t        state;       /**< Current TCP state of the connection */
};


static inline void sys_log(int level, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (0 == daemon_cfg.opt.mode) {
		vsyslog(level, format, args);
	} else {
		vprintf(format, args);
	}
	va_end(args);
}


static inline char *sys_addr2str(struct sockaddr_in *addr)
{
	static __thread char addrbuf[100];
	static char buf[100];
	inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf) - 1);
	sprintf(addrbuf, "%s:%d", buf, ntohs(addr->sin_port));

	return addrbuf;
}


static inline ssize_t sys_sendto(int sockfd,
		const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	char *data = (char *)buf;
	int n, nb;

	nb = 0;
	do {
		n = sendto(sockfd, data, len, flags, dest_addr, addrlen);
		if (n <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				if (flags & MSG_DONTWAIT) {
					break;
				}
				continue;
			}
			return -errno;
		}
		len -= n;
		data += n;
		nb += n;
	} while (!(flags & MSG_DONTWAIT) && (len > 0));

	return nb;
}

#endif /* TOOLS_DAEMON_DAEMON_H_ */
