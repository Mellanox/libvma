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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "vlogger/vlogger.h"
#include "vma/sock/sock-redirect.h"
#include "vma/util/agent.h"

#undef  MODULE_NAME
#define MODULE_NAME     "agent"
#undef  MODULE_HDR
#define MODULE_HDR      MODULE_NAME "%d:%s() "


/* Force system call */
#define sys_call(_result, _func, ...) \
	do {                                              \
		if (orig_os_api._func)                        \
			_result = orig_os_api._func(__VA_ARGS__); \
		else                                          \
			_result = _func(__VA_ARGS__);             \
	} while (0)

static struct {
	int active;
	int sock_fd;
	int pid_fd;
	char sock_file[100];    /* size should be less than sockaddr_un.sun_path */
	char pid_file[100];
} agent_cfg = {
		0, -1, -1, "", ""
};


static int create_agent_socket(void);


int agent_open(void)
{
	int rc = 0;

	agent_cfg.sock_fd = -1;
	agent_cfg.pid_fd = -1;

	if ((mkdir(VMA_AGENT_PATH, 0777) != 0) && (errno != EEXIST)) {
		rc = -errno;
		__log_dbg("failed create folder %s (errno = %d)\n", VMA_AGENT_PATH, errno);
		goto err;
	}

	rc = snprintf(agent_cfg.sock_file, sizeof(agent_cfg.sock_file) - 1,
			"%s/%s.%d.sock", VMA_AGENT_PATH, VMA_AGENT_BASE_NAME, getpid());
	if ((rc < 0 ) || (rc == (sizeof(agent_cfg.sock_file) - 1) )) {
		rc = -ENOMEM;
		__log_dbg("failed allocate sock file (errno = %d)\n", errno);
		goto err;
	}
	rc = snprintf(agent_cfg.pid_file, sizeof(agent_cfg.pid_file) - 1,
			"%s/%s.%d.pid", VMA_AGENT_PATH, VMA_AGENT_BASE_NAME, getpid());
	if ((rc < 0 ) || (rc == (sizeof(agent_cfg.pid_file) - 1) )) {
		rc = -ENOMEM;
		__log_dbg("failed allocate pid file (errno = %d)\n", errno);
		goto err;
	}

	sys_call(agent_cfg.pid_fd, open, agent_cfg.pid_file,
			O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
	if (agent_cfg.pid_fd < 0) {
		rc = -errno;
		__log_dbg("failed allocate pid file (errno = %d)\n", errno);
		goto err;
	}

	rc = create_agent_socket();
	if (rc < 0) {
		goto err;
	}

	rc = agent_send_msg_init();
	if (rc < 0) {
		goto err;
	}

	agent_cfg.active = 1;

	return rc;

err:
	vlog_printf(VLOG_WARNING, "Peer notification functionality is not supported.\n");
	vlog_printf(VLOG_WARNING, "Increase output level to see a reason\n");

	if (agent_cfg.pid_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, agent_cfg.pid_fd);
		agent_cfg.pid_fd = -1;
		unlink(agent_cfg.pid_file);
	}

	if (agent_cfg.sock_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, agent_cfg.sock_fd);
		agent_cfg.sock_fd = -1;
		unlink(agent_cfg.sock_file);
	}

	return rc;
}

void agent_close(void)
{
	if (!agent_cfg.active) {
		return ;
	}

	agent_send_msg_exit();

	if (agent_cfg.sock_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, agent_cfg.sock_fd);
		unlink(agent_cfg.sock_file);
	}

	if (agent_cfg.pid_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, agent_cfg.pid_fd);
		unlink(agent_cfg.pid_file);
	}

	agent_cfg.active = 0;
}

int agent_send_msg_init(void)
{
	int rc = 0;
	struct sockaddr_un server_addr;
	struct vma_msg_init data;
	uint8_t *version;

	if (agent_cfg.sock_fd < 0) {
		return -EBADF;
	}

	/* Set server address */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path, VMA_AGENT_ADDR, sizeof(server_addr.sun_path) - 1);

	sys_call(rc, connect, agent_cfg.sock_fd, (struct sockaddr *)&server_addr,
			sizeof(struct sockaddr_un));
	if (rc < 0) {
		__log_dbg("Failed to connect() errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_INIT;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	version = (uint8_t *)&data.ver;
	version[0] = VMA_LIBRARY_MAJOR;
	version[1] = VMA_LIBRARY_MINOR;
	version[2] = VMA_LIBRARY_RELEASE;
	version[3] = VMA_LIBRARY_REVISION;

	/* send(VMA_MSG_INIT) in blocking manner */
	sys_call(rc, send, agent_cfg.sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_INIT) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* recv(VMA_MSG_INIT|ACK) in blocking manner */
	memset(&data, 0, sizeof(data));
	sys_call(rc, recv, agent_cfg.sock_fd, &data, sizeof(data), 0);
	if (rc < (int)sizeof(data)) {
		__log_dbg("Failed to recv(VMA_MSG_INIT) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	if (data.hdr.code != (VMA_MSG_INIT | VMA_MSG_ACK) ||
			data.hdr.ver < VMA_AGENT_VER ||
			data.hdr.pid != getpid()) {
		__log_dbg("Protocol version mismatch: code = 0x%X ver = 0x%X pid = %d\n",
				data.hdr.code, data.hdr.ver, data.hdr.pid);
		rc = -EPROTO;
		goto err;
	}

err:
	return rc;
}

int agent_send_msg_exit(void)
{
	int rc = 0;
	struct vma_msg_exit data;

	if (agent_cfg.sock_fd < 0) {
		return -EBADF;
	}

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_EXIT;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();

	/* send(VMA_MSG_EXIT) in blocking manner */
	sys_call(rc, send, agent_cfg.sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_EXIT) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}

int agent_send_msg_state(uint32_t fid, uint8_t state, uint8_t type,
		uint32_t src_ip, uint16_t src_port,
		uint32_t dst_ip, uint16_t dst_port)
{
	int rc = 0;
	struct vma_msg_state data;

	if (!agent_cfg.active) {
		return -ENODEV;
	}

	if (agent_cfg.sock_fd < 0) {
		return -EBADF;
	}

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_STATE;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	data.fid = fid;
	data.state = state;
	data.type = type;
	data.src_ip = src_ip;
	data.src_port = src_port;
	data.dst_ip = dst_ip;
	data.dst_port = dst_port;

	/* send(VMA_MSG_STATE) in blocking manner */
	sys_call(rc, send, agent_cfg.sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_STATE) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}

static int create_agent_socket(void)
{
	int rc = 0;
	int optval = 1;
	struct timeval opttv;
	struct sockaddr_un sock_addr;

	/* Create UNIX UDP socket to receive data from VMA processes */
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, agent_cfg.sock_file, sizeof(sock_addr.sun_path) - 1);
	/* remove possible old socket */
	unlink(agent_cfg.sock_file);

	sys_call(agent_cfg.sock_fd, socket, AF_UNIX, SOCK_DGRAM, 0);
	if (agent_cfg.sock_fd < 0) {
		__log_dbg("Failed to call socket() errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	optval = 1;
	sys_call(rc, setsockopt, agent_cfg.sock_fd, SOL_SOCKET, SO_REUSEADDR,
			(const void *)&optval, sizeof(optval));
	if (rc < 0) {
		__log_dbg("Failed to call setsockopt(SO_REUSEADDR) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* Sets the timeout value as 1 sec that specifies the maximum amount of time
	 * an input function waits until it completes.
	 */
	opttv.tv_sec = 1;
	opttv.tv_usec = 0;
	sys_call(rc, setsockopt, agent_cfg.sock_fd, SOL_SOCKET, SO_RCVTIMEO,
			(const void *)&opttv, sizeof(opttv));
	if (rc < 0) {
		__log_dbg("Failed to call setsockopt(SO_RCVTIMEO) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* bind created socket */
	sys_call(rc, bind, agent_cfg.sock_fd, (struct sockaddr *)&sock_addr,
			sizeof(sock_addr));
	if (rc < 0) {
		__log_dbg("Failed to call bind() errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}
