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
#include "utils/lock_wrapper.h"
#include "vma/sock/sock-redirect.h"
#include "vma/util/list.h"
#include "vma/util/agent.h"

#undef  MODULE_NAME
#define MODULE_NAME     "agent:"
#undef  MODULE_HDR
#define MODULE_HDR      MODULE_NAME "%d:%s() "


/* Force system call */
#define sys_call(_result, _func, ...) \
	do {                                              \
		if (orig_os_api._func)                        \
			_result = orig_os_api._func(__VA_ARGS__); \
		else                                          \
			_result = ::_func(__VA_ARGS__);           \
	} while (0)

/* Print user notification */
#define output_warn() \
	vlog_printf(VLOG_DEBUG, "Peer notification functionality is not active.\n"); \
	vlog_printf(VLOG_DEBUG, "Check daemon state\n");

#define output_fatal() \
	vlog_printf(VLOG_DEBUG, "Peer notification functionality is not supported.\n"); \
	vlog_printf(VLOG_DEBUG, "Increase output level to see a reason\n");

agent* g_p_agent = NULL;


agent::agent() :
		m_state(AGENT_CLOSED), m_sock_fd(-1), m_pid_fd(-1),
		m_msg_num(512), m_msg_grow(16)
{
	int rc = 0;
	agent_msg_t *msg = NULL;
	int i = 0;

	INIT_LIST_HEAD(&m_free_queue);
	INIT_LIST_HEAD(&m_wait_queue);

	/* Fill free queue with empty messages */
	i = m_msg_num;
	m_msg_num = 0;
	while (i--) {
		/* coverity[overwrite_var] */
		msg = (agent_msg_t *)malloc(sizeof(*msg));
		if (NULL == msg) {
			rc = -ENOMEM;
			__log_dbg("failed queue creation (rc = %d)\n", rc);
			goto err;
		}
		msg->length = 0;
		list_add_tail(&msg->item, &m_free_queue);
		m_msg_num++;
	}

	if ((mkdir(VMA_AGENT_PATH, 0777) != 0) && (errno != EEXIST)) {
		rc = -errno;
		__log_dbg("failed create folder %s (rc = %d)\n", VMA_AGENT_PATH, rc);
		goto err;
	}

	rc = snprintf(m_sock_file, sizeof(m_sock_file) - 1,
			"%s/%s.%d.sock", VMA_AGENT_PATH, VMA_AGENT_BASE_NAME, getpid());
	if ((rc < 0 ) || (rc == (sizeof(m_sock_file) - 1) )) {
		rc = -ENOMEM;
		__log_dbg("failed allocate sock file (rc = %d)\n", rc);
		goto err;
	}

	rc = snprintf(m_pid_file, sizeof(m_pid_file) - 1,
			"%s/%s.%d.pid", VMA_AGENT_PATH, VMA_AGENT_BASE_NAME, getpid());
	if ((rc < 0 ) || (rc == (sizeof(m_pid_file) - 1) )) {
		rc = -ENOMEM;
		__log_dbg("failed allocate pid file (rc = %d)\n", rc);
		goto err;
	}

	sys_call(m_pid_fd, open, m_pid_file,
			O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
	if (m_pid_fd < 0) {
		rc = -errno;
		__log_dbg("failed open pid file (rc = %d)\n", rc);
		goto err;
	}

	rc = create_agent_socket();
	if (rc < 0) {
		__log_dbg("failed open sock file (rc = %d)\n", rc);
		goto err;
	}

	/* Initialization is mostly completed
	 * At the moment it does not matter if connection with
	 * daemon can be done here or later
	 */
	m_state = AGENT_INACTIVE;

	rc = send_msg_init();
	if (rc < 0) {
		__log_dbg("failed establish connection with daemon (rc = %d)\n", rc);
		output_warn();
		if (rc != -ECONNREFUSED) {
			goto err;
		}
	}

	/* coverity[leaked_storage] */
	return ;

err:
	/* There is no chance to establish connection with daemon
	 * because of internal problems or communication protocol
	 * variance
	 * So do not try anymore
	 */
	m_state = AGENT_CLOSED;

	output_fatal();

	while (!list_empty(&m_free_queue)) {
		/* coverity[overwrite_var] */
		msg = list_first_entry(&m_free_queue, agent_msg_t, item);
		list_del_init(&msg->item);
		free(msg);
	}

	if (m_pid_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, m_pid_fd);
		m_pid_fd = -1;
		unlink(m_pid_file);
	}

	if (m_sock_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, m_sock_fd);
		m_sock_fd = -1;
		unlink(m_sock_file);
	}

	/* coverity[leaked_storage] */
	return ;
}

agent::~agent()
{
	agent_msg_t *msg = NULL;

	if (AGENT_CLOSED == m_state) {
		return ;
	}

	progress();
	send_msg_exit();

	m_state = AGENT_CLOSED;

	while (!list_empty(&m_free_queue)) {
		msg = list_first_entry(&m_free_queue, agent_msg_t, item);
		list_del_init(&msg->item);
		free(msg);
	}

	if (m_sock_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, m_sock_fd);
		unlink(m_sock_file);
	}

	if (m_pid_fd > 0) {
		int ret = 0;
		NOT_IN_USE(ret);
		sys_call(ret, close, m_pid_fd);
		unlink(m_pid_file);
	}
}

void agent::progress(void)
{
	agent_msg_t* msg = NULL;

	lock();
	while (!list_empty(&m_wait_queue)) {
		msg = list_first_entry(&m_wait_queue, agent_msg_t, item);
		list_del_init(&msg->item);
		send(msg);
		list_add_tail(&msg->item, &m_free_queue);
	}
	unlock();
}

int agent::send(agent_msg_t *msg)
{
	int rc = 0;

	if (AGENT_ACTIVE != m_state) {
		return -ENODEV;
	}

	if (m_sock_fd < 0) {
		return -EBADF;
	}

	if (NULL == msg) {
		return -EINVAL;
	}

	/* send() in blocking manner */
	sys_call(rc, send, m_sock_fd, (void *)&msg->data, msg->length, 0);
	if (rc < 0) {
		__log_dbg("Failed to send() errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}

int agent::send_msg_init(void)
{
	int rc = 0;
	struct sockaddr_un server_addr;
	struct vma_msg_init data;
	uint8_t *version;

	if (m_sock_fd < 0) {
		return -EBADF;
	}

	/* Set server address */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path, VMA_AGENT_ADDR, sizeof(server_addr.sun_path) - 1);

	sys_call(rc, connect, m_sock_fd, (struct sockaddr *)&server_addr,
			sizeof(struct sockaddr_un));
	if (rc < 0) {
		__log_dbg("Failed to connect() errno %d (%s)\n",
				errno, strerror(errno));
		rc = -ECONNREFUSED;
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
	sys_call(rc, send, m_sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_INIT) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -ECONNREFUSED;
		goto err;
	}

	/* recv(VMA_MSG_INIT|ACK) in blocking manner */
	memset(&data, 0, sizeof(data));
	sys_call(rc, recv, m_sock_fd, &data, sizeof(data), 0);
	if (rc < (int)sizeof(data)) {
		__log_dbg("Failed to recv(VMA_MSG_INIT) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -ECONNREFUSED;
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

	m_state = AGENT_ACTIVE;

err:
	return rc;
}

int agent::send_msg_exit(void)
{
	int rc = 0;
	struct vma_msg_exit data;

	if (AGENT_ACTIVE != m_state) {
		return -ENODEV;
	}

	if (m_sock_fd < 0) {
		return -EBADF;
	}

	m_state = AGENT_INACTIVE;

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_EXIT;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();

	/* send(VMA_MSG_EXIT) in blocking manner */
	sys_call(rc, send, m_sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_EXIT) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}

int agent::send_msg_state(uint32_t fid, uint8_t st, uint8_t type,
		uint32_t src_ip, uint16_t src_port,
		uint32_t dst_ip, uint16_t dst_port)
{
	int rc = 0;
	struct vma_msg_state data;

	if (AGENT_ACTIVE != m_state) {
		return -ENODEV;
	}

	if (m_sock_fd < 0) {
		return -EBADF;
	}

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_STATE;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	data.fid = fid;
	data.state = st;
	data.type = type;
	data.src_ip = src_ip;
	data.src_port = src_port;
	data.dst_ip = dst_ip;
	data.dst_port = dst_port;

	/* send(VMA_MSG_STATE) in blocking manner */
	sys_call(rc, send, m_sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_STATE) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}

int agent::create_agent_socket(void)
{
	int rc = 0;
	int optval = 1;
	struct timeval opttv;
	struct sockaddr_un sock_addr;

	/* Create UNIX UDP socket to receive data from VMA processes */
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, m_sock_file, sizeof(sock_addr.sun_path) - 1);
	/* remove possible old socket */
	unlink(m_sock_file);

	sys_call(m_sock_fd, socket, AF_UNIX, SOCK_DGRAM, 0);
	if (m_sock_fd < 0) {
		__log_dbg("Failed to call socket() errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	optval = 1;
	sys_call(rc, setsockopt, m_sock_fd, SOL_SOCKET, SO_REUSEADDR,
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
	sys_call(rc, setsockopt, m_sock_fd, SOL_SOCKET, SO_RCVTIMEO,
			(const void *)&opttv, sizeof(opttv));
	if (rc < 0) {
		__log_dbg("Failed to call setsockopt(SO_RCVTIMEO) errno %d (%s)\n",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* bind created socket */
	sys_call(rc, bind, m_sock_fd, (struct sockaddr *)&sock_addr,
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
