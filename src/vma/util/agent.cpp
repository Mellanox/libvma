/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#define AGENT_DEFAULT_MSG_NUM    (512)
#define AGENT_DEFAULT_MSG_GROW   (16) /* number of messages to grow */
#define AGENT_DEFAULT_INACTIVE   (10) /* periodic time for establishment connection attempts (in sec) */
#define AGENT_DEFAULT_ALIVE      (1)  /* periodic time for alive check (in sec) */


/* Force system call */
#define sys_call(_result, _func, ...) \
	do {                                              \
		if (orig_os_api._func)                        \
			_result = orig_os_api._func(__VA_ARGS__); \
		else                                          \
			_result = ::_func(__VA_ARGS__);           \
	} while (0)

/* Print user notification */
#define output_fatal() \
	do { \
		vlog_levels_t _level = (mce_sys_var::HYPER_MSHV == safe_mce_sys().hypervisor ?          \
						VLOG_WARNING : VLOG_DEBUG); \
		vlog_printf(_level, "*************************************************************\n"); \
		if (rc == -EPROTONOSUPPORT) \
			vlog_printf(_level, "* Protocol version mismatch was found between the library and the service. *\n"); \
		else 																			        \
			vlog_printf(_level, "* Can not establish connection with the service.      *\n"); \
		vlog_printf(_level, "* UDP/TCP connections are likely to be limited.             *\n"); \
		vlog_printf(_level, "*************************************************************\n"); \
	} while (0)

agent* g_p_agent = NULL;


agent::agent() :
		m_state(AGENT_CLOSED), m_sock_fd(-1), m_pid_fd(-1),
		m_msg_num(AGENT_DEFAULT_MSG_NUM)
{
	int rc = 0;
	agent_msg_t *msg = NULL;
	int i = 0;

	INIT_LIST_HEAD(&m_cb_queue);
	INIT_LIST_HEAD(&m_free_queue);
	INIT_LIST_HEAD(&m_wait_queue);

	/* Fill free queue with empty messages */
	i = m_msg_num;
	m_msg_num = 0;
	const char *path = safe_mce_sys().service_notify_dir;
	while (i--) {
		/* coverity[overwrite_var] */
		msg = (agent_msg_t *)calloc(1, sizeof(*msg));
		if (NULL == msg) {
			rc = -ENOMEM;
			__log_dbg("failed queue creation (rc = %d)", rc);
			goto err;
		}
		msg->length = 0;
		msg->tag = AGENT_MSG_TAG_INVALID;
		list_add_tail(&msg->item, &m_free_queue);
		m_msg_num++;
	}

	if ((mkdir(path, 0777) != 0) && (errno != EEXIST)) {
		rc = -errno;
		__log_dbg("failed create folder %s (rc = %d)", path, rc);
		goto err;
	}

	rc = snprintf(m_sock_file, sizeof(m_sock_file) - 1,
			"%s/%s.%d.sock", path, VMA_AGENT_BASE_NAME, getpid());
	if ((rc < 0 ) || (rc == (sizeof(m_sock_file) - 1) )) {
		rc = -ENOMEM;
		__log_dbg("failed allocate sock file (rc = %d)", rc);
		goto err;
	}

	rc = snprintf(m_pid_file, sizeof(m_pid_file) - 1,
			"%s/%s.%d.pid", path, VMA_AGENT_BASE_NAME, getpid());
	if ((rc < 0 ) || (rc == (sizeof(m_pid_file) - 1) )) {
		rc = -ENOMEM;
		__log_dbg("failed allocate pid file (rc = %d)", rc);
		goto err;
	}

	sys_call(m_pid_fd, open, m_pid_file,
			O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
	if (m_pid_fd < 0) {
		rc = -errno;
		__log_dbg("failed open pid file (rc = %d)", rc);
		goto err;
	}

	rc = create_agent_socket();
	if (rc < 0) {
		__log_dbg("failed open sock file (rc = %d)", rc);
		goto err;
	}

	/* Initialization is mostly completed
	 * At the moment it does not matter if connection with
	 * daemon can be done here or later
	 */
	m_state = AGENT_INACTIVE;

	rc = send_msg_init();
	if (rc < 0) {
		__log_dbg("failed establish connection with daemon (rc = %d)", rc);
		goto err;
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
	agent_callback_t *cb = NULL;

	if (AGENT_CLOSED == m_state) {
		return ;
	}

	progress();
	send_msg_exit();

	m_state = AGENT_CLOSED;

	/* This delay is needed to allow process EXIT message
	 * before event from system file monitor is raised
	 */
	usleep(1000);

	while (!list_empty(&m_cb_queue)) {
		cb = list_first_entry(&m_cb_queue, agent_callback_t, item);
		list_del_init(&cb->item);
		free(cb);
	}

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

void agent::register_cb(agent_cb_t fn, void *arg)
{
	agent_callback_t *cb = NULL;
	struct list_head *entry = NULL;

	if (AGENT_CLOSED == m_state) {
		return ;
	}

	if (NULL == fn) {
		return ;
	}

	m_cb_lock.lock();
	/* check if it exists in the queue */
	list_for_each(entry, &m_cb_queue) {
		cb = list_entry(entry, agent_callback_t, item);
		if ((cb->cb == fn) && (cb->arg == arg)) {
			m_cb_lock.unlock();
			return ;
		}
	}
	/* allocate new callback element and add to the queue */
	cb = (agent_callback_t *)calloc(1, sizeof(*cb));
	if (cb) {
		cb->cb = fn;
		cb->arg = arg;
		list_add_tail(&cb->item, &m_cb_queue);
	}
	m_cb_lock.unlock();
	/* coverity[leaked_storage] */
}

void agent::unregister_cb(agent_cb_t fn, void *arg)
{
	agent_callback_t *cb = NULL;
	struct list_head *entry = NULL;

	if (AGENT_CLOSED == m_state) {
		return ;
	}

	m_cb_lock.lock();
	/* find element in the queue and remove one */
	list_for_each(entry, &m_cb_queue) {
		cb = list_entry(entry, agent_callback_t, item);
		if ((cb->cb == fn) && (cb->arg == arg)) {
			list_del_init(&cb->item);
			free(cb);
			m_cb_lock.unlock();
			return ;
		}
	}
	m_cb_lock.unlock();
}

int agent::put(const void *data, size_t length, intptr_t tag)
{
	agent_msg_t *msg = NULL;
	int i = 0;

	if (AGENT_CLOSED == m_state) {
		return 0;
	}

	if (m_sock_fd < 0) {
		return -EBADF;
	}

	if (length > sizeof(msg->data)) {
		return -EINVAL;
	}

	m_msg_lock.lock();

	/* put any message in case agent is active to avoid queue uncontrolled grow
         * progress() function is able to call registered callbacks in case
         * it detects that link with daemon is up
         */
	if (AGENT_ACTIVE == m_state) {
		/* allocate new message in case free queue is empty */
		if (list_empty(&m_free_queue)) {
			for (i = 0; i < AGENT_DEFAULT_MSG_GROW; i++) {
				/* coverity[overwrite_var] */
				msg = (agent_msg_t *)malloc(sizeof(*msg));
				if (NULL == msg) {
					break;
				}
				msg->length = 0;
				msg->tag = AGENT_MSG_TAG_INVALID;
				list_add_tail(&msg->item, &m_free_queue);
				m_msg_num++;
			}
		}
		/* get message from free queue */
		/* coverity[overwrite_var] */
		msg = list_first_entry(&m_free_queue, agent_msg_t, item);
		list_del_init(&msg->item);

		/* put message into wait queue */
		list_add_tail(&msg->item, &m_wait_queue);
	}

	/* update message */
	if (msg) {
		memcpy(&msg->data, data, length);
		msg->length = length;
		msg->tag = tag;
	}

	m_msg_lock.unlock();

	return 0;
}

void agent::progress(void)
{
	agent_msg_t* msg = NULL;
	struct timeval tv_now = TIMEVAL_INITIALIZER;
	static struct timeval tv_inactive_elapsed = TIMEVAL_INITIALIZER;
	static struct timeval tv_alive_elapsed = TIMEVAL_INITIALIZER;

	if (AGENT_CLOSED == m_state) {
		return ;
	}

	gettime(&tv_now);

	/* Attempt to establish connection with daemon */
	if (AGENT_INACTIVE == m_state) {
		/* Attempt can be done less often than progress in active state */
		if (tv_cmp(&tv_inactive_elapsed, &tv_now, <)) {
			tv_inactive_elapsed = tv_now;
			tv_inactive_elapsed.tv_sec += AGENT_DEFAULT_INACTIVE;
			if (0 <= send_msg_init()) {
				progress_cb();
				goto go;
			}
		}
		return ;
	}

go:
	/* Check connection with daemon during active state */
	if (list_empty(&m_wait_queue)) {
		if (tv_cmp(&tv_alive_elapsed, &tv_now, <)) {
			check_link();
		}
	} else {
		tv_alive_elapsed = tv_now;
		tv_alive_elapsed.tv_sec += AGENT_DEFAULT_ALIVE;

		/* Process all messages that are in wait queue */
		m_msg_lock.lock();
		while (!list_empty(&m_wait_queue)) {
			msg = list_first_entry(&m_wait_queue, agent_msg_t, item);
			if (0 > send(msg)) {
				break;
			}
			list_del_init(&msg->item);
			msg->length = 0;
			msg->tag = AGENT_MSG_TAG_INVALID;
			list_add_tail(&msg->item, &m_free_queue);
		}
		m_msg_lock.unlock();
	}
}

void agent::progress_cb(void)
{
	agent_callback_t *cb = NULL;
	struct list_head *entry = NULL;

	m_cb_lock.lock();
	list_for_each(entry, &m_cb_queue) {
		cb = list_entry(entry, agent_callback_t, item);
		cb->cb(cb->arg);
	}
	m_cb_lock.unlock();
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
		__log_dbg("Failed to send() errno %d (%s)",
				errno, strerror(errno));
		rc = -errno;
		m_state = AGENT_INACTIVE;
		__log_dbg("Agent is inactivated. state = %d", m_state);
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

	if (AGENT_ACTIVE == m_state) {
		return 0;
	}

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
		__log_dbg("Failed to connect() errno %d (%s)",
				errno, strerror(errno));
		rc = -ECONNREFUSED;
		goto err;
	}

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_INIT;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	version = (uint8_t *)&data.ver;
	version[0] = PRJ_LIBRARY_MAJOR;
	version[1] = PRJ_LIBRARY_MINOR;
	version[2] = PRJ_LIBRARY_RELEASE;
	version[3] = PRJ_LIBRARY_REVISION;

	/* send(VMA_MSG_INIT) in blocking manner */
	sys_call(rc, send, m_sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_INIT) errno %d (%s)",
				errno, strerror(errno));
		rc = -ECONNREFUSED;
		goto err;
	}

	/* recv(VMA_MSG_INIT|ACK) in blocking manner */
	memset(&data, 0, sizeof(data));
	sys_call(rc, recv, m_sock_fd, &data, sizeof(data), 0);
	if (rc < (int)sizeof(data)) {
		__log_dbg("Failed to recv(VMA_MSG_INIT) errno %d (%s)",
				errno, strerror(errno));
		rc = -ECONNREFUSED;
		goto err;
	}

	if (data.hdr.code != (VMA_MSG_INIT | VMA_MSG_ACK) ||
			data.hdr.pid != getpid()) {
		__log_dbg("Protocol is not supported: code = 0x%X pid = %d",
				data.hdr.code, data.hdr.pid);
		rc = -EPROTO;
		goto err;
	}

	if (data.hdr.ver < VMA_AGENT_VER) {
		__log_dbg("Protocol version mismatch: agent ver = 0x%X service ver = 0x%X",
				VMA_AGENT_VER, data.hdr.ver);
		rc = -EPROTONOSUPPORT;
		goto err;
	}

	m_state = AGENT_ACTIVE;
	__log_dbg("Agent is activated. state = %d", m_state);

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
	__log_dbg("Agent is inactivated. state = %d", m_state);

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_EXIT;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();

	/* send(VMA_MSG_EXIT) in blocking manner */
	sys_call(rc, send, m_sock_fd, &data, sizeof(data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_EXIT) errno %d (%s)",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	return 0;
err:
	return rc;
}

int agent::send_msg_flow(struct vma_msg_flow *data)
{
	int rc = 0;
	struct vma_msg_flow answer;

	if (AGENT_ACTIVE != m_state) {
		return -ENODEV;
	}

	if (m_sock_fd < 0) {
		return -EBADF;
	}

	/* wait answer */
	data->hdr.status = 1;

	/* send(VMA_MSG_TC) in blocking manner */
	sys_call(rc, send, m_sock_fd, data, sizeof(*data), 0);
	if (rc < 0) {
		__log_dbg("Failed to send(VMA_MSG_TC) errno %d (%s)",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* recv(VMA_MSG_TC|ACK) in blocking manner */
	memset(&answer, 0, sizeof(answer));
	sys_call(rc, recv, m_sock_fd, &answer.hdr, sizeof(answer.hdr), 0);
	if (rc < (int)sizeof(answer.hdr)) {
		__log_dbg("Failed to recv(VMA_MSG_TC) errno %d (%s)",
				errno, strerror(errno));
		rc = -ECONNREFUSED;
		goto err;
	}

	/* reply sanity check */
	if (!(answer.hdr.code == (data->hdr.code | VMA_MSG_ACK) &&
			answer.hdr.ver == data->hdr.ver &&
			answer.hdr.pid == data->hdr.pid)) {
		__log_dbg("Protocol version mismatch: code = 0x%X ver = 0x%X pid = %d",
				answer.hdr.code, answer.hdr.ver, answer.hdr.pid);
		rc = -EPROTO;
		goto err;
	}

	rc = answer.hdr.status;
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
		__log_dbg("Failed to call socket() errno %d (%s)",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	optval = 1;
	sys_call(rc, setsockopt, m_sock_fd, SOL_SOCKET, SO_REUSEADDR,
			(const void *)&optval, sizeof(optval));
	if (rc < 0) {
		__log_dbg("Failed to call setsockopt(SO_REUSEADDR) errno %d (%s)",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* Sets the timeout value as 3 sec that specifies the maximum amount of time
	 * an input function waits until it completes.
	 */
	opttv.tv_sec = 3;
	opttv.tv_usec = 0;
	sys_call(rc, setsockopt, m_sock_fd, SOL_SOCKET, SO_RCVTIMEO,
			(const void *)&opttv, sizeof(opttv));
	if (rc < 0) {
		__log_dbg("Failed to call setsockopt(SO_RCVTIMEO) errno %d (%s)",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* bind created socket */
	sys_call(rc, bind, m_sock_fd, (struct sockaddr *)&sock_addr,
			sizeof(sock_addr));
	if (rc < 0) {
		__log_dbg("Failed to call bind() errno %d (%s)",
				errno, strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}

void agent::check_link(void)
{
	int rc = 0;
	static struct sockaddr_un server_addr;
	static int flag = 0;

	/* Set server address */
	if (!flag) {
		flag = 1;
		memset(&server_addr, 0, sizeof(server_addr));
		server_addr.sun_family = AF_UNIX;
		strncpy(server_addr.sun_path, VMA_AGENT_ADDR, sizeof(server_addr.sun_path) - 1);
	}

	sys_call(rc, connect, m_sock_fd, (struct sockaddr *)&server_addr,
			sizeof(struct sockaddr_un));
	if (rc < 0) {
		__log_dbg("Failed to connect() errno %d (%s)",
				errno, strerror(errno));
		m_state = AGENT_INACTIVE;
		__log_dbg("Agent is inactivated. state = %d", m_state);
	}
}
