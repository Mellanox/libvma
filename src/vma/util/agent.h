/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef SRC_VMA_UTIL_AGENT_H_
#define SRC_VMA_UTIL_AGENT_H_

#include "vma/util/agent_def.h"

typedef struct agent_msg {
	struct list_head item;
	int length;
	intptr_t tag;
	union {
		struct vma_msg_state state;
		char raw[1];
	} data;
} agent_msg_t;

typedef enum {
	AGENT_INACTIVE,
	AGENT_ACTIVE,
	AGENT_CLOSED
} agent_state_t;

#define AGENT_MSG_TAG_INVALID (-1)

class agent : lock_spin {
public:
	agent();
	virtual ~agent();

	inline agent_state_t state(void) const
	{
		return m_state;
	}

	int put(const void *data, size_t length, intptr_t tag, void **saveptr);
	void progress(void);

private:
	/* state of this object */
	agent_state_t m_state;

	/* socket used for communication with daemon */
	int m_sock_fd;

	/* file descriptor that is tracked by daemon */
	int m_pid_fd;

	/* unix socket name
	 * size should be less than sockaddr_un.sun_path
	 */
	char m_sock_file[100];

	/* name of pid file */
	char m_pid_file[100];

	/* queue of message elements
	 * this queue stores unused messages
	 */
	struct list_head         m_free_queue;

	/* queue of message elements
	 * this queue stores messages from different sockinfo (sockets)
	 */
	struct list_head         m_wait_queue;

	/* total number of allocated messages
	 * some amount of messages are allocated during initialization
	 * but total number can grow during run-time
	 */
	int m_msg_num;

	/* number of messages to grow */
	int m_msg_grow;

	/* periodic time for establishment connection attempts (in sec) */
	int m_interval_treshold;

	int create_agent_socket(void);
	int send(agent_msg_t *msg);
	int send_msg_init(void);
	int send_msg_exit(void);
};

extern agent* g_p_agent;

#endif /* SRC_VMA_UTIL_AGENT_H_ */
