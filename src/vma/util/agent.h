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

#ifndef SRC_VMA_UTIL_AGENT_H_
#define SRC_VMA_UTIL_AGENT_H_

#include "vma/util/agent_def.h"

typedef struct agent_msg {
	struct list_head item;
	int length;
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

class agent : lock_spin {
public:
	agent();
	virtual ~agent();

	void progress(void);

	inline agent_state_t state(void) const
	{
		return m_state;
	}

	inline void put_msg(agent_msg_t *msg)
	{
		lock();
		list_add_tail(&msg->item, &m_wait_queue);
		unlock();
	}

	inline agent_msg_t* get_msg(void)
	{
		agent_msg_t *msg = NULL;
		int i = 0;

		lock();
		if (list_empty(&m_free_queue)) {
			for (i = 0; i < m_msg_grow; i++) {
				/* coverity[overwrite_var] */
				msg = (agent_msg_t *)malloc(sizeof(*msg));
				if (NULL == msg) {
					break;
				}
				msg->length = 0;
				list_add_tail(&msg->item, &m_free_queue);
				m_msg_num++;
			}
		}
		/* coverity[overwrite_var] */
		msg = list_first_entry(&m_free_queue, agent_msg_t, item);
		msg->length = 0;
		list_del_init(&msg->item);
		unlock();
		return msg;
	}

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

	int create_agent_socket(void);
	int send(agent_msg_t *msg);
	int send_msg_init(void);
	int send_msg_exit(void);
	int send_msg_state(uint32_t fid, uint8_t st, uint8_t type,
			uint32_t src_ip, uint16_t src_port,
			uint32_t dst_ip, uint16_t dst_port);
};

extern agent* g_p_agent;

#endif /* SRC_VMA_UTIL_AGENT_H_ */
