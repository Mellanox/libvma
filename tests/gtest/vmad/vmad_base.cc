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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "vmad_base.h"

#include "src/vma/util/agent_def.h"
#include "config.h"

void vmad_base::SetUp()
{
	int rc = 0 ;
	int optval = 1;
	struct timeval opttv;
	struct sockaddr_un sock_addr;

	errno = EOK;
	m_self_pid = getpid();
	m_vmad_pid = sys_procpid("vmad");
	m_base_name = "vma_gtest";
	SKIP_TRUE((m_vmad_pid > 0), "This test requires VMA daemon running");

	ASSERT_FALSE((mkdir(VMA_AGENT_PATH, 0777) != 0) && (errno != EEXIST));

	rc = snprintf(m_sock_file, sizeof(m_sock_file) - 1,
			"%s/%s.%d.sock", VMA_AGENT_PATH, m_base_name, m_self_pid);
	ASSERT_FALSE((rc < 0 ) || (rc == (sizeof(m_sock_file) - 1)));

	rc = snprintf(m_pid_file, sizeof(m_pid_file) - 1,
			"%s/%s.%d.pid", VMA_AGENT_PATH, m_base_name, m_self_pid);
	ASSERT_FALSE((rc < 0 ) || (rc == (sizeof(m_pid_file) - 1) ));

	m_pid_fd = open(m_pid_file,	O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
	ASSERT_FALSE(m_pid_fd < 0);

	/* Create UNIX UDP socket to receive data from VMA processes */
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, m_sock_file, sizeof(sock_addr.sun_path) - 1);
	/* remove possible old socket */
	unlink(m_sock_file);

	m_sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_FALSE(m_sock_fd < 0);

	optval = 1;
	rc = setsockopt(m_sock_fd, SOL_SOCKET, SO_REUSEADDR,
			(const void *)&optval, sizeof(optval));
	ASSERT_FALSE(rc < 0);

	/* Sets the timeout value as 1 sec that specifies the maximum amount of time
	 * an input function waits until it completes.
	 */
	opttv.tv_sec = 1;
	opttv.tv_usec = 0;
	rc = setsockopt(m_sock_fd, SOL_SOCKET, SO_RCVTIMEO,
			(const void *)&opttv, sizeof(opttv));
	ASSERT_FALSE(rc < 0);

	/* bind created socket */
	rc = bind(m_sock_fd, (struct sockaddr *)&sock_addr,
			sizeof(sock_addr));
	ASSERT_FALSE(rc < 0);

	/* Set server address */
	memset(&m_server_addr, 0, sizeof(m_server_addr));
	m_server_addr.sun_family = AF_UNIX;
	strncpy(m_server_addr.sun_path, VMA_AGENT_ADDR, sizeof(m_server_addr.sun_path) - 1);

	rc = connect(m_sock_fd, (struct sockaddr *)&m_server_addr,
			sizeof(struct sockaddr_un));
	ASSERT_FALSE(rc < 0);
}

void vmad_base::TearDown()
{
	close(m_sock_fd);
	unlink(m_sock_file);

	close(m_pid_fd);
	unlink(m_pid_file);
}

int vmad_base::msg_init(pid_t pid)
{
	int rc = 0;
	struct vma_msg_init data;
	uint8_t *version;

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_INIT;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = pid;
	version = (uint8_t *)&data.ver;
	version[0] = PRJ_LIBRARY_MAJOR;
	version[1] = PRJ_LIBRARY_MINOR;
	version[2] = PRJ_LIBRARY_RELEASE;
	version[3] = PRJ_LIBRARY_REVISION;

	errno = 0;
	rc = send(m_sock_fd, &data, sizeof(data), 0);
	if (rc != sizeof(data)) {
		rc = -ECONNREFUSED;
		goto err;
	}

	memset(&data, 0, sizeof(data));
	rc = recv(m_sock_fd, &data, sizeof(data), 0);
	if (rc != sizeof(data)) {
		rc = -ECONNREFUSED;
		goto err;
	}

	if (data.hdr.code != (VMA_MSG_INIT | VMA_MSG_ACK) ||
			data.hdr.ver < VMA_AGENT_VER ||
			data.hdr.pid != pid) {
		log_error("Protocol version mismatch: code = 0x%X ver = 0x%X pid = %d\n",
				data.hdr.code, data.hdr.ver, data.hdr.pid);
		rc = -EPROTO;
		goto err;
	}

err:
	return rc;
}

int vmad_base::msg_exit(pid_t pid)
{
	int rc = 0;
	struct vma_msg_exit data;

	memset(&data, 0, sizeof(data));
	data.hdr.code = VMA_MSG_EXIT;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = pid;

	errno = 0;
	rc = send(m_sock_fd, &data, sizeof(data), 0);
	if (rc != sizeof(data)) {
		rc = -ECONNREFUSED;
		goto err;
	}

err:
	return rc;
}
