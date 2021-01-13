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

class vmad_flow : public vmad_base {
protected:
	struct vma_msg_flow m_data;
	pid_t m_pid;
	int m_if;
	int m_tap;
	vmad_flow()
	{

		char opt_val[IF_NAMESIZE];
		socklen_t opt_len;

		m_pid = 0x464C4F57;
		memset(&m_data, 0, sizeof(m_data));
		m_data.hdr.code = VMA_MSG_FLOW;
		m_data.hdr.ver = VMA_AGENT_VER;
		m_data.hdr.pid = m_pid;

		opt_val[0] = '\0';
		opt_len = sizeof(opt_val);
		sys_addr2dev(&server_addr, opt_val, opt_len);
		m_if = if_nametoindex(opt_val);
		sys_addr2dev(&client_addr, opt_val, opt_len);
		m_tap = if_nametoindex(opt_val);
		m_data.if_id = m_if;
		m_data.tap_id = m_tap;
	}

};

/**
 * @test vmad_flow.ti_1
 * @brief
 *    Send valid TCP 3tuple VMA_MSG_FLOW(ADD)
 * @details
 */
TEST_F(vmad_flow, ti_1) {
	int rc = 0;
	struct vma_hdr answer;

	rc = vmad_base::msg_init(m_pid);
	ASSERT_LT(0, rc);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_ADD;
	m_data.type = VMA_MSG_FLOW_TCP_3T;
	m_data.flow.dst_ip = server_addr.sin_addr.s_addr;
	m_data.flow.dst_port = server_addr.sin_port;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	rc = vmad_base::msg_exit(m_pid);
	ASSERT_LT(0, rc);
}

/**
 * @test vmad_flow.ti_2
 * @brief
 *    Send valid TCP 5tuple VMA_MSG_FLOW(ADD)
 * @details
 */
TEST_F(vmad_flow, ti_2) {
	int rc = 0;
	struct vma_hdr answer;

	rc = vmad_base::msg_init(m_pid);
	ASSERT_LT(0, rc);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_ADD;
	m_data.type = VMA_MSG_FLOW_TCP_5T;
	m_data.flow.dst_ip = server_addr.sin_addr.s_addr;
	m_data.flow.dst_port = server_addr.sin_port;
	m_data.flow.t5.src_ip = client_addr.sin_addr.s_addr;
	m_data.flow.t5.src_port = client_addr.sin_port;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	rc = vmad_base::msg_exit(m_pid);
	ASSERT_LT(0, rc);
}

/**
 * @test vmad_flow.ti_3
 * @brief
 *    Send valid 3tuple VMA_MSG_FLOW(ADD) and VMA_MSG_FLOW(DEL)
 * @details
 */
TEST_F(vmad_flow, ti_3) {
	int rc = 0;
	struct vma_hdr answer;

	rc = vmad_base::msg_init(m_pid);
	ASSERT_LT(0, rc);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_ADD;
	m_data.type = VMA_MSG_FLOW_TCP_3T;
	m_data.flow.dst_ip = server_addr.sin_addr.s_addr;
	m_data.flow.dst_port = server_addr.sin_port;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_DEL;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	rc = vmad_base::msg_exit(m_pid);
	ASSERT_LT(0, rc);
}

/**
 * @test vmad_flow.ti_4
 * @brief
 *    Send valid 5tuple VMA_MSG_FLOW(ADD) and VMA_MSG_FLOW(DEL)
 * @details
 */
TEST_F(vmad_flow, ti_4) {
	int rc = 0;
	struct vma_hdr answer;

	rc = vmad_base::msg_init(m_pid);
	ASSERT_LT(0, rc);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_ADD;
	m_data.type = VMA_MSG_FLOW_TCP_5T;
	m_data.flow.dst_ip = server_addr.sin_addr.s_addr;
	m_data.flow.dst_port = server_addr.sin_port;
	m_data.flow.t5.src_ip = client_addr.sin_addr.s_addr;
	m_data.flow.t5.src_port = client_addr.sin_port;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_DEL;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	rc = vmad_base::msg_exit(m_pid);
	ASSERT_LT(0, rc);
}

/**
 * @test vmad_flow.ti_51
 * @brief
 *    Send valid UDP 3tuple VMA_MSG_FLOW(ADD)
 * @details
 */
TEST_F(vmad_flow, ti_5) {
	int rc = 0;
	struct vma_hdr answer;

	rc = vmad_base::msg_init(m_pid);
	ASSERT_LT(0, rc);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_ADD;
	m_data.type = VMA_MSG_FLOW_UDP_3T;
	m_data.flow.dst_ip = server_addr.sin_addr.s_addr;
	m_data.flow.dst_port = server_addr.sin_port;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	rc = vmad_base::msg_exit(m_pid);
	ASSERT_LT(0, rc);
}

/**
 * @test vmad_flow.ti_6
 * @brief
 *    Send valid UDP 5tuple VMA_MSG_FLOW(ADD)
 * @details
 */
TEST_F(vmad_flow, ti_6) {
	int rc = 0;
	struct vma_hdr answer;

	rc = vmad_base::msg_init(m_pid);
	ASSERT_LT(0, rc);

	m_data.hdr.status = 1;
	m_data.action = VMA_MSG_FLOW_ADD;
	m_data.type = VMA_MSG_FLOW_UDP_5T;
	m_data.flow.dst_ip = server_addr.sin_addr.s_addr;
	m_data.flow.dst_port = server_addr.sin_port;
	m_data.flow.t5.src_ip = client_addr.sin_addr.s_addr;
	m_data.flow.t5.src_port = client_addr.sin_port;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	memset(&answer, 0, sizeof(answer));
	rc = recv(m_sock_fd, &answer, sizeof(answer), 0);
	EXPECT_EQ((int)sizeof(answer), rc);

	EXPECT_EQ((VMA_MSG_FLOW | VMA_MSG_ACK), answer.code);
	EXPECT_LE(VMA_AGENT_VER, answer.ver);
	EXPECT_EQ(m_pid, answer.pid);
	EXPECT_EQ(0, answer.status);

	rc = vmad_base::msg_exit(m_pid);
	ASSERT_LT(0, rc);
}

