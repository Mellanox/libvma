/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "vmad_base.h"

#include "src/vma/util/agent_def.h"
#include "src/vma/lwip/tcp.h"

class vmad_state : public vmad_base {
protected:
	void SetUp()
	{
		vmad_base::SetUp();

		m_pid = 0x53544154;
		memset(&m_data, 0, sizeof(m_data));
		m_data.hdr.code = VMA_MSG_STATE;
		m_data.hdr.ver = VMA_AGENT_VER;
		m_data.hdr.pid = m_pid;
	}
	void TearDown()
	{
		vmad_base::TearDown();
	}

protected:
	struct vma_msg_state m_data;
	pid_t m_pid;
};

/**
 * @test vmad_state.ti_1
 * @brief
 *    Send valid VMA_MSG_STATE
 * @details
 */
TEST_F(vmad_state, ti_1) {
	int rc = 0;

	rc = vmad_base::msg_init(m_pid);
	ASSERT_LT(0, rc);

	m_data.fid = 0;
	m_data.state = ESTABLISHED;
	m_data.type = SOCK_STREAM;
	m_data.src_ip = client_addr.sin_addr.s_addr;
	m_data.src_port = client_addr.sin_port;
	m_data.dst_ip = server_addr.sin_addr.s_addr;
	m_data.dst_port = server_addr.sin_port;

	errno = 0;
	rc = send(m_sock_fd, &m_data, sizeof(m_data), 0);
	EXPECT_EQ(0, errno);
	EXPECT_EQ((int)sizeof(m_data), rc);

	rc = vmad_base::msg_exit(m_pid);
	ASSERT_LT(0, rc);
}
