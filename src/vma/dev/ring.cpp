/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "ring.h"
#include "vma/proto/route_table_mgr.h"

#undef  MODULE_NAME
#define MODULE_NAME     "ring"
#undef  MODULE_HDR
#define MODULE_HDR      MODULE_NAME "%d:%s() "

ring::ring() :
	m_p_n_rx_channel_fds(NULL), m_parent(NULL)
{
	m_if_index = 0;

	print_val();
}

ring::~ring()
{
}

void ring::print_val()
{
	ring_logdbg("%d: %p: parent %p",
			m_if_index, this, ((uintptr_t)this == (uintptr_t)m_parent ? 0 : m_parent));
}
