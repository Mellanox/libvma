/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "vma/lwip/cc.h"
#include "vma/lwip/tcp.h"

#if TCP_CC_ALGO_MOD

static void	none_cc_conn_init(struct tcp_pcb *pcb);

struct cc_algo none_cc_algo = {
		.name = "none_cc",
		.conn_init = none_cc_conn_init,
};

static void
none_cc_conn_init(struct tcp_pcb *pcb)
{
	pcb->cwnd = UINT32_MAX;
}

#endif //TCP_CC_ALGO_MOD
