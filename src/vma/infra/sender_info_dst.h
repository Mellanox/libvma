/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef SENDER_INFO_DST_H
#define SENDER_INFO_DST_H

#include "sender.h"
#include "proto/dst_entry.h"

class sender::send_info_dst: public sender::send_info
{
public:
	sender::send_info_dst(ibv_send_wr *send_wqe, dst_entry *dst_entry): m_p_send_wqe(send_wqe) {};
	sender::send_info_dst(): m_p_send_wqe(NULL) {};
	virtual ~send_info() {};

	dst_entry *m_p_send_wqe;

};



#endif /* SENDER_INFO_DST_H */
