/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef PKT_SNDR_SOURCE_H
#define PKT_SNDR_SOURCE_H

/**
 * @class pkt_sndr_source
 * An object must implement pkt_sndr_source to register with ib_conn_mgr_base
 * When no packet transmitters (or receivers) are registered the objects will be
 * deleted.
 */
class pkt_sndr_source
{
public:
	virtual ~pkt_sndr_source() {};
};


#endif
