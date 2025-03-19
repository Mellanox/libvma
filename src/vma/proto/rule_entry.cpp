/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "rule_entry.h"
#include "rule_table_mgr.h"
#include "vma/infra/cache_subject_observer.h"

#define MODULE_NAME 		"rre"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[%s]:%d:%s() "
#undef	__INFO__
#define __INFO__		to_str().c_str()

#define rr_entry_logdbg		__log_info_dbg

rule_entry::rule_entry(route_rule_table_key rrk) :
	cache_entry_subject<route_rule_table_key, std::deque<rule_val*>*>(rrk)
{
	m_val = &values;
}

bool rule_entry::get_val(INOUT std::deque<rule_val*>* &val)
{
	rr_entry_logdbg("");
	val = m_val;
	return is_valid();
}

