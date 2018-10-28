/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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

#include "data_updater.h"

data_updater::~data_updater()
{

}

header_ttl_updater::header_ttl_updater(uint8_t ttl)
	: data_updater()
	, m_ttl(ttl)
{

}

bool header_ttl_updater::update_field(dst_entry &dst)
{
	dst.set_ip_ttl(m_ttl);
	return true;
}

header_pcp_updater::header_pcp_updater(uint8_t pcp)
	: data_updater()
	, m_pcp(pcp)
{

}

bool header_pcp_updater::update_field(dst_entry &dst)
{
	return dst.set_pcp(m_pcp);
}

header_tos_updater::header_tos_updater(uint8_t tos)
	: data_updater()
	, m_tos(tos)
{

}

bool header_tos_updater::update_field(dst_entry &dst)
{
	dst.set_ip_tos(m_tos);
	return true;
}

