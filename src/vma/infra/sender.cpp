/*
 * Copyright © 2013-2024 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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

/*
 * sender.cpp
 *
 *  Created on: Feb 28, 2013
 *      Author: olgas
 */

#include "vma/infra/sender.h"

send_data::send_data(const send_info *si)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if(si == NULL) {
		m_iov.iov_base = NULL;
		m_iov.iov_len = 0;
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	uint8_t* buff = NULL;
	size_t total_len = 0;

	for(uint32_t i = 0;i < si->m_sz_iov;i++){
		total_len += si->m_p_iov[i].iov_len;
	}

	buff = new uint8_t[total_len];
	BULLSEYE_EXCLUDE_BLOCK_START
	if (NULL == buff) {
		m_iov.iov_base = NULL;
		m_iov.iov_len = 0;
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	memcpy_fromiovec(buff, si->m_p_iov, si->m_sz_iov, 0, total_len);
	m_iov.iov_base = buff;
	m_iov.iov_len = total_len;
}

send_data::~send_data()
{
	if(m_iov.iov_base) {
		delete[]((uint8_t *)m_iov.iov_base);
	}
}

