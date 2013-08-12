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
		delete((uint8_t *)m_iov.iov_base);
	}
}

