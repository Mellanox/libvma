/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#include "vma/proto/L2_address.h"
#include "vlogger/vlogger.h"
#include "vma/util/bullseye.h"


#define MODULE_NAME 		"L2_addr"

#define L2_panic		__log_panic
#define	L2_logerr               __log_info_err
#define L2_logwarn              __log_info_warn
#define L2_loginfo              __log_info_info
#define L2_logdbg               __log_info_dbg
#define L2_logfunc              __log_info_func
#define L2_logfuncall           __log_info_funcall

L2_address::L2_address(address_t const address, addrlen_t const len)
{
	set(address, len);
}

void L2_address::set(address_t const address, addrlen_t const len)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (len <= 0 || len > L2_ADDR_MAX)
		L2_panic("len = %d", len);

	if (address == NULL)
		L2_panic("address == NULL");
	BULLSEYE_EXCLUDE_BLOCK_END

	// Copy the new address
	m_len = len;
	memcpy((void*)m_p_raw_address, (void*)address, m_len);
}

bool L2_address::compare(L2_address const& other) const
{
	if (other.m_len != m_len)
		return false;
	return (!memcmp((void*)other.m_p_raw_address, (void*)m_p_raw_address, m_len));
}

const std::string ETH_addr::to_str() const
{
	char s[100];
	if (m_len > 0)
		sprintf(s, ETH_HW_ADDR_PRINT_FMT, ETH_HW_ADDR_PRINT_ADDR(m_p_raw_address));
	return (std::string(s));
}

const std::string IPoIB_addr::to_str() const
{
	char s[100];
	if (m_len > 0)
		sprintf(s, IPOIB_HW_ADDR_PRINT_FMT, IPOIB_HW_ADDR_PRINT_ADDR(m_p_raw_address));
	return (std::string(s));
}

void IPoIB_addr::extract_qpn()
{
	unsigned char rem_qpn[4];

	rem_qpn[0] = m_p_raw_address[3];
	rem_qpn[1] = m_p_raw_address[2];
	rem_qpn[2] = m_p_raw_address[1];
	rem_qpn[3] = 0;
	memcpy(&m_qpn, rem_qpn, 4);
	L2_logdbg("qpn = %#x", m_qpn);
}


