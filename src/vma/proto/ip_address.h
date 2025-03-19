/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include <stdio.h>
#include "vma/util/to_str.h"
#include "vma/util/vtypes.h"

/* coverity[missing_move_assignment] */
class ip_address : public tostr
{
public:
	ip_address(in_addr_t ip): m_ip(ip){};
	~ip_address(){};

	const std::string to_str() const
	{
		char s[20];
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		sprintf(s, "%d.%d.%d.%d", NIPQUAD(m_ip));
		return(std::string(s));
	}

	in_addr_t 	get_in_addr() const { return m_ip; };
	bool 		is_mc() { return (IN_MULTICAST_N(m_ip)); };

	bool operator==(const ip_address &ip) const { return (m_ip == ip.get_in_addr()); };

private:
	in_addr_t m_ip;
};

namespace std {
template<>
class hash<ip_address>
{
public:
	size_t operator()(const ip_address &key) const
	{
		hash<int>_hash;
		return _hash(key.get_in_addr());
	}
};
}


#endif /* IP_ADDRESS_H */
