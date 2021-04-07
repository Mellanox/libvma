/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include <stdio.h>
#include "vma/util/to_str.h"
#include "vma/util/vtypes.h"
#include <tr1/unordered_map>

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

namespace std { namespace tr1 {
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
}}


#endif /* IP_ADDRESS_H */
