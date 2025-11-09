/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef L2_ADDRESS_H
#define L2_ADDRESS_H

#include <infiniband/verbs.h>
#include <stdio.h>
#include <string.h>

#include "vma/util/to_str.h"
#include "vma/util/vtypes.h"

typedef size_t 		addrlen_t;
typedef unsigned char* 	address_t;

// 20 Bytes will
#define L2_ADDR_MAX	20

class L2_address : public tostr
{
public:
	L2_address(address_t const address, addrlen_t const len);
	L2_address() : m_len(0) {};
	virtual ~L2_address() {};

	virtual L2_address* clone() const = 0;

	void		set(address_t const address, addrlen_t const len);

	addrlen_t	get_addrlen() const { return m_len; };
	address_t	get_address() const { return (address_t)m_p_raw_address; };

	virtual bool 	compare(L2_address const& other) const;

protected:
	addrlen_t	m_len;
	unsigned char	m_p_raw_address[L2_ADDR_MAX];
};

class ETH_addr : public L2_address
{
public:
	ETH_addr(address_t const address) : L2_address(address, 6) {};
	~ETH_addr() {};
	const std::string to_str() const;

	virtual L2_address* clone() const
	{
		return (new ETH_addr(get_address()));
	}
};

#endif /* L2_ADDRESS_H */
