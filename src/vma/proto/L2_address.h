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
	address_t	get_address() const { return (const address_t)m_p_raw_address; };

	virtual bool 	compare(L2_address const& other) const;

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual void 	operator=(L2_address const& other) const
	{
		memcpy((void*)this, (void*)&other, sizeof(L2_address));
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

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

class IPoIB_addr : public L2_address
{
public:
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	IPoIB_addr(): L2_address(), m_qpn(0)
	{

	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	//This constructor is for UC
	IPoIB_addr(address_t const address) : L2_address(address, 20), m_qpn(0)
	{
		extract_qpn();
	};
	//This constructor is for MC
	IPoIB_addr(uint32_t qpn, address_t const address) : L2_address(address, 20), m_qpn(qpn) {};
	~IPoIB_addr() {};

	virtual L2_address* clone() const
	{
		uint32_t qpn = ((IPoIB_addr*)this)->get_qpn();
		return (new IPoIB_addr(qpn, get_address()));
	}

	void 		set_qpn(uint32_t qpn) { m_qpn = qpn; };
	uint32_t 	get_qpn() { return m_qpn; };

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual void 	operator=(IPoIB_addr const& other) const
	{
		memcpy((void*)this, (void*)&other, sizeof(IPoIB_addr));
	}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	const std::string to_str() const;

private:
	uint32_t 	m_qpn;

	void		extract_qpn();
};

#endif /* L2_ADDRESS_H */
