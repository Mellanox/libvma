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
#ifndef __PEER_KEY_H__
#define __PEER_KEY_H__

/**
 * Use union for representing ip:port as one uint64_t primitive,
 *
 * NOTE: this type provides automatic silent cast to uint64_t.  Hence, it natively supports containers such as map and hash.
 * NO NEED to implement various operators (such as operator size_t(), operator==, operator<) for map and hash
 */
union peer_key {
public:
	peer_key(uint32_t _ip, uint16_t _port) : key(0), ip(_ip), port(_port){}
	operator uint64_t() const {return key;} // this will save the need for operator< and for operator== and for operator size_t() with map/hash

private:
	uint64_t key;

	struct {
		uint32_t ip;
		uint16_t port;
	};
};

#endif /* ! __PEER_KEY_H__ */
