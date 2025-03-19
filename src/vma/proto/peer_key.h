/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef __PEER_KEY_H__
#define __PEER_KEY_H__

/**
 * Use union for representing ip:port as one uint64_t primitive,
 *
 * NOTE: this type provides implicit cast to uint64_t. Hence, it natively supports containers such as map and hash.
 */
union peer_key {
public:
	peer_key(uint32_t _ip, uint16_t _port) : ip(_ip), port(_port){}
	operator uint64_t() const {return key;} // this saves the need for operator< and for operator== and for operator size_t() with map/hash

private:
	uint64_t key;

	struct {
		uint32_t ip;
		uint32_t port; // 32 bits for making sure all bits of key are initialized
	};
};

#endif /* ! __PEER_KEY_H__ */
