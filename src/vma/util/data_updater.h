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

#ifndef SRC_VMA_UTIL_DATA_UPDATER_H_
#define SRC_VMA_UTIL_DATA_UPDATER_H_

#include "vma/proto/dst_entry.h"

class data_updater {
public:
	data_updater() {};
	virtual ~data_updater() = 0;
	virtual bool update_field(dst_entry &dst) = 0;
};

class header_ttl_updater: public data_updater {
public:
    header_ttl_updater(uint8_t ttl, bool is_unicast);
    virtual ~header_ttl_updater() {};
    virtual bool update_field(dst_entry &hdr);
private:
    uint8_t m_ttl;
    bool m_is_multicast;
};

class header_pcp_updater: public data_updater {
public:
    header_pcp_updater(uint8_t pcp);
    virtual ~header_pcp_updater() {};
    virtual bool update_field(dst_entry &hdr);
private:
    uint32_t m_pcp;
};

class header_tos_updater: public data_updater {
public:
    header_tos_updater(uint8_t pcp);
    virtual ~header_tos_updater() {};
    virtual bool update_field(dst_entry &hdr);
private:
    uint8_t m_tos;
};

class ring_alloc_logic_updater: public data_updater {
public:
    ring_alloc_logic_updater(int fd, lock_base & socket_lock,
    			     resource_allocation_key & ring_alloc_logic,
			     socket_stats_t* socket_stats);
    virtual ~ring_alloc_logic_updater() {};
    virtual bool update_field(dst_entry &hdr);
private:
    int m_fd;
    lock_base & m_socket_lock;
    resource_allocation_key & m_key;
    socket_stats_t* m_sock_stats;
};
#endif /* SRC_VMA_UTIL_DATA_UPDATER_H_ */
