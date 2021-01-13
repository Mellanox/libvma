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


#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "vtime.h"

#include <vector>
#include <string>
#include <arpa/inet.h>
#include <boost/shared_ptr.hpp>
#include <boost/noncopyable.hpp>

class options;

class client {
public:
    client(const options& opts);

    void run();
private:

    struct request {
        uint32_t    id;
        uint64_t    send_time;
    };


    class connection : private boost::noncopyable {
    public:
        connection(unsigned id, const std::string& server, unsigned port,
                   size_t packet_rate);
        ~connection();

        void operator()();

        std::string destination() const;

    private:
        struct packet {
            uint64_t   psn;
            uint64_t   send_time;
        };

        const unsigned        m_id;
        size_t                m_packet_rate;
        size_t                m_head, m_tail;
        struct sockaddr_in    m_dest_addr;
        int                   m_sockfd;
        int                   m_epfd;
        packet                m_sendbuf;
        packet                m_recvbuf;
        uint64_t              m_psn;
        size_t                m_recv_count;
        size_t                m_send_count;
        vtime::time_t         m_start_time;
        vtime::time_t         m_rtt_sum;
    };

    typedef boost::shared_ptr<connection> connection_ptr;

    std::vector<connection_ptr> m_connections;
};

#endif
