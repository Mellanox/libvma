/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
