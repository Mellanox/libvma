/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef _SERVER_H_
#define _SERVER_H_

#include <boost/shared_ptr.hpp>
#include <boost/noncopyable.hpp>
#include <vector>

class options;

class server {
public:
    server(const options& opts);
    ~server();
    void run();
private:

    class worker : private boost::noncopyable {
    public:
        worker(int id, int sockfd);
        ~worker();

        void operator()();

        void process_message();

    private:
        int m_id;
        int m_recv_sockfd;
        int m_reply_sockfd;
        int m_epfd;
        std::vector<uint8_t> m_buffer;
    };

    typedef boost::shared_ptr<worker> worker_ptr;

    int m_udp_sockfd;
    int m_tcp_sockfd;
    int m_epfd;
    std::vector<worker_ptr> m_workers;
};

#endif
