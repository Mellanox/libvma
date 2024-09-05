/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
