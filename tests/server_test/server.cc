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


#include "server.h"
#include "options.h"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <cstring>
#include <stdexcept>
#include <boost/foreach.hpp>
#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <boost/format.hpp>
#include <boost/ref.hpp>
#include <iostream>

server::server(const options& opts) {

    struct sockaddr_in bind_addr;
    int ret;

    // Create the UDP socket
    m_udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_udp_sockfd < 0) {
        throw std::runtime_error("failed to create socket");
    }

    // Create the UDP socket
    m_tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_udp_sockfd < 0) {
        throw std::runtime_error("failed to create socket");
    }

    // Bind the socket to the given port
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(opts.port());
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    ret = bind(m_udp_sockfd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr));
    if (ret < 0) {
        throw std::runtime_error("failed to bind the UDP socket");
    }

    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(opts.port());
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    ret = bind(m_tcp_sockfd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr));
    if (ret < 0) {
        throw std::runtime_error("failed to bind the TCP socket");
    }

    ret = listen(m_tcp_sockfd, 100);
    if (ret < 0) {
        throw std::runtime_error("failed to listen");
    }

    ret = fcntl(m_udp_sockfd, F_SETFL, fcntl(m_udp_sockfd, F_GETFL) | O_NONBLOCK);
    if (ret < 0) {
        throw std::runtime_error("failed to make UDP socket nonblocking");
    }

    ret = fcntl(m_tcp_sockfd, F_SETFL, fcntl(m_tcp_sockfd, F_GETFL) | O_NONBLOCK);
    if (ret < 0) {
        throw std::runtime_error("failed to make TCP socket nonblocking");
    }

    // Create main epoll set
    m_epfd = epoll_create(2);
    if (m_epfd < 0) {
        throw std::runtime_error("failed to create epfd");
    }

    // Add the socket to the main epoll set
    struct epoll_event evt;
    evt.events    = EPOLLIN;
    evt.data.fd   = m_tcp_sockfd;
    ret = epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_tcp_sockfd, &evt);
    if (ret < 0) {
        throw std::runtime_error("failed to add socket fd to epoll set");
    }

    // Create the workers
    for (unsigned i = 0; i < opts.num_threads(); ++i) {
        m_workers.push_back(boost::make_shared<worker>(i, m_udp_sockfd));
    }
}

server::~server() {
    close(m_epfd);
    close(m_udp_sockfd);
}

void server::run() {
    boost::thread_group tg;

    BOOST_FOREACH(const worker_ptr& worker, m_workers) {
        tg.create_thread(boost::ref(*worker.get()));
    }

    do {
        const size_t maxevents = 2;
        struct epoll_event events[maxevents];

        epoll_wait(m_epfd, events, maxevents, 1000);
    } while(1);

    tg.join_all();
}

server::worker::worker(int id, int sockfd) :
        m_id(id), m_recv_sockfd(sockfd), m_buffer(1024)
{
    int ret;

    m_reply_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_reply_sockfd < 0) {
        throw std::runtime_error("failed to create socket");
    }

    // Create worker epoll set
    m_epfd = epoll_create(1);
    if (m_epfd < 0) {
        throw std::runtime_error("failed to create epfd");
    }

    // Add the socket to the main epoll set
    struct epoll_event evt;
    evt.events   = EPOLLIN;
    evt.data.fd  = m_recv_sockfd;
    ret = epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_recv_sockfd, &evt);
    if (ret < 0) {
        throw std::runtime_error("failed to add socket fd to epoll set");
    }

    // Add a pipe to the main epoll set
    int pipefds[2];
    pipe(pipefds);

    evt.events   = EPOLLIN;
    evt.data.fd  = pipefds[0];
    ret = epoll_ctl(m_epfd, EPOLL_CTL_ADD, pipefds[0], &evt);
    if (ret < 0) {
        throw std::runtime_error("failed to add pipe fd to epoll set");
    }
}

server::worker::~worker() {
    close(m_epfd);
    close(m_reply_sockfd);
}

void server::worker::operator()() {
    const size_t maxevents = 2;
    struct epoll_event events[maxevents];
    unsigned next_worker = 0;

    do {
        int nevents = epoll_wait(m_epfd, events, maxevents, 1000);
        if (nevents < 0 && errno == EINTR) {
            continue;
        }

        if (nevents < 0) {
            std::cerr << "errno=" << errno << std::endl;
            throw std::runtime_error("epoll_wait failed, errno");
        }

        for (int i = 0; i < nevents; ++i) {
            if (events[i].data.fd == m_recv_sockfd) {
                process_message();
            }
        }

    } while (1);
}

void server::worker::process_message() {
    struct sockaddr_in sender_addr;
    socklen_t sender_addrlen = sizeof(sender_addr);

    ssize_t recvd = recvfrom(m_recv_sockfd, &m_buffer[0], m_buffer.size(), 0,
                             reinterpret_cast<sockaddr*>(&sender_addr),
                             &sender_addrlen);
    if (recvd == -1 && errno == EAGAIN) {
        /* Some other time ... */
        return;
    }

    if (recvd < 0) {
        std::cerr << "recvfrom returned " << recvd << " errno=" << errno << std::endl;
        throw std::runtime_error("recvfrom failed");
    }

    ssize_t sent = sendto(m_reply_sockfd, &m_buffer[0], recvd, 0,
                          reinterpret_cast<sockaddr*>(&sender_addr),
                          sender_addrlen);
    if (recvd <= 0) {
        throw std::runtime_error("sendto failed");
    }

}
