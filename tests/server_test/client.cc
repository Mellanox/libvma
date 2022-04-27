/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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


#include "client.h"
#include "options.h"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <cstring>
#include <stdexcept>
#include <boost/foreach.hpp>
#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <boost/format.hpp>
#include <boost/ref.hpp>
#include <algorithm>
#include <iostream>


client::client(const options& opts) {
    for (unsigned id = 0; id < opts.num_threads(); ++id) {
        m_connections.push_back(boost::make_shared<connection>(id,
                                                               opts.server(),
                                                               opts.port(),
                                                               opts.packet_rate()));
    }
}

void client::run() {
    boost::thread_group tg;

    BOOST_FOREACH(const connection_ptr& conn, m_connections) {
        tg.create_thread(boost::ref(*conn.get()));
    }

    tg.join_all();
}

client::connection::connection(unsigned id, const std::string& server,
                               unsigned port, size_t packet_rate) :
        m_id(id),
        m_packet_rate(packet_rate),
        m_psn(0)
{
    struct hostent *he = gethostbyname(server.c_str());
    if (!he) {
        throw std::runtime_error(std::string("failed to resolve ") + server);
    }

    m_dest_addr.sin_family = he->h_addrtype;
    m_dest_addr.sin_port = htons(port);
    if (he->h_length != sizeof(m_dest_addr.sin_addr)) {
        throw std::runtime_error("invalid address length");
    }

    memcpy(&m_dest_addr.sin_addr, he->h_addr_list[0], he->h_length);
    memset(m_dest_addr.sin_zero, 0, sizeof(m_dest_addr.sin_zero));
    m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_sockfd < 0) {
        throw std::runtime_error("failed to create socket");
    }

    m_epfd = epoll_create(1);
    if (m_epfd < 0) {
        throw std::runtime_error("failed to create epfd");
    }

    // Add the socket to the main epoll set
    struct epoll_event evt;
    evt.events   = EPOLLIN|EPOLLOUT;
    evt.data.fd  = m_sockfd;
    int ret = epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_sockfd, &evt);
    if (ret < 0) {
        throw std::runtime_error("failed to add socket fd to epoll set");
    }
}

client::connection::~connection() {
    close(m_epfd);
    close(m_sockfd);
}

std::string client::connection::destination() const {
    char buf[256] = {0};
    inet_ntop(m_dest_addr.sin_family, &m_dest_addr.sin_addr, buf, sizeof(buf) - 1);
    return (boost::format("%s:%d") % buf % ntohs(m_dest_addr.sin_port)).str();
}

void client::connection::operator()() {
    const size_t maxevents = 2;
    struct epoll_event events[maxevents];
    unsigned next_worker = 0;

    m_start_time = vtime::current();
    m_recv_count = 0;
    m_send_count = 0;
    m_rtt_sum = 0;

    size_t sent_prev = 0;
    size_t recv_prev = 0;
    vtime::time_t time_prev = m_start_time;
    vtime::time_t prev_rtt_sum = 0;
    vtime::time_t packet_interval = vtime::time_from_sec(1.0 / m_packet_rate);
    vtime::time_t last_send_time = m_start_time;
    size_t print_rate = std::min(200000ul, m_packet_rate);

    std::cout << "connection " << m_id << ": sending to " << destination() << std::endl;
    do {
        int nevents = epoll_wait(m_epfd, events, maxevents, -1);
        if (nevents < 0) {
            throw std::runtime_error("epoll_wait failed");
        }

        vtime:time_t current_time = vtime::current();

        for (int i = 0; i < nevents; ++i) {
            if (events[i].data.fd == m_sockfd) {
                if (events[i].events & EPOLLIN) {
                    int nrecvd = recvfrom(m_sockfd, &m_recvbuf, sizeof(m_recvbuf),
                                          0, NULL, NULL);
                    if (nrecvd != sizeof(m_sendbuf)) {
                        throw std::runtime_error("recvfrom failed");
                    }

                    m_rtt_sum += (current_time - m_recvbuf.send_time);
                    ++m_recv_count;
                }

                if (events[i].events & EPOLLOUT) {
                    if (current_time >= last_send_time + packet_interval) {
                        // TODO maintain packet rate
                        m_sendbuf.psn = m_psn++;
                        m_sendbuf.send_time = current_time;
                        int nsent = sendto(m_sockfd, &m_sendbuf, sizeof(m_sendbuf), 0,
                                           reinterpret_cast<struct sockaddr*>(&m_dest_addr),
                                           sizeof(m_dest_addr));
                        if (nsent != sizeof(m_sendbuf)) {
                            throw std::runtime_error("sendto failed");
                        }

                        ++m_send_count;
                        /*last_send_time += packet_interval;*/
                        last_send_time =
                                        (current_time + last_send_time + packet_interval) / 2;
                    }
                }
            }
        }

        if (m_send_count - sent_prev >= print_rate) {
            double rtt = (m_recv_count) > 0 ?
                            vtime::time_to_sec(
                                            (m_rtt_sum - prev_rtt_sum) * 1000000.0 /
                                            (m_recv_count - recv_prev)) :
                            0;

            double packet_rate = (m_send_count - sent_prev) /
                            vtime::time_to_sec(current_time - time_prev);

            double recv_ratio = (m_recv_count - recv_prev) /
                            static_cast<double>(m_send_count - sent_prev);

            printf("sent: %Zu rate: %7.2f recvd: %Zu (%5.2f%%) rtt: %5.2f\n",
                   m_send_count, packet_rate, m_recv_count, recv_ratio * 100.0,
                   rtt);

            sent_prev = m_send_count;
            recv_prev = m_recv_count;
            time_prev = current_time;
            prev_rtt_sum = m_rtt_sum;
        }

    } while (1);
}

