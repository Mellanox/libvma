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
