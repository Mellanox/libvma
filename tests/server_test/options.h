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


#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include <string>

class options {
public:
    options (int argc, char **argv);

    const std::string server() const;

    unsigned port() const;

    unsigned packet_rate() const;

    unsigned num_threads() const;

    size_t window() const;

    bool is_server() const;

private:
    std::string  m_server;
    unsigned     m_port;
    unsigned     m_packet_rate;
    unsigned     m_num_threads;
    size_t       m_window;  /* NUmber of requests to remember */
};

#endif
