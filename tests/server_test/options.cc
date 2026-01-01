/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "options.h"

#include <getopt.h>
#include <cstdlib>


options::options (int argc, char **argv) :
    m_port(13737),
    m_packet_rate(0),
    m_num_threads(1),
    m_window(65536)
{
    char c;
    while ((c = getopt (argc, argv, "t:p:r:w:")) != -1) {
        switch (c) {
        case 't':
            m_num_threads = atoi(optarg);
            break;
        case 'p':
            m_port = atoi(optarg);
            break;
        case 'r':
            m_packet_rate = atol(optarg);
            break;
        case 'w':
            m_window = atol(optarg);
            break;
        }
    }

    if (optind < argc) {
        m_server = argv[optind];
    }
}

const std::string options::server() const {
    return m_server;
}

unsigned options::port() const {
    return m_port;
}

unsigned options::packet_rate() const {
    return m_packet_rate;
}

unsigned options::num_threads() const {
    return m_num_threads;
}

size_t options::window() const {
    return m_window;
}

bool options::is_server() const {
    return m_server.empty();
}
