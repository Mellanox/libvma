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
