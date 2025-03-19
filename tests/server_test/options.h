/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
