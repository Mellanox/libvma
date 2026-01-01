/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "client.h"
#include "server.h"
#include "options.h"


int main(int argc, char **argv)
{
    options opts(argc, argv);

    if (opts.is_server()) {
        server s(opts);
        s.run();
    } else {
        client c(opts);
        c.run();
    }
    return 0;
}
