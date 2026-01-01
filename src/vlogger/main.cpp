/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include <stdlib.h>

#include "vlogger.h"

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

int main(int argc, char **argv)
{
    vlog_levels_t vlog_levels_init = VLOG_WARNING;
    if (argc > 1)
        vlog_levels_init = (vlog_levels_t)atoi(argv[1]);

    printf(">> starting vlogger in level: %d\n", (int)vlog_levels_init);
    vlog_start("Voltaire Logger test module: ", vlog_levels_init);

    vlog_printf(VLOG_PANIC, "%s: test log_print in level VLOG_PANIC\n", __func__);
    vlog_printf(VLOG_ERROR, "%s: test log_print in level VLOG_ERROR\n", __func__);
    vlog_printf(VLOG_WARNING, "%s: test log_print in level VLOG_WARNING\n", __func__);
    vlog_printf(VLOG_INFO, "%s: test log_print in level VLOG_INFO\n", __func__);
    vlog_printf(VLOG_DEBUG, "%s: test log_print in level VLOG_DEBUG\n", __func__);
    vlog_printf(VLOG_FUNC, "%s: test log_print in level VLOG_FUNC\n", __func__);
    vlog_printf(VLOG_FUNC_ALL, "%s: test log_print in level VLOG_FUNC_ALL\n", __func__);

    usleep(10000);

    vlog_stop();

	return 0;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
