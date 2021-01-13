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
