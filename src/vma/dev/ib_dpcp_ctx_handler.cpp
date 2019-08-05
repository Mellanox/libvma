/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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
#include "ib_dpcp_ctx_handler.h"
#include "util/valgrind.h"
#include "vma/ib/mlx5/ib_mlx5.h"

#ifdef HAVE_DPCP
#include <mellanox/dpcp.h>

using namespace dpcp;

#define MODULE_NAME             "ibchdp"

#define ibdp_logpanic           __log_panic
#define ibdp_logerr             __log_err
#define ibdp_logwarn            __log_warn
#define ibdp_loginfo            __log_info
#define ibdp_logdbg             __log_info_dbg
#define ibdp_logfunc            __log_info_func
#define ibdp_logfuncall         __log_info_funcall

#endif /* HAVE_DPCP */
