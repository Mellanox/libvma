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

ib_dpcp_ctx_handler::ib_dpcp_ctx_handler(ib_ctx_handler_desc *desc,
					 dpcp::adapter *adapter)
	: ib_ctx_handler(desc),
	  m_p_adapter(adapter),
	  m_copied_ext(false)
{
	if (!m_p_ibv_device) {
		return;
	}
	m_is_ok = false;
	m_p_ibv_context = (ibv_context*)m_p_adapter->get_ibv_context();
	m_p_ibv_pd = ibv_alloc_pd(m_p_ibv_context);
	if (m_p_ibv_pd == NULL) {
		ibdp_logerr("ibv device %p pd allocation failure (ibv context %p) (errno=%d %m)",
			    m_p_ibv_device, m_p_ibv_context, errno);
		return;
	}
	VALGRIND_MAKE_MEM_DEFINED(m_p_ibv_pd, sizeof(struct ibv_pd));
	// get PD num and TD num and replace with the once inside adapter
	mlx5dv_obj mlx5_obj;
	mlx5_obj.pd.in = m_p_ibv_pd;
	mlx5dv_pd out_pd;
	mlx5_obj.pd.out = &out_pd;
	int ret = vma_ib_mlx5dv_init_obj(&mlx5_obj, MLX5DV_OBJ_PD);
	if (ret) {
		ibdp_logerr("failed getting mlx5_pd for %p (errno=%d %m) ",
			    m_p_ibv_pd, errno);
		return;
	}
	m_p_adapter->set_pd(out_pd.pdn);
	dpcp::status stat = adapter->open();
	if (stat != DPCP_OK) {
		ibdp_logerr("failed opening dpcp adapter %s got %d",
			    adapter->get_name().c_str(), stat);
		return;
	}
	m_is_ok = true;
}

bool ib_dpcp_ctx_handler::post_umr_wr(vma_ibv_send_wr &wr)
{
	NOT_IN_USE(wr);
	return false;
}

ib_dpcp_ctx_handler::~ib_dpcp_ctx_handler() {
	clean();
	if (m_p_ibv_pd) {
		ibv_dealloc_pd(m_p_ibv_pd);
	}
	delete m_p_adapter;
}

#endif /* HAVE_DPCP */
