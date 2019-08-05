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

#ifndef SRC_VMA_DEV_IB_DPCP_CTX_HANDLER_H_
#define SRC_VMA_DEV_IB_DPCP_CTX_HANDLER_H_

#include "ib_ctx_handler.h"
#include "config.h"

#ifdef HAVE_DPCP
#include <mellanox/dpcp.h>

class ib_dpcp_ctx_handler: public ib_ctx_handler {
public:
	ib_dpcp_ctx_handler(struct ib_ctx_handler_desc *desc, dpcp::adapter *adapter);
	virtual                 ~ib_dpcp_ctx_handler();
	virtual bool            can_delete() { return m_copied_ext; }
	void                    set_used_ext() { m_copied_ext = true;}
	dpcp::adapter*          get_adapter() { return m_p_adapter; }
	virtual bool            post_umr_wr(vma_ibv_send_wr &wr);
private:
	dpcp::adapter *m_p_adapter;
	bool m_copied_ext;
};

#endif /* HAVE_DPCP */
#endif /* SRC_VMA_DEV_IB_DPCP_CTX_HANDLER_H_ */
