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


#ifndef IB_VERBS_CTX_HANDLER_H
#define IB_VERBS_CTX_HANDLER_H

#include <infiniband/verbs.h>
#include <tr1/unordered_map>

#include "vma/dev/ib_ctx_handler.h"
#include "vma/event/event_handler_ibverbs.h"
#include "vma/dev/time_converter.h"
#include "vma/ib/base/verbs_extra.h"
#include "utils/lock_wrapper.h"


class ib_verbs_ctx_handler : public ib_ctx_handler
{

public:
	ib_verbs_ctx_handler(struct ib_ctx_handler_desc *desc);
	virtual ~ib_verbs_ctx_handler();

	/*
	 * on init or constructor:
	 *      register to event manager with m_channel and this.
	 * */
	virtual bool            post_umr_wr(vma_ibv_send_wr &wr);
private:
	bool                    create_umr_qp();
	lock_spin               m_lock_umr;
	struct ibv_cq*          m_umr_cq;
	struct ibv_qp*          m_umr_qp;

};

#endif
