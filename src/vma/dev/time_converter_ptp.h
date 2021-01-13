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


#ifndef TIME_CONVERTER_PTP_H
#define TIME_CONVERTER_PTP_H

#include <infiniband/verbs.h>
#include "vma/event/timer_handler.h"
#include <vma/util/sys_vars.h>
#include "time_converter.h"

#ifdef DEFINED_IBV_CLOCK_INFO

class time_converter_ptp : public time_converter
{
public:
	time_converter_ptp(struct ibv_context* ctx);
	virtual ~time_converter_ptp() {};

	inline void               convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime);
	virtual void              handle_timer_expired(void* user_data);

private:
	struct ibv_context*       m_p_ibv_context;

	vma_ibv_clock_info        m_clock_values[2];
	int                       m_clock_values_id;
};

#endif // DEFINED_IBV_CLOCK_INFO
#endif // TIME_CONVERTER_PTP_H
