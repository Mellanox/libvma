/*-
 * Copyright (c) 2007-2008
 * 	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart and
 * James Healy, made possible in part by a grant from the Cisco University
 * Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * This software was first released in 2007 by James Healy and Lawrence Stewart
 * whilst working on the NewTCP research project at Swinburne University of
 * Technology's Centre for Advanced Internet Architectures, Melbourne,
 * Australia, which was made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 * More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "vma/lwip/cc.h"
#include "vma/lwip/tcp.h"

#if TCP_CC_ALGO_MOD

inline void cc_init(struct tcp_pcb *pcb)
{
	if (pcb->cc_algo->init != NULL) {
		pcb->cc_algo->init(pcb);
	}
}

inline void cc_destroy(struct tcp_pcb *pcb)
{
	if (pcb->cc_algo->destroy != NULL) {
		pcb->cc_algo->destroy(pcb);
	}
}

inline void cc_ack_received(struct tcp_pcb *pcb, uint16_t type)
{
	if (pcb->cc_algo->ack_received != NULL) {
		pcb->cc_algo->ack_received(pcb, type);
	}
}

inline void cc_conn_init(struct tcp_pcb *pcb)
{
	if (pcb->cc_algo->conn_init != NULL) {
		pcb->cc_algo->conn_init(pcb);
	}
}

inline void cc_cong_signal(struct tcp_pcb *pcb, uint32_t type)
{

	if (pcb->cc_algo->cong_signal != NULL) {
		pcb->cc_algo->cong_signal(pcb, type);
	}
}

inline void cc_post_recovery(struct tcp_pcb *pcb)
{
	if (pcb->cc_algo->post_recovery != NULL) {
		pcb->cc_algo->post_recovery(pcb);
	}
}

#endif //TCP_CC_ALGO_MOD
