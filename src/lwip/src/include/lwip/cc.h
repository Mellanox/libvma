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
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */

#ifndef CC_H_
#define CC_H_


struct cc_algo;

#include <stdint.h>
#include "lwip/tcp.h"

/* types of different cc algorithms */
enum cc_algo_mod {
	CC_MOD_LWIP,
	CC_MOD_CUBIC
};

/* ACK types passed to the ack_received() hook. */
#define	CC_ACK		0x0001	/* Regular in sequence ACK. */
#define	CC_DUPACK	0x0002	/* Duplicate ACK. */
#define	CC_PARTIALACK	0x0004	/* Not yet. */
#define	CC_SACK		0x0008	/* Not yet. */

/*
 * Congestion signal types passed to the cong_signal() hook. The highest order 8
 * bits (0x01000000 - 0x80000000) are reserved for CC algos to declare their own
 * congestion signal types.
 */
#define	CC_ECN		0x00000001	/* ECN marked packet received. */
#define	CC_RTO		0x00000002	/* RTO fired. */
#define	CC_RTO_ERR	0x00000004	/* RTO fired in error. */
#define	CC_NDUPACK	0x00000008	/* Threshold of dupack's reached. */

#define	CC_SIGPRIVMASK	0xFF000000	/* Mask to check if sig is private. */


#define	TCP_CA_NAME_MAX	16	/* max congestion control name length */

/*
 * Structure to hold data and function pointers that together represent a
 * congestion control algorithm.
 */
struct cc_algo {
	char	name[TCP_CA_NAME_MAX];

	/* Init cc_data */
	int	(*init)(struct tcp_pcb *pcb);

	/* Destroy cc_data */
	void	(*destroy)(struct tcp_pcb *pcb);

	/* Init variables for a newly established connection. */
	void	(*conn_init)(struct tcp_pcb *pcb);

	/* Called on receipt of an ack. */
	void	(*ack_received)(struct tcp_pcb *pcb, uint16_t type);

	/* Called on detection of a congestion signal. */
	void	(*cong_signal)(struct tcp_pcb *pcb, uint32_t type);

	/* Called after exiting congestion recovery. */
	void	(*post_recovery)(struct tcp_pcb *pcb);

	/* Called when data transfer resumes after an idle period. */
	void	(*after_idle)(struct tcp_pcb *pcb);

};

extern struct cc_algo ork_cc_algo;
extern struct cc_algo lwip_cc_algo;
extern struct cc_algo cubic_cc_algo;

void inline cc_init(struct tcp_pcb *pcb);
void inline cc_destroy(struct tcp_pcb *pcb);
void inline cc_ack_received(struct tcp_pcb *pcb, uint16_t type);
void inline cc_conn_init(struct tcp_pcb *pcb);
void inline cc_cong_signal(struct tcp_pcb *pcb, uint32_t type);
void inline cc_post_recovery(struct tcp_pcb *pcb);

#endif /* CC_H_ */
