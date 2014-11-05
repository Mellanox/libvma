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

#ifndef CC_CUBIC_H_
#define CC_CUBIC_H_

#include "lwip/cc.h"
#include "lwip/tcp_impl.h"
#include "lwip/timers.h"
#include <math.h>

/*
 * once we add support for ECN and ABC rfc in VMA/LWIP, need to add support in the algorithm.
 */

typedef unsigned long long tscval_t;

#define hz 100 //according to VMA internal thread


/* Number of bits of precision for fixed point math calcs. */
#define	CUBIC_SHIFT		8

#define	CUBIC_SHIFT_4		32

/* 0.5 << CUBIC_SHIFT. */
#define	RENO_BETA		128

/* ~0.8 << CUBIC_SHIFT. */
#define	CUBIC_BETA		204

/* ~0.2 << CUBIC_SHIFT. */
#define	ONE_SUB_CUBIC_BETA	51

/* 3 * ONE_SUB_CUBIC_BETA. */
#define	THREE_X_PT2		153

/* (2 << CUBIC_SHIFT) - ONE_SUB_CUBIC_BETA. */
#define	TWO_SUB_PT2		461

/* ~0.4 << CUBIC_SHIFT. */
#define	CUBIC_C_FACTOR		102

/* CUBIC fast convergence factor: ~0.9 << CUBIC_SHIFT. */
#define	CUBIC_FC_FACTOR		230

/* Don't trust s_rtt until this many rtt samples have been taken. */
#define	CUBIC_MIN_RTT_SAMPLES	8


/*
 * Implementation based on the formulae found in the CUBIC Internet Draft
 * "draft-rhee-tcpm-cubic-02".
 *
 * Note BETA used in cc_cubic is equal to (1-beta) in the I-D
 */

/*
 * Compute the CUBIC K value used in the cwnd calculation, using an
 * implementation of eqn 2 in the I-D. The method used
 * here is adapted from Apple Computer Technical Report #KT-32.
 */
static inline int64_t
cubic_k(unsigned long wmax_pkts)
{
	int64_t s, K;
	uint16_t p;

	K = s = 0;
	p = 0;

	/* (wmax * beta)/C with CUBIC_SHIFT worth of precision. */
	s = ((wmax_pkts * ONE_SUB_CUBIC_BETA) << CUBIC_SHIFT) / CUBIC_C_FACTOR;

	/* Rebase s to be between 1 and 1/8 with a shift of CUBIC_SHIFT. */
	while (s >= 256) {
		s >>= 3;
		p++;
	}

	/*
	 * Some magic constants taken from the Apple TR with appropriate
	 * shifts: 275 == 1.072302 << CUBIC_SHIFT, 98 == 0.3812513 <<
	 * CUBIC_SHIFT, 120 == 0.46946116 << CUBIC_SHIFT.
	 */
	K = (((s * 275) >> CUBIC_SHIFT) + 98) -
	    (((s * s * 120) >> CUBIC_SHIFT) >> CUBIC_SHIFT);

	/* Multiply by 2^p to undo the rebasing of s from above. */
	return (K <<= p);
}

/*
 * Compute the new cwnd value using an implementation of eqn 1 from the I-D.
 * Thanks to Kip Macy for help debugging this function.
 *
 * XXXLAS: Characterise bounds for overflow.
 */
static inline unsigned long
cubic_cwnd(tscval_t ticks_since_cong, unsigned long wmax, uint32_t smss, int64_t K)
{
	int64_t cwnd;

	/* K is in fixed point form with CUBIC_SHIFT worth of precision. */

	/* t - K, with CUBIC_SHIFT worth of precision. */
	cwnd = ((int64_t)(ticks_since_cong << CUBIC_SHIFT) - (K * hz)) / hz;

	/* (t - K)^3, with CUBIC_SHIFT^3 worth of precision. */
	cwnd *= (cwnd * cwnd);

	/*
	 * C(t - K)^3 + wmax
	 * The down shift by CUBIC_SHIFT_4 is because cwnd has 4 lots of
	 * CUBIC_SHIFT included in the value. 3 from the cubing of cwnd above,
	 * and an extra from multiplying through by CUBIC_C_FACTOR.
	 */
	cwnd = ((cwnd * CUBIC_C_FACTOR * smss) >> CUBIC_SHIFT_4) + wmax;

	return ((unsigned long)cwnd);
}

/*
 * Compute an approximation of the "TCP friendly" cwnd some number of ticks
 * after a congestion event that is designed to yield the same average cwnd as
 * NewReno while using CUBIC's beta of 0.8. RTT should be the average RTT
 * estimate for the path measured over the previous congestion epoch and wmax is
 * the value of cwnd at the last congestion event.
 */
static inline unsigned long
tf_cwnd(tscval_t ticks_since_cong, tscval_t rtt_ticks, unsigned long wmax,
    uint32_t smss)
{

	/* Equation 4 of I-D. */
	return (((wmax * CUBIC_BETA) + (((THREE_X_PT2 * ticks_since_cong *
	    smss) << CUBIC_SHIFT) / TWO_SUB_PT2 / rtt_ticks)) >> CUBIC_SHIFT);
}


#endif /* CC_CUBIC_H_ */
