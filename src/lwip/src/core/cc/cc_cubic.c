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

#include "cc_cubic.h"
#include "errno.h"

#if TCP_CC_ALGO_MOD

#define ticks tcp_ticks

static int	cubic_cb_init(struct tcp_pcb *pcb);
static void	cubic_cb_destroy(struct tcp_pcb *pcb);
static void	cubic_ack_received(struct tcp_pcb *pcb, uint16_t type);
static void	cubic_cong_signal(struct tcp_pcb *pcb, uint32_t type);
static void	cubic_conn_init(struct tcp_pcb *pcb);
static void	cubic_post_recovery(struct tcp_pcb *pcb);
static void	cubic_record_rtt(struct tcp_pcb *pcb);
static void	cubic_ssthresh_update(struct tcp_pcb *pcb);

struct cubic {
	/* Cubic K in fixed point form with CUBIC_SHIFT worth of precision. */
	int64_t		K;
	/* Sum of RTT samples across an epoch in ticks. */
	tscval_t	sum_rtt_ticks;
	/* cwnd at the most recent congestion event. */
	unsigned long	max_cwnd;
	/* cwnd at the previous congestion event. */
	unsigned long	prev_max_cwnd;
	/* Number of congestion events. */
	uint32_t	num_cong_events;
	/* Minimum observed rtt in ticks. */
	tscval_t	min_rtt_ticks;
	/* Mean observed rtt between congestion epochs. */
	tscval_t	mean_rtt_ticks;
	/* ACKs since last congestion event. */
	int		epoch_ack_count;
	/* Time of last congestion event in ticks. */
	tscval_t	t_last_cong;
};

struct cc_algo cubic_cc_algo = {
		.name = "cubic",
		.init = cubic_cb_init,
		.destroy = cubic_cb_destroy,
		.ack_received = cubic_ack_received,
		.cong_signal = cubic_cong_signal,
		.conn_init = cubic_conn_init,
		.post_recovery = cubic_post_recovery
};

static void
cubic_ack_received(struct tcp_pcb *pcb, uint16_t type)
{
	struct cubic *cubic_data;
	unsigned long w_tf, w_cubic_next;
	tscval_t ticks_since_cong;

	cubic_data = pcb->cc_data;
	cubic_record_rtt(pcb);

	/*
	 * Regular ACK and we're not in cong/fast recovery and we're cwnd
	 * limited and we're either not doing ABC or are slow starting or are
	 * doing ABC and we've sent a cwnd's worth of bytes.
	 */
	if (type == CC_ACK && !(pcb->flags & TF_INFR) &&
			(pcb->cwnd < pcb->snd_wnd)) {
		/* Use the logic in NewReno ack_received() for slow start. */
		if (pcb->cwnd <= pcb->ssthresh /*||
		    cubic_data->min_rtt_ticks == 0*/)
			pcb->cwnd += pcb->mss;
		else if (cubic_data->min_rtt_ticks > 0) {
			ticks_since_cong = ticks - cubic_data->t_last_cong;

			/*
			 * The mean RTT is used to best reflect the equations in
			 * the I-D. Using min_rtt in the tf_cwnd calculation
			 * causes w_tf to grow much faster than it should if the
			 * RTT is dominated by network buffering rather than
			 * propogation delay.
			 */
			w_tf = tf_cwnd(ticks_since_cong,
					cubic_data->mean_rtt_ticks, cubic_data->max_cwnd, pcb->mss);

			w_cubic_next = cubic_cwnd(ticks_since_cong +
					cubic_data->mean_rtt_ticks, cubic_data->max_cwnd,
					pcb->mss, cubic_data->K);

			if (w_cubic_next < w_tf)
				/*
				 * TCP-friendly region, follow tf
				 * cwnd growth.
				 */
				pcb->cwnd = w_tf;

			else if (pcb->cwnd < w_cubic_next) {
				/*
				 * Concave or convex region, follow CUBIC
				 * cwnd growth.
				 */
				pcb->cwnd += ((w_cubic_next - pcb->cwnd) * pcb->mss) / pcb->cwnd;
			}

			/*
			 * If we're not in slow start and we're probing for a
			 * new cwnd limit at the start of a connection
			 * (happens when hostcache has a relevant entry),
			 * keep updating our current estimate of the
			 * max_cwnd.
			 */
			if (cubic_data->num_cong_events == 0 &&
					cubic_data->max_cwnd < pcb->cwnd)
				cubic_data->max_cwnd = pcb->cwnd;
		}
	}
}

static void
cubic_cb_destroy(struct tcp_pcb *pcb)
{
	if (pcb->cc_data != NULL) {
		free(pcb->cc_data);
		pcb->cc_data = NULL;
	}
}

static int
cubic_cb_init(struct tcp_pcb *pcb)
{
	struct cubic *cubic_data;

	cubic_data = malloc(sizeof(struct cubic));
	memset(cubic_data, 0, sizeof(struct cubic));
	if (cubic_data == NULL)
		return (ENOMEM);

	/* Init some key variables with sensible defaults. */
	cubic_data->t_last_cong = ticks;
	cubic_data->min_rtt_ticks = 0;
	cubic_data->mean_rtt_ticks = 1;

	pcb->cc_data = cubic_data;

	return (0);
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
cubic_cong_signal(struct tcp_pcb *pcb, uint32_t type)
{
	struct cubic *cubic_data = pcb->cc_data;

	switch (type) {
	case CC_NDUPACK:

		if (!(pcb->flags & TF_INFR)) {
			cubic_ssthresh_update(pcb);
			cubic_data->num_cong_events++;
			cubic_data->prev_max_cwnd = cubic_data->max_cwnd;
			cubic_data->max_cwnd = pcb->cwnd;
		}
		break;

	case CC_RTO:
		/* Set ssthresh to half of the minimum of the current
		 * cwnd and the advertised window */
		if (pcb->cwnd > pcb->snd_wnd) {
			pcb->ssthresh = pcb->snd_wnd / 2;
		} else {
			pcb->ssthresh = pcb->cwnd / 2;
		}

		/* The minimum value for ssthresh should be 2 MSS */
		if (pcb->ssthresh < 2*pcb->mss) {
			LWIP_DEBUGF(TCP_FR_DEBUG,
					("tcp_receive: The minimum value for ssthresh %"U16_F
							" should be min 2 mss %"U16_F"...\n",
							pcb->ssthresh, 2*pcb->mss));
			pcb->ssthresh = 2*pcb->mss;
		}

		pcb->cwnd = pcb->mss;

		/*
		 * Grab the current time and record it so we know when the
		 * most recent congestion event was. Only record it when the
		 * timeout has fired more than once, as there is a reasonable
		 * chance the first one is a false alarm and may not indicate
		 * congestion.
		 */
		if (pcb->nrtx >= 1)
			cubic_data->num_cong_events++;
		cubic_data->t_last_cong = ticks;

		break;
	}
}

static void
cubic_conn_init(struct tcp_pcb *pcb)
{
	struct cubic *cubic_data = pcb->cc_data;

	pcb->cwnd = ((pcb->cwnd == 1) ? (pcb->mss * 2) : pcb->mss);
	pcb->ssthresh = pcb->mss * 3;
	/*
	 * Ensure we have a sane initial value for max_cwnd recorded. Without
	 * this here bad things happen when entries from the TCP hostcache
	 * get used.
	 */
	cubic_data->max_cwnd = pcb->cwnd;
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
static void
cubic_post_recovery(struct tcp_pcb *pcb)
{
	struct cubic *cubic_data = pcb->cc_data;

	/* Fast convergence heuristic. */
	if (cubic_data->max_cwnd < cubic_data->prev_max_cwnd)
		cubic_data->max_cwnd = (cubic_data->max_cwnd * CUBIC_FC_FACTOR) >> CUBIC_SHIFT;

	if (pcb->flags & TF_INFR) {
		/*
		 * If inflight data is less than ssthresh, set cwnd
		 * conservatively to avoid a burst of data, as suggested in
		 * the NewReno RFC. Otherwise, use the CUBIC method.
		 *
		 * XXXLAS: Find a way to do this without needing curack
		 */
		if (pcb->last_unacked && TCP_SEQ_GT(pcb->lastack + pcb->ssthresh, pcb->last_unacked->seqno))
			pcb->cwnd = pcb->last_unacked->seqno - pcb->lastack + pcb->mss;
		else {
			/* Update cwnd based on beta and adjusted max_cwnd. */
			if (((CUBIC_BETA * cubic_data->max_cwnd) >> CUBIC_SHIFT) > 1)
				pcb->cwnd = ((CUBIC_BETA * cubic_data->max_cwnd) >> CUBIC_SHIFT);
			else
				pcb->cwnd = pcb->mss;
		}
	}
	cubic_data->t_last_cong = ticks;

	/* Calculate the average RTT between congestion epochs. */
	if (cubic_data->epoch_ack_count > 0 &&
			cubic_data->sum_rtt_ticks >= cubic_data->epoch_ack_count) {
		cubic_data->mean_rtt_ticks = (cubic_data->sum_rtt_ticks/cubic_data->epoch_ack_count);
	}

	cubic_data->epoch_ack_count = 0;
	cubic_data->sum_rtt_ticks = 0;
	cubic_data->K = cubic_k(cubic_data->max_cwnd / pcb->mss);
}

/*
 * Record the min RTT and sum samples for the epoch average RTT calculation.
 */
static void
cubic_record_rtt(struct tcp_pcb *pcb)
{
	struct cubic *cubic_data = pcb->cc_data;
	tscval_t t_srtt_ticks;

	/* Ignore srtt until a min number of samples have been taken. */
	if (pcb->t_rttupdated >= CUBIC_MIN_RTT_SAMPLES) {

		t_srtt_ticks = pcb->rttest;

		/*
		 * Record the current SRTT as our minrtt if it's the smallest
		 * we've seen or minrtt is currently equal to its initialised
		 * value.
		 *
		 * XXXLAS: Should there be some hysteresis for minrtt?
		 */
		if ((t_srtt_ticks < cubic_data->min_rtt_ticks ||
				cubic_data->min_rtt_ticks == 0)) {
			if (t_srtt_ticks > 1)
				cubic_data->min_rtt_ticks = t_srtt_ticks;
			else
				cubic_data->min_rtt_ticks = 1;

			/*
			 * If the connection is within its first congestion
			 * epoch, ensure we prime mean_rtt_ticks with a
			 * reasonable value until the epoch average RTT is
			 * calculated in cubic_post_recovery().
			 */
			if (cubic_data->min_rtt_ticks > cubic_data->mean_rtt_ticks) {
				cubic_data->mean_rtt_ticks = cubic_data->min_rtt_ticks;
			}
		}

		/* Sum samples for epoch average RTT calculation. */
		cubic_data->sum_rtt_ticks += t_srtt_ticks;
		cubic_data->epoch_ack_count++;
	}
}

/*
 * Update the ssthresh in the event of congestion.
 */
static void
cubic_ssthresh_update(struct tcp_pcb *pcb)
{
	struct cubic *cubic_data = pcb->cc_data;

	/*
	 * On the first congestion event, set ssthresh to cwnd * 0.5, on
	 * subsequent congestion events, set it to cwnd * beta.
	 */
	if (cubic_data->num_cong_events == 0)
		pcb->ssthresh = pcb->cwnd >> 1;
	else
		pcb->ssthresh = (pcb->cwnd * CUBIC_BETA) >> CUBIC_SHIFT;
}

#endif //TCP_CC_ALGO_MOD
