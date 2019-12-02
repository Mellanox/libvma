/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef __LWIP_STATS_H__
#define __LWIP_STATS_H__

#include "vma/lwip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_STATS

#ifndef LWIP_STATS_LARGE
#define LWIP_STATS_LARGE 0
#endif

#if LWIP_STATS_LARGE
#define STAT_COUNTER     u32_t
#define STAT_COUNTER_F   U32_F
#else
#define STAT_COUNTER     u16_t
#define STAT_COUNTER_F   U16_F
#endif 

struct stats_proto {
  STAT_COUNTER xmit;             /* Transmitted packets. */
  STAT_COUNTER recv;             /* Received packets. */
  STAT_COUNTER fw;               /* Forwarded packets. */
  STAT_COUNTER drop;             /* Dropped packets. */
  STAT_COUNTER chkerr;           /* Checksum error. */
  STAT_COUNTER lenerr;           /* Invalid length error. */
  STAT_COUNTER memerr;           /* Out of memory error. */
  STAT_COUNTER rterr;            /* Routing error. */
  STAT_COUNTER proterr;          /* Protocol error. */
  STAT_COUNTER opterr;           /* Error in options. */
  STAT_COUNTER err;              /* Misc error. */
  STAT_COUNTER cachehit;
};


struct stats_ {
#if TCP_STATS
  struct stats_proto tcp;
#endif
};

extern struct stats_ lwip_stats;

void stats_init(void);

#define STATS_INC(x) ++lwip_stats.x
#define STATS_DEC(x) --lwip_stats.x
#define STATS_INC_USED(x, y) do { lwip_stats.x.used += y; \
                                if (lwip_stats.x.max < lwip_stats.x.used) { \
                                    lwip_stats.x.max = lwip_stats.x.used; \
                                } \
                             } while(0)
#else /* LWIP_STATS */
#define stats_init()
#define STATS_INC(x)
#define STATS_DEC(x)
#define STATS_INC_USED(x)
#endif /* LWIP_STATS */

#if TCP_STATS
#define TCP_STATS_INC(x) STATS_INC(x)
#define TCP_STATS_DISPLAY() stats_display_proto(&lwip_stats.tcp, "TCP")
#else
#define TCP_STATS_INC(x)
#define TCP_STATS_DISPLAY()
#endif


/* Display of statistics */
#if LWIP_STATS_DISPLAY
void stats_display(void);
void stats_display_proto(struct stats_proto *proto, char *name);
#else /* LWIP_STATS_DISPLAY */
#define stats_display()
#define stats_display_proto(proto, name)
#endif /* LWIP_STATS_DISPLAY */

#ifdef DEFINED_EXTRA_STATS

struct socket_tcp_stats {
  u32_t n_rto;            /* number of RTO */
  u32_t n_rtx_fast;       /* fast retransmits */
  u32_t n_rtx_rto;        /* retransmits caused by RTO */
  u32_t n_rtx_ss;         /* retransmits in slow start phase */
  u32_t n_rtx_spurious;   /* number of segments removed from unsent queue */
  u32_t n_recovered_fast; /* recovered after fast retransmit without RTO */
  u32_t n_dupacks;        /* duplicate ACKs */
  u32_t n_ofo;            /* out of order segments */
  u32_t n_underruns;      /* underruns (no segments to send) */
  u32_t n_blocked_cwnd;   /* sending blocked by cwnd */
  u32_t n_blocked_rwnd;   /* sending blocked by rwnd */
  u32_t n_blocked_sndbuf; /* sending blocked by snd_buf */
  u32_t n_updates_rtt;    /* RTT measurements */
  u32_t n_rst;            /* RST segments */

  u32_t n_rx_ignored;     /* ignored incoming segments */
  u32_t n_dropped;        /* dropped segments due to an error */
  u32_t n_memerr_pbuf;    /* pbuf allocation errors */
  u32_t n_memerr_seg;     /* segment allocation errors */

  u32_t n_mss;
  u32_t n_rto_timer;
  u32_t n_snd_wnd;
  u32_t n_cwnd;
  u32_t n_ssthresh;
  u32_t n_snd_nxt;
  u32_t n_lastack;
  u32_t n_unsent_q;
  u32_t n_unacked_q;
  u32_t n_ooseq_q;
};

typedef struct socket_tcp_stats socket_tcp_stats_t;

#define EXTRA_STATS_INC(x) ++x

#else /* DEFINED_EXTRA_STATS */
#define EXTRA_STATS_INC(x) do {} while (0)
#endif /* DEFINED_EXTRA_STATS */

#define PCB_STATS_INC(x) EXTRA_STATS_INC(pcb->p_stats->x)

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_STATS_H__ */
