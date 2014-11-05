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
#ifndef __LWIP_TCP_H__
#define __LWIP_TCP_H__

#include "lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/sys.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

extern u16_t lwip_tcp_mss;

#if LWIP_3RD_PARTY_L3
typedef err_t (*ip_output_fn)(struct pbuf *p, void* p_conn, int is_rexmit);
          
void register_ip_output(ip_output_fn fn);

typedef u16_t (*ip_route_mtu_fn)(ip_addr_t *dest);
void register_ip_route_mtu(ip_route_mtu_fn fn);

#endif

#if LWIP_3RD_PARTY_BUFS
typedef struct pbuf * (*tcp_tx_pbuf_alloc_fn)(void* p_conn);

void register_tcp_tx_pbuf_alloc(tcp_tx_pbuf_alloc_fn fn);

typedef void (*tcp_tx_pbuf_free_fn)(void* p_conn, struct pbuf * p);

void register_tcp_tx_pbuf_free(tcp_tx_pbuf_free_fn fn);

typedef struct tcp_seg * (*tcp_seg_alloc_fn)(void* p_conn);

void register_tcp_seg_alloc(tcp_seg_alloc_fn fn);

typedef void (*tcp_seg_free_fn)(void* p_conn, struct tcp_seg * seg);

void register_tcp_seg_free(tcp_seg_free_fn fn);


extern tcp_tx_pbuf_alloc_fn external_tcp_tx_pbuf_alloc;
extern tcp_tx_pbuf_free_fn external_tcp_tx_pbuf_free;
extern tcp_seg_alloc_fn external_tcp_seg_alloc;
extern tcp_seg_free_fn external_tcp_seg_free;
#endif


struct tcp_pcb;

#include "lwip/cc.h"

extern enum cc_algo_mod lwip_cc_algo_module;

/** Function prototype for tcp accept callback functions. Called when a new
 * connection can be accepted on a listening pcb.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param newpcb The new connection pcb
 * @param err An error code if there has been an error accepting.
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_accept_fn)(void *arg, struct tcp_pcb *newpcb, err_t err);

/** Function prototype for tcp syn received callback functions. Called when a new
 * syn is received.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param newpcb The new connection pcb
 * @param err An error code if there has been an error.
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_syn_handled_fn)(void *arg, struct tcp_pcb *newpcb, err_t err);

/** Function prototype for tcp clone callback functions. Called to clone listen pcb
 * on connection establishment.
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param newpcb The new connection pcb
 * @param err An error code if there has been an error.
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 *
 */
typedef err_t (*tcp_clone_conn_fn)(void *arg, struct tcp_pcb **newpcb, err_t err);


/** Function prototype for tcp receive callback functions. Called when data has
 * been received.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb which received data
 * @param p The received data (or NULL when the connection has been closed!)
 * @param err An error code if there has been an error receiving
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_recv_fn)(void *arg, struct tcp_pcb *tpcb,
                             struct pbuf *p, err_t err);

/** Function prototype for tcp sent callback functions. Called when sent data has
 * been acknowledged by the remote side. Use it to free corresponding resources.
 * This also means that the pcb has now space available to send new data.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb for which data has been acknowledged
 * @param len The amount of bytes acknowledged
 * @return ERR_OK: try to send some data by calling tcp_output
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_sent_fn)(void *arg, struct tcp_pcb *tpcb,
                              u16_t len);

/** Function prototype for tcp poll callback functions. Called periodically as
 * specified by @see tcp_poll.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb tcp pcb
 * @return ERR_OK: try to send some data by calling tcp_output
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_poll_fn)(void *arg, struct tcp_pcb *tpcb);

/** Function prototype for tcp error callback functions. Called when the pcb
 * receives a RST or is unexpectedly closed for any other reason.
 *
 * @note The corresponding pcb is already freed when this callback is called!
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param err Error code to indicate why the pcb has been closed
 *            ERR_ABRT: aborted through tcp_abort or by a TCP timer
 *            ERR_RST: the connection was reset by the remote host
 */
typedef void  (*tcp_err_fn)(void *arg, err_t err);

/** Function prototype for tcp connected callback functions. Called when a pcb
 * is connected to the remote side after initiating a connection attempt by
 * calling tcp_connect().
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb which is connected
 * @param err An unused error code, always ERR_OK currently ;-) TODO!
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 *
 * @note When a connection attempt fails, the error callback is currently called!
 */
typedef err_t (*tcp_connected_fn)(void *arg, struct tcp_pcb *tpcb, err_t err);

enum tcp_state {
  CLOSED      = 0,
  LISTEN      = 1,
  SYN_SENT    = 2,
  SYN_RCVD    = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1  = 5,
  FIN_WAIT_2  = 6,
  CLOSE_WAIT  = 7,
  CLOSING     = 8,
  LAST_ACK    = 9,
  TIME_WAIT   = 10
};

#define PCB_IN_CLOSED_STATE(pcb) (pcb->state == CLOSED)
#define PCB_IN_LISTEN_STATE(pcb) (pcb->state == LISTEN)
#define PCB_IN_ACTIVE_STATE(pcb) (pcb->state > LISTEN && pcb->state < TIME_WAIT)
#define PCB_IN_TIME_WAIT_STATE(pcb) (pcb->state == TIME_WAIT)

#if LWIP_CALLBACK_API
  /* Function to call when a listener has been connected.
   * @param arg user-supplied argument (tcp_pcb.callback_arg)
   * @param pcb a new tcp_pcb that now is connected
   * @param err an error argument (TODO: that is current always ERR_OK?)
   * @return ERR_OK: accept the new connection,
   *                 any other err_t abortsthe new connection
   */
#define DEF_ACCEPT_CALLBACK  tcp_accept_fn accept;
#else /* LWIP_CALLBACK_API */
#define DEF_ACCEPT_CALLBACK
#endif /* LWIP_CALLBACK_API */

/**
 * members common to struct tcp_pcb and struct tcp_listen_pcb
 */
#define TCP_PCB_COMMON(type) \
  type *next; /* for the linked list */ \
  enum tcp_state state; /* TCP state */ \
  u8_t prio; \
  void *callback_arg; \
  void *my_container; \
  /* the accept callback for listen- and normal pcbs, if LWIP_CALLBACK_API */ \
  DEF_ACCEPT_CALLBACK \
  /* ports are in host byte order */ \
  u16_t local_port

#if TCP_RCVSCALE
#define RCV_WND_SCALE(pcb, wnd) (htons((u16_t)((wnd) >> (pcb)->rcv_scale)))
#define SND_WND_SCALE(pcb, wnd) ((u32_t)(wnd) << (pcb)->snd_scale)
#else
#define RCV_WND_SCALE(pcb, wnd) (wnd)
#define SND_WND_SCALE(pcb, wnd) (wnd)
#endif

/* the TCP protocol control block */
struct tcp_pcb {
/** common PCB members */
  IP_PCB;
/** protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb);

  /* ports are in host byte order */
  u16_t remote_port;

  u8_t flags;
#define TF_ACK_DELAY   ((u8_t)0x01U)   /* Delayed ACK. */
#define TF_ACK_NOW     ((u8_t)0x02U)   /* Immediate ACK. */
#define TF_INFR        ((u8_t)0x04U)   /* In fast recovery. */
#define TF_TIMESTAMP   ((u8_t)0x08U)   /* Timestamp option enabled */
#define TF_RXCLOSED    ((u8_t)0x10U)   /* rx closed by tcp_shutdown */
#define TF_FIN         ((u8_t)0x20U)   /* Connection was closed locally (FIN segment enqueued). */
#define TF_NODELAY     ((u8_t)0x40U)   /* Disable Nagle algorithm */
#define TF_NAGLEMEMERR ((u8_t)0x80U)   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */

  /* the rest of the fields are in host byte order
     as we have to do some math with them */
  /* receiver variables */
  u32_t rcv_nxt;   /* next seqno expected */
#if TCP_RCVSCALE
  u32_t rcv_wnd;   /* receiver window available */
  u32_t rcv_ann_wnd; /* receiver window to announce */
#else
  u16_t rcv_wnd;   /* receiver window available */
  u16_t rcv_ann_wnd; /* receiver window to announce */
#endif
  u32_t rcv_ann_right_edge; /* announced right edge of window */

  /* Timers */
  u8_t tcp_timer; /* Timer counter to handle calling slow-timer from tcp_tmr() */
  u32_t tmr;
  u8_t polltmr, pollinterval;
  
  /* Retransmission timer. */
  s16_t rtime;
  
  u16_t mss;   /* maximum segment size */
  u16_t advtsd_mss; /* advertised maximum segment size */
  
  /* RTT (round trip time) estimation variables */
  u32_t rttest; /* RTT estimate in 10ms ticks */
  u32_t rtseq;  /* sequence number being timed */
#if TCP_CC_ALGO_MOD
  u32_t t_rttupdated; /* number of RTT estimations taken so far */
#endif
  s16_t sa, sv; /* @todo document this */

  s16_t rto;    /* retransmission time-out */
  u8_t nrtx;    /* number of retransmissions */

  /* fast retransmit/recovery */
  u32_t lastack; /* Highest acknowledged seqno. */
  u8_t dupacks;
  
  /* congestion avoidance/control variables */
#if TCP_CC_ALGO_MOD
  struct cc_algo* cc_algo;
  void* cc_data;
#endif
#if TCP_RCVSCALE
  u32_t cwnd;
  u32_t ssthresh;
#else
  u16_t cwnd;
  u16_t ssthresh;
#endif

  /* sender variables */
  u32_t snd_nxt;   /* next new seqno to be sent */
  u32_t snd_wnd;   /* sender window */
  u32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                             window update. */
  u32_t snd_lbb;       /* Sequence number of next byte to be buffered. */

#if TCP_RCVSCALE
  u32_t acked;
#else
  u16_t acked;
#endif
  
  u32_t snd_buf;   /* Available buffer space for sending (in bytes). */
  u32_t max_snd_buff;

  u32_t snd_sml_snt; /* maintain state for minshall's algorithm */
  u32_t snd_sml_add; /* maintain state for minshall's algorithm */

#if TCP_RCVSCALE
#define TCP_SNDQUEUELEN_OVERFLOW (0xffffffU-3)
  u32_t snd_queuelen; /* Available buffer space for sending (in tcp_segs). */
#else
#define TCP_SNDQUEUELEN_OVERFLOW (0xffff-3)
  u16_t snd_queuelen; /* Available buffer space for sending (in tcp_segs). */
#endif

#if TCP_OVERSIZE
  /* Extra bytes available at the end of the last pbuf in unsent. */
  u16_t unsent_oversize;
#endif /* TCP_OVERSIZE */ 
  u16_t max_unsent_len;
  /* These are ordered by sequence number: */
  struct tcp_seg *unsent;   /* Unsent (queued) segments. */
  struct tcp_seg *last_unsent;   /* Last unsent (queued) segment. */
  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */
  struct tcp_seg *last_unacked;  /* Lase element in unacknowledged segments list. */
#if TCP_QUEUE_OOSEQ  
  struct tcp_seg *ooseq;    /* Received out of sequence segments. */
#endif /* TCP_QUEUE_OOSEQ */

  struct pbuf *refused_data; /* Data previously received but not yet taken by upper layer */

#if LWIP_CALLBACK_API
  /* Function to be called when more send buffer space is available. */
  tcp_sent_fn sent;
  /* Function to be called when (in-sequence) data has arrived. */
  tcp_recv_fn recv;
  /* Function to be called when a connection has been set up. */
  tcp_connected_fn connected;
  /* Function which is called periodically. */
  tcp_poll_fn poll;
  /* Function to be called whenever a fatal error occurs. */
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */

#if LWIP_TCP_TIMESTAMPS
  u32_t ts_lastacksent;
  u32_t ts_recent;
#endif /* LWIP_TCP_TIMESTAMPS */

  /* idle time before KEEPALIVE is sent */
  u32_t keep_idle;
#if LWIP_TCP_KEEPALIVE
  u32_t keep_intvl;
  u32_t keep_cnt;
#endif /* LWIP_TCP_KEEPALIVE */
  
  /* Persist timer counter */
  u32_t persist_cnt;
  /* Persist timer back-off */
  u8_t persist_backoff;

  /* KEEPALIVE counter */
  u8_t keep_cnt_sent;

#if TCP_RCVSCALE
  u8_t snd_scale;
  u8_t rcv_scale;
#endif
};

struct tcp_pcb_listen {  
/* Common members of all PCB types */
  IP_PCB;
/* Protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb_listen);
  tcp_syn_handled_fn syn_handled_cb;
  tcp_clone_conn_fn clone_conn;

#if TCP_LISTEN_BACKLOG
  u8_t backlog;
  u8_t accepts_pending;
#endif /* TCP_LISTEN_BACKLOG */
};

#if LWIP_EVENT_API

enum lwip_event {
  LWIP_EVENT_ACCEPT,
  LWIP_EVENT_SENT,
  LWIP_EVENT_RECV,
  LWIP_EVENT_CONNECTED,
  LWIP_EVENT_POLL,
  LWIP_EVENT_ERR
};

err_t lwip_tcp_event(void *arg, struct tcp_pcb *pcb,
         enum lwip_event,
         struct pbuf *p,
         u16_t size,
         err_t err);

#endif /* LWIP_EVENT_API */

/* Application program's interface: */
struct tcp_pcb * tcp_new     (void);
/* Application program's interface: */

/*Initialization of tcp_pcb structure*/
void tcp_pcb_init (struct tcp_pcb* pcb, u8_t prio);

void             tcp_arg     		(struct tcp_pcb *pcb, void *arg);
void             tcp_accept  		(struct tcp_pcb *pcb, tcp_accept_fn accept);
void             tcp_syn_handled	(struct tcp_pcb_listen *pcb, tcp_syn_handled_fn syn_handled);
void             tcp_clone_conn		(struct tcp_pcb_listen *pcb, tcp_clone_conn_fn clone_conn);
void             tcp_recv    		(struct tcp_pcb *pcb, tcp_recv_fn recv);
void             tcp_sent    		(struct tcp_pcb *pcb, tcp_sent_fn sent);
void             tcp_poll    		(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval);
void             tcp_err     		(struct tcp_pcb *pcb, tcp_err_fn err);

#define          tcp_mss(pcb)             (((pcb)->flags & TF_TIMESTAMP) ? ((pcb)->mss - 12)  : (pcb)->mss)
#define          tcp_sndbuf(pcb)          ((pcb)->snd_buf)
#define          tcp_sndqueuelen(pcb)     ((pcb)->snd_queuelen)
#define          tcp_nagle_disable(pcb)   ((pcb)->flags |= TF_NODELAY)
#define          tcp_nagle_enable(pcb)    ((pcb)->flags &= ~TF_NODELAY)
#define          tcp_nagle_disabled(pcb)  (((pcb)->flags & TF_NODELAY) != 0)

#if TCP_LISTEN_BACKLOG
#define          tcp_accepted(pcb) do { \
  LWIP_ASSERT("pcb->state == LISTEN (called for wrong pcb?)", pcb->state == LISTEN); \
  (((struct tcp_pcb_listen *)(pcb))->accepts_pending--); } while(0)
#else  /* TCP_LISTEN_BACKLOG */
#define          tcp_accepted(pcb) LWIP_ASSERT("pcb->state == LISTEN (called for wrong pcb?)", \
                                               pcb->state == LISTEN)
#endif /* TCP_LISTEN_BACKLOG */

void             tcp_recved  (struct tcp_pcb *pcb, u32_t len);
err_t            tcp_bind    (struct tcp_pcb *pcb, ip_addr_t *ipaddr,
                              u16_t port);
err_t            tcp_connect (struct tcp_pcb *pcb, ip_addr_t *ipaddr,
                              u16_t port, tcp_connected_fn connected);

err_t			tcp_listen_with_backlog(struct tcp_pcb_listen *listen_pcb, struct tcp_pcb *conn_pcb, u8_t backlog);
#define			tcp_listen(listen_pcb, conn_pcb) tcp_listen_with_backlog(listen_pcb, conn_pcb, TCP_DEFAULT_LISTEN_BACKLOG)

void             tcp_abort (struct tcp_pcb *pcb);
err_t            tcp_close   (struct tcp_pcb *pcb);
err_t            tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx);

/* Flags for "apiflags" parameter in tcp_write */
#define TCP_WRITE_FLAG_COPY 0x01
#define TCP_WRITE_FLAG_MORE 0x02

err_t            tcp_write   (struct tcp_pcb *pcb, const void *dataptr, u32_t len,
                              u8_t apiflags);

void             tcp_setprio (struct tcp_pcb *pcb, u8_t prio);

#define TCP_PRIO_MIN    1
#define TCP_PRIO_NORMAL 64
#define TCP_PRIO_MAX    127

err_t            tcp_output  (struct tcp_pcb *pcb);


const char* tcp_debug_state_str(enum tcp_state s);


#ifdef __cplusplus
}
#endif

#endif /* LWIP_TCP */

#endif /* __LWIP_TCP_H__ */
