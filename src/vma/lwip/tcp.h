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

#include <sys/uio.h>

#include "vma/lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "vma/lwip/pbuf.h"
#include "vma/lwip/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef u32_t (*sys_now_fn)(void);
void register_sys_now(sys_now_fn fn);

#define LWIP_MEM_ALIGN_SIZE(size) (((size) + MEM_ALIGNMENT - 1) & ~(MEM_ALIGNMENT-1))

extern u16_t lwip_tcp_mss;

#if LWIP_3RD_PARTY_L3
#if LWIP_TSO
typedef err_t (*ip_output_fn)(struct pbuf *p, void* p_conn, u16_t flags);
#else
typedef err_t (*ip_output_fn)(struct pbuf *p, void* p_conn, int is_rexmit, u8_t is_dummy);
#endif /* LWIP_TSO */
void register_ip_output(ip_output_fn fn);

typedef ssize_t (*sys_readv_fn)(int __fd, const struct iovec *iov, int iovcnt);
void register_sys_readv(sys_readv_fn fn);

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

#include "vma/lwip/cc.h"

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

static const char * const tcp_state_str[] = {
  "CLOSED",
  "LISTEN",
  "SYN_SENT",
  "SYN_RCVD",
  "ESTABLISHED",
  "FIN_WAIT_1",
  "FIN_WAIT_2",
  "CLOSE_WAIT",
  "CLOSING",
  "LAST_ACK",
  "TIME_WAIT"
};

#define PCB_IN_CLOSED_STATE(pcb) (get_tcp_state(pcb) == CLOSED)
#define PCB_IN_LISTEN_STATE(pcb) (get_tcp_state(pcb) == LISTEN)
#define PCB_IN_ACTIVE_STATE(pcb) (get_tcp_state(pcb) > LISTEN && get_tcp_state(pcb) < TIME_WAIT)
#define PCB_IN_TIME_WAIT_STATE(pcb) (get_tcp_state(pcb) == TIME_WAIT)

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


/* allow user to be notified upon tcp_state changes */
typedef void (*tcp_state_observer_fn)(void* pcb_container, enum tcp_state new_state);
void register_tcp_state_observer(tcp_state_observer_fn fn);
extern tcp_state_observer_fn external_tcp_state_observer;

/**
 * members common to struct tcp_pcb and struct tcp_listen_pcb
 */
#define TCP_PCB_COMMON(type) \
  enum tcp_state private_state; /* TCP state - should only be touched thru get/set functions */ \
  u8_t prio; \
  void *callback_arg; \
  void *my_container; \
  /* Function to be called when sending data. */ \
  ip_output_fn ip_output; \
  /* the accept callback for listen- and normal pcbs, if LWIP_CALLBACK_API */ \
  DEF_ACCEPT_CALLBACK \
  /* ports are in host byte order */ \
  u16_t local_port; \
  u32_t rcv_wnd;   /* receiver window available */ \
  u32_t rcv_ann_wnd; /* receiver window to announce */ \
  u32_t rcv_wnd_max; /* maximum available receive window */ \
  u32_t rcv_wnd_max_desired;

#define RCV_WND_SCALE(pcb, wnd) (((wnd) >> (pcb)->rcv_scale))
#define SND_WND_SCALE(pcb, wnd) ((u32_t)(wnd) << (pcb)->snd_scale)

#define TCPWND_MIN16(x)    ((u16_t)LWIP_MIN((x), 0xFFFF))
#define VMA_NO_TCP_PCB_LISTEN_STRUCT 1
/* Note: max_tcp_snd_queuelen is now a multiple by 16 (was 4 before) to match max_unsent_len */
#define UPDATE_PCB_BY_MSS(pcb, snd_mss) \
	(pcb)->mss = (snd_mss); \
	(pcb)->max_tcp_snd_queuelen = (16*((pcb)->max_snd_buff)/((pcb)->mss)) ; \
	(pcb)->max_unsent_len = (16*((pcb)->max_snd_buff)/((pcb)->mss)); \
	(pcb)->tcp_oversize_val = (pcb)->mss; 

/* the TCP protocol control block */
struct tcp_pcb {
/** common PCB members */
  IP_PCB;
/** protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb);

  /* ports are in host byte order */
  u16_t remote_port;

  u16_t flags;
#define TF_ACK_DELAY   ((u16_t)0x0001U)   /* Delayed ACK. */
#define TF_ACK_NOW     ((u16_t)0x0002U)   /* Immediate ACK. */
#define TF_INFR        ((u16_t)0x0004U)   /* In fast recovery. */
#define TF_TIMESTAMP   ((u16_t)0x0008U)   /* Timestamp option enabled */
#define TF_RXCLOSED    ((u16_t)0x0010U)   /* rx closed by tcp_shutdown */
#define TF_FIN         ((u16_t)0x0020U)   /* Connection was closed locally (FIN segment enqueued). */
#define TF_NODELAY     ((u16_t)0x0040U)   /* Disable Nagle algorithm */
#define TF_NAGLEMEMERR ((u16_t)0x0080U)   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */
#define TF_WND_SCALE   ((u16_t)0x0100U) /* Window Scale option enabled */

  /* the rest of the fields are in host byte order
     as we have to do some math with them */
  /* receiver variables */
  u32_t rcv_nxt;   /* next seqno expected */
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
  u32_t cwnd;
  u32_t ssthresh;

  /* sender variables */
  u32_t snd_nxt;   /* next new seqno to be sent */
  u32_t snd_wnd;   /* sender window */
  u32_t snd_wnd_max;   /* the maximum sender window announced by the remote host */
  u32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                             window update. */
  u32_t snd_lbb;       /* Sequence number of next byte to be buffered. */

  u32_t acked;
  
  u32_t snd_buf;   /* Available buffer space for sending (in bytes). */
  u32_t max_snd_buff;

  u32_t snd_sml_snt; /* maintain state for minshall's algorithm */
  u32_t snd_sml_add; /* maintain state for minshall's algorithm */

#define TCP_SNDQUEUELEN_OVERFLOW (0xffffffU-3)
  u32_t snd_queuelen; /* Available buffer space for sending (in tcp_segs). */
  u32_t max_tcp_snd_queuelen; 

#if TCP_OVERSIZE
  /* Extra bytes available at the end of the last pbuf in unsent. */
  u16_t unsent_oversize;
  u16_t tcp_oversize_val;
#endif /* TCP_OVERSIZE */ 
  u16_t max_unsent_len;
  /* These are ordered by sequence number: */
  struct tcp_seg *unsent;   /* Unsent (queued) segments. */
  struct tcp_seg *last_unsent;   /* Last unsent (queued) segment. */
  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */
  struct tcp_seg *last_unacked;  /* Last element in unacknowledged segments list. */
#if TCP_QUEUE_OOSEQ  
  struct tcp_seg *ooseq;    /* Received out of sequence segments. */
#endif /* TCP_QUEUE_OOSEQ */

  struct pbuf *refused_data; /* Data previously received but not yet taken by upper layer */
  struct tcp_seg *seg_alloc; /* Available tcp_seg element for use */
  struct pbuf *pbuf_alloc; /* Available pbuf element for use */

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

  u8_t enable_ts_opt;
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

  u8_t snd_scale;
  u8_t rcv_scale;
#ifdef VMA_NO_TCP_PCB_LISTEN_STRUCT
  tcp_syn_handled_fn syn_handled_cb;
  tcp_clone_conn_fn clone_conn;

#endif /* VMA_NO_TCP_PCB_LISTEN_STRUCT */

  /* Delayed ACK control: number of quick acks */
  u8_t quickack;

#if LWIP_TSO
  /* TSO description */
  struct {
    /* Maximum length of memory buffer */
    u32_t max_buf_sz;

    /* Maximum length of TCP payload for TSO */
    u32_t max_payload_sz;

    /* Maximum length of header for TSO */
    u16_t max_header_sz;

    /* Maximum number of SGE */
    u32_t max_send_sge;
  } tso;
#endif /* LWIP_TSO */
};

typedef u16_t (*ip_route_mtu_fn)(struct tcp_pcb *pcb);
void register_ip_route_mtu(ip_route_mtu_fn fn);

#ifdef VMA_NO_TCP_PCB_LISTEN_STRUCT
#define tcp_pcb_listen tcp_pcb
#else
struct tcp_pcb_listen {  
/* Common members of all PCB types */
  IP_PCB;
/* Protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb_listen);
  tcp_syn_handled_fn syn_handled_cb;
  tcp_clone_conn_fn clone_conn;
};
#endif /* VMA_NO_TCP_PCB_LISTEN_STRUCT */

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

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility push(hidden)
#endif


/*Initialization of tcp_pcb structure*/
void tcp_pcb_init (struct tcp_pcb* pcb, u8_t prio);

void             tcp_arg     		(struct tcp_pcb *pcb, void *arg);
void             tcp_ip_output          (struct tcp_pcb *pcb, ip_output_fn ip_output);
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

#if LWIP_TSO
#define          tcp_tso(pcb)          ((pcb)->tso.max_payload_sz)
#else
#define          tcp_tso(pcb)          (0)
#endif /* LWIP_TSO */

#define          tcp_accepted(pcb) LWIP_ASSERT("get_tcp_state(pcb) == LISTEN (called for wrong pcb?)", \
		get_tcp_state(pcb) == LISTEN)

void             tcp_recved  (struct tcp_pcb *pcb, u32_t len);
err_t            tcp_bind    (struct tcp_pcb *pcb, ip_addr_t *ipaddr,
                              u16_t port);
err_t            tcp_connect (struct tcp_pcb *pcb, ip_addr_t *ipaddr,
                              u16_t port, tcp_connected_fn connected);

err_t            tcp_listen(struct tcp_pcb_listen *listen_pcb, struct tcp_pcb *conn_pcb);

void             tcp_abort (struct tcp_pcb *pcb);
err_t            tcp_close   (struct tcp_pcb *pcb);
err_t            tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx);

/* Flags for "apiflags" parameter in tcp_write */
#define TCP_WRITE_FLAG_COPY 0x01
#define TCP_WRITE_FLAG_MORE 0x02
#define TCP_WRITE_REXMIT    0x08
#define TCP_WRITE_DUMMY     0x10
#define TCP_WRITE_TSO       0x20
#define TCP_WRITE_FILE      0x40

err_t            tcp_write   (struct tcp_pcb *pcb, const void *dataptr, u32_t len,
                              u8_t apiflags);

#define TCP_PRIO_MIN    1
#define TCP_PRIO_NORMAL 64
#define TCP_PRIO_MAX    127

err_t            tcp_output  (struct tcp_pcb *pcb);

s32_t            tcp_is_wnd_available(struct tcp_pcb *pcb, u32_t data_len);

#if defined(__GNUC__) && (((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC visibility pop
#endif

#define get_tcp_state(pcb) ((pcb)->private_state)
#define set_tcp_state(pcb, state) external_tcp_state_observer((pcb)->my_container, (pcb)->private_state = state)

#ifdef __cplusplus
}
#endif

#endif /* LWIP_TCP */

#endif /* __LWIP_TCP_H__ */
