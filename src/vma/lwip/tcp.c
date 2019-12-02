/**
 * @file
 * Transmission Control Protocol for IP
 *
 * This file contains common functions for the TCP implementation, such as functinos
 * for manipulating the data structures and the TCP timer functions. TCP functions
 * related to input and output is found in tcp_in.c and tcp_out.c respectively.
 *
 */

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

#include "vma/lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */
#include "vma/lwip/cc.h"
#include "vma/lwip/tcp.h"
#include "vma/lwip/tcp_impl.h"
#include "vma/lwip/stats.h"

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if LWIP_3RD_PARTY_BUFS
tcp_tx_pbuf_alloc_fn external_tcp_tx_pbuf_alloc;

void register_tcp_tx_pbuf_alloc(tcp_tx_pbuf_alloc_fn fn)
{
    external_tcp_tx_pbuf_alloc = fn;
}

tcp_tx_pbuf_free_fn external_tcp_tx_pbuf_free;

void register_tcp_tx_pbuf_free(tcp_tx_pbuf_free_fn fn)
{
    external_tcp_tx_pbuf_free = fn;
}

tcp_seg_alloc_fn external_tcp_seg_alloc;

void register_tcp_seg_alloc(tcp_seg_alloc_fn fn)
{
    external_tcp_seg_alloc = fn;
}

tcp_seg_free_fn external_tcp_seg_free;

void register_tcp_seg_free(tcp_seg_free_fn fn)
{
    external_tcp_seg_free = fn;
}
#endif

/* allow user to be notified upon tcp_state changes */
tcp_state_observer_fn external_tcp_state_observer;

void register_tcp_state_observer(tcp_state_observer_fn fn)
{
	external_tcp_state_observer = fn;
}


enum cc_algo_mod lwip_cc_algo_module = CC_MOD_LWIP;

u16_t lwip_tcp_mss = CONST_TCP_MSS;

u8_t enable_ts_option = 0;
/* slow timer value */
static u32_t slow_tmr_interval;
/* Incremented every coarse grained timer shot (typically every slow_tmr_interval ms). */
u32_t tcp_ticks = 0;
const u8_t tcp_backoff[13] =
    { 1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7};
 /* Times per slowtmr hits */
const u8_t tcp_persist_backoff[7] = { 3, 6, 12, 24, 48, 96, 120 };

/** Only used for temporary storage. */
struct tcp_pcb *tcp_tmp_pcb;

#ifdef DEFINED_EXTRA_STATS
static void copy_tcp_metrics(struct tcp_pcb *pcb)
{
  struct tcp_seg *seg;
  u32_t n;

  pcb->stats.n_mss = pcb->mss;
  pcb->stats.n_rto_timer = pcb->rto * slow_tmr_interval;
  pcb->stats.n_snd_wnd = pcb->snd_wnd;
  pcb->stats.n_cwnd = pcb->cwnd;
  pcb->stats.n_ssthresh = pcb->ssthresh;
  pcb->stats.n_snd_nxt = pcb->snd_nxt;
  pcb->stats.n_lastack = pcb->lastack;

  for (seg = pcb->unsent, n = 0; seg != NULL; seg = seg->next, ++n);
  pcb->stats.n_unsent_q = n;
  for (seg = pcb->unacked, n = 0; seg != NULL; seg = seg->next, ++n);
  pcb->stats.n_unacked_q = n;
  for (seg = pcb->ooseq, n = 0; seg != NULL; seg = seg->next, ++n);
  pcb->stats.n_ooseq_q = n;
}
#else /* DEFINED_EXTRA_STATS */
static void copy_tcp_metrics(struct tcp_pcb *pcb)
{
  /* Do nothing is extra statistics is off. */
  (void)pcb;
}
#endif /* DEFINED_EXTRA_STATS */

/**
 *
 * @param v value to set
 */
void
set_tmr_resolution(u32_t v)
{
	slow_tmr_interval = v * 2;
}
/**
 * Called periodically to dispatch TCP timers.
 *
 */
void
tcp_tmr(struct tcp_pcb* pcb)
{
  /* Call tcp_fasttmr() every (slow_tmr_interval / 2) ms */
  tcp_fasttmr(pcb);

  if (++(pcb->tcp_timer) & 1) {
    /* Call tcp_tmr() every slow_tmr_interval ms, i.e., every other timer
       tcp_tmr() is called. */
    tcp_slowtmr(pcb);
  }

  copy_tcp_metrics(pcb);
}

/**
 * Closes the TX side of a connection held by the PCB.
 * For tcp_close(), a RST is sent if the application didn't receive all data
 * (tcp_recved() not called for all data passed to recv callback).
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it.
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */
static err_t
tcp_close_shutdown(struct tcp_pcb *pcb, u8_t rst_on_unacked_data)
{
  err_t err;

  if (rst_on_unacked_data && ((get_tcp_state(pcb) == ESTABLISHED) || (get_tcp_state(pcb) == CLOSE_WAIT))) {
    if ((pcb->refused_data != NULL) || (pcb->rcv_wnd != pcb->rcv_wnd_max)) {
      /* Not all data received by application, send RST to tell the remote
         side about this. */
      LWIP_ASSERT("pcb->flags & TF_RXCLOSED", pcb->flags & TF_RXCLOSED);

      /* don't call tcp_abort here: we must not deallocate the pcb since
         that might not be expected when calling tcp_close */
      tcp_rst(pcb->snd_nxt, pcb->rcv_nxt, pcb->local_port, pcb->remote_port, pcb);

      tcp_pcb_purge(pcb);

      if (get_tcp_state(pcb) == ESTABLISHED) {
              /* move to TIME_WAIT since we close actively */
    	  set_tcp_state(pcb, TIME_WAIT);
      } else {
              /* CLOSE_WAIT: deallocate the pcb since we already sent a RST for it */
      }

      return ERR_OK;
    }
  }

  switch (get_tcp_state(pcb)) {
  case CLOSED:
    /* Closing a pcb in the CLOSED state might seem erroneous,
     * however, it is in this state once allocated and as yet unused
     * and the user needs some way to free it should the need arise.
     * Calling tcp_close() with a pcb that has already been closed, (i.e. twice)
     * or for a pcb that has been used and then entered the CLOSED state 
     * is erroneous, but this should never happen as the pcb has in those cases
     * been freed, and so any remaining handles are bogus. */
    err = ERR_OK;
    pcb = NULL;
    break;
  case LISTEN:
    err = ERR_OK;
    tcp_pcb_remove(pcb);
    pcb = NULL;
    break;
  case SYN_SENT:
    err = ERR_OK;
    tcp_pcb_remove(pcb);
    pcb = NULL;
    break;
  case SYN_RCVD:
    err = tcp_send_fin(pcb);
    if (err == ERR_OK) {
      set_tcp_state(pcb, FIN_WAIT_1);
    }
    break;
  case ESTABLISHED:
    err = tcp_send_fin(pcb);
    if (err == ERR_OK) {
      set_tcp_state(pcb, FIN_WAIT_1);
    }
    break;
  case CLOSE_WAIT:
    err = tcp_send_fin(pcb);
    if (err == ERR_OK) {
      set_tcp_state(pcb, LAST_ACK);
    }
    break;
  default:
    /* Has already been closed, do nothing. */
    err = ERR_OK;
    pcb = NULL;
    break;
  }

  if (pcb != NULL && err == ERR_OK) {
    /* To ensure all data has been sent when tcp_close returns, we have
       to make sure tcp_output doesn't fail.
       Since we don't really have to ensure all data has been sent when tcp_close
       returns (unsent data is sent from tcp timer functions, also), we don't care
       for the return value of tcp_output for now. */
    /* @todo: When implementing SO_LINGER, this must be changed somehow:
       If SOF_LINGER is set, the data should be sent and acked before close returns.
       This can only be valid for sequential APIs, not for the raw API. */
    tcp_output(pcb);
  }
  return err;
}

/**
 * Closes the connection held by the PCB.
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it (unless an error is returned).
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */
err_t
tcp_close(struct tcp_pcb *pcb)
{
#if TCP_DEBUG
  LWIP_DEBUGF(TCP_DEBUG, ("tcp_close: closing in "));
  tcp_debug_print_state(get_tcp_state(pcb));
#endif /* TCP_DEBUG */

  if (get_tcp_state(pcb) != LISTEN) {
    /* Set a flag not to receive any more data... */
    pcb->flags |= TF_RXCLOSED;
  }
  /* ... and close */
  return tcp_close_shutdown(pcb, 1);
}

/**
 * Causes all or part of a full-duplex connection of this PCB to be shut down.
 * This doesn't deallocate the PCB!
 *
 * @param pcb PCB to shutdown
 * @param shut_rx shut down receive side if this is != 0
 * @param shut_tx shut down send side if this is != 0
 * @return ERR_OK if shutdown succeeded (or the PCB has already been shut down)
 *         another err_t on error.
 */
err_t
tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx)
{
  if (get_tcp_state(pcb) == LISTEN) {
    return ERR_CONN;
  }
  if (shut_rx) {
    /* shut down the receive side: set a flag not to receive any more data... */
    pcb->flags |= TF_RXCLOSED;
    if (shut_tx) {
      /* shutting down the tx AND rx side is the same as closing for the raw API */
      return tcp_close_shutdown(pcb, 1);
    }
    /* ... and free buffered data */
    if (pcb->refused_data != NULL) {
      pbuf_free(pcb->refused_data);
      pcb->refused_data = NULL;
    }
  }
  if (shut_tx) {
    /* This can't happen twice since if it succeeds, the pcb's state is changed.
       Only close in these states as the others directly deallocate the PCB */
    switch (get_tcp_state(pcb)) {
  case SYN_RCVD:
  case ESTABLISHED:
  case CLOSE_WAIT:
    return tcp_close_shutdown(pcb, 0);
  default:
      /* Not (yet?) connected, cannot shutdown the TX side as that would bring us
	into CLOSED state, where the PCB is deallocated. */
      return ERR_CONN;
    }
  }
  /* @todo: return another err_t if not in correct state or already shut? */
  return ERR_OK;
}

/**
 * Abandons a connection and optionally sends a RST to the remote
 * host.  Deletes the local protocol control block. This is done when
 * a connection is killed because of shortage of memory.
 *
 * @param pcb the tcp_pcb to abort
 * @param reset boolean to indicate whether a reset should be sent
 */
void
tcp_abandon(struct tcp_pcb *pcb, int reset)
{
  u32_t seqno, ackno;
  u16_t remote_port, local_port;
  ip_addr_t remote_ip, local_ip;
#if LWIP_CALLBACK_API  
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */
  void *errf_arg;

  /* get_tcp_state(pcb) LISTEN not allowed here */
  LWIP_ASSERT("don't call tcp_abort/tcp_abandon for listen-pcbs",
		  get_tcp_state(pcb) != LISTEN);
  /* Figure out on which TCP PCB list we are, and remove us. If we
     are in an active state, call the receive function associated with
     the PCB with a NULL argument, and send an RST to the remote end. */
  if (get_tcp_state(pcb) == TIME_WAIT) {
    tcp_pcb_remove(pcb);
  } else {
    int send_rst = reset && (get_tcp_state(pcb) != CLOSED);
    seqno = pcb->snd_nxt;
    ackno = pcb->rcv_nxt;
    ip_addr_copy(local_ip, pcb->local_ip);
    ip_addr_copy(remote_ip, pcb->remote_ip);
    local_port = pcb->local_port;
    remote_port = pcb->remote_port;
#if LWIP_CALLBACK_API
    errf = pcb->errf;
#endif /* LWIP_CALLBACK_API */
    errf_arg = pcb->my_container;
    tcp_pcb_remove(pcb);
    if (pcb->unacked != NULL) {
      tcp_tx_segs_free(pcb, pcb->unacked);
      pcb->unacked = NULL;
    }
    if (pcb->unsent != NULL) {
      tcp_tx_segs_free(pcb, pcb->unsent);
      pcb->unsent = NULL;
    }
#if TCP_QUEUE_OOSEQ    
    if (pcb->ooseq != NULL) {
      tcp_segs_free(pcb, pcb->ooseq);
    }
#endif /* TCP_QUEUE_OOSEQ */
    TCP_EVENT_ERR(errf, errf_arg, ERR_ABRT);
    if (send_rst) {
      LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_abandon: sending RST\n"));
      tcp_rst(seqno, ackno, local_port, remote_port, pcb);
    }
  }
  (void)local_ip;  /* Fix warning -Wunused-but-set-variable */
  (void)remote_ip; /* Fix warning -Wunused-but-set-variable */
}

/**
 * Aborts the connection by sending a RST (reset) segment to the remote
 * host. The pcb is deallocated. This function never fails.
 *
 * ATTENTION: When calling this from one of the TCP callbacks, make
 * sure you always return ERR_ABRT (and never return ERR_ABRT otherwise
 * or you will risk accessing deallocated memory or memory leaks!
 *
 * @param pcb the tcp pcb to abort
 */
void
tcp_abort(struct tcp_pcb *pcb)
{
  tcp_abandon(pcb, 1);
}

/**
 * Binds the connection to a local portnumber and IP address. If the
 * IP address is not given (i.e., ipaddr == NULL), the IP address of
 * the outgoing network interface is used instead.
 *
 * @param pcb the tcp_pcb to bind (no check is done whether this pcb is
 *        already bound!)
 * @param ipaddr the local ip address to bind to (use IP_ADDR_ANY to bind
 *        to any local address
 * @param port the local port to bind to
 * @return ERR_USE if the port is already in use
 *         ERR_OK if bound
 */
err_t
tcp_bind(struct tcp_pcb *pcb, ip_addr_t *ipaddr, u16_t port)
{
  LWIP_ERROR("tcp_bind: can only bind in state CLOSED", get_tcp_state(pcb) == CLOSED, return ERR_ISCONN);

 if (!ip_addr_isany(ipaddr)) {
    pcb->local_ip = *ipaddr;
  }
  pcb->local_port = port;
  LWIP_DEBUGF(TCP_DEBUG, ("tcp_bind: bind to port %"U16_F"\n", port));

  return ERR_OK;
}
#if LWIP_CALLBACK_API
/**
 * Default accept callback if no accept callback is specified by the user.
 */
static err_t
tcp_accept_null(void *arg, struct tcp_pcb *pcb, err_t err)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(err);

  return ERR_ABRT;
}
#endif /* LWIP_CALLBACK_API */

/**
 * Set the state of the connection to be LISTEN, which means that it
 * is able to accept incoming connections.
 *
 * @param listen_pcb used for listening
 * @param pcb the original tcp_pcb
 * @return ERR_ISCONN if the conn_pcb is already in LISTEN state
 * and ERR_OK on success
 *
 */
err_t
tcp_listen(struct tcp_pcb_listen *listen_pcb, struct tcp_pcb *pcb)
{
  /*
  * LWIP_ERROR("tcp_listen: conn_pcb already connected", get_tcp_state(pcb) == CLOSED, ERR_ISCONN);
  */

  /* already listening? */
  if (!listen_pcb || (!pcb || get_tcp_state(pcb) == LISTEN)) {
    return ERR_ISCONN;
  }
  listen_pcb->callback_arg = pcb->callback_arg;
  listen_pcb->local_port = pcb->local_port;
  set_tcp_state(listen_pcb, LISTEN);
  listen_pcb->prio = pcb->prio;
  listen_pcb->so_options = pcb->so_options;
  listen_pcb->so_options |= SOF_ACCEPTCONN;
  listen_pcb->ttl = pcb->ttl;
  listen_pcb->tos = pcb->tos;
  ip_addr_copy(listen_pcb->local_ip, pcb->local_ip);
#if LWIP_CALLBACK_API
  listen_pcb->accept = tcp_accept_null;
#endif /* LWIP_CALLBACK_API */
  return ERR_OK;

}

/** 
 * Update the state that tracks the available window space to advertise.
 *
 * Returns how much extra window would be advertised if we sent an
 * update now.
 */
u32_t tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb)
{
  u32_t new_right_edge = pcb->rcv_nxt + pcb->rcv_wnd;

  if (TCP_SEQ_GEQ(new_right_edge, pcb->rcv_ann_right_edge + LWIP_MIN((pcb->rcv_wnd_max / 2), pcb->mss))) {
    /* we can advertise more window */
    pcb->rcv_ann_wnd = pcb->rcv_wnd;
    return new_right_edge - pcb->rcv_ann_right_edge;
  } else {
    if (TCP_SEQ_GT(pcb->rcv_nxt, pcb->rcv_ann_right_edge)) {
      /* Can happen due to other end sending out of advertised window,
       * but within actual available (but not yet advertised) window */
      pcb->rcv_ann_wnd = 0;
    } else {
      /* keep the right edge of window constant */
      u32_t new_rcv_ann_wnd = pcb->rcv_ann_right_edge - pcb->rcv_nxt;
      LWIP_ASSERT("new_rcv_ann_wnd <= 0xffff00", new_rcv_ann_wnd <= 0xffff00);
      pcb->rcv_ann_wnd = new_rcv_ann_wnd;
    }
    return 0;
  }
}

/**
 * This function should be called by the application when it has
 * processed the data. The purpose is to advertise a larger window
 * when the data has been processed.
 *
 * @param pcb the tcp_pcb for which data is read
 * @param len the amount of bytes that have been read by the application
 */
void
tcp_recved(struct tcp_pcb *pcb, u32_t len)
{
  u32_t wnd_inflation;

  LWIP_ASSERT("tcp_recved: len would wrap rcv_wnd\n",
              len <= 0xffffffffU - pcb->rcv_wnd );

  pcb->rcv_wnd += len;
  if (pcb->rcv_wnd > pcb->rcv_wnd_max) {
    pcb->rcv_wnd = pcb->rcv_wnd_max;
  } else if(pcb->rcv_wnd == 0) {
  /* rcv_wnd overflowed */
    if ((get_tcp_state(pcb) == CLOSE_WAIT) || (get_tcp_state(pcb) == LAST_ACK)) {
      /* In passive close, we allow this, since the FIN bit is added to rcv_wnd
         by the stack itself, since it is not mandatory for an application
         to call tcp_recved() for the FIN bit, but e.g. the netconn API does so. */
      pcb->rcv_wnd = pcb->rcv_wnd_max;
    } else {
      LWIP_ASSERT("tcp_recved: len wrapped rcv_wnd\n", 0);
    }
  }

  wnd_inflation = tcp_update_rcv_ann_wnd(pcb);

  /* If the change in the right edge of window is significant (default
   * watermark is TCP_WND/4), then send an explicit update now.
   * Otherwise wait for a packet to be sent in the normal course of
   * events (or more window to be available later) */
  if (wnd_inflation >= TCP_WND_UPDATE_THRESHOLD) {
    tcp_ack_now(pcb);
    tcp_output(pcb);
  }

  LWIP_DEBUGF(TCP_DEBUG, ("tcp_recved: recveived %"U16_F" bytes, wnd %"U16_F" (%"U16_F").\n",
         len, pcb->rcv_wnd, TCP_WND_SCALED(pcb) - pcb->rcv_wnd));
}

/**
 * Connects to another host. The function given as the "connected"
 * argument will be called when the connection has been established.
 *
 * @param pcb the tcp_pcb used to establish the connection
 * @param ipaddr the remote ip address to connect to
 * @param port the remote tcp port to connect to
 * @param connected callback function to call when connected (or on error)
 * @return ERR_VAL if invalid arguments are given
 *         ERR_OK if connect request has been sent
 *         other err_t values if connect request couldn't be sent
 */
err_t
tcp_connect(struct tcp_pcb *pcb, ip_addr_t *ipaddr, u16_t port,
      tcp_connected_fn connected)
{
  err_t ret;
  u32_t iss;

  LWIP_ERROR("tcp_connect: can only connected from state CLOSED", get_tcp_state(pcb) == CLOSED, return ERR_ISCONN);

  LWIP_DEBUGF(TCP_DEBUG, ("tcp_connect to port %"U16_F"\n", port));
  if (ipaddr != NULL) {
    pcb->remote_ip = *ipaddr;
  } else {
    return ERR_VAL;
  }
  pcb->remote_port = port;

  /* check if we have a route to the remote host */
  if (ip_addr_isany(&(pcb->local_ip))) {
	  LWIP_ASSERT("tcp_connect: need to find route to host", 0);
  }

  if (pcb->local_port == 0) {
    return ERR_VAL;
  }
  iss = tcp_next_iss();
  pcb->rcv_nxt = 0;
  pcb->snd_nxt = iss;
  pcb->lastack = iss - 1;
  pcb->snd_lbb = iss - 1;
  pcb->rcv_ann_right_edge = pcb->rcv_nxt;
  pcb->snd_wnd = TCP_WND;
  /* 
   * For effective and advertized MSS without MTU consideration:
   * If MSS is configured - do not accept a higher value than 536 
   * If MSS is not configured assume minimum value of 536 
   * The send MSS is updated when an MSS option is received 
   */
  u16_t snd_mss = pcb->advtsd_mss = (LWIP_TCP_MSS) ? ((LWIP_TCP_MSS > 536) ? 536 : LWIP_TCP_MSS) : 536;
  UPDATE_PCB_BY_MSS(pcb, snd_mss); 
#if TCP_CALCULATE_EFF_SEND_MSS
  /* 
   * For advertized MSS with MTU knowledge - it is highly likely that it can be derived from the MTU towards the remote IP address. 
   * Otherwise (if unlikely MTU==0)
   * If LWIP_TCP_MSS>0 use it as MSS 
   * If LWIP_TCP_MSS==0 set advertized MSS value to default 536
   */
  pcb->advtsd_mss = (LWIP_TCP_MSS > 0) ? tcp_eff_send_mss(LWIP_TCP_MSS, pcb) : tcp_mss_follow_mtu_with_default(536, pcb);
  /* 
   * For effective MSS with MTU knowledge - get the minimum between pcb->mss and the MSS derived from the 
   * MTU towards the remote IP address 
   * */
  u16_t eff_mss = tcp_eff_send_mss(pcb->mss, pcb);
  UPDATE_PCB_BY_MSS(pcb, eff_mss);
#endif /* TCP_CALCULATE_EFF_SEND_MSS */
  pcb->cwnd = 1;
  pcb->ssthresh = pcb->mss * 10;
  pcb->connected = connected;

  /* Send a SYN together with the MSS option. */
  ret = tcp_enqueue_flags(pcb, TCP_SYN);
  if (ret == ERR_OK) {
    /* SYN segment was enqueued, changed the pcbs state now */
	  set_tcp_state(pcb, SYN_SENT);

    tcp_output(pcb);
  }
  return ret;
}

/**
 * Called every slow_tmr_interval ms and implements the retransmission timer and the timer that
 * closes the psb if it in TIME_WAIT state for enough time. It also increments
 * various timers such as the inactivity timer in PCB.
 *
 * Automatically called from tcp_tmr().
 */
void
tcp_slowtmr(struct tcp_pcb* pcb)
{
#if !TCP_CC_ALGO_MOD
  u32_t eff_wnd;
#endif //!TCP_CC_ALGO_MOD
  u8_t pcb_remove;      /* flag if a PCB should be removed */
  u8_t pcb_reset;       /* flag if a RST should be sent when removing */
  err_t err;

  err = ERR_OK;

  if (pcb == NULL) {
	LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: no active pcbs\n"));
  }

  if (pcb && PCB_IN_ACTIVE_STATE(pcb)) {
	LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: processing active pcb\n"));
	LWIP_ASSERT("tcp_slowtmr: active get_tcp_state(pcb) != CLOSED\n", get_tcp_state(pcb) != CLOSED);
	LWIP_ASSERT("tcp_slowtmr: active get_tcp_state(pcb) != LISTEN\n", get_tcp_state(pcb) != LISTEN);
	LWIP_ASSERT("tcp_slowtmr: active get_tcp_state(pcb) != TIME-WAIT\n", get_tcp_state(pcb) != TIME_WAIT);

	pcb_remove = 0;
	pcb_reset = 0;

	if (get_tcp_state(pcb) == SYN_SENT && pcb->nrtx == TCP_SYNMAXRTX) {
	  ++pcb_remove;
	  err = ERR_TIMEOUT;
	  LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: max SYN retries reached\n"));
	}
	else if (pcb->nrtx == TCP_MAXRTX) {
	  ++pcb_remove;
	  err = ERR_ABRT;
	  LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: max DATA retries reached\n"));
	} else {
	  if (pcb->persist_backoff > 0) {
		/* If snd_wnd is zero and pcb->unacked is NULL , use persist timer to send 1 byte probes
		 * instead of using the standard retransmission mechanism. */
		pcb->persist_cnt++;
		if (pcb->persist_cnt >= tcp_persist_backoff[pcb->persist_backoff-1]) {
		  pcb->persist_cnt = 0;
		  if (pcb->persist_backoff < sizeof(tcp_persist_backoff)) {
			pcb->persist_backoff++;
		  }
		  /* Use tcp_keepalive() instead of tcp_zero_window_probe() to probe for window update
		   * without sending any data (which will force us to split the segment).
		   * tcp_zero_window_probe(pcb); */
		  tcp_keepalive(pcb);
		}
	  } else {
		/* Increase the retransmission timer if it is running */
		if(pcb->rtime >= 0)
		  ++pcb->rtime;

		if (pcb->unacked != NULL && pcb->rtime >= pcb->rto) {
		  /* Time for a retransmission. */
		  LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_slowtmr: rtime %"S16_F
									  " pcb->rto %"S16_F"\n",
									  pcb->rtime, pcb->rto));

		  /* Double retransmission time-out unless we are trying to
		   * connect to somebody (i.e., we are in SYN_SENT). */
		  if (get_tcp_state(pcb) != SYN_SENT) {
			pcb->rto = ((pcb->sa >> 3) + pcb->sv) << tcp_backoff[pcb->nrtx];
		  }

		  /* Reset the retransmission timer. */
		  pcb->rtime = 0;

#if TCP_CC_ALGO_MOD
		  cc_cong_signal(pcb, CC_RTO);
#else
		  /* Reduce congestion window and ssthresh. */
		  eff_wnd = LWIP_MIN(pcb->cwnd, pcb->snd_wnd);
		  pcb->ssthresh = eff_wnd >> 1;
		  if (pcb->ssthresh < (u32_t)(pcb->mss << 1)) {
			pcb->ssthresh = (pcb->mss << 1);
		  }
		  pcb->cwnd = pcb->mss;
#endif
		  LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_slowtmr: cwnd %"U16_F
									   " ssthresh %"U16_F"\n",
									   pcb->cwnd, pcb->ssthresh));

		  /* The following needs to be called AFTER cwnd is set to one
			 mss - STJ */
		  tcp_rexmit_rto(pcb);
		}
	  }
	}
	/* Check if this PCB has stayed too long in FIN-WAIT-2 */
	if (get_tcp_state(pcb) == FIN_WAIT_2) {
		/* If this PCB is in FIN_WAIT_2 because of SHUT_WR don't let it time out. */
		if (pcb->flags & TF_RXCLOSED) {
			/* PCB was fully closed (either through close() or SHUT_RDWR):
	   	   	   normal FIN-WAIT timeout handling. */
			if ((u32_t)(tcp_ticks - pcb->tmr) >
			TCP_FIN_WAIT_TIMEOUT / slow_tmr_interval) {
				++pcb_remove;
				err = ERR_ABRT;
				LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: removing pcb stuck in FIN-WAIT-2\n"));
			}
		}
	}

	/* Check if KEEPALIVE should be sent */
	if((pcb->so_options & SOF_KEEPALIVE) &&
	   ((get_tcp_state(pcb) == ESTABLISHED) ||
		(get_tcp_state(pcb) == CLOSE_WAIT))) {
#if LWIP_TCP_KEEPALIVE
	  if((u32_t)(tcp_ticks - pcb->tmr) >
		 (pcb->keep_idle + (pcb->keep_cnt*pcb->keep_intvl))
		 / slow_tmr_interval)
#else
	  if((u32_t)(tcp_ticks - pcb->tmr) >
		 (pcb->keep_idle + TCP_MAXIDLE) / slow_tmr_interval)
#endif /* LWIP_TCP_KEEPALIVE */
	  {
		LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: KEEPALIVE timeout. Aborting connection to %"U16_F".%"U16_F".%"U16_F".%"U16_F".\n",
								ip4_addr1_16(&pcb->remote_ip), ip4_addr2_16(&pcb->remote_ip),
								ip4_addr3_16(&pcb->remote_ip), ip4_addr4_16(&pcb->remote_ip)));

		++pcb_remove;
		err = ERR_ABRT;
		++pcb_reset;
	  }
#if LWIP_TCP_KEEPALIVE
	  else if((u32_t)(tcp_ticks - pcb->tmr) >
			  (pcb->keep_idle + pcb->keep_cnt_sent * pcb->keep_intvl)
			  / slow_tmr_interval)
#else
	  else if((u32_t)(tcp_ticks - pcb->tmr) >
			  (pcb->keep_idle + pcb->keep_cnt_sent * TCP_KEEPINTVL_DEFAULT)
			  / slow_tmr_interval)
#endif /* LWIP_TCP_KEEPALIVE */
	  {
		tcp_keepalive(pcb);
		pcb->keep_cnt_sent++;
	  }
	}

	/* If this PCB has queued out of sequence data, but has been
	   inactive for too long, will drop the data (it will eventually
	   be retransmitted). */
#if TCP_QUEUE_OOSEQ
	if (pcb->ooseq != NULL &&
		(u32_t)tcp_ticks - pcb->tmr >= pcb->rto * TCP_OOSEQ_TIMEOUT) {
	  tcp_segs_free(pcb, pcb->ooseq);
	  pcb->ooseq = NULL;
	  LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_slowtmr: dropping OOSEQ queued data\n"));
	}
#endif /* TCP_QUEUE_OOSEQ */

	/* Check if this PCB has stayed too long in SYN-RCVD */
	if (get_tcp_state(pcb) == SYN_RCVD) {
	  if ((u32_t)(tcp_ticks - pcb->tmr) >
		  TCP_SYN_RCVD_TIMEOUT / slow_tmr_interval) {
		++pcb_remove;
		err = ERR_ABRT;
		LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: removing pcb stuck in SYN-RCVD\n"));
	  }
	}

	/* Check if this PCB has stayed too long in LAST-ACK */
	if (get_tcp_state(pcb) == LAST_ACK) {
	  if ((u32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / slow_tmr_interval) {
		++pcb_remove;
		err = ERR_ABRT;
		LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: removing pcb stuck in LAST-ACK\n"));
	  }
	}

	/* If the PCB should be removed, do it. */
	if (pcb_remove) {
	  tcp_pcb_purge(pcb);

	  TCP_EVENT_ERR(pcb->errf, pcb->my_container, err);

	  if (pcb_reset) {
		tcp_rst(pcb->snd_nxt, pcb->rcv_nxt, pcb->local_port, pcb->remote_port, pcb);
	  }
	  set_tcp_state(pcb, CLOSED);
	} else {
	   /* We check if we should poll the connection. */
	  ++pcb->polltmr;
	  if (pcb->polltmr >= pcb->pollinterval) {
		  pcb->polltmr = 0;
		LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: polling application\n"));
		TCP_EVENT_POLL(pcb, err);
		/* if err == ERR_ABRT, 'prev' is already deallocated */
		if (err == ERR_OK) {
		  tcp_output(pcb);
		}
	  }
	}
  }


  if (pcb && PCB_IN_TIME_WAIT_STATE(pcb)) {
	LWIP_ASSERT("tcp_slowtmr: TIME-WAIT get_tcp_state(pcb) == TIME-WAIT", get_tcp_state(pcb) == TIME_WAIT);
	pcb_remove = 0;

	/* Check if this PCB has stayed long enough in TIME-WAIT */
	if ((u32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / slow_tmr_interval) {
	  ++pcb_remove;
	  /* err = ERR_ABRT; */ /* Note: suppress warning 'err' is never read */
	}

	/* If the PCB should be removed, do it. */
	if (pcb_remove) {
	  tcp_pcb_purge(pcb);

	  set_tcp_state(pcb, CLOSED);
	}
  }
}


/**
 * Is called every slow_tmr_interval and process data previously
 * "refused" by upper layer (application) and sends delayed ACKs.
 *
 * Automatically called from tcp_tmr().
 */
void
tcp_fasttmr(struct tcp_pcb* pcb)
{
  if(pcb != NULL && PCB_IN_ACTIVE_STATE(pcb)) {
    /* If there is data which was previously "refused" by upper layer */
	  while (pcb->refused_data != NULL) { // 'while' instead of 'if' because windows scale uses large pbuf
		  struct pbuf *rest;
		  /* Notify again application with data previously received. */
		  err_t err;
		  pbuf_split_64k(pcb->refused_data, &rest);
		  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_fasttmr: notify kept packet\n"));
		  TCP_EVENT_RECV(pcb, pcb->refused_data, ERR_OK, err);
		  if (err == ERR_OK) {
			  pcb->refused_data = rest;
		  } else {
			  if (rest) {
				  pbuf_cat(pcb->refused_data, rest); /* undo splitting */
			  }
			  if (err == ERR_ABRT) {
				  /* if err == ERR_ABRT, 'pcb' is already deallocated */
				  pcb = NULL;
			  }
			  break;
		  }
    }

    /* send delayed ACKs */
    if (pcb && (pcb->flags & TF_ACK_DELAY)) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_fasttmr: delayed ACK\n"));
      tcp_ack_now(pcb);
      tcp_output(pcb);
      pcb->flags &= ~(TF_ACK_DELAY | TF_ACK_NOW);
    }
  }
}

/**
 * Deallocates a list of TCP segments (tcp_seg structures).
 *
 * @param seg tcp_seg list of TCP segments to free
 */
void
tcp_segs_free(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
  while (seg != NULL) {
    struct tcp_seg *next = seg->next;
    seg->next = NULL;
    tcp_seg_free(pcb, seg);
    seg = next;
  }
}

/**
 * Frees a TCP segment (tcp_seg structure).
 *
 * @param seg single tcp_seg to free
 */
void
tcp_seg_free(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
  if (seg != NULL) {
    if (seg->p != NULL) {
      pbuf_free(seg->p);
#if TCP_DEBUG
      seg->p = NULL;
#endif /* TCP_DEBUG */
    }
    external_tcp_seg_free(pcb, seg);
  }
}

/**
 * Deallocates a list of TCP segments (tcp_seg structures).
 *
 * @param seg tcp_seg list of TCP segments to free
 */
void
tcp_tx_segs_free(struct tcp_pcb * pcb, struct tcp_seg *seg)
{
  while (seg != NULL) {
    struct tcp_seg *next = seg->next;
    seg->next = NULL;
    tcp_tx_seg_free(pcb, seg);
    seg = next;
  }
}

/**
 * Frees a TCP segment (tcp_seg structure).
 *
 * @param seg single tcp_seg to free
 */
void
tcp_tx_seg_free(struct tcp_pcb * pcb, struct tcp_seg *seg)
{
  if (seg != NULL) {
    if (seg->p != NULL) {
      tcp_tx_pbuf_free(pcb, seg->p);
    }
    external_tcp_seg_free(pcb, seg);
  }
}

#if TCP_QUEUE_OOSEQ
/**
 * Returns a copy of the given TCP segment.
 * The pbuf and data are not copied, only the pointers
 *
 * @param seg the old tcp_seg
 * @return a copy of seg
 */ 
struct tcp_seg *
tcp_seg_copy(struct tcp_pcb* pcb, struct tcp_seg *seg)
{
  struct tcp_seg *cseg;

  cseg = external_tcp_seg_alloc(pcb);
  if (cseg == NULL) {
    return NULL;
  }
  SMEMCPY((u8_t *)cseg, (const u8_t *)seg, sizeof(struct tcp_seg)); 
  pbuf_ref(cseg->p);
  return cseg;
}
#endif /* TCP_QUEUE_OOSEQ */

#if LWIP_CALLBACK_API
/**
 * Default receive callback that is called if the user didn't register
 * a recv callback for the pcb.
 */
err_t
tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  LWIP_UNUSED_ARG(arg);
  if (p != NULL) {
    tcp_recved(pcb, (u32_t)p->tot_len);
    pbuf_free(p);
  } else if (err == ERR_OK) {
    return tcp_close(pcb);
  }
  return ERR_OK;
}
#endif /* LWIP_CALLBACK_API */

void tcp_pcb_init (struct tcp_pcb* pcb, u8_t prio)
{
	u32_t iss;

	memset(pcb, 0, sizeof(*pcb));
	pcb->max_snd_buff = TCP_SND_BUF;
	pcb->prio = prio;
	pcb->snd_buf = pcb->max_snd_buff;
	pcb->snd_queuelen = 0;
	pcb->snd_scale = 0;
	pcb->rcv_scale = 0;
	pcb->rcv_wnd = TCP_WND_SCALED(pcb);
	pcb->rcv_ann_wnd = TCP_WND_SCALED(pcb);
	pcb->rcv_wnd_max = TCP_WND_SCALED(pcb);
	pcb->rcv_wnd_max_desired = TCP_WND_SCALED(pcb);
	pcb->tos = 0;
	pcb->ttl = TCP_TTL;
	/* As initial send MSS, we use TCP_MSS but limit it to 536.
	   The send MSS is updated when an MSS option is received. */
	u16_t snd_mss = pcb->advtsd_mss = (LWIP_TCP_MSS) ? ((LWIP_TCP_MSS > 536) ? 536 : LWIP_TCP_MSS) : 536;
	UPDATE_PCB_BY_MSS(pcb, snd_mss);
	pcb->max_unsent_len = pcb->max_tcp_snd_queuelen;
	pcb->rto = 3000 / slow_tmr_interval;
	pcb->sa = 0;
	pcb->sv = 3000 / slow_tmr_interval;
	pcb->rtime = -1;
#if TCP_CC_ALGO_MOD
	switch (lwip_cc_algo_module) {
	case CC_MOD_CUBIC:
		pcb->cc_algo = &cubic_cc_algo;
		break;
	case CC_MOD_NONE:
		pcb->cc_algo = &none_cc_algo;
		break;
	case CC_MOD_LWIP:
	default:
		pcb->cc_algo = &lwip_cc_algo;
		break;
	}
	cc_init(pcb);
#endif
	pcb->cwnd = 1;
	iss = tcp_next_iss();
	pcb->snd_wl2 = iss;
	pcb->snd_nxt = iss;
	pcb->lastack = iss;
	pcb->snd_lbb = iss;
	pcb->tmr = tcp_ticks;
	pcb->snd_sml_snt = 0;
	pcb->snd_sml_add = 0;

	pcb->polltmr = 0;
	pcb->tcp_timer = 0;
#if LWIP_CALLBACK_API
	pcb->recv = tcp_recv_null;
#endif /* LWIP_CALLBACK_API */

	/* Init KEEPALIVE timer */
	pcb->keep_idle  = TCP_KEEPIDLE_DEFAULT;

#if LWIP_TCP_KEEPALIVE
	pcb->keep_intvl = TCP_KEEPINTVL_DEFAULT;
	pcb->keep_cnt   = TCP_KEEPCNT_DEFAULT;
#endif /* LWIP_TCP_KEEPALIVE */

	pcb->keep_cnt_sent = 0;
	pcb->quickack = 0;
	pcb->enable_ts_opt = enable_ts_option;
	pcb->seg_alloc = NULL;
	pcb->pbuf_alloc = NULL;
}

struct pbuf *
tcp_tx_pbuf_alloc(struct tcp_pcb * pcb, u16_t length, pbuf_type type)
{
	struct pbuf * p;

	if (!pcb->pbuf_alloc) {

		// pbuf_alloc is not valid, we should allocate a new pbuf.
		p = external_tcp_tx_pbuf_alloc(pcb);
		if (!p) {
			PCB_STATS_INC(n_memerr_pbuf);
			return NULL;
		}

		p->next = NULL;
		p->type = type;
		/* set reference count */
		p->ref = 1;
		/* set flags */
		p->flags = 0;
	} else {
		// pbuf_alloc is valid, we dont need to allocate a new pbuf element.
		p = pcb->pbuf_alloc;
		pcb->pbuf_alloc = NULL;
	}

	/* Set up internal structure of the pbuf. */
	p->len = p->tot_len = length;

	return p;
}

// Release preallocated buffers
void tcp_tx_preallocted_buffers_free(struct tcp_pcb * pcb)
{
	if (pcb->seg_alloc) {
		tcp_tx_seg_free(pcb, pcb->seg_alloc);
		pcb->seg_alloc = NULL;
	}

	if (pcb->pbuf_alloc) {
		tcp_tx_pbuf_free(pcb, pcb->pbuf_alloc);
		pcb->pbuf_alloc = NULL;
	}
}

void
tcp_tx_pbuf_free(struct tcp_pcb * pcb, struct pbuf * p)
{
	struct pbuf * p_next = NULL;
	while (p) {
		p_next = p->next;
		p->next = NULL;
		if (p->type  == PBUF_RAM) {
			external_tcp_tx_pbuf_free(pcb, p);
		} else {
			pbuf_free(p);
		}
		p = p_next;
	}
}

/**
 * Used to specify the argument that should be passed callback
 * functions.
 *
 * @param pcb tcp_pcb to set the callback argument
 * @param arg void pointer argument to pass to callback functions
 */ 
void
tcp_arg(struct tcp_pcb *pcb, void *arg)
{  
  pcb->callback_arg = arg;
}
#if LWIP_CALLBACK_API

/**
 * Used to specify the function that should be called when a TCP
 * connection receives data.
 *
 * @param pcb tcp_pcb to set the recv callback
 * @param recv callback function to call for this pcb when data is received
 */ 
void
tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv)
{
  pcb->recv = recv;
}

/**
 * Used to specify the function that should be called when TCP data
 * has been successfully delivered to the remote host.
 *
 * @param pcb tcp_pcb to set the sent callback
 * @param sent callback function to call for this pcb when data is successfully sent
 */ 
void
tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent)
{
  pcb->sent = sent;
}

/**
 * Used to specify the function that should be called when a fatal error
 * has occured on the connection.
 *
 * @param pcb tcp_pcb to set the err callback
 * @param err callback function to call for this pcb when a fatal error
 *        has occured on the connection
 */ 
void
tcp_err(struct tcp_pcb *pcb, tcp_err_fn err)
{
  pcb->errf = err;
}

/**
 * Used for specifying the function that should be called when a
 * LISTENing connection has been connected to another host.
 *
 * @param pcb tcp_pcb to set the accept callback
 * @param accept callback function to call for this pcb when LISTENing
 *        connection has been connected to another host
 */ 
void
tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept)
{
  pcb->accept = accept;
}

/**
 * Used for specifying the function that should be called 
 * for sending packets.
 *
 * @param pcb tcp_pcb to set the outputcallback
 * @param output callback function
 */ 
void
tcp_ip_output(struct tcp_pcb *pcb, ip_output_fn ip_output)
{
  pcb->ip_output = ip_output;
}

/**
 * Used for specifying the function that should be called when a
 * SYN was received.
 *
 * @param pcb tcp_pcb to set the accept callback
 * @param accept callback function to call for this pcb when SYN
 *        is received
 */
void
tcp_syn_handled(struct tcp_pcb_listen *pcb, tcp_syn_handled_fn syn_handled)
{
  pcb->syn_handled_cb = syn_handled;
}

/**
 * Used for specifying the function that should be called to clone pcb
 *
 * @param listen pcb to clone
 * @param clone callback function to call in order to clone the pcb
 */
void
tcp_clone_conn(struct tcp_pcb_listen *pcb, tcp_clone_conn_fn clone_conn)
{
  pcb->clone_conn = clone_conn;
}
#endif /* LWIP_CALLBACK_API */


/**
 * Used to specify the function that should be called periodically
 * from TCP. The interval is specified in terms of the TCP coarse
 * timer interval, which is called twice a second.
 *
 */ 
void
tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval)
{
#if LWIP_CALLBACK_API
  pcb->poll = poll;
#else /* LWIP_CALLBACK_API */  
  LWIP_UNUSED_ARG(poll);
#endif /* LWIP_CALLBACK_API */  
  pcb->pollinterval = interval;
}

/**
 * Purges a TCP PCB. Removes any buffered data and frees the buffer memory
 * (pcb->ooseq, pcb->unsent and pcb->unacked are freed).
 *
 * @param pcb tcp_pcb to purge. The pcb itself is not deallocated!
 */
void
tcp_pcb_purge(struct tcp_pcb *pcb)
{
  if (get_tcp_state(pcb) != CLOSED &&
     get_tcp_state(pcb) != TIME_WAIT &&
     get_tcp_state(pcb) != LISTEN) {

    LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge\n"));

    if (pcb->refused_data != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: data left on ->refused_data\n"));
      pbuf_free(pcb->refused_data);
      pcb->refused_data = NULL;
    }
    if (pcb->unsent != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: not all data sent\n"));
    }
    if (pcb->unacked != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: data left on ->unacked\n"));
    }
#if TCP_QUEUE_OOSEQ
    if (pcb->ooseq != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: data left on ->ooseq\n"));
    }
    tcp_segs_free(pcb, pcb->ooseq);
    pcb->ooseq = NULL;
#endif /* TCP_QUEUE_OOSEQ */

    /* Stop the retransmission timer as it will expect data on unacked
       queue if it fires */
    pcb->rtime = -1;

    tcp_tx_segs_free(pcb, pcb->unsent);
    tcp_tx_segs_free(pcb, pcb->unacked);
    pcb->unacked = pcb->unsent = NULL;
#if TCP_OVERSIZE
    pcb->unsent_oversize = 0;
#endif /* TCP_OVERSIZE */
#if TCP_CC_ALGO_MOD
    cc_destroy(pcb);
#endif
  }
}

/**
 * Purges the PCB and removes it from a PCB list. Any delayed ACKs are sent first.
 *
 * @param pcblist PCB list to purge.
 * @param pcb tcp_pcb to purge. The pcb itself is NOT deallocated!
 */
void
tcp_pcb_remove(struct tcp_pcb *pcb)
{
  tcp_pcb_purge(pcb);
  
  /* if there is an outstanding delayed ACKs, send it */
  if (get_tcp_state(pcb) != TIME_WAIT &&
		  get_tcp_state(pcb) != LISTEN &&
     pcb->flags & TF_ACK_DELAY) {
    pcb->flags |= TF_ACK_NOW;
    tcp_output(pcb);
  }

  if (get_tcp_state(pcb) != LISTEN) {
    LWIP_ASSERT("unsent segments leaking", pcb->unsent == NULL);
    LWIP_ASSERT("unacked segments leaking", pcb->unacked == NULL);
#if TCP_QUEUE_OOSEQ
    LWIP_ASSERT("ooseq segments leaking", pcb->ooseq == NULL);
#endif /* TCP_QUEUE_OOSEQ */
  }

  set_tcp_state(pcb, CLOSED);

  LWIP_ASSERT("tcp_pcb_remove: tcp_pcbs_sane()", tcp_pcbs_sane());
}

/**
 * Calculates a new initial sequence number for new connections.
 *
 * @return u32_t pseudo random sequence number
 */
u32_t
tcp_next_iss(void)
{
  static u32_t iss = 6510;
  
  iss += tcp_ticks;       /* XXX */
  return iss;
}

#if TCP_CALCULATE_EFF_SEND_MSS
/**
 * Calcluates the effective send mss that can be used for a specific IP address
 * by using ip_route to determine the netif used to send to the address and
 * calculating the minimum of TCP_MSS and that netif's mtu (if set).
 */
u16_t
tcp_eff_send_mss(u16_t sendmss, struct tcp_pcb *pcb)
{
  u16_t mtu;

  mtu = external_ip_route_mtu(pcb);
  if (mtu != 0) {
    sendmss = LWIP_MIN(sendmss, mtu - IP_HLEN - TCP_HLEN);
  }
  return sendmss;
}

/**
 * Calcluates the send mss that can be used for a specific IP address
 * by using ip_route to determine the netif used to send to the address. 
 * In case MTU is unkonw - return the default MSS 
 */
u16_t
tcp_mss_follow_mtu_with_default(u16_t defsendmss, struct tcp_pcb *pcb)
{
  u16_t mtu;

  mtu = external_ip_route_mtu(pcb);
  if (mtu != 0) {
    defsendmss = mtu - IP_HLEN - TCP_HLEN;
    defsendmss = LWIP_MAX(defsendmss, 1); /* MSS must be a positive number */
  }
  return defsendmss;
}
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

#if TCP_DEBUG || TCP_INPUT_DEBUG || TCP_OUTPUT_DEBUG
/**
 * Print a tcp header for debugging purposes.
 *
 * @param tcphdr pointer to a struct tcp_hdr
 */
void
tcp_debug_print(struct tcp_hdr *tcphdr)
{
  LWIP_DEBUGF(TCP_DEBUG, ("TCP header:\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|    %5"U16_F"      |    %5"U16_F"      | (src port, dest port)\n",
         ntohs(tcphdr->src), ntohs(tcphdr->dest)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|           %010"U32_F"          | (seq no)\n",
          ntohl(tcphdr->seqno)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|           %010"U32_F"          | (ack no)\n",
         ntohl(tcphdr->ackno)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("| %2"U16_F" |   |%"U16_F"%"U16_F"%"U16_F"%"U16_F"%"U16_F"%"U16_F"|     %5"U16_F"     | (hdrlen, flags (",
       TCPH_HDRLEN(tcphdr),
         TCPH_FLAGS(tcphdr) >> 5 & 1,
         TCPH_FLAGS(tcphdr) >> 4 & 1,
         TCPH_FLAGS(tcphdr) >> 3 & 1,
         TCPH_FLAGS(tcphdr) >> 2 & 1,
         TCPH_FLAGS(tcphdr) >> 1 & 1,
         TCPH_FLAGS(tcphdr) & 1,
         ntohs(tcphdr->wnd)));
  tcp_debug_print_flags(TCPH_FLAGS(tcphdr));
  LWIP_DEBUGF(TCP_DEBUG, ("), win)\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|    0x%04"X16_F"     |     %5"U16_F"     | (chksum, urgp)\n",
         ntohs(tcphdr->chksum), ntohs(tcphdr->urgp)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
}

/**
 * Print a tcp state for debugging purposes.
 *
 * @param s enum tcp_state to print
 */
void
tcp_debug_print_state(enum tcp_state s)
{
  LWIP_UNUSED_ARG(s);
  LWIP_DEBUGF(TCP_DEBUG, ("State: %s\n", tcp_state_str[s]));
}

/**
 * Print tcp flags for debugging purposes.
 *
 * @param flags tcp flags, all active flags are printed
 */
void
tcp_debug_print_flags(u8_t flags)
{
  if (flags & TCP_FIN) {
    LWIP_DEBUGF(TCP_DEBUG, ("FIN "));
  }
  if (flags & TCP_SYN) {
    LWIP_DEBUGF(TCP_DEBUG, ("SYN "));
  }
  if (flags & TCP_RST) {
    LWIP_DEBUGF(TCP_DEBUG, ("RST "));
  }
  if (flags & TCP_PSH) {
    LWIP_DEBUGF(TCP_DEBUG, ("PSH "));
  }
  if (flags & TCP_ACK) {
    LWIP_DEBUGF(TCP_DEBUG, ("ACK "));
  }
  if (flags & TCP_URG) {
    LWIP_DEBUGF(TCP_DEBUG, ("URG "));
  }
  if (flags & TCP_ECE) {
    LWIP_DEBUGF(TCP_DEBUG, ("ECE "));
  }
  if (flags & TCP_CWR) {
    LWIP_DEBUGF(TCP_DEBUG, ("CWR "));
  }
  LWIP_DEBUGF(TCP_DEBUG, ("\n"));
}

/**
 * Print all tcp_pcbs in every list for debugging purposes.
 */
void
tcp_debug_print_pcbs(void)
{
  LWIP_DEBUGF(TCP_DEBUG, ("Listen PCB states: REMOVED\n"));
}
#endif /* TCP_DEBUG */

#endif /* LWIP_TCP */
