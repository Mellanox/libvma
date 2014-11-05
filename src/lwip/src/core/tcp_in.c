/**
 * @file
 * Transmission Control Protocol, incoming traffic
 *
 * The input processing functions of the TCP layer.
 *
 * These functions are generally called in the order (ip_input() ->)
 * tcp_input() -> * tcp_process() -> tcp_receive() (-> application).
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

#include "lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/tcp_impl.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/inet_chksum.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "arch/perf.h"

typedef struct tcp_in_data {
	struct pbuf *recv_data;
	struct tcp_hdr *tcphdr;
	struct ip_hdr *iphdr;
	u32_t seqno;
	u32_t ackno;
	struct tcp_seg inseg;
	u16_t tcplen;
	u8_t flags;
	u8_t recv_flags;
} tcp_in_data;

struct tcp_pcb *tcp_input_pcb;

/* Forward declarations. */
static err_t tcp_process(struct tcp_pcb *pcb, tcp_in_data* in_data);
static void tcp_receive(struct tcp_pcb *pcb, tcp_in_data* in_data);
static void tcp_parseopt(struct tcp_pcb *pcb, tcp_in_data* in_data);

static err_t tcp_listen_input(struct tcp_pcb_listen *pcb, tcp_in_data* in_data);
static err_t tcp_timewait_input(struct tcp_pcb *pcb, tcp_in_data* in_data);

/**
 * The initial input processing of TCP. It verifies the TCP header, demultiplexes
 * the segment between the PCBs and passes it on to tcp_process(), which implements
 * the TCP finite state machine. This function is called by the IP layer (in
 * ip_input()).
 *
 * @param p received TCP segment to process (p->payload pointing to the IP header)
 * @param inp network interface on which this segment was received
 */
void
tcp_input(struct pbuf *p, struct netif *inp)
{
  struct tcp_pcb *pcb, *prev;
  struct tcp_pcb_listen *lpcb;
#if SO_REUSE
  struct tcp_pcb *lpcb_prev = NULL;
  struct tcp_pcb_listen *lpcb_any = NULL;
#endif /* SO_REUSE */
  u8_t hdrlen;
  err_t err;
  tcp_in_data in_data;

  PERF_START;

  TCP_STATS_INC(tcp.recv);
  snmp_inc_tcpinsegs();

  in_data.iphdr = (struct ip_hdr *)p->payload;
  in_data.tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + IPH_HL(in_data.iphdr) * 4);

#if TCP_INPUT_DEBUG
  tcp_debug_print(in_data.tcphdr);
#endif

  /* remove header from payload */
  if (pbuf_header(p, -((s16_t)(IPH_HL(in_data.iphdr) * 4))) || (p->tot_len < sizeof(struct tcp_hdr))) {
    /* drop short packets */
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: short packet (%"U16_F" bytes) discarded\n", (u16_t)p->tot_len));
    TCP_STATS_INC(tcp.lenerr);
    TCP_STATS_INC(tcp.drop);
    snmp_inc_tcpinerrs();
    pbuf_free(p);
    return;
  }

  /* Don't even process incoming broadcasts/multicasts. */
  if (ip_addr_isbroadcast(&current_iphdr_dest, inp) ||
      ip_addr_ismulticast(&current_iphdr_dest)) {
    TCP_STATS_INC(tcp.proterr);
    TCP_STATS_INC(tcp.drop);
    snmp_inc_tcpinerrs();
    pbuf_free(p);
    return;
  }

#if CHECKSUM_CHECK_TCP
  /* Verify TCP checksum. */
  if (inet_chksum_pseudo(p, ip_current_src_addr(), ip_current_dest_addr(),
      IP_PROTO_TCP, (u16_t)p->tot_len) != 0) {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packet discarded due to failing checksum 0x%04"X16_F"\n",
        inet_chksum_pseudo(p, ip_current_src_addr(), ip_current_dest_addr(),
      IP_PROTO_TCP, (u16_t)p->tot_len)));
#if TCP_DEBUG
    tcp_debug_print(in_data.tcphdr);
#endif /* TCP_DEBUG */
    TCP_STATS_INC(tcp.chkerr);
    TCP_STATS_INC(tcp.drop);
    snmp_inc_tcpinerrs();
    pbuf_free(p);
    return;
  }
#endif

  /* Move the payload pointer in the pbuf so that it points to the
     TCP data instead of the TCP header. */
  hdrlen = TCPH_HDRLEN(in_data.tcphdr);
  if(pbuf_header(p, -(hdrlen * 4))){
    /* drop short packets */
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: short packet\n"));
    TCP_STATS_INC(tcp.lenerr);
    TCP_STATS_INC(tcp.drop);
    snmp_inc_tcpinerrs();
    pbuf_free(p);
    return;
  }

  /* Convert fields in TCP header to host byte order. */
  in_data.tcphdr->src = ntohs(in_data.tcphdr->src);
  in_data.tcphdr->dest = ntohs(in_data.tcphdr->dest);
  in_data.seqno = in_data.tcphdr->seqno = ntohl(in_data.tcphdr->seqno);
  in_data.ackno = in_data.tcphdr->ackno = ntohl(in_data.tcphdr->ackno);
  in_data.tcphdr->wnd = ntohs(in_data.tcphdr->wnd);

  in_data.flags = TCPH_FLAGS(in_data.tcphdr);
  in_data.tcplen = p->tot_len + ((in_data.flags & (TCP_FIN | TCP_SYN)) ? 1 : 0);

  /* Demultiplex an incoming segment. First, we check if it is destined
     for an active connection. */
  prev = NULL;

  
  for(pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_ASSERT("tcp_input: active pcb->state != CLOSED", pcb->state != CLOSED);
    LWIP_ASSERT("tcp_input: active pcb->state != TIME-WAIT", pcb->state != TIME_WAIT);
    LWIP_ASSERT("tcp_input: active pcb->state != LISTEN", pcb->state != LISTEN);
    if (pcb->remote_port == in_data.tcphdr->src &&
       pcb->local_port == in_data.tcphdr->dest &&
       ip_addr_cmp(&(pcb->remote_ip), &current_iphdr_src) &&
       ip_addr_cmp(&(pcb->local_ip), &current_iphdr_dest)) {

      /* Move this PCB to the front of the list so that subsequent
         lookups will be faster (we exploit locality in TCP segment
         arrivals). */
      LWIP_ASSERT("tcp_input: pcb->next != pcb (before cache)", pcb->next != pcb);
      if (prev != NULL) {
        prev->next = pcb->next;
        pcb->next = tcp_active_pcbs;
        tcp_active_pcbs = pcb;
      }
      LWIP_ASSERT("tcp_input: pcb->next != pcb (after cache)", pcb->next != pcb);
      break;
    }
    prev = pcb;
  }

  if (pcb == NULL) {
    /* If it did not go to an active connection, we check the connections
       in the TIME-WAIT state. */
    for(pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
      LWIP_ASSERT("tcp_input: TIME-WAIT pcb->state == TIME-WAIT", pcb->state == TIME_WAIT);
      if (pcb->remote_port == in_data.tcphdr->src &&
         pcb->local_port == in_data.tcphdr->dest &&
         ip_addr_cmp(&(pcb->remote_ip), &current_iphdr_src) &&
         ip_addr_cmp(&(pcb->local_ip), &current_iphdr_dest)) {
        /* We don't really care enough to move this PCB to the front
           of the list since we are not very likely to receive that
           many segments for connections in TIME-WAIT. */
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for TIME_WAITing connection.\n"));
        tcp_timewait_input(pcb, &in_data);
        pbuf_free(p);
        return;
      }
    }

    /* Finally, if we still did not get a match, we check all PCBs that
       are LISTENing for incoming connections. */
    prev = NULL;
    for(lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
      if (lpcb->local_port == in_data.tcphdr->dest) {
#if SO_REUSE
        if (ip_addr_cmp(&(lpcb->local_ip), &current_iphdr_dest)) {
          /* found an exact match */
          break;
        } else if(ip_addr_isany(&(lpcb->local_ip))) {
          /* found an ANY-match */
          lpcb_any = lpcb;
          lpcb_prev = prev;
        }
#else /* SO_REUSE */
        if (ip_addr_cmp(&(lpcb->local_ip), &current_iphdr_dest) ||
            ip_addr_isany(&(lpcb->local_ip))) {
          /* found a match */
          break;
        }
#endif /* SO_REUSE */
      }
      prev = (struct tcp_pcb *)lpcb;
    }
#if SO_REUSE
    /* first try specific local IP */
    if (lpcb == NULL) {
      /* only pass to ANY if no specific local IP has been found */
      lpcb = lpcb_any;
      prev = lpcb_prev;
    }
#endif /* SO_REUSE */
    if (lpcb != NULL) {
      /* Move this PCB to the front of the list so that subsequent
         lookups will be faster (we exploit locality in TCP segment
         arrivals). */
      if (prev != NULL) {
        ((struct tcp_pcb_listen *)prev)->next = lpcb->next;
              /* our successor is the remainder of the listening list */
        lpcb->next = tcp_listen_pcbs.listen_pcbs;
              /* put this listening pcb at the head of the listening list */
        tcp_listen_pcbs.listen_pcbs = lpcb;
      }
    
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for LISTENing connection.\n"));
      tcp_listen_input(lpcb, &in_data);
      pbuf_free(p);
      return;
    }
  }

#if TCP_INPUT_DEBUG
  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("+-+-+-+-+-+-+-+-+-+-+-+-+-+- tcp_input: flags "));
  tcp_debug_print_flags(TCPH_FLAGS(in_data.tcphdr));
  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"));
#endif /* TCP_INPUT_DEBUG */


  if (pcb != NULL) {
    /* The incoming segment belongs to a connection. */
#if TCP_INPUT_DEBUG
#if TCP_DEBUG
    tcp_debug_print_state(pcb->state);
#endif /* TCP_DEBUG */
#endif /* TCP_INPUT_DEBUG */

    /* Set up a tcp_seg structure. */
    in_data.inseg.next = NULL;
    in_data.inseg.len = p->tot_len;
    in_data.inseg.dataptr = p->payload;
    in_data.inseg.p = p;
    in_data.inseg.tcphdr = in_data.tcphdr;

    in_data.recv_data = NULL;
    in_data.recv_flags = 0;

    /* If there is data which was previously "refused" by upper layer */
    while (pcb->refused_data != NULL) { // 'while' instead of 'if' because windows scale uses large pbuf
	    struct pbuf *rest;
	    pbuf_split_64k(pcb->refused_data, &rest);

	    /* Notify again application with data previously received. */
	    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: notify kept packet\n"));
	    TCP_EVENT_RECV(pcb, pcb->refused_data, ERR_OK, err);
	    if (err == ERR_OK) {
		    pcb->refused_data = rest;
	    } else {
		    if (rest) {
			    pbuf_cat(pcb->refused_data, rest); /* undo splitting */
		    }
		    /* if err == ERR_ABRT, 'pcb' is already deallocated */
		    /* drop incoming packets, because pcb is "full" */
		    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: drop incoming packets, because pcb is \"full\"\n"));
		    TCP_STATS_INC(tcp.drop);
		    snmp_inc_tcpinerrs();
		    pbuf_free(p);
		    return;
	    }
    }
    tcp_input_pcb = pcb;
    err = tcp_process(pcb, &in_data);
    /* A return value of ERR_ABRT means that tcp_abort() was called
       and that the pcb has been freed. If so, we don't do anything. */
    if (err != ERR_ABRT) {
      if (in_data.recv_flags & TF_RESET) {
        /* TF_RESET means that the connection was reset by the other
           end. We then call the error callback to inform the
           application that the connection is dead before we
           deallocate the PCB. */
        TCP_EVENT_ERR(pcb->errf, pcb->my_container, ERR_RST);
        tcp_pcb_remove(pcb);
      } else if (in_data.recv_flags & TF_CLOSED) {
        /* The connection has been closed and we will deallocate the
           PCB. */
        tcp_pcb_remove(pcb);
      } else {
        err = ERR_OK;
        /* If the application has registered a "sent" function to be
           called when new send buffer space is available, we call it
           now. */
        if (pcb->acked > 0) {
          TCP_EVENT_SENT(pcb, pcb->acked, err);
          if (err == ERR_ABRT) {
            goto aborted;
          }
        }

        while (in_data.recv_data != NULL) { // 'while' instead of 'if' because windows scale uses large pbuf
        	struct pbuf *rest = NULL;
        	if (pcb->flags & TF_RXCLOSED) {
        		/* received data although already closed -> abort (send RST) to
                       notify the remote host that not all data has been processed */
        		pbuf_free(in_data.recv_data);
        		tcp_abort(pcb);
        		goto aborted;
        	}
        	pbuf_split_64k(in_data.recv_data, &rest);
        	if (in_data.flags & TCP_PSH) {
        		in_data.recv_data->flags |= PBUF_FLAG_PUSH;
        	}

        	/* Notify application that data has been received. */
        	TCP_EVENT_RECV(pcb, in_data.recv_data, ERR_OK, err);
        	if (err == ERR_ABRT) {
        		if (rest) {
        			pbuf_cat(in_data.recv_data, rest); /* undo splitting */
        		}
        		goto aborted;
        	}

        	/* If the upper layer can't receive this data, store it */
        	if (err != ERR_OK) {
        		if (rest) {
        			pbuf_cat(in_data.recv_data, rest); /* undo splitting */
        		}
        		pcb->refused_data = in_data.recv_data;
        		LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: keep incoming packet, because pcb is \"full\"\n"));
        		break;
        	} else {
        		in_data.recv_data = rest;
        	}
        }

        /* If a FIN segment was received, we call the callback
           function with a NULL buffer to indicate EOF. */
        if (in_data.recv_flags & TF_GOT_FIN) {
          /* correct rcv_wnd as the application won't call tcp_recved()
             for the FIN's seqno */
          if (pcb->rcv_wnd != TCP_WND_SCALED) {
            pcb->rcv_wnd++;
          }
          TCP_EVENT_CLOSED(pcb, err);
          if (err == ERR_ABRT) {
            goto aborted;
          }
        }

        tcp_input_pcb = NULL;
        /* Try to send something out. */
        tcp_output(pcb);
#if TCP_INPUT_DEBUG
#if TCP_DEBUG
        tcp_debug_print_state(pcb->state);
#endif /* TCP_DEBUG */
#endif /* TCP_INPUT_DEBUG */
      }
    }
    /* Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
       Below this line, 'pcb' may not be dereferenced! */
aborted:
    tcp_input_pcb = NULL;
    in_data.recv_data = NULL;

    /* give up our reference to inseg.p */
    if (in_data.inseg.p != NULL)
    {
      pbuf_free(in_data.inseg.p);
      in_data.inseg.p = NULL;
    }
  } else {

    /* If no matching PCB was found, send a TCP RST (reset) to the
       sender. */
    LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_input: no PCB match found, resetting.\n"));
    if (!(TCPH_FLAGS(in_data.tcphdr) & TCP_RST)) {
      TCP_STATS_INC(tcp.proterr);
      TCP_STATS_INC(tcp.drop);
      tcp_rst(in_data.ackno, in_data.seqno + in_data.tcplen,
        ip_current_dest_addr(), ip_current_src_addr(),
        in_data.tcphdr->dest, in_data.tcphdr->src, pcb);
    }
    pbuf_free(p);
  }

  LWIP_ASSERT("tcp_input: tcp_pcbs_sane()", tcp_pcbs_sane());
  PERF_STOP("tcp_input");
}

#if LWIP_3RD_PARTY_L3
void
L3_level_tcp_input(struct pbuf *p, struct tcp_pcb* pcb)
{
    u8_t hdrlen;
    err_t err;
    u16_t iphdr_len;
    tcp_in_data in_data;

    PERF_START;

    TCP_STATS_INC(tcp.recv);
    snmp_inc_tcpinsegs();
    in_data.iphdr = (struct ip_hdr *)p->payload;


    iphdr_len = ntohs(IPH_LEN(in_data.iphdr));
    /* Trim pbuf. This should have been done at the netif layer,
     * but we'll do it anyway just to be sure that its done. */
    pbuf_realloc(p, iphdr_len);

    in_data.tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + IPH_HL(in_data.iphdr) * 4);

#if TCP_INPUT_DEBUG
    tcp_debug_print(in_data.tcphdr);
#endif


    /* remove header from payload */
    if (pbuf_header(p, -((s16_t)(IPH_HL(in_data.iphdr) * 4))) || (p->tot_len < sizeof(struct tcp_hdr))) {
        /* drop short packets */
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: short packet (%"U16_F" bytes) discarded\n", (u16_t)p->tot_len));
        TCP_STATS_INC(tcp.lenerr);
        TCP_STATS_INC(tcp.drop);
        snmp_inc_tcpinerrs();
        pbuf_free(p);
        return;
    }

    /* Move the payload pointer in the pbuf so that it points to the
       TCP data instead of the TCP header. */
    hdrlen = TCPH_HDRLEN(in_data.tcphdr);
    if(pbuf_header(p, -(hdrlen * 4))){
        /* drop short packets */
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: short packet\n"));
        TCP_STATS_INC(tcp.lenerr);
        TCP_STATS_INC(tcp.drop);
        snmp_inc_tcpinerrs();
        pbuf_free(p);
        return;
    }

    /* Convert fields in TCP header to host byte order. */
    in_data.tcphdr->src = ntohs(in_data.tcphdr->src);
    in_data.tcphdr->dest = ntohs(in_data.tcphdr->dest);
    in_data.seqno = in_data.tcphdr->seqno = ntohl(in_data.tcphdr->seqno);
    in_data.ackno = in_data.tcphdr->ackno = ntohl(in_data.tcphdr->ackno);
    in_data.tcphdr->wnd = ntohs(in_data.tcphdr->wnd);

    in_data.flags = TCPH_FLAGS(in_data.tcphdr);
    in_data.tcplen = p->tot_len + ((in_data.flags & (TCP_FIN | TCP_SYN)) ? 1 : 0);

    /* copy IP addresses to aligned ip_addr_t */
	ip_addr_copy(current_iphdr_dest, in_data.iphdr->dest);
	ip_addr_copy(current_iphdr_src, in_data.iphdr->src);

    if (pcb != NULL) {

    	if (PCB_IN_ACTIVE_STATE(pcb))
    	{
			/* The incoming segment belongs to a connection. */
			#if TCP_INPUT_DEBUG
			#if TCP_DEBUG
					tcp_debug_print_state(pcb->state);
			#endif /* TCP_DEBUG */
			#endif /* TCP_INPUT_DEBUG */

			/* Set up a tcp_seg structure. */
			in_data.inseg.next = NULL;
			in_data.inseg.len = p->tot_len;
			in_data.inseg.dataptr = p->payload;
			in_data.inseg.p = p;
			in_data.inseg.tcphdr = in_data.tcphdr;

			in_data.recv_data = NULL;
			in_data.recv_flags = 0;

			/* If there is data which was previously "refused" by upper layer */
			while (pcb->refused_data != NULL) { // 'while' instead of 'if' because windows scale uses large pbuf
				struct pbuf *rest;
				pbuf_split_64k(pcb->refused_data, &rest);

				/* Notify again application with data previously received. */
				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: notify kept packet\n"));
				TCP_EVENT_RECV(pcb, pcb->refused_data, ERR_OK, err);
				if (err == ERR_OK) {
					pcb->refused_data = rest;
				} else {
					if (rest) {
						pbuf_cat(pcb->refused_data, rest); /* undo splitting */
					}
					/* if err == ERR_ABRT, 'pcb' is already deallocated */
					/* drop incoming packets, because pcb is "full" */
					LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: drop incoming packets, because pcb is \"full\"\n"));
					TCP_STATS_INC(tcp.drop);
					snmp_inc_tcpinerrs();
					pbuf_free(p);
					return;
				}
			}
			tcp_input_pcb = pcb;
			err = tcp_process(pcb, &in_data);
			/* A return value of ERR_ABRT means that tcp_abort() was called
			   and that the pcb has been freed. If so, we don't do anything. */
			if (err != ERR_ABRT) {
				if (in_data.recv_flags & TF_RESET) {
					/* TF_RESET means that the connection was reset by the other
					   end. We then call the error callback to inform the
					   application that the connection is dead before we
					   deallocate the PCB. */
					TCP_EVENT_ERR(pcb->errf, pcb->my_container, ERR_RST);
					tcp_pcb_remove(pcb);
				} else if (in_data.recv_flags & TF_CLOSED) {
					/* The connection has been closed and we will deallocate the
					   PCB. */
					tcp_pcb_remove(pcb);
				} else {
					err = ERR_OK;
					/* If the application has registered a "sent" function to be
					   called when new send buffer space is available, we call it
					   now. */
					if (pcb->acked > 0) {
						TCP_EVENT_SENT(pcb, pcb->acked, err);
						if (err == ERR_ABRT) {
							goto aborted;
						}
					}

					while (in_data.recv_data != NULL) { // 'while' instead of 'if' because windows scale uses large pbuf
						struct pbuf *rest = NULL;
						if (pcb->flags & TF_RXCLOSED) {
							/* received data although already closed -> abort (send RST) to
					                       notify the remote host that not all data has been processed */
							pbuf_free(in_data.recv_data);
							tcp_abort(pcb);
							goto aborted;
						}
						pbuf_split_64k(in_data.recv_data, &rest);
						if (in_data.flags & TCP_PSH) {
							in_data.recv_data->flags |= PBUF_FLAG_PUSH;
						}
						/* Notify application that data has been received. */
						TCP_EVENT_RECV(pcb, in_data.recv_data, ERR_OK, err);
						if (err == ERR_ABRT) {
							if (rest) {
								pbuf_cat(in_data.recv_data, rest); /* undo splitting */
							}
							goto aborted;
						}
						/* If the upper layer can't receive this data, store it */
						if (err != ERR_OK) {
							if (rest) {
								pbuf_cat(in_data.recv_data, rest); /* undo splitting */
							}
							pcb->refused_data = in_data.recv_data;
							LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: keep incoming packet, because pcb is \"full\"\n"));
							break;
						} else {
							in_data.recv_data = rest;
						}
					}

					/* If a FIN segment was received, we call the callback
					   function with a NULL buffer to indicate EOF. */
					if (in_data.recv_flags & TF_GOT_FIN) {
						/* correct rcv_wnd as the application won't call tcp_recved()
						   for the FIN's seqno */
						if (pcb->rcv_wnd != TCP_WND_SCALED) {
							pcb->rcv_wnd++;
						}
						TCP_EVENT_CLOSED(pcb, err);
						if (err == ERR_ABRT) {
							goto aborted;
						}
					}

					tcp_input_pcb = NULL;
					/* Try to send something out. */
					tcp_output(pcb);
			#if TCP_INPUT_DEBUG
			#if TCP_DEBUG
						tcp_debug_print_state(pcb->state);
			#endif /* TCP_DEBUG */
			#endif /* TCP_INPUT_DEBUG */
					}
				}
				/* Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
				   Below this line, 'pcb' may not be dereferenced! */
			aborted:
				tcp_input_pcb = NULL;
				in_data.recv_data = NULL;

				/* give up our reference to inseg.p */
				if (in_data.inseg.p != NULL)
				{
					pbuf_free(in_data.inseg.p);
					in_data.inseg.p = NULL;
				}
			}
    	 else if (PCB_IN_LISTEN_STATE(pcb)) {
    		LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for LISTENing connection.\n"));
			// TODO: tcp_listen_input creates a pcb and puts in the active pcb list.
			// how should we approach?
			tcp_listen_input((struct tcp_pcb_listen*)pcb, &in_data);
			pbuf_free(p);
    	}
    	else if (PCB_IN_TIME_WAIT_STATE(pcb)){
    		LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for TIME_WAITing connection.\n"));
											tcp_timewait_input(pcb, &in_data);
											pbuf_free(p);
    	}
    	else {
    		 LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_input: illegal pcb->state.\n"));
    	}
    } else {

    	/* If no matching PCB was found, send a TCP RST (reset) to the
           sender. */
        LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_input: no PCB match found, resetting.\n"));
        if (!(TCPH_FLAGS(in_data.tcphdr) & TCP_RST)) {
            TCP_STATS_INC(tcp.proterr);
            TCP_STATS_INC(tcp.drop);
            tcp_rst(in_data.ackno, in_data.seqno + in_data.tcplen,
                    ip_current_dest_addr(), ip_current_src_addr(),
                    in_data.tcphdr->dest, in_data.tcphdr->src, pcb);
        }
        pbuf_free(p);
    }

    LWIP_ASSERT("tcp_input: tcp_pcbs_sane()", tcp_pcbs_sane());
    PERF_STOP("tcp_input");
}
#endif //LWIP_3RD_PARTY_L3
/**
 * Called by tcp_input() when a segment arrives for a listening
 * connection (from tcp_input()).
 *
 * @param pcb the tcp_pcb_listen for which a segment arrived
 * @return ERR_OK if the segment was processed
 *         another err_t on error
 *
 * @note the return value is not (yet?) used in tcp_input()
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static err_t
tcp_listen_input(struct tcp_pcb_listen *pcb, tcp_in_data* in_data)
{
  struct tcp_pcb *npcb = NULL;
  err_t rc;

  /* In the LISTEN state, we check for incoming SYN segments,
     creates a new PCB, and responds with a SYN|ACK. */
  if (in_data->flags & TCP_ACK) {
    /* For incoming segments with the ACK flag set, respond with a
       RST. */
    LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_listen_input: ACK in LISTEN, sending reset\n"));
    tcp_rst(in_data->ackno + 1, in_data->seqno + in_data->tcplen,
      ip_current_dest_addr(), ip_current_src_addr(),
      in_data->tcphdr->dest, in_data->tcphdr->src, NULL);
  } else if (in_data->flags & TCP_SYN) {
    LWIP_DEBUGF(TCP_DEBUG, ("TCP connection request %"U16_F" -> %"U16_F".\n", in_data->tcphdr->src, in_data->tcphdr->dest));
#if TCP_LISTEN_BACKLOG
    if (pcb->accepts_pending >= pcb->backlog) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_listen_input: listen backlog exceeded for port %"U16_F"\n", in_data->tcphdr->dest));
      return ERR_ABRT;
    }
#endif /* TCP_LISTEN_BACKLOG */

    TCP_EVENT_CLONE_PCB(pcb,&npcb,ERR_OK,rc);
    /* If a new PCB could not be created (probably due to lack of memory),
       we don't do anything, but rely on the sender will retransmit the
       SYN at a time when we have more memory available. */
    if (npcb == NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_listen_input: could not allocate PCB\n"));
      TCP_STATS_INC(tcp.memerr);
      return ERR_MEM;
    }
#if TCP_LISTEN_BACKLOG
    pcb->accepts_pending++;
#endif /* TCP_LISTEN_BACKLOG */
    /* Set up the new PCB. */
    ip_addr_copy(npcb->local_ip, current_iphdr_dest);
    npcb->local_port = pcb->local_port;
    ip_addr_copy(npcb->remote_ip, current_iphdr_src);
    npcb->remote_port = in_data->tcphdr->src;
    npcb->state = SYN_RCVD;
    npcb->rcv_nxt = in_data->seqno + 1;
    npcb->rcv_ann_right_edge = npcb->rcv_nxt;
    npcb->snd_wnd = in_data->tcphdr->wnd;
    npcb->ssthresh = npcb->snd_wnd;
    npcb->snd_wl1 = in_data->seqno - 1;/* initialise to seqno-1 to force window update */
    npcb->callback_arg = pcb->callback_arg;
#if LWIP_CALLBACK_API
    npcb->accept = pcb->accept;
#endif /* LWIP_CALLBACK_API */
    /* inherit socket options */
    npcb->so_options = pcb->so_options & SOF_INHERITED;

    /* Register the new PCB so that we can begin receiving segments
     for it. */
    TCP_EVENT_SYN_RECEIVED(pcb, npcb, ERR_OK, rc);
    if (rc != ERR_OK) {
          return rc;
    }

    #if TCP_RCVSCALE
      npcb->snd_scale = 0;
      npcb->rcv_scale = 0;
    #endif

    /* Parse any options in the SYN. */
    tcp_parseopt(npcb, in_data);
#if TCP_RCVSCALE
     npcb->snd_wnd = SND_WND_SCALE(npcb, in_data->tcphdr->wnd);
     npcb->ssthresh = npcb->snd_wnd;
#endif
#if TCP_CALCULATE_EFF_SEND_MSS
    npcb->advtsd_mss = npcb->mss = tcp_eff_send_mss(npcb->mss, &(npcb->remote_ip));
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

    snmp_inc_tcppassiveopens();

    /* Send a SYN|ACK together with the MSS option. */
    rc = tcp_enqueue_flags(npcb, TCP_SYN | TCP_ACK);
    if (rc != ERR_OK) {
      tcp_abandon(npcb, 0);
      return rc;
    }
    return tcp_output(npcb);
  }
  return ERR_OK;
}

/**
 * Called by tcp_input() when a segment arrives for a connection in
 * TIME_WAIT.
 *
 * @param pcb the tcp_pcb for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static err_t
tcp_timewait_input(struct tcp_pcb *pcb, tcp_in_data* in_data)
{
  /* RFC 1337: in TIME_WAIT, ignore RST and ACK FINs + any 'acceptable' segments */
  /* RFC 793 3.9 Event Processing - Segment Arrives:
   * - first check sequence number - we skip that one in TIME_WAIT (always
   *   acceptable since we only send ACKs)
   * - second check the RST bit (... return) */
  if (in_data->flags & TCP_RST)  {
    return ERR_OK;
  }
  /* - fourth, check the SYN bit, */
  if (in_data->flags & TCP_SYN) {
    /* If an incoming segment is not acceptable, an acknowledgment
       should be sent in reply */
    if (TCP_SEQ_BETWEEN(in_data->seqno, pcb->rcv_nxt, pcb->rcv_nxt+pcb->rcv_wnd)) {
      /* If the SYN is in the window it is an error, send a reset */
      tcp_rst(in_data->ackno, in_data->seqno + in_data->tcplen, ip_current_dest_addr(), ip_current_src_addr(),
        in_data->tcphdr->dest, in_data->tcphdr->src, pcb);
      return ERR_OK;
    }
  } else if (in_data->flags & TCP_FIN) {
    /* - eighth, check the FIN bit: Remain in the TIME-WAIT state.
         Restart the 2 MSL time-wait timeout.*/
    pcb->tmr = tcp_ticks;
  }

  if ((in_data->tcplen > 0))  {
    /* Acknowledge data, FIN or out-of-window SYN */
    pcb->flags |= TF_ACK_NOW;
    return tcp_output(pcb);
  }
  return ERR_OK;
}

/**
 * Implements the TCP state machine. Called by tcp_input. In some
 * states tcp_receive() is called to receive data. The tcp_seg
 * argument will be freed by the caller (tcp_input()) unless the
 * recv_data pointer in the pcb is set.
 *
 * @param pcb the tcp_pcb for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static err_t
tcp_process(struct tcp_pcb *pcb, tcp_in_data* in_data)
{
  struct tcp_seg *rseg;
  u8_t acceptable = 0;
  err_t err;

  err = ERR_OK;

  /* Process incoming RST segments. */
  if (in_data->flags & TCP_RST) {
    /* First, determine if the reset is acceptable. */
    if (pcb->state == SYN_SENT) {
      if (in_data->ackno == pcb->snd_nxt) {
        acceptable = 1;
      }
    } else {
      if (TCP_SEQ_BETWEEN(in_data->seqno, pcb->rcv_nxt,
                          pcb->rcv_nxt+pcb->rcv_wnd)) {
        acceptable = 1;
      }
    }

    if (acceptable) {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_process: Connection RESET\n"));
      LWIP_ASSERT("tcp_input: pcb->state != CLOSED", pcb->state != CLOSED);
      in_data->recv_flags |= TF_RESET;
      pcb->flags &= ~TF_ACK_DELAY;
      return ERR_RST;
    } else {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_process: unacceptable reset seqno %"U32_F" rcv_nxt %"U32_F"\n",
       in_data->seqno, pcb->rcv_nxt));
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_process: unacceptable reset seqno %"U32_F" rcv_nxt %"U32_F"\n",
       in_data->seqno, pcb->rcv_nxt));
      return ERR_OK;
    }
  }

  if ((in_data->flags & TCP_SYN) && (pcb->state != SYN_SENT && pcb->state != SYN_RCVD)) {
    /* Cope with new connection attempt after remote end crashed */
    tcp_ack_now(pcb);
    return ERR_OK;
  }
  
  if ((pcb->flags & TF_RXCLOSED) == 0) {
    /* Update the PCB (in)activity timer unless rx is closed (see tcp_shutdown) */
    pcb->tmr = tcp_ticks;
  }
  pcb->keep_cnt_sent = 0;

  tcp_parseopt(pcb, in_data);

  /* Do different things depending on the TCP state. */
  switch (pcb->state) {
  case SYN_SENT:
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("SYN-SENT: ackno %"U32_F" pcb->snd_nxt %"U32_F" unacked %"U32_F"\n", in_data->ackno,
     pcb->snd_nxt, ntohl(pcb->unacked->in_data->tcphdr->in_data->seqno)));
    /* received SYN ACK with expected sequence number? */
    if ((in_data->flags & TCP_ACK) && (in_data->flags & TCP_SYN)
        && in_data->ackno == pcb->unacked->seqno + 1) {
      pcb->snd_buf++;
      pcb->rcv_nxt = in_data->seqno + 1;
      pcb->rcv_ann_right_edge = pcb->rcv_nxt;
      pcb->lastack = in_data->ackno;
      #if TCP_RCVSCALE
            pcb->snd_wnd = SND_WND_SCALE(pcb, in_data->tcphdr->wnd);        // Which means: tcphdr->wnd << pcb->snd_scale;
      #else
            pcb->snd_wnd = in_data->tcphdr->wnd;
      #endif
      pcb->snd_wl1 = in_data->seqno - 1; /* initialise to seqno - 1 to force window update */
      pcb->state = ESTABLISHED;

#if TCP_CALCULATE_EFF_SEND_MSS
      pcb->mss = tcp_eff_send_mss(pcb->mss, &(pcb->remote_ip));
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

      /* Set ssthresh again after changing pcb->mss (already set in tcp_connect
       * but for the default value of pcb->mss) */
      pcb->ssthresh = pcb->mss * 10;
#if TCP_CC_ALGO_MOD
      cc_conn_init(pcb);
#else
      pcb->cwnd = ((pcb->cwnd == 1) ? (pcb->mss * 2) : pcb->mss);
#endif
      LWIP_ASSERT("pcb->snd_queuelen > 0", (pcb->snd_queuelen > 0));
      --pcb->snd_queuelen;
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_process: SYN-SENT --queuelen %"U16_F"\n", (u16_t)pcb->snd_queuelen));
      rseg = pcb->unacked;
      pcb->unacked = rseg->next;

      /* If there's nothing left to acknowledge, stop the retransmit
         timer, otherwise reset it to start again */
      if(pcb->unacked == NULL) {
        pcb->rtime = -1;
      } else {
        pcb->rtime = 0;
        pcb->nrtx = 0;
      }

      tcp_tx_seg_free(pcb, rseg);

      /* Call the user specified function to call when sucessfully
       * connected. */
      TCP_EVENT_CONNECTED(pcb, ERR_OK, err);
      if (err == ERR_ABRT) {
        return ERR_ABRT;
      }
      tcp_ack_now(pcb);
    }
    /* received ACK? possibly a half-open connection */
    else if (in_data->flags & TCP_ACK) {
      /* send a RST to bring the other side in a non-synchronized state. */
      tcp_rst(in_data->ackno, in_data->seqno + in_data->tcplen, ip_current_dest_addr(), ip_current_src_addr(),
        in_data->tcphdr->dest, in_data->tcphdr->src, pcb);
    }
    break;
  case SYN_RCVD:
    if (in_data->flags & TCP_ACK) {
      /* expected ACK number? */
      if (TCP_SEQ_BETWEEN(in_data->ackno, pcb->lastack+1, pcb->snd_nxt)) {
#if TCP_RCVSCALE
        u32_t old_cwnd;
#else
        u16_t old_cwnd;
#endif
        pcb->state = ESTABLISHED;
        LWIP_DEBUGF(TCP_DEBUG, ("TCP connection established %"U16_F" -> %"U16_F".\n", in_data->inseg.in_data->tcphdr->src, in_data->inseg.in_data->tcphdr->dest));
#if LWIP_CALLBACK_API
        LWIP_ASSERT("pcb->accept != NULL", pcb->accept != NULL);
#endif
        /* Call the accept function. */
        TCP_EVENT_ACCEPT(pcb, ERR_OK, err);
        if (err != ERR_OK) {
          /* If the accept function returns with an error, we abort
           * the connection. */
          /* Already aborted? */
          if (err != ERR_ABRT) {
            tcp_abort(pcb);
          }
          return ERR_ABRT;
        }
        old_cwnd = pcb->cwnd;
        /* If there was any data contained within this ACK,
         * we'd better pass it on to the application as well. */
        tcp_receive(pcb, in_data);

        /* Prevent ACK for SYN to generate a sent event */
        if (pcb->acked != 0) {
          pcb->acked--;
        }
#if TCP_CC_ALGO_MOD
        pcb->cwnd = old_cwnd;
        cc_conn_init(pcb);
#else
        pcb->cwnd = ((old_cwnd == 1) ? (pcb->mss * 2) : pcb->mss);
#endif
        if (in_data->recv_flags & TF_GOT_FIN) {
          tcp_ack_now(pcb);
          pcb->state = CLOSE_WAIT;
        }
      } else {
        /* incorrect ACK number, send RST */
        tcp_rst(in_data->ackno, in_data->seqno + in_data->tcplen, ip_current_dest_addr(), ip_current_src_addr(),
                in_data->tcphdr->dest, in_data->tcphdr->src, pcb);
      }
    } else if ((in_data->flags & TCP_SYN) && (in_data->seqno == pcb->rcv_nxt - 1)) {
      /* Looks like another copy of the SYN - retransmit our SYN-ACK */
      tcp_rexmit(pcb);
    }
    break;
  case CLOSE_WAIT:
    /* FALLTHROUGH */
  case ESTABLISHED:
    tcp_receive(pcb, in_data);
    if (in_data->recv_flags & TF_GOT_FIN) { /* passive close */
      tcp_ack_now(pcb);
      pcb->state = CLOSE_WAIT;
    }
    break;
  case FIN_WAIT_1:
    tcp_receive(pcb, in_data);
    if (in_data->recv_flags & TF_GOT_FIN) {
      if ((in_data->flags & TCP_ACK) && (in_data->ackno == pcb->snd_nxt)) {
        LWIP_DEBUGF(TCP_DEBUG,
          ("TCP connection closed: FIN_WAIT_1 %"U16_F" -> %"U16_F".\n", in_data->inseg.in_data->tcphdr->src, in_data->inseg.in_data->tcphdr->dest));
        tcp_ack_now(pcb);
        tcp_pcb_purge(pcb);
        pcb->state = TIME_WAIT;
      } else {
        tcp_ack_now(pcb);
        pcb->state = CLOSING;
      }
    } else if ((in_data->flags & TCP_ACK) && (in_data->ackno == pcb->snd_nxt)) {
      pcb->state = FIN_WAIT_2;
    }
    break;
  case FIN_WAIT_2:
    tcp_receive(pcb, in_data);
    if (in_data->recv_flags & TF_GOT_FIN) {
      LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed: FIN_WAIT_2 %"U16_F" -> %"U16_F".\n", in_data->inseg.in_data->tcphdr->src, in_data->inseg.in_data->tcphdr->dest));
      tcp_ack_now(pcb);
      tcp_pcb_purge(pcb);
      pcb->state = TIME_WAIT;
    }
    break;
  case CLOSING:
    tcp_receive(pcb, in_data);
    if (in_data->flags & TCP_ACK && in_data->ackno == pcb->snd_nxt) {
      LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed: CLOSING %"U16_F" -> %"U16_F".\n", in_data->inseg.in_data->tcphdr->src, in_data->inseg.in_data->tcphdr->dest));
      tcp_pcb_purge(pcb);
      pcb->state = TIME_WAIT;
    }
    break;
  case LAST_ACK:
    tcp_receive(pcb, in_data);
    if (in_data->flags & TCP_ACK && in_data->ackno == pcb->snd_nxt) {
      LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed: LAST_ACK %"U16_F" -> %"U16_F".\n", in_data->inseg.in_data->tcphdr->src, in_data->inseg.in_data->tcphdr->dest));
      /* bugfix #21699: don't set pcb->state to CLOSED here or we risk leaking segments */
      in_data->recv_flags |= TF_CLOSED;
    }
    break;
  default:
    break;
  }
  return ERR_OK;
}

#if TCP_QUEUE_OOSEQ
/**
 * Insert segment into the list (segments covered with new one will be deleted)
 *
 * Called from tcp_receive()
 */
static void
tcp_oos_insert_segment(struct tcp_pcb *pcb, struct tcp_seg *cseg, struct tcp_seg *next, tcp_in_data* in_data)
{
  struct tcp_seg *old_seg;

  if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN) {
    /* received segment overlaps all following segments */
    tcp_segs_free(pcb, next);
    next = NULL;
  }
  else {
    /* delete some following segments
       oos queue may have segments with FIN flag */
    while (next &&
           TCP_SEQ_GEQ((in_data->seqno + cseg->len),
                      (next->tcphdr->seqno + next->len))) {
      /* cseg with FIN already processed */
      if (TCPH_FLAGS(next->tcphdr) & TCP_FIN) {
        TCPH_SET_FLAG(cseg->tcphdr, TCP_FIN);
      }
      old_seg = next;
      next = next->next;
      tcp_seg_free(pcb, old_seg);
    }
    if (next &&
        TCP_SEQ_GT(in_data->seqno + cseg->len, next->tcphdr->seqno)) {
      /* We need to trim the incoming segment. */
      cseg->len = (u16_t)(next->tcphdr->seqno - in_data->seqno);
      pbuf_realloc(cseg->p, cseg->len);
    }
  }
  cseg->next = next;
}
#endif /* TCP_QUEUE_OOSEQ */

/**
 * Called by tcp_process. Checks if the given segment is an ACK for outstanding
 * data, and if so frees the memory of the buffered data. Next, is places the
 * segment on any of the receive queues (pcb->recved or pcb->ooseq). If the segment
 * is buffered, the pbuf is referenced by pbuf_ref so that it will not be freed until
 * i it has been removed from the buffer.
 *
 * If the incoming segment constitutes an ACK for a segment that was used for RTT
 * estimation, the RTT is estimated here as well.
 *
 * Called from tcp_process().
 */
static void
tcp_receive(struct tcp_pcb *pcb, tcp_in_data* in_data)
{
  struct tcp_seg *next;
#if TCP_QUEUE_OOSEQ
  struct tcp_seg *prev, *cseg;
#endif /* TCP_QUEUE_OOSEQ */
  struct pbuf *p;
  s32_t off;
  s16_t m;
  u32_t right_wnd_edge;
  u16_t new_tot_len;
  int found_dupack = 0;

  if (in_data->flags & TCP_ACK) {
    right_wnd_edge = pcb->snd_wnd + pcb->snd_wl2;

    /* Update window. */
    if (TCP_SEQ_LT(pcb->snd_wl1, in_data->seqno) ||
       (pcb->snd_wl1 == in_data->seqno && TCP_SEQ_LT(pcb->snd_wl2, in_data->ackno)) ||
       (pcb->snd_wl2 == in_data->ackno && SND_WND_SCALE(pcb, in_data->tcphdr->wnd) > pcb->snd_wnd)) {
      #if TCP_RCVSCALE
	  pcb->snd_wnd = SND_WND_SCALE(pcb, in_data->tcphdr->wnd);        // Which means: tcphdr->wnd << pcb->snd_scale;
      #else
	  pcb->snd_wnd = in_data->tcphdr->wnd;
      #endif
      pcb->snd_wl1 = in_data->seqno;
      pcb->snd_wl2 = in_data->ackno;
      if (pcb->snd_wnd > 0 && pcb->persist_backoff > 0) {
          pcb->persist_backoff = 0;
      }
      LWIP_DEBUGF(TCP_WND_DEBUG, ("tcp_receive: window update %"U16_F"\n", pcb->snd_wnd));
#if TCP_WND_DEBUG
    } else {
      if (pcb->snd_wnd != in_data->tcphdr->wnd) {
        LWIP_DEBUGF(TCP_WND_DEBUG, 
                    ("tcp_receive: no window update lastack %"U32_F" ackno %"
                     U32_F" wl1 %"U32_F" seqno %"U32_F" wl2 %"U32_F"\n",
                     pcb->lastack, in_data->ackno, pcb->snd_wl1, in_data->seqno, pcb->snd_wl2));
      }
#endif /* TCP_WND_DEBUG */
    }

    /* (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a
     * duplicate ack if:
     * 1) It doesn't ACK new data 
     * 2) length of received packet is zero (i.e. no payload) 
     * 3) the advertised window hasn't changed 
     * 4) There is outstanding unacknowledged data (retransmission timer running)
     * 5) The ACK is == biggest ACK sequence number so far seen (snd_una)
     * 
     * If it passes all five, should process as a dupack: 
     * a) dupacks < 3: do nothing 
     * b) dupacks == 3: fast retransmit 
     * c) dupacks > 3: increase cwnd 
     * 
     * If it only passes 1-3, should reset dupack counter (and add to
     * stats, which we don't do in lwIP)
     *
     * If it only passes 1, should reset dupack counter
     *
     */

    /* Clause 1 */
    if (TCP_SEQ_LEQ(in_data->ackno, pcb->lastack)) {
      pcb->acked = 0;
      /* Clause 2 */
      if (in_data->tcplen == 0) {
        /* Clause 3 */
        if (pcb->snd_wl2 + pcb->snd_wnd == right_wnd_edge){
          /* Clause 4 */
          if (pcb->rtime >= 0) {
            /* Clause 5 */
            if (pcb->lastack == in_data->ackno) {
              found_dupack = 1;
              if (pcb->dupacks + 1 > pcb->dupacks)
                ++pcb->dupacks;
              if (pcb->dupacks > 3) {
#if TCP_CC_ALGO_MOD
        	cc_ack_received(pcb, CC_DUPACK);
#else
                /* Inflate the congestion window, but not if it means that
                   the value overflows. */
#if TCP_RCVSCALE
        	if ((u32_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
        	  pcb->cwnd += pcb->mss;
        	}
#else
                if ((u16_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
                  pcb->cwnd += pcb->mss;
                }
#endif
#endif //TCP_CC_ALGO_MOD
              } else if (pcb->dupacks == 3) {
                /* Do fast retransmit */
                tcp_rexmit_fast(pcb);
#if TCP_CC_ALGO_MOD
                cc_ack_received(pcb, 0);
                //cc_ack_received(pcb, CC_DUPACK);
#endif
              }
            }
          }
        }
      }
      /* If Clause (1) or more is true, but not a duplicate ack, reset
       * count of consecutive duplicate acks */
      if (!found_dupack) {
        pcb->dupacks = 0;
      }
    } else if (TCP_SEQ_BETWEEN(in_data->ackno, pcb->lastack+1, pcb->snd_nxt)){
      /* We come here when the ACK acknowledges new data. */

      /* Reset the "IN Fast Retransmit" flag, since we are no longer
         in fast retransmit. Also reset the congestion window to the
         slow start threshold. */
      if (pcb->flags & TF_INFR) {
#if TCP_CC_ALGO_MOD
	cc_post_recovery(pcb);
#else
        pcb->cwnd = pcb->ssthresh;
#endif
        pcb->flags &= ~TF_INFR;
      }

      /* Reset the number of retransmissions. */
      pcb->nrtx = 0;

      /* Reset the retransmission time-out. */
      pcb->rto = (pcb->sa >> 3) + pcb->sv;

      /* Update the send buffer space. Diff between the two can never exceed 64K? */
#if TCP_RCVSCALE
      pcb->acked = (u32_t)(in_data->ackno - pcb->lastack);
#else
      pcb->acked = (u16_t)(in_data->ackno - pcb->lastack);
#endif

      pcb->snd_buf += pcb->acked;

      /* Reset the fast retransmit variables. */
      pcb->dupacks = 0;
      pcb->lastack = in_data->ackno;

      /* Update the congestion control variables (cwnd and
         ssthresh). */
      if (pcb->state >= ESTABLISHED) {
#if TCP_CC_ALGO_MOD
	 cc_ack_received(pcb, CC_ACK);
#else
        if (pcb->cwnd < pcb->ssthresh) {
#if TCP_RCVSCALE
          if ((u32_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
            pcb->cwnd += pcb->mss;
          }
          LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: slow start cwnd %"U32_F"\n", pcb->cwnd));
#else
          if ((u16_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
            pcb->cwnd += pcb->mss;
          }
          LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: slow start cwnd %"U16_F"\n", pcb->cwnd));
#endif
        } else {
#if TCP_RCVSCALE
          u32_t new_cwnd = (pcb->cwnd + ((u32_t)pcb->mss * (u32_t)pcb->mss) / pcb->cwnd);
          if (new_cwnd > pcb->cwnd) {
            pcb->cwnd = new_cwnd;
          }
          LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: congestion avoidance cwnd %"U32_F"\n", pcb->cwnd));
#else
          u16_t new_cwnd = (pcb->cwnd + pcb->mss * pcb->mss / pcb->cwnd);
          if (new_cwnd > pcb->cwnd) {
            pcb->cwnd = new_cwnd;
          }
          LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: congestion avoidance cwnd %"U16_F"\n", pcb->cwnd));
#endif
        }
#endif //TCP_CC_ALGO_MOD
      }
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: ACK for %"U32_F", unacked->seqno %"U32_F":%"U32_F"\n",
                                    in_data->ackno,
                                    pcb->unacked != NULL?
                                    ntohl(pcb->unacked->in_data->tcphdr->in_data->seqno): 0,
                                    pcb->unacked != NULL?
                                    ntohl(pcb->unacked->in_data->tcphdr->in_data->seqno) + TCP_TCPLEN(pcb->unacked): 0));

      /* Remove segment from the unacknowledged list if the incoming
         ACK acknowlegdes them. */
      while (pcb->unacked != NULL &&
             TCP_SEQ_LEQ(pcb->unacked->seqno + TCP_TCPLEN(pcb->unacked), in_data->ackno)) {
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: removing %"U32_F":%"U32_F" from pcb->unacked\n",
                                      ntohl(pcb->unacked->in_data->tcphdr->in_data->seqno),
                                      ntohl(pcb->unacked->in_data->tcphdr->in_data->seqno) +
                                      TCP_TCPLEN(pcb->unacked)));

        next = pcb->unacked;
        pcb->unacked = pcb->unacked->next;
#if TCP_RCVSCALE
        LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %"U32_F" ... ", (u32_t)pcb->snd_queuelen));
        LWIP_ASSERT("pcb->snd_queuelen >= pbuf_clen(next->p)", (pcb->snd_queuelen >= pbuf_clen(next->p)));
#else
        LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %"U16_F" ... ", (u16_t)pcb->snd_queuelen));
        LWIP_ASSERT("pcb->snd_queuelen >= pbuf_clen(next->p)", (pcb->snd_queuelen >= pbuf_clen(next->p)));
#endif
        /* Prevent ACK for FIN to generate a sent event */
        if ((pcb->acked != 0) && ((TCPH_FLAGS(next->tcphdr) & TCP_FIN) != 0)) {
          pcb->acked--;
        }

        pcb->snd_queuelen -= pbuf_clen(next->p);
        tcp_tx_seg_free(pcb, next);
#if TCP_RCVSCALE
        LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%"U32_F" (after freeing unacked)\n", (u32_t)pcb->snd_queuelen));
#else
        LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%"U16_F" (after freeing unacked)\n", (u16_t)pcb->snd_queuelen));
#endif
      }

      /* If there's nothing left to acknowledge, stop the retransmit
         timer, otherwise reset it to start again */
      if(pcb->unacked == NULL) {
        pcb->rtime = -1;
      } else {
        pcb->rtime = 0;
      }

      pcb->polltmr = 0;
    } else {
      /* Fix bug bug #21582: out of sequence ACK, didn't really ack anything */
      pcb->acked = 0;
    }

    /* We go through the ->unsent list to see if any of the segments
       on the list are acknowledged by the ACK. This may seem
       strange since an "unsent" segment shouldn't be acked. The
       rationale is that lwIP puts all outstanding segments on the
       ->unsent list after a retransmission, so these segments may
       in fact have been sent once. */
    while (pcb->unsent != NULL &&
           TCP_SEQ_BETWEEN(in_data->ackno, ntohl(pcb->unsent->tcphdr->seqno) +
                           TCP_TCPLEN(pcb->unsent), pcb->snd_nxt)) {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: removing %"U32_F":%"U32_F" from pcb->unsent\n",
                                    ntohl(pcb->unsent->in_data->tcphdr->in_data->seqno), ntohl(pcb->unsent->in_data->tcphdr->in_data->seqno) +
                                    TCP_TCPLEN(pcb->unsent)));

      next = pcb->unsent;
      pcb->unsent = pcb->unsent->next;
#if TCP_RCVSCALE
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %"U32_F" ... ", (u32_t)pcb->snd_queuelen));
      LWIP_ASSERT("pcb->snd_queuelen >= pbuf_clen(next->p)", (pcb->snd_queuelen >= pbuf_clen(next->p)));
#else
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %"U16_F" ... ", (u16_t)pcb->snd_queuelen));
      LWIP_ASSERT("pcb->snd_queuelen >= pbuf_clen(next->p)", (pcb->snd_queuelen >= pbuf_clen(next->p)));
#endif
      /* Prevent ACK for FIN to generate a sent event */
      if ((pcb->acked != 0) && ((TCPH_FLAGS(next->tcphdr) & TCP_FIN) != 0)) {
        pcb->acked--;
      }
      pcb->snd_queuelen -= pbuf_clen(next->p);
      tcp_tx_seg_free(pcb, next);
#if TCP_RCVSCALE
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%"U16_F" (after freeing unsent)\n", (u32_t)pcb->snd_queuelen));
#else
      LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%"U16_F" (after freeing unsent)\n", (u16_t)pcb->snd_queuelen));
#endif
      if (pcb->snd_queuelen != 0) {
        LWIP_ASSERT("tcp_receive: valid queue length",
          pcb->unacked != NULL || pcb->unsent != NULL);
      }
    }
    /* End of ACK for new data processing. */

    LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: pcb->rttest %"U32_F" rtseq %"U32_F" ackno %"U32_F"\n",
                                pcb->rttest, pcb->rtseq, in_data->ackno));

    /* RTT estimation calculations. This is done by checking if the
       incoming segment acknowledges the segment we use to take a
       round-trip time measurement. */
    if (pcb->rttest && TCP_SEQ_LT(pcb->rtseq, in_data->ackno)) {
      /* diff between this shouldn't exceed 32K since this are tcp timer ticks
         and a round-trip shouldn't be that long... */
#if TCP_CC_ALGO_MOD
      pcb->t_rttupdated++;
#endif
      m = (s16_t)(tcp_ticks - pcb->rttest);

      LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: experienced rtt %"U16_F" ticks (%"U16_F" msec).\n",
                                  m, m * TCP_SLOW_INTERVAL));

      /* This is taken directly from VJs original code in his paper */
      m = m - (pcb->sa >> 3);
      pcb->sa += m;
      if (m < 0) {
        m = -m;
      }
      m = m - (pcb->sv >> 2);
      pcb->sv += m;
      pcb->rto = (pcb->sa >> 3) + pcb->sv;

      LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: RTO %"U16_F" (%"U16_F" milliseconds)\n",
                                  pcb->rto, pcb->rto * TCP_SLOW_INTERVAL));

      pcb->rttest = 0;
    }
  }

  /* If the incoming segment contains data, we must process it
     further. */
  if (in_data->tcplen > 0) {
    /* This code basically does three things:

    +) If the incoming segment contains data that is the next
    in-sequence data, this data is passed to the application. This
    might involve trimming the first edge of the data. The rcv_nxt
    variable and the advertised window are adjusted.

    +) If the incoming segment has data that is above the next
    sequence number expected (->rcv_nxt), the segment is placed on
    the ->ooseq queue. This is done by finding the appropriate
    place in the ->ooseq queue (which is ordered by sequence
    number) and trim the segment in both ends if needed. An
    immediate ACK is sent to indicate that we received an
    out-of-sequence segment.

    +) Finally, we check if the first segment on the ->ooseq queue
    now is in sequence (i.e., if rcv_nxt >= ooseq->seqno). If
    rcv_nxt > ooseq->seqno, we must trim the first edge of the
    segment on ->ooseq before we adjust rcv_nxt. The data in the
    segments that are now on sequence are chained onto the
    incoming segment so that we only need to call the application
    once.
    */

    /* First, we check if we must trim the first edge. We have to do
       this if the sequence number of the incoming segment is less
       than rcv_nxt, and the sequence number plus the length of the
       segment is larger than rcv_nxt. */
    /*    if (TCP_SEQ_LT(seqno, pcb->rcv_nxt)){
          if (TCP_SEQ_LT(pcb->rcv_nxt, seqno + tcplen)) {*/
    if (TCP_SEQ_BETWEEN(pcb->rcv_nxt, in_data->seqno + 1, in_data->seqno + in_data->tcplen - 1)){
      /* Trimming the first edge is done by pushing the payload
         pointer in the pbuf downwards. This is somewhat tricky since
         we do not want to discard the full contents of the pbuf up to
         the new starting point of the data since we have to keep the
         TCP header which is present in the first pbuf in the chain.

         What is done is really quite a nasty hack: the first pbuf in
         the pbuf chain is pointed to by inseg.p. Since we need to be
         able to deallocate the whole pbuf, we cannot change this
         inseg.p pointer to point to any of the later pbufs in the
         chain. Instead, we point the ->payload pointer in the first
         pbuf to data in one of the later pbufs. We also set the
         inseg.data pointer to point to the right place. This way, the
         ->p pointer will still point to the first pbuf, but the
         ->p->payload pointer will point to data in another pbuf.

         After we are done with adjusting the pbuf pointers we must
         adjust the ->data pointer in the seg and the segment
         length.*/

      off = pcb->rcv_nxt - in_data->seqno;
      p = in_data->inseg.p;
      LWIP_ASSERT("inseg.p != NULL", in_data->inseg.p);
      LWIP_ASSERT("insane offset!", (off < 0x7fff));
      if (in_data->inseg.p->len < off) {
        LWIP_ASSERT("pbuf too short!", (((s32_t)in_data->inseg.p->tot_len) >= off));
        new_tot_len = (u16_t)(in_data->inseg.p->tot_len - off);
        while (p->len < off) {
          off -= p->len;
          /* KJM following line changed (with addition of new_tot_len var)
             to fix bug #9076
             inseg.p->tot_len -= p->len; */
          p->tot_len = new_tot_len;
          p->len = 0;
          p = p->next;
        }
        if(pbuf_header(p, (s16_t)-off)) {
          /* Do we need to cope with this failing?  Assert for now */
          LWIP_ASSERT("pbuf_header failed", 0);
        }
      } else {
        if(pbuf_header(in_data->inseg.p, (s16_t)-off)) {
          /* Do we need to cope with this failing?  Assert for now */
          LWIP_ASSERT("pbuf_header failed", 0);
        }
      }
      /* KJM following line changed to use p->payload rather than inseg->p->payload
         to fix bug #9076 */
      in_data->inseg.dataptr = p->payload;
      in_data->inseg.len -= (u16_t)(pcb->rcv_nxt - in_data->seqno);
      in_data->inseg.tcphdr->seqno = in_data->seqno = pcb->rcv_nxt;
    }
    else {
      if (TCP_SEQ_LT(in_data->seqno, pcb->rcv_nxt)){
        /* the whole segment is < rcv_nxt */
        /* must be a duplicate of a packet that has already been correctly handled */

        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: duplicate seqno %"U32_F"\n", in_data->seqno));
        tcp_ack_now(pcb);
      }
    }

    /* The sequence number must be within the window (above rcv_nxt
       and below rcv_nxt + rcv_wnd) in order to be further
       processed. */
    if (TCP_SEQ_BETWEEN(in_data->seqno, pcb->rcv_nxt,
                        pcb->rcv_nxt + pcb->rcv_wnd - 1)){
      if (pcb->rcv_nxt == in_data->seqno) {
        /* The incoming segment is the next in sequence. We check if
           we have to trim the end of the segment and update rcv_nxt
           and pass the data to the application. */
        in_data->tcplen = TCP_TCPLEN(&in_data->inseg);

        if (in_data->tcplen > pcb->rcv_wnd) {
          LWIP_DEBUGF(TCP_INPUT_DEBUG, 
                      ("tcp_receive: other end overran receive window"
                       "seqno %"U32_F" len %"U16_F" right edge %"U32_F"\n",
                       in_data->seqno, in_data->tcplen, pcb->rcv_nxt + pcb->rcv_wnd));
          if (TCPH_FLAGS(in_data->inseg.tcphdr) & TCP_FIN) {
            /* Must remove the FIN from the header as we're trimming 
             * that byte of sequence-space from the packet */
            TCPH_FLAGS_SET(in_data->inseg.tcphdr, TCPH_FLAGS(in_data->inseg.tcphdr) &~ TCP_FIN);
          }
          /* Adjust length of segment to fit in the window. */
          in_data->inseg.len = pcb->rcv_wnd;
          if (TCPH_FLAGS(in_data->inseg.tcphdr) & TCP_SYN) {
            in_data->inseg.len -= 1;
          }
          pbuf_realloc(in_data->inseg.p, in_data->inseg.len);
          in_data->tcplen = TCP_TCPLEN(&in_data->inseg);
          LWIP_ASSERT("tcp_receive: segment not trimmed correctly to rcv_wnd\n",
                      (in_data->seqno + in_data->tcplen) == (pcb->rcv_nxt + pcb->rcv_wnd));
        }
#if TCP_QUEUE_OOSEQ
        /* Received in-sequence data, adjust ooseq data if:
           - FIN has been received or
           - inseq overlaps with ooseq */
        if (pcb->ooseq != NULL) {
          if (TCPH_FLAGS(in_data->inseg.tcphdr) & TCP_FIN) {
            LWIP_DEBUGF(TCP_INPUT_DEBUG, 
                        ("tcp_receive: received in-order FIN, binning ooseq queue\n"));
            /* Received in-order FIN means anything that was received
             * out of order must now have been received in-order, so
             * bin the ooseq queue */
            while (pcb->ooseq != NULL) {
              struct tcp_seg *old_ooseq = pcb->ooseq;
              pcb->ooseq = pcb->ooseq->next;
              tcp_seg_free(pcb, old_ooseq);
            }
          }
          else {
            next = pcb->ooseq;
            /* Remove all segments on ooseq that are covered by inseg already.
             * FIN is copied from ooseq to inseg if present. */
            while (next &&
                   TCP_SEQ_GEQ(in_data->seqno + in_data->tcplen,
                               next->tcphdr->seqno + next->len)) {
              /* inseg cannot have FIN here (already processed above) */
              if (TCPH_FLAGS(next->tcphdr) & TCP_FIN &&
                  (TCPH_FLAGS(in_data->inseg.tcphdr) & TCP_SYN) == 0) {
                TCPH_SET_FLAG(in_data->inseg.tcphdr, TCP_FIN);
                in_data->tcplen = TCP_TCPLEN(&in_data->inseg);
              }
              prev = next;
              next = next->next;
              tcp_seg_free(pcb, prev);
            }
            /* Now trim right side of inseg if it overlaps with the first
             * segment on ooseq */
            if (next &&
                TCP_SEQ_GT(in_data->seqno + in_data->tcplen,
                           next->tcphdr->seqno)) {
              /* inseg cannot have FIN here (already processed above) */
              in_data->inseg.len = (u16_t)(next->tcphdr->seqno - in_data->seqno);
              if (TCPH_FLAGS(in_data->inseg.tcphdr) & TCP_SYN) {
                in_data->inseg.len -= 1;
              }
              pbuf_realloc(in_data->inseg.p, in_data->inseg.len);
              in_data->tcplen = TCP_TCPLEN(&in_data->inseg);
              LWIP_ASSERT("tcp_receive: segment not trimmed correctly to ooseq queue\n",
                          (in_data->seqno + in_data->tcplen) == next->in_data->tcphdr->in_data->seqno);
            }
            pcb->ooseq = next;
          }
        }
#endif /* TCP_QUEUE_OOSEQ */

        pcb->rcv_nxt = in_data->seqno + in_data->tcplen;

        /* Update the receiver's (our) window. */
        LWIP_ASSERT("tcp_receive: tcplen > rcv_wnd\n", pcb->rcv_wnd >= in_data->tcplen);
        pcb->rcv_wnd -= in_data->tcplen;

        tcp_update_rcv_ann_wnd(pcb);

        /* If there is data in the segment, we make preparations to
           pass this up to the application. The ->recv_data variable
           is used for holding the pbuf that goes to the
           application. The code for reassembling out-of-sequence data
           chains its data on this pbuf as well.

           If the segment was a FIN, we set the TF_GOT_FIN flag that will
           be used to indicate to the application that the remote side has
           closed its end of the connection. */
        if (in_data->inseg.p->tot_len > 0) {
          in_data->recv_data = in_data->inseg.p;
          /* Since this pbuf now is the responsibility of the
             application, we delete our reference to it so that we won't
             (mistakingly) deallocate it. */
          in_data->inseg.p = NULL;
        }
        if (TCPH_FLAGS(in_data->inseg.tcphdr) & TCP_FIN) {
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: received FIN.\n"));
          in_data->recv_flags |= TF_GOT_FIN;
        }

#if TCP_QUEUE_OOSEQ
        /* We now check if we have segments on the ->ooseq queue that
           are now in sequence. */
        while (pcb->ooseq != NULL &&
               pcb->ooseq->tcphdr->seqno == pcb->rcv_nxt) {

          cseg = pcb->ooseq;
          in_data->seqno = pcb->ooseq->tcphdr->seqno;

          pcb->rcv_nxt += TCP_TCPLEN(cseg);
          LWIP_ASSERT("tcp_receive: ooseq tcplen > rcv_wnd\n",
                      pcb->rcv_wnd >= TCP_TCPLEN(cseg));
          pcb->rcv_wnd -= TCP_TCPLEN(cseg);

          tcp_update_rcv_ann_wnd(pcb);

          if (cseg->p->tot_len > 0) {
            /* Chain this pbuf onto the pbuf that we will pass to
               the application. */
            if (in_data->recv_data) {
              pbuf_cat(in_data->recv_data, cseg->p);
            } else {
              in_data->recv_data = cseg->p;
            }
            cseg->p = NULL;
          }
          if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN) {
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: dequeued FIN.\n"));
            in_data->recv_flags |= TF_GOT_FIN;
            if (pcb->state == ESTABLISHED) { /* force passive close or we can move to active close */
              pcb->state = CLOSE_WAIT;
            } 
          }

          pcb->ooseq = cseg->next;
          tcp_seg_free(pcb, cseg);
        }
#endif /* TCP_QUEUE_OOSEQ */


        /* Acknowledge the segment(s). */
        if (in_data->recv_data && in_data->recv_data->next) {
        	tcp_ack_now(pcb);
        } else {
        	tcp_ack(pcb);
        }

      } else {
        /* We get here if the incoming segment is out-of-sequence. */
        tcp_send_empty_ack(pcb);
#if TCP_QUEUE_OOSEQ
        /* We queue the segment on the ->ooseq queue. */
        if (pcb->ooseq == NULL) {
          pcb->ooseq = tcp_seg_copy(pcb, &in_data->inseg);
        } else {
          /* If the queue is not empty, we walk through the queue and
             try to find a place where the sequence number of the
             incoming segment is between the sequence numbers of the
             previous and the next segment on the ->ooseq queue. That is
             the place where we put the incoming segment. If needed, we
             trim the second edges of the previous and the incoming
             segment so that it will fit into the sequence.

             If the incoming segment has the same sequence number as a
             segment on the ->ooseq queue, we discard the segment that
             contains less data. */

          prev = NULL;
          for(next = pcb->ooseq; next != NULL; next = next->next) {
            if (in_data->seqno == next->tcphdr->seqno) {
              /* The sequence number of the incoming segment is the
                 same as the sequence number of the segment on
                 ->ooseq. We check the lengths to see which one to
                 discard. */
              if (in_data->inseg.len > next->len) {
                /* The incoming segment is larger than the old
                   segment. We replace some segments with the new
                   one. */
                cseg = tcp_seg_copy(pcb, &in_data->inseg);
                if (cseg != NULL) {
                  if (prev != NULL) {
                    prev->next = cseg;
                  } else {
                    pcb->ooseq = cseg;
                  }
                  tcp_oos_insert_segment(pcb, cseg, next, in_data);
                }
                break;
              } else {
                /* Either the lenghts are the same or the incoming
                   segment was smaller than the old one; in either
                   case, we ditch the incoming segment. */
                break;
              }
            } else {
              if (prev == NULL) {
                if (TCP_SEQ_LT(in_data->seqno, next->tcphdr->seqno)) {
                  /* The sequence number of the incoming segment is lower
                     than the sequence number of the first segment on the
                     queue. We put the incoming segment first on the
                     queue. */
                  cseg = tcp_seg_copy(pcb, &in_data->inseg);
                  if (cseg != NULL) {
                    pcb->ooseq = cseg;
                    tcp_oos_insert_segment(pcb, cseg, next, in_data);
                  }
                  break;
                }
              } else {
                /*if (TCP_SEQ_LT(prev->tcphdr->seqno, seqno) &&
                  TCP_SEQ_LT(seqno, next->tcphdr->seqno)) {*/
                if (TCP_SEQ_BETWEEN(in_data->seqno, prev->tcphdr->seqno+1, next->tcphdr->seqno-1)) {
                  /* The sequence number of the incoming segment is in
                     between the sequence numbers of the previous and
                     the next segment on ->ooseq. We trim trim the previous
                     segment, delete next segments that included in received segment
                     and trim received, if needed. */
                  cseg = tcp_seg_copy(pcb, &in_data->inseg);
                  if (cseg != NULL) {
                    if (TCP_SEQ_GT(prev->tcphdr->seqno + prev->len, in_data->seqno)) {
                      /* We need to trim the prev segment. */
                      prev->len = (u16_t)(in_data->seqno - prev->tcphdr->seqno);
                      pbuf_realloc(prev->p, prev->len);
                    }
                    prev->next = cseg;
                    tcp_oos_insert_segment(pcb, cseg, next, in_data);
                  }
                  break;
                }
              }
              /* If the "next" segment is the last segment on the
                 ooseq queue, we add the incoming segment to the end
                 of the list. */
              if (next->next == NULL &&
                  TCP_SEQ_GT(in_data->seqno, next->tcphdr->seqno)) {
                if (TCPH_FLAGS(next->tcphdr) & TCP_FIN) {
                  /* segment "next" already contains all data */
                  break;
                }
                next->next = tcp_seg_copy(pcb, &in_data->inseg);
                if (next->next != NULL) {
                  if (TCP_SEQ_GT(next->tcphdr->seqno + next->len, in_data->seqno)) {
                    /* We need to trim the last segment. */
                    next->len = (u16_t)(in_data->seqno - next->tcphdr->seqno);
                    pbuf_realloc(next->p, next->len);
                  }
                  /* check if the remote side overruns our receive window */
                  if ((u32_t)in_data->tcplen + in_data->seqno > pcb->rcv_nxt + (u32_t)pcb->rcv_wnd) {
                    LWIP_DEBUGF(TCP_INPUT_DEBUG, 
                                ("tcp_receive: other end overran receive window"
                                 "seqno %"U32_F" len %"U16_F" right edge %"U32_F"\n",
                                 in_data->seqno, in_data->tcplen, pcb->rcv_nxt + pcb->rcv_wnd));
                    if (TCPH_FLAGS(next->next->tcphdr) & TCP_FIN) {
                      /* Must remove the FIN from the header as we're trimming 
                       * that byte of sequence-space from the packet */
                      TCPH_FLAGS_SET(next->next->tcphdr, TCPH_FLAGS(next->next->tcphdr) &~ TCP_FIN);
                    }
                    /* Adjust length of segment to fit in the window. */
                    next->next->len = pcb->rcv_nxt + pcb->rcv_wnd - in_data->seqno;
                    pbuf_realloc(next->next->p, next->next->len);
                    in_data->tcplen = TCP_TCPLEN(next->next);
                    LWIP_ASSERT("tcp_receive: segment not trimmed correctly to rcv_wnd\n",
                                (in_data->seqno + in_data->tcplen) == (pcb->rcv_nxt + pcb->rcv_wnd));
                  }
                }
                break;
              }
            }
            prev = next;
          }
        }
#endif /* TCP_QUEUE_OOSEQ */

      }
    } else {
      /* The incoming segment is not withing the window. */
      tcp_send_empty_ack(pcb);
    }
  } else {
    /* Segments with length 0 is taken care of here. Segments that
       fall out of the window are ACKed. */
    /*if (TCP_SEQ_GT(pcb->rcv_nxt, seqno) ||
      TCP_SEQ_GEQ(seqno, pcb->rcv_nxt + pcb->rcv_wnd)) {*/
    if(!TCP_SEQ_BETWEEN(in_data->seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd-1)){
      tcp_ack_now(pcb);
    }
  }
}

/**
 * Parses the options contained in the incoming segment. 
 *
 * Called from tcp_listen_input() and tcp_process().
 * Currently, only the MSS and window scaling options are supported!
 *
 * @param pcb the tcp_pcb for which a segment arrived
 */
static void
tcp_parseopt(struct tcp_pcb *pcb, tcp_in_data* in_data)
{
  u16_t c, max_c;
  u16_t mss;
  u8_t *opts, opt;
#if LWIP_TCP_TIMESTAMPS
  u32_t tsval;
#endif

  opts = (u8_t *)in_data->tcphdr + TCP_HLEN;

  /* Parse the TCP MSS option, if present. */
  if(TCPH_HDRLEN(in_data->tcphdr) > 0x5) {
    max_c = (TCPH_HDRLEN(in_data->tcphdr) - 5) << 2;
    for (c = 0; c < max_c; ) {
      opt = opts[c];
      switch (opt) {
      case 0x00:
        /* End of options. */
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: EOL\n"));
        return;
      case 0x01:
        /* NOP option. */
        ++c;
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: NOP\n"));
        break;
      case 0x02:
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: MSS\n"));
        if (opts[c + 1] != 0x04 || c + 0x04 > max_c) {
          /* Bad length */
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
          return;
        }
        /* An MSS option with the right option length. */
        mss = (opts[c + 2] << 8) | opts[c + 3];
        /* Limit the mss to the configured TCP_MSS and prevent division by zero */
        pcb->mss = ((mss > TCP_MSS) || (mss == 0)) ? TCP_MSS : mss;
        /* Advance to next option */
        c += 0x04;
        break;
        #if TCP_RCVSCALE
              case 0x03:
            	LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: WND SCALE\n"));
                if (opts[c + 1] != 0x03 || (TCP_RCVSCALE < 0) || (c + 0x03 > max_c)) {
        		  /* Bad length */
        		  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
        		  return;
        		}
                /* A window scale option */
                if(enable_wnd_scale) {
                	pcb->snd_scale = opts[c + 2];
                	pcb->rcv_scale = rcv_wnd_scale;
                }
                /* Advance to next option */
                c += 0x03;
                break;
        #endif
#if LWIP_TCP_TIMESTAMPS
      case 0x08:
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: TS\n"));
        if (opts[c + 1] != 0x0A || c + 0x0A > max_c) {
          /* Bad length */
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
          return;
        }
        /* TCP timestamp option with valid length */
        tsval = (opts[c+2]) | (opts[c+3] << 8) | 
          (opts[c+4] << 16) | (opts[c+5] << 24);
        if (in_data->flags & TCP_SYN) {
          pcb->ts_recent = ntohl(tsval);
          pcb->in_data->flags |= TF_TIMESTAMP;
        } else if (TCP_SEQ_BETWEEN(pcb->ts_lastacksent, in_data->seqno, in_data->seqno+in_data->tcplen)) {
          pcb->ts_recent = ntohl(tsval);
        }
        /* Advance to next option */
        c += 0x0A;
        break;
#endif
      default:
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: other\n"));
        if (opts[c + 1] == 0) {
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
          /* If the length field is zero, the options are malformed
             and we don't process them further. */
          return;
        }
        /* All other options have a length field, so that we easily
           can skip past them. */
        c += opts[c + 1];
      }
    }
  }
}

#endif /* LWIP_TCP */
