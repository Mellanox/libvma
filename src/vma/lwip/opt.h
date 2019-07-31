/**
 * @file
 *
 * lwIP Options Configuration
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
#ifndef __LWIP_OPT_H__
#define __LWIP_OPT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
   ------------------------------------
   ---------- Memory options ----------
   ------------------------------------
*/
/**
 * MEM_ALIGNMENT: should be set to the alignment of the CPU
 *    4 byte alignment -> #define MEM_ALIGNMENT 4
 *    2 byte alignment -> #define MEM_ALIGNMENT 2
 */
#define MEM_ALIGNMENT                   4

/**
 * MEM_SIZE: the size of the heap memory. If the application will send
 * a lot of data that needs to be copied, this should be set high.
 */
//16000
#ifdef _LWIP_MIN_MEM_MODE
#define MEM_SIZE                       	16000 //128000
#else
#define MEM_SIZE                       	512000 //128000
#endif


/**
 * MEM_USE_POOLS==1: Use an alternative to malloc() by allocating from a set
 * of memory pools of various sizes. When mem_malloc is called, an element of
 * the smallest pool that can provide the length needed is returned.
 * To use this, MEMP_USE_CUSTOM_POOLS also has to be enabled.
 */
#define MEM_USE_POOLS                   1
#define MEMP_USE_CUSTOM_POOLS		1

/*
   ------------------------------------------------
   ---------- Internal Memory Pool Sizes ----------
   ------------------------------------------------
*/
/**
 * MEMP_NUM_PBUF: the number of memp struct pbufs (used for PBUF_ROM and PBUF_REF).
 * If the application sends a lot of data out of ROM (or other static memory),
 * this should be set high.
 */
//30
#ifdef _LWIP_MIN_MEM_MODE
#define MEMP_NUM_PBUF                   30
#else
#define MEMP_NUM_PBUF                   0 //1024
#endif

/**
 * MEMP_NUM_TCP_PCB: the number of simulatenously active TCP connections.
 * (requires the LWIP_TCP option)
 */
#define MEMP_NUM_TCP_PCB               	1 //32768

/**
 * MEMP_NUM_TCP_PCB_LISTEN: the number of listening TCP connections.
 * (requires the LWIP_TCP option)
 */
#define MEMP_NUM_TCP_PCB_LISTEN         1 //1024

/**
 * MEMP_NUM_TCP_SEG: the number of simultaneously queued TCP segments.
 * (requires the LWIP_TCP option)
 */
//64
#ifdef _LWIP_MIN_MEM_MODE
#define MEMP_NUM_TCP_SEG                64
#else
#define MEMP_NUM_TCP_SEG                0 //16384
#endif


/**
 * PBUF_POOL_SIZE: the number of buffers in the pbuf pool.
 */
//32
#ifdef _LWIP_MIN_MEM_MODE
#define PBUF_POOL_SIZE                  32
#else
#define PBUF_POOL_SIZE                 	0 //256000
#endif


/** ETH_PAD_SIZE: number of bytes added before the ethernet header to ensure
 * alignment of payload after that header. Since the header is 14 bytes long,
 * without this padding e.g. addresses in the IP header will not be aligned
 * on a 32-bit boundary, so setting this to 2 can speed up 32-bit-platforms.
 */
#define ETH_PAD_SIZE                    0



/*
   --------------------------------
   ---------- IP options ----------
   --------------------------------
*/
/**
 * IP_DEFAULT_TTL: Default value for Time-To-Live used by transport layers.
 */
#define IP_DEFAULT_TTL                  255

/*
   ---------------------------------
   ---------- TCP options ----------
   ---------------------------------
*/
/**
 * LWIP_TCP==1: Turn on TCP.
 */
#define LWIP_TCP                        1

/**
 * TCP_QUICKACK_THRESHOLD: TCP quickack threshold (bytes)
 * Quickack will be sent for payload <= TCP_QUICKACK_THRESHOLD.
 * if TCP_QUICKACK_THRESHOLD = 0, quickack threshold is disabled.
 * The threshold is effective only when TCP_QUICKACK is enabled.
 */
#define TCP_QUICKACK_THRESHOLD          0

/**
 * TCP_WND: The size of a TCP window.  This must be at least
 * (2 * TCP_MSS) for things to work well
 */
#define TCP_WND                         0xFFFF

/**
 * TCP_MSS: TCP Maximum segment size. (default is 536, a conservative default,
 * you might want to increase this.)
 * For the receive side, this MSS is advertised to the remote side
 * when opening a connection. For the transmit size, this MSS sets
 * an upper limit on the MSS advertised by the remote host.
 */
/*
 * If you don't want to use lwip_tcp_mss for setting the mss during runtime, define TCP_MSS to the DEFAULT_TCP_MSS
 */
#define CONST_TCP_MSS 		1460
#define LWIP_TCP_MSS                         (lwip_tcp_mss)
//#define TCP_MSS 			CONST_TCP_MSS

/**
 * TCP_SND_BUF: TCP sender buffer space (bytes).
 */
//4096
#ifdef _LWIP_MIN_MEM_MODE
#define TCP_SND_BUF                     4096 //256*1024
#else
#define TCP_SND_BUF                     1000000 //100000 //256000
#endif

#define TCP_SND_BUF_NO_NAGLE 256000

/*
   ----------------------------------
   ---------- Pbuf options ----------
   ----------------------------------
*/
/**
 * PBUF_LINK_HLEN: the number of bytes that should be allocated for a
 * link level header. The default is 14, the standard value for
 * Ethernet.
 */
#define PBUF_LINK_HLEN                  20

/*
   ----------------------------------------
   ---------- Statistics options ----------
   ----------------------------------------
*/
/**
 * LWIP_STATS==1: Enable statistics collection in lwip_stats.
 * NOTE: enabling stats adds about 300-400ns to latency
 */
#define LWIP_STATS                      0

/**
 * LWIP_STATS_DISPLAY==1: Compile in the statistics output functions.
 */
#define LWIP_STATS_DISPLAY              0
// use 32 bit counters in stats
#define LWIP_STATS_LARGE		0


/* Misc */

#define LWIP_TIMEVAL_PRIVATE 0


/*
   --------------------------------------
   ---------- Checksum options ----------
   --------------------------------------
*/
// Sasha: disable software tx checksums. Use hca hw csum offload instead
/**
 * CHECKSUM_GEN_IP==1: Generate checksums in software for outgoing IP packets.
 */
#define CHECKSUM_GEN_IP                 0

/**
 * CHECKSUM_GEN_UDP==1: Generate checksums in software for outgoing UDP packets.
 */
#define CHECKSUM_GEN_UDP                0

/**
 * CHECKSUM_GEN_TCP==1: Generate checksums in software for outgoing TCP packets.
 */
#define CHECKSUM_GEN_TCP                0

/**
 * CHECKSUM_CHECK_IP==1: Check checksums in software for incoming IP packets.
 */
#define CHECKSUM_CHECK_IP               0

/**
 * CHECKSUM_CHECK_UDP==1: Check checksums in software for incoming UDP packets.
 */
#define CHECKSUM_CHECK_UDP              0

/**
 * CHECKSUM_CHECK_TCP==1: Check checksums in software for incoming TCP packets.
 */
#define CHECKSUM_CHECK_TCP              0

/**
 * LWIP_CHECKSUM_ON_COPY==1: Calculate checksum when copying data from
 * application buffers to pbufs.
 */
#define LWIP_CHECKSUM_ON_COPY           1


// replace lwip byte swapping to optimized one
#include <byteswap.h>

#define LWIP_PLATFORM_BYTESWAP         1
#define LWIP_PLATFORM_HTONS(x) bswap_16(x)
#define LWIP_PLATFORM_HTONL(x) bswap_32(x)

#define LWIP_3RD_PARTY_L3 1
#define LWIP_3RD_PARTY_BUFS 1

//enable LWIP DEBUG here
#if 1
//#define PBUF_DEBUG				LWIP_DBG_ON
//#define TCP_DEBUG 				LWIP_DBG_ON
//#define TCP_INPUT_DEBUG			LWIP_DBG_ON
//#define TCP_FR_DEBUG				LWIP_DBG_ON
//#define TCP_RTO_DEBUG 			LWIP_DBG_ON
//#define TCP_CWND_DEBUG			LWIP_DBG_ON
//#define TCP_WND_DEBUG 			LWIP_DBG_ON
//#define TCP_OUTPUT_DEBUG			LWIP_DBG_ON
//#define TCP_RST_DEBUG 			LWIP_DBG_ON
//#define TCP_QLEN_DEBUG			LWIP_DBG_ON
//#define TCP_TSO_DEBUG				LWIP_DBG_ON
#endif

/*
   -----------------------------------------------
   ---------- Platform specific locking ----------
   -----------------------------------------------
*/

/**
 * SYS_LIGHTWEIGHT_PROT==1: if you want inter-task protection for certain
 * critical regions during buffer allocation, deallocation and memory
 * allocation and deallocation.
 */
#ifndef SYS_LIGHTWEIGHT_PROT
#define SYS_LIGHTWEIGHT_PROT            0
#endif

/** 
 * NO_SYS==1: Provides VERY minimal functionality. Otherwise,
 * use lwIP facilities.
 */
#ifndef NO_SYS
#define NO_SYS                          0
#endif

/**
 * NO_SYS_NO_TIMERS==1: Drop support for sys_timeout when NO_SYS==1
 * Mainly for compatibility to old versions.
 */
#ifndef NO_SYS_NO_TIMERS
#define NO_SYS_NO_TIMERS                0
#endif

/**
 * MEMCPY: override this if you have a faster implementation at hand than the
 * one included in your C library
 */
#ifndef MEMCPY
#define MEMCPY(dst,src,len)             memcpy(dst,src,len)
#endif

/**
 * SMEMCPY: override this with care! Some compilers (e.g. gcc) can inline a
 * call to memcpy() if the length is known at compile time and is small.
 */
#ifndef SMEMCPY
#define SMEMCPY(dst,src,len)            memcpy(dst,src,len)
#endif

/*
   ------------------------------------
   ---------- Memory options ----------
   ------------------------------------
*/
/**
 * MEM_LIBC_MALLOC==1: Use malloc/free/realloc provided by your C-library
 * instead of the lwip internal allocator. Can save code size if you
 * already use it.
 */
#ifndef MEM_LIBC_MALLOC
#define MEM_LIBC_MALLOC                 0
#endif

/**
* MEMP_MEM_MALLOC==1: Use mem_malloc/mem_free instead of the lwip pool allocator.
* Especially useful with MEM_LIBC_MALLOC but handle with care regarding execution
* speed and usage from interrupts!
*/
#ifndef MEMP_MEM_MALLOC
#define MEMP_MEM_MALLOC                 0
#endif

/**
 * MEM_ALIGNMENT: should be set to the alignment of the CPU
 *    4 byte alignment -> #define MEM_ALIGNMENT 4
 *    2 byte alignment -> #define MEM_ALIGNMENT 2
 */
#ifndef MEM_ALIGNMENT
#define MEM_ALIGNMENT                   1
#endif

/**
 * MEM_SIZE: the size of the heap memory. If the application will send
 * a lot of data that needs to be copied, this should be set high.
 */
#ifndef MEM_SIZE
#define MEM_SIZE                        1600
#endif

/**
 * MEMP_SEPARATE_POOLS: if defined to 1, each pool is placed in its own array.
 * This can be used to individually change the location of each pool.
 * Default is one big array for all pools
 */
#ifndef MEMP_SEPARATE_POOLS
#define MEMP_SEPARATE_POOLS             0
#endif

/**
 * MEMP_OVERFLOW_CHECK: memp overflow protection reserves a configurable
 * amount of bytes before and after each memp element in every pool and fills
 * it with a prominent default value.
 *    MEMP_OVERFLOW_CHECK == 0 no checking
 *    MEMP_OVERFLOW_CHECK == 1 checks each element when it is freed
 *    MEMP_OVERFLOW_CHECK >= 2 checks each element in every pool every time
 *      memp_malloc() or memp_free() is called (useful but slow!)
 */
#ifndef MEMP_OVERFLOW_CHECK
#define MEMP_OVERFLOW_CHECK             0
#endif

/**
 * MEMP_SANITY_CHECK==1: run a sanity check after each memp_free() to make
 * sure that there are no cycles in the linked lists.
 */
#ifndef MEMP_SANITY_CHECK
#define MEMP_SANITY_CHECK               0
#endif

/**
 * MEM_USE_POOLS==1: Use an alternative to malloc() by allocating from a set
 * of memory pools of various sizes. When mem_malloc is called, an element of
 * the smallest pool that can provide the length needed is returned.
 * To use this, MEMP_USE_CUSTOM_POOLS also has to be enabled.
 */
#ifndef MEM_USE_POOLS
#define MEM_USE_POOLS                   0
#endif

/**
 * MEM_USE_POOLS_TRY_BIGGER_POOL==1: if one malloc-pool is empty, try the next
 * bigger pool - WARNING: THIS MIGHT WASTE MEMORY but it can make a system more
 * reliable. */
#ifndef MEM_USE_POOLS_TRY_BIGGER_POOL
#define MEM_USE_POOLS_TRY_BIGGER_POOL   1
#endif

/**
 * MEMP_USE_CUSTOM_POOLS==1: whether to include a user file lwippools.h
 * that defines additional pools beyond the "standard" ones required
 * by lwIP. If you set this to 1, you must have lwippools.h in your 
 * inlude path somewhere. 
 */
#ifndef MEMP_USE_CUSTOM_POOLS
#define MEMP_USE_CUSTOM_POOLS           0
#endif

/**
 * Set this to 1 if you want to free PBUF_RAM pbufs (or call mem_free()) from
 * interrupt context (or another context that doesn't allow waiting for a
 * semaphore).
 * If set to 1, mem_malloc will be protected by a semaphore and SYS_ARCH_PROTECT,
 * while mem_free will only use SYS_ARCH_PROTECT. mem_malloc SYS_ARCH_UNPROTECTs
 * with each loop so that mem_free can run.
 *
 * ATTENTION: As you can see from the above description, this leads to dis-/
 * enabling interrupts often, which can be slow! Also, on low memory, mem_malloc
 * can need longer.
 *
 * If you don't want that, at least for NO_SYS=0, you can still use the following
 * functions to enqueue a deallocation call which then runs in the tcpip_thread
 * context:
 * - pbuf_free_callback(p);
 * - mem_free_callback(m);
 */
#ifndef LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT
#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT 0
#endif

/*
   ------------------------------------------------
   ---------- Internal Memory Pool Sizes ----------
   ------------------------------------------------
*/
/**
 * MEMP_NUM_PBUF: the number of memp struct pbufs (used for PBUF_ROM and PBUF_REF).
 * If the application sends a lot of data out of ROM (or other static memory),
 * this should be set high.
 */
#ifndef MEMP_NUM_PBUF
#define MEMP_NUM_PBUF                   16
#endif

/**
 * MEMP_NUM_TCP_PCB: the number of simulatenously active TCP connections.
 * (requires the LWIP_TCP option)
 */
#ifndef MEMP_NUM_TCP_PCB
#define MEMP_NUM_TCP_PCB                5
#endif

/**
 * MEMP_NUM_TCP_PCB_LISTEN: the number of listening TCP connections.
 * (requires the LWIP_TCP option)
 */
#ifndef MEMP_NUM_TCP_PCB_LISTEN
#define MEMP_NUM_TCP_PCB_LISTEN         8
#endif

/**
 * MEMP_NUM_TCP_SEG: the number of simultaneously queued TCP segments.
 * (requires the LWIP_TCP option)
 */
#ifndef MEMP_NUM_TCP_SEG
#define MEMP_NUM_TCP_SEG                16
#endif

/**
 * PBUF_POOL_SIZE: the number of buffers in the pbuf pool. 
 */
#ifndef PBUF_POOL_SIZE
#define PBUF_POOL_SIZE                  16
#endif

/** ETH_PAD_SIZE: number of bytes added before the ethernet header to ensure
 * alignment of payload after that header. Since the header is 14 bytes long,
 * without this padding e.g. addresses in the IP header will not be aligned
 * on a 32-bit boundary, so setting this to 2 can speed up 32-bit-platforms.
 */
#ifndef ETH_PAD_SIZE
#define ETH_PAD_SIZE                    0
#endif

/**
 * IP_DEFAULT_TTL: Default value for Time-To-Live used by transport layers.
 */
#ifndef IP_DEFAULT_TTL
#define IP_DEFAULT_TTL                  255
#endif

/*
   ---------------------------------
   ---------- TCP options ----------
   ---------------------------------
*/
/**
 * LWIP_TCP==1: Turn on TCP.
 */
#ifndef LWIP_TCP
#define LWIP_TCP                        1
#endif

/**
 * TCP_TTL: Default Time-To-Live value.
 */
#ifndef TCP_TTL
#define TCP_TTL                         (IP_DEFAULT_TTL)
#endif

/**
 * TCP_WND: The size of a TCP window.  This must be at least 
 * (2 * TCP_MSS) for things to work well
 */
#ifndef TCP_WND
#error make sure TCP_WND is not defined here
/* If ever this definition is effective - please note that LWIP_TCP_MSS may be 0 */
#define TCP_WND                         (4 * LWIP_TCP_MSS)
#endif 

/*
 * use custom congestion control algorithms
 */
#ifndef TCP_CC_ALGO_MOD
#define TCP_CC_ALGO_MOD 1
#endif

 /**
 * window scaling parameter
 */
#define TCP_WND_SCALED(pcb) 		(TCP_WND << (pcb)->rcv_scale)

/**
 * TCP_MAXRTX: Maximum number of retransmissions of data segments.
 */
#ifndef TCP_MAXRTX
#define TCP_MAXRTX                      12
#endif

/**
 * TCP_SYNMAXRTX: Maximum number of retransmissions of SYN segments.
 */
#ifndef TCP_SYNMAXRTX
#define TCP_SYNMAXRTX                   6
#endif

/**
 * TCP_QUEUE_OOSEQ==1: TCP will queue segments that arrive out of order.
 * Define to 0 if your device is low on memory.
 */
#ifndef TCP_QUEUE_OOSEQ
#define TCP_QUEUE_OOSEQ                 (LWIP_TCP)
#endif

/**
 * TCP_CALCULATE_EFF_SEND_MSS: "The maximum size of a segment that TCP really
 * sends, the 'effective send MSS,' MUST be the smaller of the send MSS (which
 * reflects the available reassembly buffer size at the remote host) and the
 * largest size permitted by the IP layer" (RFC 1122)
 * Setting this to 1 enables code that checks TCP_MSS against the MTU of the
 * netif used for a connection and limits the MSS if it would be too big otherwise.
 */
#ifndef TCP_CALCULATE_EFF_SEND_MSS
#define TCP_CALCULATE_EFF_SEND_MSS      1
#endif


/**
 * TCP_SND_BUF: TCP sender buffer space (bytes). 
 */
#ifndef TCP_SND_BUF
#define TCP_SND_BUF                     256
#endif

/**
 * TCP_SND_QUEUELEN: TCP sender buffer space (pbufs). This must be at least
 * as much as (2 * TCP_SND_BUF/TCP_MSS) for things to work.
 */
#ifndef TCP_SND_QUEUELEN
#define CONST_TCP_SND_QUEUELEN                (4 * (TCP_SND_BUF)/(CONST_TCP_MSS))
#endif

/**
 * TCP_SNDLOWAT: TCP writable space (bytes). This must be less than
 * TCP_SND_BUF. It is the amount of space which must be available in the
 * TCP snd_buf for select to return writable (combined with TCP_SNDQUEUELOWAT).
 */
#ifndef TCP_SNDLOWAT
#define TCP_SNDLOWAT                    ((TCP_SND_BUF)/2)
#endif

/**
 * TCP_SNDQUEUELOWAT: TCP writable bufs (pbuf count). This must be grater
 * than TCP_SND_QUEUELEN. If the number of pbufs queued on a pcb drops below
 * this number, select returns writable (combined with TCP_SNDLOWAT).
 */
#ifndef TCP_SNDQUEUELOWAT
#define TCP_SNDQUEUELOWAT               ((TCP_SND_QUEUELEN)/2)
#endif

/**
 * TCP_OVERSIZE: The maximum number of bytes that tcp_write may
 * allocate ahead of time in an attempt to create shorter pbuf chains
 * for transmission. The meaningful range is 0 to TCP_MSS. Some
 * suggested values are:
 *
 * 0:         Disable oversized allocation. Each tcp_write() allocates a new
              pbuf (old behaviour).
 * 1:         Allocate size-aligned pbufs with minimal excess. Use this if your
 *            scatter-gather DMA requires aligned fragments.
 * 128:       Limit the pbuf/memory overhead to 20%.
 * TCP_MSS:   Try to create unfragmented TCP packets.
 * TCP_MSS/4: Try to create 4 fragments or less per TCP packet.
 */
#ifndef TCP_OVERSIZE
#define TCP_OVERSIZE                    CONST_TCP_MSS
#endif

/**
 * LWIP_TCP_TIMESTAMPS==1: support the TCP timestamp option.
 */
#ifndef LWIP_TCP_TIMESTAMPS
#define LWIP_TCP_TIMESTAMPS             1
#endif

/**
 * TCP_WND_UPDATE_THRESHOLD: difference in window to trigger an
 * explicit window update
 */
#ifndef TCP_WND_UPDATE_THRESHOLD
#define TCP_WND_UPDATE_THRESHOLD   (pcb->rcv_wnd_max / 4)
#endif

/**
 * LWIP_EVENT_API and LWIP_CALLBACK_API: Only one of these should be set to 1.
 *     LWIP_EVENT_API==1: The user defines lwip_tcp_event() to receive all
 *         events (accept, sent, etc) that happen in the system.
 *     LWIP_CALLBACK_API==1: The PCB callback function is called directly
 *         for the event.
 */
#ifndef LWIP_EVENT_API
#define LWIP_EVENT_API                  0
#define LWIP_CALLBACK_API               1
#else 
#define LWIP_EVENT_API                  1
#define LWIP_CALLBACK_API               0
#endif


/*
   ----------------------------------
   ---------- Pbuf options ----------
   ----------------------------------
*/
/**
 * PBUF_LINK_HLEN: the number of bytes that should be allocated for a
 * link level header. The default is 14, the standard value for
 * Ethernet.
 */
#ifndef PBUF_LINK_HLEN
#define PBUF_LINK_HLEN                  (14 + ETH_PAD_SIZE)
#endif


/*
   ------------------------------------
   ---------- Socket options ----------
   ------------------------------------
*/
/**
 * LWIP_TCP_KEEPALIVE==1: Enable TCP_KEEPIDLE, TCP_KEEPINTVL and TCP_KEEPCNT
 * options processing. Note that TCP_KEEPIDLE and TCP_KEEPINTVL have to be set
 * in seconds. (does not require sockets.c, and will affect tcp.c)
 */
#ifndef LWIP_TCP_KEEPALIVE
#define LWIP_TCP_KEEPALIVE              0
#endif

/*
   ----------------------------------------
   ---------- Statistics options ----------
   ----------------------------------------
*/
/**
 * LWIP_STATS==1: Enable statistics collection in lwip_stats.
 */
#ifndef LWIP_STATS
#define LWIP_STATS                      1
#endif

#if LWIP_STATS

/**
 * LWIP_STATS_DISPLAY==1: Compile in the statistics output functions.
 */
#ifndef LWIP_STATS_DISPLAY
#define LWIP_STATS_DISPLAY              0
#endif

/**
 * LINK_STATS==1: Enable link stats.
 */
#ifndef LINK_STATS
#define LINK_STATS                      1
#endif

/**
 * ETHARP_STATS==1: Enable etharp stats.
 */
#ifndef ETHARP_STATS
#define ETHARP_STATS                    (LWIP_ARP)
#endif

/**
 * IP_STATS==1: Enable IP stats.
 */
#ifndef IP_STATS
#define IP_STATS                        1
#endif

/**
 * IPFRAG_STATS==1: Enable IP fragmentation stats. Default is
 * on if using either frag or reass.
 */
#ifndef IPFRAG_STATS
#define IPFRAG_STATS                    (IP_REASSEMBLY || IP_FRAG)
#endif

/**
 * TCP_STATS==1: Enable TCP stats. Default is on if TCP
 * enabled, otherwise off.
 */
#ifndef TCP_STATS
#define TCP_STATS                       (LWIP_TCP)
#endif

#else

#define LINK_STATS                      0
#define IP_STATS                        0
#define IPFRAG_STATS                    0
#define TCP_STATS                       0
#define LWIP_STATS_DISPLAY              0

#endif /* LWIP_STATS */

/*
   --------------------------------------
   ---------- Checksum options ----------
   --------------------------------------
*/
/**
 * CHECKSUM_GEN_IP==1: Generate checksums in software for outgoing IP packets.
 */
#ifndef CHECKSUM_GEN_IP
#define CHECKSUM_GEN_IP                 1
#endif
 
/**
 * CHECKSUM_GEN_UDP==1: Generate checksums in software for outgoing UDP packets.
 */
#ifndef CHECKSUM_GEN_UDP
#define CHECKSUM_GEN_UDP                1
#endif
 
/**
 * CHECKSUM_GEN_TCP==1: Generate checksums in software for outgoing TCP packets.
 */
#ifndef CHECKSUM_GEN_TCP
#define CHECKSUM_GEN_TCP                1
#endif
 
/**
 * CHECKSUM_CHECK_IP==1: Check checksums in software for incoming IP packets.
 */
#ifndef CHECKSUM_CHECK_IP
#define CHECKSUM_CHECK_IP               1
#endif
 
/**
 * CHECKSUM_CHECK_UDP==1: Check checksums in software for incoming UDP packets.
 */
#ifndef CHECKSUM_CHECK_UDP
#define CHECKSUM_CHECK_UDP              1
#endif

/**
 * CHECKSUM_CHECK_TCP==1: Check checksums in software for incoming TCP packets.
 */
#ifndef CHECKSUM_CHECK_TCP
#define CHECKSUM_CHECK_TCP              1
#endif

/**
 * LWIP_CHECKSUM_ON_COPY==1: Calculate checksum when copying data from
 * application buffers to pbufs.
 */
#ifndef LWIP_CHECKSUM_ON_COPY
#define LWIP_CHECKSUM_ON_COPY           0
#endif

/**
 * LWIP_TSO: Enable Large Segment Offload capability.
 */
#ifndef LWIP_TSO
#ifdef DEFINED_TSO
#define LWIP_TSO                        1
#else
#define LWIP_TSO                        0
#endif /* DEFINED_TSO */
#endif

/* Define platform endianness */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif /* BYTE_ORDER */

/* Define generic types used in lwIP */
typedef unsigned   char    u8_t;
typedef signed     char    s8_t;
typedef unsigned   short   u16_t;
typedef signed     short   s16_t;
typedef unsigned   int     u32_t;
typedef signed     int     s32_t;

typedef unsigned long mem_ptr_t;

/* Define (sn)printf formatters for these lwIP types */
#define X8_F  "02x"
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"

/* If only we could use C99 and get %zu */
#if defined(__x86_64__)
#define SZT_F "lu"
#else
#define SZT_F "u"
#endif

/* Compiler hints for packing structures */
#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

/* prototypes for printf() and abort() */
#include <stdio.h>
#include <stdlib.h>

#define LWIP_PLATFORM_ASSERT(x) do {printf("Assertion \"%s\" failed at line %d in %s\n", \
                                     x, __LINE__, __FILE__); fflush(NULL);} while(0)

//#define LWIP_PLATFORM_DIAG(x) __log_err x
//#define LWIP_PLATFORM_ASSERT(x) __log_panic(x)
// disable assertions
#define LWIP_NOASSERT

#define LWIP_RAND() ((u32_t)rand())


#ifndef LWIP_UNUSED_ARG
#define LWIP_UNUSED_ARG(x) (void)x
#endif /* LWIP_UNUSED_ARG */

/*
   ---------------------------------------
   ---------- Debugging options ----------
   ---------------------------------------
*/

/** lower two bits indicate debug level
 * - 0 all
 * - 1 warning
 * - 2 serious
 * - 3 severe
 */
#define LWIP_DBG_LEVEL_ALL     0x00
#define LWIP_DBG_LEVEL_OFF     LWIP_DBG_LEVEL_ALL /* compatibility define only */
#define LWIP_DBG_LEVEL_WARNING 0x01 /* bad checksums, dropped packets, ... */
#define LWIP_DBG_LEVEL_SERIOUS 0x02 /* memory allocation failures, ... */
#define LWIP_DBG_LEVEL_SEVERE  0x03
#define LWIP_DBG_MASK_LEVEL    0x03

/** flag for LWIP_DEBUGF to enable that debug message */
#define LWIP_DBG_ON            0x80U
/** flag for LWIP_DEBUGF to disable that debug message */
#define LWIP_DBG_OFF           0x00U

/** flag for LWIP_DEBUGF indicating a tracing message (to follow program flow) */
#define LWIP_DBG_TRACE         0x40U
/** flag for LWIP_DEBUGF indicating a state debug message (to follow module states) */
#define LWIP_DBG_STATE         0x20U
/** flag for LWIP_DEBUGF indicating newly added code, not thoroughly tested yet */
#define LWIP_DBG_FRESH         0x10U
/** flag for LWIP_DEBUGF to halt after printing this debug message */
#define LWIP_DBG_HALT          0x08U

#define LWIP_ASSERT(message, assertion)

/** if "expression" isn't true, then print "message" and abort process*/
#ifndef LWIP_ERROR_ABORT
#define LWIP_ERROR_ABORT(message, expression, handler) do { if (!(expression)) { \
  LWIP_PLATFORM_ASSERT(message); abort(); handler;}} while(0)
#endif /* LWIP_ERROR_ABORT */

/** if "expression" isn't true, then print "message" and execute "handler" expression */
#ifndef LWIP_ERROR
#define LWIP_ERROR(message, expression, handler) do { if (!(expression)) { \
  LWIP_PLATFORM_ASSERT(message); handler;}} while(0)
#endif /* LWIP_ERROR */

/**
 * LWIP_DBG_MIN_LEVEL: After masking, the value of the debug is
 * compared against this value. If it is smaller, then debugging
 * messages are written.
 */
#ifndef LWIP_DBG_MIN_LEVEL
#define LWIP_DBG_MIN_LEVEL              LWIP_DBG_LEVEL_ALL
#endif

/**
 * LWIP_DBG_TYPES_ON: A mask that can be used to globally enable/disable
 * debug messages of certain types.
 */
#ifndef LWIP_DBG_TYPES_ON
#define LWIP_DBG_TYPES_ON               LWIP_DBG_ON
#endif

/**
 * PBUF_DEBUG: Enable debugging in pbuf.c.
 */
#ifndef PBUF_DEBUG
#define PBUF_DEBUG                      LWIP_DBG_OFF
#endif

/**
 * TCP_DEBUG: Enable debugging for TCP.
 */
#ifndef TCP_DEBUG
#define TCP_DEBUG                       LWIP_DBG_OFF
#endif

/**
 * TCP_INPUT_DEBUG: Enable debugging in tcp_in.c for incoming debug.
 */
#ifndef TCP_INPUT_DEBUG
#define TCP_INPUT_DEBUG                 LWIP_DBG_OFF
#endif

/**
 * TCP_FR_DEBUG: Enable debugging in tcp_in.c for fast retransmit.
 */
#ifndef TCP_FR_DEBUG
#define TCP_FR_DEBUG                    LWIP_DBG_OFF
#endif

/**
 * TCP_RTO_DEBUG: Enable debugging in TCP for retransmit
 * timeout.
 */
#ifndef TCP_RTO_DEBUG
#define TCP_RTO_DEBUG                   LWIP_DBG_OFF
#endif

/**
 * TCP_CWND_DEBUG: Enable debugging for TCP congestion window.
 */
#ifndef TCP_CWND_DEBUG
#define TCP_CWND_DEBUG                  LWIP_DBG_OFF
#endif

/**
 * TCP_WND_DEBUG: Enable debugging in tcp_in.c for window updating.
 */
#ifndef TCP_WND_DEBUG
#define TCP_WND_DEBUG                   LWIP_DBG_OFF
#endif

/**
 * TCP_OUTPUT_DEBUG: Enable debugging in tcp_out.c output functions.
 */
#ifndef TCP_OUTPUT_DEBUG
#define TCP_OUTPUT_DEBUG                LWIP_DBG_OFF
#endif

/**
 * TCP_RST_DEBUG: Enable debugging for TCP with the RST message.
 */
#ifndef TCP_RST_DEBUG
#define TCP_RST_DEBUG                   LWIP_DBG_OFF
#endif

/**
 * TCP_QLEN_DEBUG: Enable debugging for TCP queue lengths.
 */
#ifndef TCP_QLEN_DEBUG
#define TCP_QLEN_DEBUG                  LWIP_DBG_OFF
#endif

/**
 * TCP_TSO_DEBUG: Enable debugging for TSO.
 */
#ifndef TCP_TSO_DEBUG
#define TCP_TSO_DEBUG                  LWIP_DBG_OFF
#endif

#define LWIP_DEBUG_ENABLE PBUF_DEBUG | TCP_DEBUG | TCP_INPUT_DEBUG | TCP_FR_DEBUG | TCP_RTO_DEBUG \
	| TCP_CWND_DEBUG | TCP_WND_DEBUG | TCP_OUTPUT_DEBUG | TCP_RST_DEBUG | TCP_QLEN_DEBUG \
	| TCP_TSO_DEBUG

#if LWIP_DEBUG_ENABLE

/* Plaform specific diagnostic output */
#define LWIP_PLATFORM_DIAG(x)	do {printf x; fflush(0);} while(0)

/** print debug message only if debug message type is enabled...
 *  AND is of correct type AND is at least LWIP_DBG_LEVEL
 */
#define LWIP_DEBUGF(debug, message) do { \
                               if ( \
                                   ((debug) & LWIP_DBG_ON) && \
                                   ((debug) & LWIP_DBG_TYPES_ON) && \
                                   ((s16_t)((debug) & LWIP_DBG_MASK_LEVEL) >= LWIP_DBG_MIN_LEVEL)) { \
                                 LWIP_PLATFORM_DIAG(message); \
                                 if ((debug) & LWIP_DBG_HALT) { \
                                   while(1); \
                                 } \
                               } \
                             } while(0)

#else  /* LWIP_DEBUG_ENABLE */
#define LWIP_PLATFORM_DIAG(x)
#define LWIP_DEBUGF(debug, message)
#endif /* LWIP_DEBUG_ENABLE */

#endif /* __LWIP_OPT_H__ */
