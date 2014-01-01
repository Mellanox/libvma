/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2011.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef V_CLOCK_H
#define V_CLOCK_H

#include <sys/time.h>



/* 
 * Parameters used to convert the time values:
 */
#define MSEC_PER_SEC	1000L
#define USEC_PER_MSEC	1000L
#define NSEC_PER_USEC	1000L
#define NSEC_PER_MSEC	1000000L
#define USEC_PER_SEC	1000000L
#define NSEC_PER_SEC	1000000000L
#define FSEC_PER_SEC	1000000000000000L


/*
 * Convenience macros for operations on timevals
 */
#define TIMEVAL_INITIALIZER	{0,0}

#define tv_to_sec(tvp)	( (tvp)->tv_sec)
#define tv_to_msec(tvp)	((int64_t((tvp)->tv_sec) * MSEC_PER_SEC) + (int64_t((tvp)->tv_usec) / USEC_PER_MSEC))
#define tv_to_usec(tvp)	((int64_t((tvp)->tv_sec) * USEC_PER_SEC) + (int64_t((tvp)->tv_usec) ))
#define tv_to_nsec(tvp)	((int64_t((tvp)->tv_sec) * NSEC_PER_SEC) + (int64_t((tvp)->tv_usec) * NSEC_PER_USEC))

#define tv_isset(tvp)		timerisset(tvp)
#define tv_clear(tvp)		timerclear(tvp)

#define tv_cmp(a, b, CMP)	timercmp(a, b, CMP)
#define tv_add(a, b, result)	timeradd(a, b, result)
#define tv_sub(a, b, result)	timersub(a, b, result)


/* Convenience macros for operations on timespecs */
#define TIMESPEC_INITIALIZER	{0,0}

#define ts_to_sec(tsp)	( (tsp)->tv_sec)
#define ts_to_msec(tsp)	((int64_t((tsp)->tv_sec) * MSEC_PER_SEC) + (int64_t((tsp)->tv_nsec) / NSEC_PER_MSEC))
#define ts_to_usec(tsp)	((int64_t((tsp)->tv_sec) * USEC_PER_SEC) + (int64_t((tsp)->tv_nsec) / NSEC_PER_USEC))
#define ts_to_nsec(tsp)	((int64_t((tsp)->tv_sec) * NSEC_PER_SEC) + (int64_t((tsp)->tv_nsec) ))

#define ts_isset(tvp)	((tvp)->tv_sec || (tvp)->tv_nsec)
#define ts_clear(tvp)	((tvp)->tv_sec = (tvp)->tv_nsec = 0)

#define ts_cmp(a, b, CMP) 						      \
  (((a)->tv_sec == (b)->tv_sec) ? 					      \
   ((a)->tv_nsec CMP (b)->tv_nsec) : 					      \
   ((a)->tv_sec CMP (b)->tv_sec))

#define ts_add(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
    (result)->tv_nsec = (a)->tv_nsec + (b)->tv_nsec;			      \
    if ((result)->tv_nsec >= NSEC_PER_SEC)				      \
      {									      \
	++(result)->tv_sec;						      \
	(result)->tv_nsec -= NSEC_PER_SEC;				      \
      }									      \
  } while (0)

#define ts_sub(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;			      \
    if ((result)->tv_nsec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_nsec += NSEC_PER_SEC;				      \
    }									      \
  } while (0)


#endif //V_CLOCK_H
