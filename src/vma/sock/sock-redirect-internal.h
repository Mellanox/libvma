/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef SOCK_REDIRECT_INTERNAL_H
#define SOCK_REDIRECT_INTERNAL_H

#include "config.h"

/*
 * Workaround for clang compilation error with fortified wrapper redefinition.
 */
#ifdef __clang__
#ifdef HAVE___READ_CHK
#define read read_unused
#endif
#ifdef HAVE___RECV_CHK
#define recv recv_unused
#endif
#ifdef HAVE___RECVFROM_CHK
#define recvfrom recvfrom_unused
#endif
#ifdef HAVE___POLL_CHK
#define poll poll_unused
#endif
#ifdef HAVE___PPOLL_CHK
#define ppoll ppoll_unused
#endif
#endif /* __clang__ */
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#ifdef __clang__
#ifdef HAVE___READ_CHK
#undef read
#endif
#ifdef HAVE___RECV_CHK
#undef recv
#endif
#ifdef HAVE___RECVFROM_CHK
#undef recvfrom
#endif
#ifdef HAVE___POLL_CHK
#undef poll
#endif
#ifdef HAVE___PPOLL_CHK
#undef ppoll
#endif
#endif /* __clang__ */

#endif /* SOCK_REDIRECT_INTERNAL_H */
