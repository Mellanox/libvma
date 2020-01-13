/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef NETMAP_VMA_H
#define NETMAP_VMA_H

#ifdef NETMAP_VMA
#define	STRIDE_SIZE	2048
#define	nm_open		nm_open_vma
#define	nm_close	nm_close_vma
#define	nm_nextpkt	nm_nextpkt_vma
#define	nm_dispatch	nm_dispatch_vma
struct nm_desc *nm_open_vma(const char *ifname, const struct nmreq *req,
		uint64_t flags, const struct nm_desc *arg);
int nm_close_vma(struct nm_desc *);
u_char* nm_nextpkt_vma(struct nm_desc *d, struct nm_pkthdr *hdr);
int poll_nm_vma(struct nm_desc *d, int timeout);
int nm_dispatch_vma(struct nm_desc *d, int cnt, nm_cb_t cb, u_char *arg);
#endif

#endif /* NETMAP_VMA_H */
