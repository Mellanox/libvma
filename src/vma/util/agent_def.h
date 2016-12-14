/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef SRC_VMA_UTIL_AGENT_DEF_H_
#define SRC_VMA_UTIL_AGENT_DEF_H_

/* List of supported messages in range 0..63
 * Two bits as 6-7 are reserved.
 * 6-bit is reserved
 * 7-bit in message code is for ACK flag in case specific
 * message requires the confirmation
 */
#define VMA_MSG_INIT    0x01
#define VMA_MSG_STATE   0x02
#define VMA_MSG_EXIT    0x03

#define VMA_MSG_ACK     0x80

#define VMA_AGENT_VER   0x01

#define VMA_AGENT_BASE_NAME "vma_agent"
#define VMA_AGENT_ADDR      "/var/run/" VMA_AGENT_BASE_NAME ".sock"
#define VMA_AGENT_PATH      "/tmp/vma"


#pragma pack(push, 1)
struct vma_hdr {
	uint8_t        code;
	uint8_t        ver;
	uint8_t        reserve[2];
	int32_t        pid;

};

struct vma_msg_init {
	struct vma_hdr hdr;
	uint32_t       ver;
};

struct vma_msg_exit {
	struct vma_hdr hdr;
};

struct vma_msg_state {
	struct vma_hdr hdr;
	uint32_t       fid;
	uint32_t       src_ip;
	uint32_t       dst_ip;
	uint16_t       src_port;
	uint16_t       dst_port;
	uint8_t        type;
	uint8_t        state;
};
#pragma pack( pop )

#endif /* SRC_VMA_UTIL_AGENT_DEF_H_ */
