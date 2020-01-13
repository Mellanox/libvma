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

#ifndef SRC_VMA_UTIL_AGENT_DEF_H_
#define SRC_VMA_UTIL_AGENT_DEF_H_

#ifndef offsetof
#define offsetof(type, member) ((uintptr_t) &((type *)0)->member)
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) (type *)((char *)(ptr) - offsetof(type,member))
#endif

/* List of supported messages in range 0..63
 * Two bits as 6-7 are reserved.
 * 6-bit is reserved
 * 7-bit in message code is for ACK flag in case specific
 * message requires the confirmation
 */
#define VMA_MSG_INIT    0x01
#define VMA_MSG_STATE   0x02
#define VMA_MSG_EXIT    0x03
#define VMA_MSG_FLOW    0x04

#define VMA_MSG_ACK     0x80

#define VMA_AGENT_VER   0x03

#define VMA_AGENT_BASE_NAME "vma_agent"
#define VMA_AGENT_ADDR      "/var/run/" VMA_AGENT_BASE_NAME ".sock"
#define VMA_AGENT_PATH      "/tmp/vma"


#pragma pack(push, 1)
struct vma_hdr {
	uint8_t        code;       /* code of message */
	uint8_t        ver;        /* format version */
	uint8_t        status;     /* status (require answer or return code for reply message) */
	uint8_t        reserve[1]; /* unused */
	int32_t        pid;        /* process id */

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

enum {
	VMA_MSG_FLOW_EGRESS = 0,
	VMA_MSG_FLOW_UDP_5T = 1,
	VMA_MSG_FLOW_UDP_3T = 2,
	VMA_MSG_FLOW_TCP_5T = 3,
	VMA_MSG_FLOW_TCP_3T = 4
};

typedef enum {
	VMA_MSG_FLOW_ADD = 1,
	VMA_MSG_FLOW_DEL = 2
} msg_flow_t;

struct vma_msg_flow {
	struct vma_hdr hdr;
	uint8_t        type;       /* format of tc rule command */
	uint8_t        action;     /* add, del */
	uint32_t       if_id;      /* interface index */
	uint32_t       tap_id;     /* tap device index */
	struct {
		uint32_t       dst_ip;
		uint16_t       dst_port;
		struct {
			uint32_t       src_ip;
			uint16_t       src_port;
		} t5;
	} flow;
};

#pragma pack( pop )

#endif /* SRC_VMA_UTIL_AGENT_DEF_H_ */
