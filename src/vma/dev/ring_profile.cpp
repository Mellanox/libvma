/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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

#include <dev/ring_profile.h>

ring_profiles_collection *g_p_ring_profile = NULL;


ring_profile::ring_profile(struct vma_ring_type_attr *ring_desc) {
	memset(&m_ring_desc,0,sizeof(m_ring_desc));
	m_ring_desc.comp_mask = ring_desc->comp_mask;
	m_ring_desc.ring_type = ring_desc->ring_type;
	switch (ring_desc->ring_type) {
	case VMA_RING_CYCLIC_BUFFER: {
		vma_cyclic_buffer_ring_attr &r = m_ring_desc.ring_cyclicb;
		r.comp_mask = ring_desc->ring_cyclicb.comp_mask;
		r.num = ring_desc->ring_cyclicb.num;
		r.stride_bytes = ring_desc->ring_cyclicb.stride_bytes;
		if (r.comp_mask & CB_COMP_HDR_BYTE) {
			r.hdr_bytes = ring_desc->ring_cyclicb.hdr_bytes;
		}
		break;
	}
	case VMA_RING_PACKET:
		m_ring_desc.ring_pktq.comp_mask = ring_desc->ring_pktq.comp_mask;
		break;
	default:

		break;
	}
	create_string();
};

const char* ring_profile::get_vma_ring_type_str()
{
	switch (m_ring_desc.ring_type) {
	case VMA_RING_PACKET:	return "VMA_PKTS_RING";
	case VMA_RING_CYCLIC_BUFFER:	return "VMA_CB_RING";
	default:		return "";
	}
};

ring_profile::ring_profile()
{
	m_ring_desc.ring_type = VMA_RING_PACKET;
	m_ring_desc.comp_mask = 0;
	m_ring_desc.ring_pktq.comp_mask = 0;
	create_string();
};


void ring_profile::create_string()
{
	ostringstream s;

	if (m_ring_desc.ring_type == VMA_RING_PACKET) {
		s<<get_vma_ring_type_str();
	} else {
		s<<get_vma_ring_type_str()
		 <<" packets_num:"<<m_ring_desc.ring_cyclicb.num
		 <<" stride_bytes:"<<m_ring_desc.ring_cyclicb.stride_bytes
		 <<" hdr size:"<<m_ring_desc.ring_cyclicb.hdr_bytes;
	}
	m_str = s.str();
}

ring_profiles_collection::ring_profiles_collection(): m_curr_idx(START_RING_INDEX) {

}

vma_ring_profile_key ring_profiles_collection::add_profile(vma_ring_type_attr *profile)
{
	// key 0 is invalid
	vma_ring_profile_key key = m_curr_idx;
	m_curr_idx++;
	ring_profile *prof = new ring_profile(profile);
	m_profs_map[key] = prof;
	return key;
}

ring_profile* ring_profiles_collection::get_profile(vma_ring_profile_key key)
{
	ring_profile_map_t::iterator iter = m_profs_map.find(key);
	if (iter != m_profs_map.end()) {
		return iter->second;
	}
	return NULL;
}

ring_profiles_collection::~ring_profiles_collection()
{
	ring_profile_map_t::iterator iter = m_profs_map.begin();
	for (;iter != m_profs_map.end(); ++iter) {
		delete (iter->second);
	}
}
