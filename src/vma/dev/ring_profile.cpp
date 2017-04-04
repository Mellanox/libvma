/*
 * ring_profile.cpp
 *
 *  Created on: Mar 27, 2017
 *      Author: root
 */

#include <dev/ring_profile.h>

ring_profiles_collection *g_p_ring_profile = NULL;


ring_profile::ring_profile(struct vma_ring_type_attr *ring_desc): m_ring_desc(*ring_desc) {
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
	m_ring_desc.comp_mask = VMA_RING_TYPE_MASK;
	m_ring_desc.ring_pktq.comp_mask = 0;
	create_string();
};


void ring_profile::create_string()
{
	if (m_ring_desc.ring_type == VMA_RING_PACKET) {
		snprintf(m_p_chr, RING_PROF_STR_LEN, "%s",
			get_vma_ring_type_str());
	}
	else {
		snprintf(m_p_chr, RING_PROF_STR_LEN, "%s, pps = %d hdr_bytes %d "
			"stride_bytes %d", get_vma_ring_type_str(),
			m_ring_desc.ring_cyclicb.num,
			m_ring_desc.ring_cyclicb.stride_bytes,
			m_ring_desc.ring_cyclicb.hdr_bytes);
	}
}

// key 0 is invalid
ring_profiles_collection::ring_profiles_collection(): m_curr_idx(START_RING_INDEX) {

}

int ring_profiles_collection::add_profile(vma_ring_type_attr *profile)
{
	// first 32 bits are reserved for backward compatibility
	uint64_t key = m_curr_idx;
	m_curr_idx++;
	ring_profile *prof = new ring_profile(profile);
	m_profs_map[key] = prof;
	return key;
}

ring_profile* ring_profiles_collection::get_profile(uint64_t key)
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
