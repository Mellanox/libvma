/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <dev/ring_profile.h>

ring_profiles_collection *g_p_ring_profile = NULL;


ring_profile::ring_profile(const vma_ring_type_attr *ring_desc) {
	m_ring_desc.comp_mask = ring_desc->comp_mask;
	m_ring_desc.ring_type = ring_desc->ring_type;
	switch (ring_desc->ring_type) {
	case VMA_RING_PACKET:
		m_ring_desc.ring_pktq.comp_mask = ring_desc->ring_pktq.comp_mask;
		break;
	case VMA_RING_EXTERNAL_MEM:
		m_ring_desc.ring_ext.comp_mask = ring_desc->ring_ext.comp_mask;
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
	case VMA_RING_EXTERNAL_MEM:	return "VMA_EXTERNAL_MEM_RING";
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

	s<<get_vma_ring_type_str();
	m_str = s.str();
}

bool ring_profile::operator==(const vma_ring_type_attr &p2)
{
	ring_profile other(&p2);

	return (m_str.compare(other.to_str()) == 0);
}

ring_profiles_collection::ring_profiles_collection(): m_curr_idx(START_RING_INDEX) {

}

vma_ring_profile_key ring_profiles_collection::add_profile(vma_ring_type_attr *profile)
{
	// first check if this profile exists
	ring_profile_map_t::iterator it = m_profs_map.begin();
	for (;it != m_profs_map.end(); it++) {
		if (*it->second == *profile) {
			return it->first;
		}
	}
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
	ring_profile_map_t::iterator iter;

	while ((iter = m_profs_map.begin()) != m_profs_map.end()) {
		delete (iter->second);
		m_profs_map.erase(iter);
	}
}
