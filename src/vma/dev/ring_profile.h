/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SRC_VMA_DEV_RING_PROFILE_H_
#define SRC_VMA_DEV_RING_PROFILE_H_

#include <unordered_map>
#include "net_device_val.h"
#include "vma_extra.h"

#define START_RING_INDEX	1 // beneath it's not defined

class ring_profile;
class ring_profiles_collection;


typedef std::unordered_map<vma_ring_profile_key, ring_profile *> ring_profile_map_t;

extern ring_profiles_collection *g_p_ring_profile;


class ring_profile
{
public:
	ring_profile();
	ring_profile(const vma_ring_type_attr *ring_desc);
	vma_ring_type get_ring_type() {return m_ring_desc.ring_type;}
	struct vma_ring_type_attr* get_desc(){return &m_ring_desc;}
	bool operator==(const vma_ring_type_attr &p2);
	const char* to_str(){ return m_str.c_str();}
	const char* get_vma_ring_type_str();
private:
	void			create_string();
	std::string		m_str;
	vma_ring_type_attr	m_ring_desc;
};

class ring_profiles_collection
{
public:
	ring_profiles_collection();
	~ring_profiles_collection();
	vma_ring_profile_key	add_profile(vma_ring_type_attr *profile);
	ring_profile*		get_profile(vma_ring_profile_key key);

private:
	ring_profile_map_t	m_profs_map;
	vma_ring_profile_key	m_curr_idx;
};
#endif /* SRC_VMA_DEV_RING_PROFILE_H_ */
