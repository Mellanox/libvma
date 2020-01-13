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

#ifndef SRC_VMA_DEV_RING_PROFILE_H_
#define SRC_VMA_DEV_RING_PROFILE_H_

#include <tr1/unordered_map>
#include "net_device_val.h"
#include "vma_extra.h"

#define START_RING_INDEX	1 // beneath it's not defined

class ring_profile;
class ring_profiles_collection;


typedef std::tr1::unordered_map<vma_ring_profile_key, ring_profile *> ring_profile_map_t;

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
