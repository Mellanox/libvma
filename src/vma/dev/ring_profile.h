/*
 * ring_profile.h
 *
 *  Created on: Mar 27, 2017
 *      Author: root
 */

#ifndef SRC_VMA_DEV_RING_PROFILE_H_
#define SRC_VMA_DEV_RING_PROFILE_H_

#include <tr1/unordered_map>
#include "net_device_val.h"
#include "vma_extra.h"

#define START_RING_INDEX	1 // beneath it's not defined

class ring_profile;
class ring_profiles_collection;


typedef std::tr1::unordered_map<uint64_t, ring_profile *> ring_profile_map_t;

extern ring_profiles_collection *g_p_ring_profile;

const int RING_PROF_STR_LEN = 256;

class ring_profile
{
public:
	ring_profile();
	ring_profile(uint64_t type);
	ring_profile(vma_ring_type_attr *ring_desc);
	bool is_default(){return m_ring_desc.ring_type == VMA_RING_PACKET;}
	vma_ring_type get_ring_type() {return m_ring_desc.ring_type;}
	struct vma_ring_type_attr* get_desc(){return &m_ring_desc;}
	const char* to_str(){ return m_p_chr;}
	const char* get_vma_ring_type_str();
private:
	void	create_string();
	char	m_p_chr[RING_PROF_STR_LEN];
	struct	vma_ring_type_attr m_ring_desc;
};

class ring_profiles_collection
{
public:
	ring_profiles_collection();
	~ring_profiles_collection();
	int			add_profile(vma_ring_type_attr *profile);
	ring_profile*		get_profile(uint64_t key);

private:
	ring_profile_map_t	m_profs_map;
	uint64_t		m_curr_idx;
};
#endif /* SRC_VMA_DEV_RING_PROFILE_H_ */
