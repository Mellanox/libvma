/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SG_ARRAY_H
#define SG_ARRAY_H

#include <stdio.h>

#include "vma/ib/base/verbs_extra.h"

//! sg_array - helper class on top of scatter/gather elements array.
//Represent it like a virtual one dimension vector/array.

class sg_array {
public:
	sg_array(ibv_sge *sg_, int num_sge_):
	 m_sg(sg_)
	,m_current(sg_)
	,m_num_sge(num_sge_)
	,m_length(0)
	,m_index(0)
	,m_pos(0)
	{
	}
//! Index operator
#if 0 //TODO: testing
	inline uint8_t* operator[](int ind_)
	{
		int index = -1;
		int pos = 0;
		if (unlikely(m_sg == NULL))
			return NULL;
		while (index++ <= m_num_sge) {

			if (pos+(int)m_sg[index].length > ind_) {
				return (uint8_t*)m_sg[index].addr+(ind_-pos);
			} else {
				pos += m_sg[index].length;
			}
		}
		return NULL;
	}
#endif //0
//! Get pointer to data for get_len size from current position.
//In case there is no full requested range in current SGE returns
//the rest in current sge. Next call will start from the beginning
//of next SGE
	inline uint8_t* get_data(int* get_len)
	{
		if (likely(m_index < m_num_sge)) {

			m_current = m_sg + m_index;

			if (likely((m_pos+*get_len) < (int)m_current->length)) {
				uint8_t* old_p = (uint8_t*)m_sg[m_index].addr+m_pos;
				m_pos += *get_len;
				if (unlikely(m_pos < 0))
					return NULL;
				return old_p;
			} else {
				*get_len = m_current->length - m_pos;

				if (unlikely(m_pos < 0))
					return NULL;
				uint8_t* old_p = (uint8_t*)m_sg[m_index++].addr+m_pos;
				// moving to next sge
				m_pos = 0;
				return old_p;
			}
		}
		return NULL;
	}

	inline int get_num_sge(void) { return m_sg ? m_num_sge : -1; }
	inline int length(void) 
	{
		if (unlikely(m_sg==NULL || m_num_sge==0) )
			return 0;
		for (int i=0; i<m_num_sge; i++)
			m_length += m_sg[i].length;
		return m_length; 
	}
	inline int get_current_lkey(void) { return m_current->lkey; }

private:
	struct ibv_sge*	m_sg;
	struct ibv_sge* m_current;
	int     	m_num_sge;
	int		m_length;
	int		m_index;
	int     	m_pos;

};

#endif // SG_ARRAY_H
