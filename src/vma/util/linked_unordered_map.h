/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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

#if 0

#ifndef LINKED_UNORDERED_MAP_H_
#define LINKED_UNORDERED_MAP_H_

#include <tr1/unordered_map>

/*template <typename T> struct map_node {
	T val;
	struct map_node<T> *p_prev;
	struct map_node<T> *p_next;
};

template <typename T> inline bool
operator==(struct map_node<T> const& node1, struct map_node<T> const& node2)
{
	return (node1.val == node2.val);
}

template <typename T> inline bool
operator<(struct map_node<T> const& node1, struct map_node<T> const& node2)
{
	return (node1.val < node2.val);
}*/

template<class K, class V>
class linked_unordered_map
{
public:
	struct pair {
		// coverity[member_decl]
		K first;
		// coverity[member_decl]
		V second;
	};

	struct map_node {
		struct pair m_pair;
		struct map_node *p_prev;
		struct map_node *p_next;
		map_node() : p_prev(NULL), p_next(NULL) {}
		map_node(V val) : p_prev(NULL), p_next(NULL) { m_pair.second = val; }
		map_node& operator=( const V& val ) {
			m_pair.second = val;
			return *this;;
		}
		map_node& operator=( const map_node& rhs ) {
			if( this != &rhs ) {
				//m_pair.key = rhs.m_pair.key;
				m_pair.second = rhs.m_pair.second;
				//p_prev = rhs.p_prev;
				//p_next = rhs.p_next;
			}
			return *this;;
		}
	};

	class iterator {
	public:
		iterator() : m_node(NULL) {}

		struct pair *operator->() {
			if (m_node) {
				return &(m_node->m_pair);
			}
			return &(m_pair);
		}

		iterator& operator++() {
			if (m_node) {
				m_node = m_node->p_next;
			}
			return *this;
		}

		bool operator!=(const iterator &other) const {
			return m_node != other.m_node;
		}

	private:
		iterator(struct map_node *node) : m_node(node) {}

		struct map_node *m_node;
		struct pair m_pair;

		friend class linked_unordered_map;
	};

	linked_unordered_map() : p_head(NULL) {}

	inline bool empty() { return m_map.empty(); }
	inline size_t size() { return m_map.size(); }

	inline V& operator[] ( const K& k ) {
		struct map_node& node = m_map[k];
		if (!node.p_next && !node.p_prev) {
			node.m_pair.first = k;
			if (p_head) p_head->p_prev = &node;
			node.p_next = p_head;
			p_head = &node;
		}
		return node.m_pair.second;
	}

	inline size_t erase ( const K& k ) {
		typename std::tr1::unordered_map<K, struct map_node>::iterator iter = m_map.find(k);
		if (iter == m_map.end()) return 0;
		struct map_node* tmp = &iter->second;
		if (tmp->p_prev) tmp->p_prev->p_next = tmp->p_next;
		if (tmp->p_next) tmp->p_next->p_prev = tmp->p_prev;
		if (p_head == tmp) p_head = tmp->p_next;
		return m_map.erase(k);
	}

	inline iterator erase ( iterator position ) {
		if (position.m_node) {
			struct map_node * tmp = position.m_node->p_next;
			if (position.m_node->p_prev) position.m_node->p_prev->p_next = position.m_node->p_next;
			if (position.m_node->p_next) position.m_node->p_next->p_prev = position.m_node->p_prev;
			if (p_head == position.m_node) p_head = position.m_node->p_next;
			m_map.erase(position.m_node->m_pair.first);
			position.m_node = tmp;
		}
		return position;
	}

	inline void insert ( const K& k, const V& v) {
		struct map_node& node = m_map[k];
		node.m_pair.first = k;
		node.m_pair.second = v;
		if (p_head) p_head->p_prev = &node;
		node.p_next = p_head;
		p_head = &node;
	}

	iterator begin() const {
		return iterator(p_head);
	}

	iterator end() const {
		return iterator(NULL);
	}

	inline iterator find ( const K& k ) {
		typename std::tr1::unordered_map<K, struct map_node>::iterator iter = m_map.find(k);
		if (iter == m_map.end()) return end();
		else return iterator(&(iter->second));
	}

	std::tr1::unordered_map<K, struct map_node > m_map;
	struct map_node *p_head;


};



#endif /* LINKED_UNORDERED_MAP_H_ */

#endif
