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


#ifndef HASH_MAP_H
#define HASH_MAP_H

#include "utils/lock_wrapper.h"


/**
 * Map keys to values (K -> V).
 * The map supports SET and GET operations.
 * The map does not do any kind of locking, however it is
 * guaranteed that SET does not interfere with GET.
 *
 * In order to perform find/add new operation, do:
 *   if GET:
 *   	return elem
 *   lock()
 *   if not GET:
 *      SET(new_elem)
 *   unlock()
 *   return GET
 *
 * This is correct because there are no DELETE operations.
 * hash_map
 * @param K key type
 * @param V value type
 * @param MAP_SIZE hash table size (better be a power of 2)
 * @param NULL_VALUE invalid (sentinel) value for type V, i.e NULL for pointers.
 */

#define HASH_MAP_SIZE	4096

template <typename K, typename V>
class hash_map {
public:
	hash_map();
	virtual ~hash_map();

public:
	struct map_node {
		K	key;
		V	value;
		map_node *next;
	};

	struct pair {
		// coverity[member_decl]
		K first;
		// coverity[member_decl]
		V second;
	};

	class iterator {
	public:
		iterator() :
			m_index(HASH_MAP_SIZE), m_node(NULL), m_hash_table(NULL) {
		}

		pair *operator->() {
			if (m_node) {
				m_pair.first = m_node->key;
				m_pair.second = m_node->value;
			}
			return &m_pair;
		}

		iterator& operator++() {
			if (m_node) {
				m_node = m_node->next;
			}
			advance();
			return *this;
		}

		bool operator!=(const iterator &other) const {
			return m_node != other.m_node;
		}

	private:
		iterator(int index, map_node *node, map_node* const *hash_table) :
			m_index(index), m_node(node), m_hash_table(hash_table) {
			advance();
		}

		// Skip empty nodes
		void advance() {
			while (!m_node && m_index < HASH_MAP_SIZE) {
				m_node = m_hash_table[++m_index];
			}
			if (m_index >= HASH_MAP_SIZE) {
				m_node = NULL;
			}
		}

		int m_index;
		map_node *m_node;
		map_node * const *m_hash_table;
		pair m_pair;

		friend class hash_map;
	};

	/**
	 * Adds a (key,value) pair to the map.
	 * If the key already there, the value is updated.
	 */
	void set(const K &key, V value);

	/**
	 * Adds a (key,value) pair to the map.
	 * If the key already there, the value is updated.
	 *
	 * If a mapping with null_value is found, it is replaced
	 * with the new mapping (instead of allocating more room).
	 * This way mappings can be deleted in a GET-safe manner,
	 * and not wasting too much memory (There will be at most
	 * one empty item for each bucket).
	 */
	void set_replace(const K &key, V value, V null_value);

	/**
	 * Retrieves a value for a given key.
	 *
	 * @param key Key to find.
	 * @param default_value Return this if not found.
	 * @return Value for key, of defaultValue if not found.
	 */
	inline V get(const K &key, V default_value);

	/**
	 * Removes a mapping from the map.
	 * NOTE: This is not synchronized with GET. In order to be safe, delete
	 * items by replacing the mapping with some NULL value, and set items
	 * with set_replace to replace the empty mappings.
	 *
	 * @param key Key to delete.
	 * @return true if deleted, false if not found.
	 */
	inline bool del(const K &key);

	iterator begin() const {
		return iterator(0, m_hash_table[0], m_hash_table);
	}

	iterator end() const {
		return iterator(HASH_MAP_SIZE, NULL, m_hash_table);
	}

private:
	/**
	 * Calculate key bucket number by it's hash (XOR of all bytes)
	 * @param key Key to hash.
	 * @return Bucket number.
	 */
	 inline int calc_hash(const K &key);

	/// holds the hash table
	map_node *m_hash_table[HASH_MAP_SIZE];

	/// last used element optimization
	map_node *m_last;
};

#include "hash_map.inl"

#endif
