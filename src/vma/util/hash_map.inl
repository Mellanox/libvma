/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


template <typename K, typename V>
hash_map<K, V>::hash_map() : m_last(NULL) {
	int i;

	for (i = 0; i < HASH_MAP_SIZE; ++i) {
		m_hash_table[i] = NULL;
	}
}

template <typename K, typename V>
hash_map<K, V>::~hash_map() {
	map_node *head, *tmp;
	int i;

	// Release all map nodes
	for (i = 0; i < HASH_MAP_SIZE; ++i) {
		head = m_hash_table[i];
		while (head) {
			tmp = head->next;
			delete head;
			head = tmp;
		}
	}
}

template <typename K, typename V>
inline V hash_map<K, V>::get(const K &key, V default_value) {
	map_node *node, *last;

	last = m_last; // Copy last before it changes
	if (last && last->key == key) {
		return last->value;
	}

	node = m_hash_table[calc_hash(key)];
	while (node) {
		if (node->key == key) {
			m_last = node;
			return node->value;
		}
		node = node->next;
	}
	return default_value;
}

template <typename K, typename V>
void hash_map<K, V>::set(const K &key, V value) {
	map_node **pptail, *new_node;

	// find last pointer
	pptail = &( m_hash_table[calc_hash(key)] );
	while (*pptail) {
		if ((*pptail)->key == key) {
			(*pptail)->value = value;
			return;
		}
		pptail = &( (*pptail)->next );
	}

	// create new node
	new_node = new map_node();
	new_node->key = key;
	new_node->value = value;
	new_node->next = NULL;

	// add
	*pptail = new_node;
}

template <typename K, typename V>
void hash_map<K, V>::set_replace(const K &key, V value, V null_value) {
	map_node **pptail, *new_node = NULL;

	// find last pointer
	pptail = &( m_hash_table[calc_hash(key)] );
	while (*pptail) {
		if ((*pptail)->key == key) {
			(*pptail)->value = value;
			return;
		} else if ((*pptail)->key == null_value) {
			new_node = *pptail;
			break;
		}
		pptail = &( (*pptail)->next );
	}

	if (!new_node) {
		// create new node
		new_node = new map_node();
		new_node->next = NULL;
	}

	new_node->key = key;
	new_node->value = value;

	// add
	*pptail = new_node;
}

template <typename K, typename V>
inline int hash_map<K, V>::calc_hash(const K &key) {
	uint8_t *pval, *csum8;
	uint16_t csum;
	size_t i, j;

	// uint32_t-size checksum on key
	csum = 0;
	csum8 = (uint8_t*)&csum;
	pval = (uint8_t*)&key;
	// start toggle from 1, as the keys are usually succeders, and gone through htons 
	for (i = 0, j = 1; i < sizeof(K); ++i, j ^= 1) {
		csum8[j] ^= *pval;
		++pval;
	}
	// to 12 bit
	csum = (csum8[0] ^ csum8[1]) | ((((csum >> 4) ^ (csum >> 8)) & 0xf) << 8);
	// or modolu prime close to 4096
	//csum %= 4093;
	return csum;
}

template <typename K, typename V>
bool hash_map<K, V>::del(const K &key) {
	map_node **pprev, *tmp;

	// find last pointer
	pprev = &( m_hash_table[calc_hash(key)] );
	while (*pprev) {
		if ((*pprev)->key == key) {
			tmp = *pprev;
			*pprev = (*pprev)->next;
			if (m_last == tmp)
				m_last = NULL;
			delete tmp;
			return true;
		}
		pprev = &( (*pprev)->next );
	}
	return false;
}
