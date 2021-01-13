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


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "hash.h"


#define HASH_KEY_INVALID    (hash_key_t)(-1)

/**
 * @struct hash_element
 * @brief It is an object to be stored in a hash container
 */
struct hash_element {
	hash_key_t key; /**< key */
	void *value;    /**< value */
};

/**
 * @struct hash_object
 * @brief hash container
 */
struct hash_object {
	struct hash_element *hash_table; /**< hash table */
	struct hash_element *last;       /**< last accessed */
	int size;                        /**< maximum number of elements */
	int count;                       /**< current count of elements */
	hash_freefunc_t free;            /**< free function */
};

static struct hash_element* hash_find(hash_t ht, hash_key_t key, int flag);
static int check_prime(int value);


hash_t hash_create(hash_freefunc_t free_func, size_t size)
{
	hash_t ht = NULL;

	/* Check passed size */
	if (!check_prime(size)) {
		return NULL;
	}

	ht = (struct hash_object *)malloc(sizeof(*ht));
	if (ht) {
		ht->size = size;
		ht->hash_table = (struct hash_element *)calloc(ht->size,
				sizeof(*ht->hash_table));
		if (ht->hash_table) {
			int i = 0;

			ht->last = NULL;
			ht->count = 0;
			ht->free = free_func;
			for (i = 0; i < ht->size; i++) {
				ht->hash_table[i].key = HASH_KEY_INVALID;
			}
		} else {
			free(ht);
			ht = NULL;
		}
	}

	return ht;
}

void hash_destroy(hash_t ht)
{
	if (ht) {
		if (ht->hash_table) {
			int i = 0;

			for (i = 0; i < ht->size; i++) {
				if (ht->hash_table[i].key != HASH_KEY_INVALID) {
					if (ht->free && ht->hash_table[i].value) {
						ht->free(ht->hash_table[i].value);
					}
					ht->hash_table[i].key = HASH_KEY_INVALID;
					ht->hash_table[i].value = NULL;
				}
			}
			free(ht->hash_table);
			ht->hash_table = NULL;
		}
		free(ht);
		ht = NULL;
	}
}

int hash_count(hash_t ht)
{
	return ht->count;
}

int hash_size(hash_t ht)
{
	return ht->size;
}

void *hash_get(hash_t ht, hash_key_t key)
{
	if (ht) {
		struct hash_element *entry = NULL;

		entry = hash_find(ht, key, 0);
		if (entry) {
			return entry->value;
		}
	}

	return NULL;
}

void *hash_enum(hash_t ht, size_t index)
{
	if (ht) {
		struct hash_element *entry = NULL;

		entry = &(ht->hash_table[index]);
		if (entry) {
			return entry->value;
		}
	}

	return NULL;
}

void *hash_put(hash_t ht, hash_key_t key, void *value)
{
	if (ht && (ht->count < ht->size)) {
		struct hash_element *entry = NULL;

		entry = hash_find(ht, key, 0);
		if (NULL == entry) {
			entry = hash_find(ht, key, 1);
		}
		if (entry) {
			if (ht->free && entry->value) {
				ht->free(entry->value);
			}
			if (entry->key == HASH_KEY_INVALID) {
				ht->count++;
			}
			entry->key = key;
			entry->value = value;
			return value;
		}
	}

	return NULL;
}

void hash_del(hash_t ht, hash_key_t key)
{
	if (ht) {
		struct hash_element *entry = NULL;

		entry = hash_find(ht, key, 0);
		if (entry) {
			if (ht->free && entry->value) {
				ht->free(entry->value);
			}
			if (entry->key != HASH_KEY_INVALID) {
				ht->count--;
			}
			entry->key = HASH_KEY_INVALID;
			entry->value = NULL;
		}
	}
}

/* hash_find():
 *
 * Find a place (hash element) in the hash related key or
 * new element.
 * @param ht - point to hash object
 * @param key - key identified data
 * @param flag - 1 - add new, 0 - find existing
 * @return hash element or NULL in case there is no place.
 */
static struct hash_element* hash_find(hash_t ht, hash_key_t key, int flag)
{
	struct hash_element *entry = NULL;
	int attempts = 0;
	int idx = 0;
	hash_key_t expect_key;

	if (ht->last && ht->last->key == key)
		return ht->last;

	expect_key = (flag ? HASH_KEY_INVALID : key);

	idx = key % ht->size;

	do {
		entry = &(ht->hash_table[idx]);

		if (entry->key == expect_key) {
			break;
		} else {
			if (attempts >= (ht->size - 1)) {
				entry = NULL;
				break;
			}
			attempts++;
			idx = (idx + 1) % ht->size;
		}
	} while (1);

	ht->last = (entry ? entry : ht->last);

	return entry;
}

static int check_prime(int value)
{
	int i = 0;

	for (i = 2; i <= value / 2; i++) {
		if ((value % i) == 0) {
			return 0;
		}
	}

	return 1;
}
