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

#ifndef TOOLS_DAEMON_HASH_H_
#define TOOLS_DAEMON_HASH_H_

#ifdef __cplusplus
extern "C" {
#endif

/* The hash_t opaque data type
 */
typedef struct hash_object* hash_t;

/* The hash key data type
 */
typedef uint32_t hash_key_t;


/* This type of function is used to free data inserted into hash table
 */
typedef void (*hash_freefunc_t)(void *);


/* hash_create():
 *
 * Create a hash object.
 * @param free_func - user defined function for destroy data
 *       inserted into hash
 * @param size - size of hash that should be Prime number
 * @return the newly allocated hash table. Must be freed with hash_destory.
 */
hash_t hash_create(hash_freefunc_t free_func, size_t size);

/* hash_destroy():
 *
 * Destroy a hash object.
 * @param ht - hash to be freed
 * @return @a none
 */
void hash_destroy(hash_t ht);

/* hash_count():
 *
 * Return number of valid elements in the hash object.
 * @param ht - point to hash object
 * @return number of elements
 */
int hash_count(hash_t ht);

/* hash_size():
 *
 * Return maximum number of elements in the hash object.
 * @param ht - point to hash object
 * @return maximum number of elements
 */
int hash_size(hash_t ht);

/* hash_get():
 *
 * Return value stored in hash object by found by key.
 * @param ht - point to hash object
 * @param key - key identified data
 * @return value
 */
void *hash_get(hash_t ht, hash_key_t key);

/* hash_enum():
 *
 * Return value stored in hash object by index.
 * @param ht - point to hash object
 * @param index - index in hash object
 * @return value
 */
void *hash_enum(hash_t ht, size_t index);

/* hash_put():
 *
 * Store data in hash object.
 * @param ht - point to hash object
 * @param key - key identified data
 * @param value - stored data
 * @return value or NULL in case of error.
 */
void *hash_put(hash_t ht, hash_key_t key, void *value);

/* hash_del():
 *
 * Remove value stored in hash object and free memory
 * if freefunc() is passed during hash object creation.
 * @param ht - point to hash object
 * @param key - key identified data
 * @return @a none
 */
void hash_del(hash_t ht, hash_key_t key);

#ifdef __cplusplus
}
#endif

#endif /* TOOLS_DAEMON_HASH_H_ */
