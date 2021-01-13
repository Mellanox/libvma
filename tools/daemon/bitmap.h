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


/**
 * @file ibwu_bitmap.h
 *
 * @brief Bitmap operations.
 *
 **/
#ifndef TOOLS_DAEMON_BITMAP_H_
#define TOOLS_DAEMON_BITMAP_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t bitmap_item_t;

typedef struct bitmap bitmap_t;
struct bitmap {
	bitmap_item_t *bitmap; /**< The actual bitmap array of characters */
	size_t size; /**< Bitmap size */
};

/* Number of bits in single bitmap item */
#define BITMAP_ITEM_SIZE        (8 * sizeof(bitmap_item_t))

/* Number of items needed to store n bits */
#define BITMAP_ARRAY_SIZE(n)    (((n) + BITMAP_ITEM_SIZE - 1) / BITMAP_ITEM_SIZE)

/**
 * Initialize a bitmap.
 *
 * @param bm    Bitmap to initialize.
 * @param size  Bit count in bitmap.
 *
 * @retval @a none
 ***************************************************************************/
static inline void bitmap_create(bitmap_t **bm, size_t size)
{
	*bm = (bitmap_t *)malloc(sizeof(**bm));
	if (*bm) {
		(*bm)->size = size;
		(*bm)->bitmap =	(bitmap_item_t *)calloc(BITMAP_ARRAY_SIZE(size), sizeof(bitmap_item_t));
		if (NULL == (*bm)->bitmap) {
			free(*bm);
			*bm = NULL;
		}
	}
}

/**
 * Destroy a bitmap.
 *
 * @param bm    Bitmap to destroy.
 *
 * @retval @a none
 ***************************************************************************/
static inline void bitmap_destroy(bitmap_t *bm)
{
	free(bm->bitmap);
	bm->size = 0;
}

/**
 * Returns the index of the element in internal array that contains the bit.
 *
 * @param bit   Bit index.
 *
 * @retval Array index
 ***************************************************************************/
static inline size_t elem_idx(size_t bit)
{
	return (bit / BITMAP_ITEM_SIZE);
}

/**
 * Returns the value with one bit is on.
 *
 * @param bit   Bit index.
 *
 * @retval Element value
 ***************************************************************************/
static inline bitmap_item_t bit_mask(size_t bit_idx)
{
	return (bitmap_item_t)(1 << (bit_idx % BITMAP_ITEM_SIZE));
}

/**
 * Returns the size of the bitmap in bits.
 *
 * @param bm    Bitmap handle.
 *
 * @retval Bitmap size
 ***************************************************************************/
static inline size_t bitmap_size(bitmap_t *bm)
{
	return (bm->size);
}

/**
 * Atomically sets the bit (set 1).
 *
 * @param bm    Bitmap handle.
 * @param bit   Bit index.
 *
 * @retval @a none
 ***************************************************************************/
static inline void bitmap_set(bitmap_t *bm, size_t bit)
{
	size_t idx = elem_idx(bit);
	bitmap_item_t mask = bit_mask(bit);
	bm->bitmap[idx] |= mask;
}

/**
 * Atomically clears the bit (set 0).
 *
 * @param bm    Bitmap handle.
 * @param bit   Bit index.
 *
 * @retval @a none
 ***************************************************************************/
static inline void bitmap_clear(bitmap_t *bm, size_t bit)
{
	size_t idx = elem_idx(bit);
	bitmap_item_t mask = bit_mask(bit);
	bm->bitmap[idx] &= ~mask;
}

/**
 * Atomically inverse the bit.
 *
 * @param bm    Bitmap handle.
 * @param bit   Bit index.
 *
 * @retval @a none
 ***************************************************************************/
static inline void bitmap_flip(bitmap_t *bm, size_t bit)
{
	size_t idx = elem_idx(bit);
	bitmap_item_t mask = bit_mask(bit);
	bm->bitmap[idx] ^= mask;
}

/**
 * Tests the bit.
 *
 * @param bm    Bitmap handle.
 * @param bit   Bit index.
 *
 * @retval bit value
 ***************************************************************************/
static inline int bitmap_test(bitmap_t *bm, size_t bit)
{
	size_t idx = elem_idx(bit);
	bitmap_item_t mask = bit_mask(bit);
	return (0 != (bm->bitmap[idx] & mask));
}

/**
 * Tests if defined interval is a group of bits with identical values.
 *
 * @param bm    Bitmap handle.
 * @param start Start bit index.
 * @param count Number of bits in the group.
 *
 * @retval 0|1  - on success
 * @retval  -1  - on failure
 ***************************************************************************/
static inline int bitmap_test_group(bitmap_t *bm, size_t start, size_t count)
{
	size_t i;
	int value = -1;

	if ((start + count) <= bm->size) {
		value = bitmap_test(bm, start);
		for (i = 1; i < count; i++) {
			if (bitmap_test(bm, start + i) != value) {
				return -1;
			}
		}
	}
	return value;
}

/**
 * Find a group of bits with identical values.
 *
 * @param bm    Bitmap handle.
 * @param start Start bit index.
 * @param count Number of bits in the group.
 * @param value Value of the group.
 *
 * @retval  index  - on success
 * @retval  -1     - on failure
 ***************************************************************************/
static inline int bitmap_find_group(bitmap_t *bm, size_t start, size_t count,
		int value)
{
	size_t i;
	size_t last;

	if ((start + count) <= bm->size) {
		last = bm->size - count;
		for (i = start; i <= last; i++) {
			if (value == bitmap_test_group(bm, i, count)) {
				return i;
			}
		}
	}
	return -1;
}

/**
 * Find first unset.
 *
 * @param bm    Bitmap handle.
 *
 * @retval  index  - on success
 * @retval  -1     - on failure
 ***************************************************************************/
static inline int bitmap_find_first_zero(bitmap_t *bm)
{
	size_t i;

	for (i = 0; i < BITMAP_ARRAY_SIZE(bm->size); i++) {
		if (((bitmap_item_t)(-1)) != bm->bitmap[i]) {
			return (i * BITMAP_ITEM_SIZE + ffs(~bm->bitmap[i]) - 1);
		}
	}
	return -1;
}

#ifdef __cplusplus
}
#endif

#endif /* TOOLS_DAEMON_BITMAP_H_ */

