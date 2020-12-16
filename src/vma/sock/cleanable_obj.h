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


#ifndef CLEANABLE_OBJ_H_
#define CLEANABLE_OBJ_H_

// This interface should be implemented by classes that we do not want to delete explicitly.
// For example, classes that inherit timer_handler should be deleted only from the context of the internal thread.
// Instead of calling delete for the object, call clean_obj() which should handle the deletion of the object.
class cleanable_obj
{
public:
	cleanable_obj(){ m_b_cleaned = false; };

	virtual ~cleanable_obj(){};

	/* This function should be used just for objects that
	 * was allocated via new() (not by new[], nor by placement new, nor a local object on the stack,
	 * nor a namespace-scope / global, nor a member of another object; but by plain ordinary new)
	 */
	virtual void clean_obj(){
		set_cleaned();
		delete this;
	};

	bool is_cleaned(){ return m_b_cleaned; };

protected:

	void set_cleaned(){ m_b_cleaned = true; };

private:

	bool m_b_cleaned; // indicate that clean_obj() was called.
};

#endif /* CLEANABLE_OBJ_H_ */
