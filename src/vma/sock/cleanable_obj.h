/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
