/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
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

	virtual void clean_obj(){ set_cleaned(); delete this; };

	bool is_cleaned(){ return m_b_cleaned; };

protected:

	void set_cleaned(){ m_b_cleaned = true; };

private:

	bool m_b_cleaned; // indicate that clean_obj() was called.
};

#endif /* CLEANABLE_OBJ_H_ */
