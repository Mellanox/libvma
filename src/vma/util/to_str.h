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


/* This class should be inherited by all classed that need to be printed
*/
#ifndef TO_STR_H_
#define TO_STR_H_

#include <string>

class tostr
{
public:
	virtual ~tostr(){};
	virtual const std::string to_str() const { return std::string(""); };
};

#endif /* TO_STR_H_ */
