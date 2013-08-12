/*
 * netlink/attr.h		Netlink Attributes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_ATTR_H_
#define NETLINK_ATTR_H_

#include <netlink/netlink.h>
#include <netlink/object.h>
#include <netlink/addr.h>
#include <netlink/data.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nl_msg;

/**
 * @name Validation Policy Types
 * @{
 */

 /**
  * @ingroup attr
  * Standard attribute types to specify validation policy
  */
enum {
	NLA_UNSPEC,	/**< Unspecified type */
	NLA_U8,		/**< 8bit integer */
	NLA_U16,	/**< 16bit integer */
	NLA_U32,	/**< 32bit integer */
	NLA_U64,	/**< 64bit integer */
	NLA_STRING,	/**< character string */
	NLA_FLAG,	/**< flag */
	NLA_MSECS,	/**< micro seconds (64bit) */
	NLA_NESTED,	/**< nested attributes */
	__NLA_TYPE_MAX,
};

/**
 * @ingroup attr
 * Maximum netlink validation policy type
 */
#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

/** @} */

/**
 * @ingroup attr
 * attribute validation policy
 *
 * Policies are defined as arrays of this struct, the array must
 * be accessible by attribute type up to the highest identifier
 * to be expected.
 *
 * Example:
 * @code
 * static struct nla_policy my_policy[ATTR_MAX+1] __read_mostly = {
 * 	[ATTR_FOO] = { .type = NLA_U16 },
 *	[ATTR_BAR] = { .type = NLA_STRING },
 *	[ATTR_BAZ] = { .minlen = sizeof(struct mystruct) },
 * };
 * @endcode
 */
struct nla_policy {
	/** Type of attribute or NLA_UNSPEC */
	uint16_t	type;

	/** Minimal length of payload required to be available */
	uint16_t	minlen;

	/** Maximal length of payload required to be available */
	uint16_t	maxlen;
};

/* size calculations */
extern int		nla_attr_size(int payload);
extern int		nla_total_size(int payload);
extern int		nla_padlen(int payload);

/* payload access */
extern int		nla_type(const struct nlattr *);
extern void *		nla_data(const struct nlattr *);
extern int		nla_len(const struct nlattr *);

/* attribute parsing */
extern int		nla_ok(const struct nlattr *, int);
extern struct nlattr *	nla_next(const struct nlattr *, int *);
extern int		nla_parse(struct nlattr **, int, struct nlattr *,
				  int, struct nla_policy *);
extern int		nla_parse_nested(struct nlattr **, int, struct nlattr *,
					 struct nla_policy *);
extern int		nla_validate(struct nlattr *, int, int,
				     struct nla_policy *);
extern struct nlattr *	nla_find(struct nlattr *, int, int);

/* utilities */
extern int		nla_memcpy(void *, struct nlattr *, int);
extern size_t		nla_strlcpy(char *, const struct nlattr *, size_t);
extern int		nla_memcmp(const struct nlattr *, const void *, size_t);
extern int		nla_strcmp(const struct nlattr *, const char *);

/* attribute construction */
extern struct nlattr *	nla_reserve(struct nl_msg *, int, int);
extern int		nla_put(struct nl_msg *, int, int, const void *);
extern int		nla_put_nested(struct nl_msg *, int, struct nl_msg *);
extern int		nla_put_u8(struct nl_msg *, int, uint8_t);
extern int		nla_put_u16(struct nl_msg *, int, uint16_t);
extern int		nla_put_u32(struct nl_msg *, int, uint32_t);
extern int		nla_put_u64(struct nl_msg *, int, uint64_t);
extern int		nla_put_string(struct nl_msg *, int, const char *);
extern int		nla_put_flag(struct nl_msg *, int);
extern int		nla_put_msecs(struct nl_msg *, int, unsigned long);
extern int		nla_put_data(struct nl_msg *, int, struct nl_data *);
extern int		nla_put_addr(struct nl_msg *, int, struct nl_addr *);

/* attribute nesting */
extern struct nlattr *	nla_nest_start(struct nl_msg *, int);
extern int		nla_nest_end(struct nl_msg *, struct nlattr *);

/* attribute reading */
extern uint8_t		nla_get_u8(struct nlattr *);
extern uint16_t		nla_get_u16(struct nlattr *);
extern uint32_t		nla_get_u32(struct nlattr *);
extern uint64_t		nla_get_u64(struct nlattr *);
extern char *		nla_get_string(struct nlattr *);
extern int		nla_get_flag(struct nlattr *);
extern unsigned long	nla_get_msecs(struct nlattr *);
extern struct nl_data *	nla_get_data(struct nlattr *);
extern struct nl_addr *	nla_get_addr(struct nlattr *, int);

/**
 * @name Attribute Construction (Exception Based)
 *
 * All these functions jump to nla_put_failure in case of a failure
 * instead of returning an error code.
 * 
 * @{
 */

/**
 * @ingroup attr
 * Add a netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg attrlen		length of attribute payload
 * @arg data		head of attribute payload
 */
#define NLA_PUT(n, attrtype, attrlen, data) \
	do { \
		if (nla_put(n, attrtype, attrlen, data) < 0) \
			goto nla_put_failure; \
	} while(0)

/**
 * @ingroup attr
 * Add a basic netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg type		atomic type
 * @arg attrtype	attribute type
 * @arg value		head of attribute payload
 */
#define NLA_PUT_TYPE(n, type, attrtype, value) \
	do { \
		type __tmp = value; \
		NLA_PUT(n, attrtype, sizeof(type), &__tmp); \
	} while(0)

/**
 * Add a u8 netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg value		numeric value
 */
#define NLA_PUT_U8(n, attrtype, value) \
	NLA_PUT_TYPE(n, uint8_t, attrtype, value)

/**
 * Add a u16 netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg value		numeric value
 */
#define NLA_PUT_U16(n, attrtype, value) \
	NLA_PUT_TYPE(n, uint16_t, attrtype, value)

/**
 * Add a u32 netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg value		numeric value
 */
#define NLA_PUT_U32(n, attrtype, value) \
	NLA_PUT_TYPE(n, uint32_t, attrtype, value)

/**
 * Add a u64 netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg value		numeric value
 */
#define NLA_PUT_U64(n, attrtype, value) \
	NLA_PUT_TYPE(n, uint64_t, attrtype, value)

/**
 * Add a character string netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg value		character string
 */
#define NLA_PUT_STRING(n, attrtype, value) \
	NLA_PUT(n, attrtype, strlen(value) + 1, value)

/**
 * Add a flag netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 */
#define NLA_PUT_FLAG(n, attrtype) \
	NLA_PUT(n, attrtype, 0, NULL)

/**
 * Add a msecs netlink attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg msecs		numeric value in micro seconds
 */
#define NLA_PUT_MSECS(n, attrtype, msecs) \
	NLA_PUT_U64(n, attrtype, msecs)

/**
 * Add a address attribute to a netlink message
 * @arg n		netlink message
 * @arg attrtype	attribute type
 * @arg addr		abstract address object
 */
#define NLA_PUT_ADDR(n, attrtype, addr) \
	NLA_PUT(n, attrtype, nl_addr_get_len(addr), \
		nl_addr_get_binary_addr(addr))

/** @} */

/**
 * @name Iterators
 * @{
 */

/**
 * @ingroup attr
 * iterate over a stream of attributes
 * @arg pos	loop counter, set to current attribute
 * @arg head	head of attribute stream
 * @arg len	length of attribute stream
 * @arg rem	initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))

/**
 * @ingroup attr
 * iterate over a stream of nested attributes
 * @arg pos	loop counter, set to current attribute
 * @arg nla	attribute containing the nested attributes
 * @arg rem	initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_nested(pos, nla, rem) \
	for (pos = nla_data(nla), rem = nla_len(nla); \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))

/** @} */

#ifdef __cplusplus
}
#endif

#endif
