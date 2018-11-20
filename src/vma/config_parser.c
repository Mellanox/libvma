/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison implementation for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.7"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         libvma_yyparse
#define yylex           libvma_yylex
#define yyerror         libvma_yyerror
#define yylval          libvma_yylval
#define yychar          libvma_yychar
#define yydebug         libvma_yydebug
#define yynerrs         libvma_yynerrs

/* Copy the first part of user declarations.  */
/* Line 371 of yacc.c  */
/* Line 39 of config_parser.y */


/* header section */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vma/util/libvma.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

typedef enum
{
	CONF_RULE
} configuration_t;

#define YYERROR_VERBOSE 1

extern int yyerror(const char *msg);
extern int yylex(void);
static int parse_err = 0;

struct dbl_lst	__instance_list;

/* some globals to store intermidiate parser state */
static struct use_family_rule __vma_rule;
static struct address_port_rule *__vma_address_port_rule = NULL;
static int __vma_rule_push_head = 0;
static int current_role = 0;
static configuration_t current_conf_type = CONF_RULE;
static struct instance *curr_instance = NULL;

int __vma_config_empty(void)
{
	return ((__instance_list.head == NULL) && (__instance_list.tail == NULL));
}

/* define the address by 4 integers */
static void __vma_set_ipv4_addr(short a0, short a1, short a2, short a3)
{
	char buf[16];
	struct in_addr *p_ipv4 = NULL;
  
	p_ipv4 = &(__vma_address_port_rule->ipv4);
  
	snprintf(buf, sizeof(buf), "%hd.%hd.%hd.%hd", a0, a1, a2, a3);
	if (1 != inet_pton(AF_INET, (const char*)buf, p_ipv4)) {
		parse_err = 1;
		yyerror("provided address is not legal");
	}
}

static void __vma_set_inet_addr_prefix_len(unsigned char prefixlen)
{
	if (prefixlen > 32)
		prefixlen = 32;
	
	__vma_address_port_rule->prefixlen = prefixlen;
}

// SM: log part is  not used...
int __vma_min_level = 9;

void __vma_dump_address_port_rule_config_state(char *buf) {
	if (__vma_address_port_rule->match_by_addr) {
		char str_addr[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &(__vma_address_port_rule->ipv4), str_addr, sizeof(str_addr));
		if ( __vma_address_port_rule->prefixlen != 32 ) {
 			sprintf(buf+strlen(buf), " %s/%d", str_addr,
					__vma_address_port_rule->prefixlen);
		} else {
			sprintf(buf+strlen(buf), " %s", str_addr);
		}
	} else {
		sprintf(buf+strlen(buf), " *");
	}
	
	if (__vma_address_port_rule->match_by_port) {
		sprintf(buf+strlen(buf), ":%d",__vma_address_port_rule->sport);
		if (__vma_address_port_rule->eport > __vma_address_port_rule->sport) 
			sprintf(buf+strlen(buf), "-%d",__vma_address_port_rule->eport);
	}
	else
		sprintf(buf+strlen(buf), ":*");
}

/* dump the current state in readable format */
static void  __vma_dump_rule_config_state(void) {
	char buf[1024];
	sprintf(buf, "\tACCESS CONFIG: use %s %s %s ", 
			__vma_get_transport_str(__vma_rule.target_transport), 
			__vma_get_role_str(current_role),
			__vma_get_protocol_str(__vma_rule.protocol));
	__vma_address_port_rule = &(__vma_rule.first);
	__vma_dump_address_port_rule_config_state(buf);
	if (__vma_rule.use_second) {
		__vma_address_port_rule = &(__vma_rule.second);
		__vma_dump_address_port_rule_config_state(buf);
	}
	sprintf(buf+strlen(buf), "\n");
	__vma_log(1, "%s", buf);
}

/* dump configuration properites of new instance */
static void  __vma_dump_instance(void) {
	char buf[1024];
	
	if (curr_instance) {
		sprintf(buf, "CONFIGURATION OF INSTANCE ");
		if (curr_instance->id.prog_name_expr)
			sprintf(buf+strlen(buf), "%s ", curr_instance->id.prog_name_expr);
		if (curr_instance->id.user_defined_id)
			sprintf(buf+strlen(buf), "%s", curr_instance->id.user_defined_id);
		sprintf(buf+strlen(buf), ":\n");
		__vma_log(1, "%s", buf);
	}
}

static void __vma_add_dbl_lst_node_head(struct dbl_lst *lst, struct dbl_lst_node *node)
{
	if (node && lst) {
	
		node->prev = NULL;
		node->next = lst->head;
		
		if (!lst->head)
			lst->tail = node;
		else 
			lst->head->prev = node;	
					
		lst->head = node;
	}
}

static void __vma_add_dbl_lst_node(struct dbl_lst *lst, struct dbl_lst_node *node)
{
	if (node && lst) {
		node->prev = lst->tail;
	
		if (!lst->head) 
			lst->head = node;
		else 
			lst->tail->next = node;
		lst->tail = node;
	}
}

static struct dbl_lst_node* __vma_allocate_dbl_lst_node(void)
{
	struct dbl_lst_node *ret_val = NULL;
	
	ret_val = (struct dbl_lst_node*) malloc(sizeof(struct dbl_lst_node));
	if (!ret_val) {
		yyerror("fail to allocate new node");
		parse_err = 1;		
	}
	else
		memset((void*) ret_val, 0, sizeof(struct dbl_lst_node));	
	return ret_val;
}

/* use the above state for adding a new instance */
static void __vma_add_instance(char *prog_name_expr, char *user_defined_id) {
	struct dbl_lst_node *curr, *new_node;
	struct instance *new_instance;
  
	curr = __instance_list.head;
	while (curr) {
		struct instance *instance = (struct instance*)curr->data;
		if (!strcmp(prog_name_expr, instance->id.prog_name_expr) && !strcmp(user_defined_id, instance->id.user_defined_id)) {
			curr_instance = (struct instance*)curr->data;
			if (__vma_min_level <= 1) __vma_dump_instance();
			return;  		
		}
		curr = curr->next;
	}
  
	if (!(new_node = __vma_allocate_dbl_lst_node())) 
		return;
	
	new_instance = (struct instance*) malloc(sizeof(struct instance));
	if (!new_instance) {
		yyerror("fail to allocate new instance");
		parse_err = 1;
		free(new_node);
		return;
	}

	memset((void*) new_instance, 0, sizeof(struct instance));
	new_instance->id.prog_name_expr = strdup(prog_name_expr);
	new_instance->id.user_defined_id = strdup(user_defined_id);
  
	if (!new_instance->id.prog_name_expr || !new_instance->id.user_defined_id) {
		yyerror("failed to allocate memory");
		parse_err = 1;
		if (new_instance->id.prog_name_expr)
			free(new_instance->id.prog_name_expr);
		if (new_instance->id.user_defined_id)
			free(new_instance->id.user_defined_id);
		free(new_node);
		free(new_instance);
		return;
	}
	new_node->data = (void*)new_instance;
	__vma_add_dbl_lst_node(&__instance_list, new_node);
	curr_instance = new_instance;
	if (__vma_min_level <= 1) __vma_dump_instance();
}

static void __vma_add_inst_with_int_uid(char *prog_name_expr, int user_defined_id) {
	char str_id[50];
	sprintf(str_id, "%d", user_defined_id);
	__vma_add_instance(prog_name_expr, str_id);
}

/* use the above state for making a new rule */
static void __vma_add_rule(void) {
	struct dbl_lst *p_lst;
	struct use_family_rule *rule;
	struct dbl_lst_node *new_node;

	if (!curr_instance)
		__vma_add_instance((char *)"*", (char *)"*");
  	if (!curr_instance)
		return;
  
	if (__vma_min_level <= 1) __vma_dump_rule_config_state();
	switch (current_role) {
	case ROLE_TCP_SERVER:
		p_lst = &curr_instance->tcp_srv_rules_lst;
		break;
	case ROLE_TCP_CLIENT:
		p_lst = &curr_instance->tcp_clt_rules_lst;
		break;
	case ROLE_UDP_SENDER:
		p_lst = &curr_instance->udp_snd_rules_lst;
		break;
	case ROLE_UDP_RECEIVER:
		p_lst = &curr_instance->udp_rcv_rules_lst;
		break;
	case ROLE_UDP_CONNECT:
		p_lst = &curr_instance->udp_con_rules_lst;
		break;
	default:
		yyerror("ignoring unknown role");
		parse_err = 1;
		return;
		break;
	}

	if (!(new_node = __vma_allocate_dbl_lst_node())) 
		return;
	
	rule = (struct use_family_rule *)malloc(sizeof(*rule));
	if (!rule) {
		yyerror("fail to allocate new rule");
		parse_err = 1;
		free(new_node);
		return;
	}
	memset(rule, 0, sizeof(*rule));
	new_node->data = (void*)rule;
	*((struct use_family_rule *)new_node->data) = __vma_rule; 
	if (__vma_rule_push_head)
		__vma_add_dbl_lst_node_head(p_lst, new_node);
	else
		__vma_add_dbl_lst_node(p_lst, new_node);
}


/* Line 371 of yacc.c  */
/* Line 341 of config_parser.c  */

# ifndef YY_NULL
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULL nullptr
#  else
#   define YY_NULL 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_LIBVMA_YY_Y_TAB_H_INCLUDED
# define YY_LIBVMA_YY_Y_TAB_H_INCLUDED
/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int libvma_yydebug;
#endif

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     USE = 258,
     TCP_CLIENT = 259,
     TCP_SERVER = 260,
     UDP_SENDER = 261,
     UDP_RECEIVER = 262,
     UDP_CONNECT = 263,
     TCP = 264,
     UDP = 265,
     OS = 266,
     VMA = 267,
     SDP = 268,
     SA = 269,
     INT = 270,
     APP_ID = 271,
     PROGRAM = 272,
     USER_DEFINED_ID_STR = 273,
     LOG = 274,
     DEST = 275,
     STDERR = 276,
     SYSLOG = 277,
     FILENAME = 278,
     NAME = 279,
     LEVEL = 280,
     LINE = 281
   };
#endif
/* Tokens.  */
#define USE 258
#define TCP_CLIENT 259
#define TCP_SERVER 260
#define UDP_SENDER 261
#define UDP_RECEIVER 262
#define UDP_CONNECT 263
#define TCP 264
#define UDP 265
#define OS 266
#define VMA 267
#define SDP 268
#define SA 269
#define INT 270
#define APP_ID 271
#define PROGRAM 272
#define USER_DEFINED_ID_STR 273
#define LOG 274
#define DEST 275
#define STDERR 276
#define SYSLOG 277
#define FILENAME 278
#define NAME 279
#define LEVEL 280
#define LINE 281



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
/* Line 387 of yacc.c  */
/* Line 306 of config_parser.y */

  int        ival;
  char      *sval;


/* Line 387 of yacc.c  */
/* Line 442 of config_parser.c */
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE libvma_yylval;

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int libvma_yyparse (void *YYPARSE_PARAM);
#else
int libvma_yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int libvma_yyparse (void);
#else
int libvma_yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */

#endif /* !YY_LIBVMA_YY_Y_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */
/* Line 390 of yacc.c  */
/* Line 339 of config_parser.y */

  long __vma_config_line_num;

/* Line 390 of yacc.c  */
/* Line 474 of config_parser.c */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(N) (N)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (YYID (0))
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  7
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   48

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  32
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  26
/* YYNRULES -- Number of rules.  */
#define YYNRULES  50
/* YYNRULES -- Number of states.  */
#define YYNSTATES  74

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   281

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,    27,     2,     2,    31,    30,    29,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    28,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
       0,     0,     3,     5,     8,     9,    10,    12,    15,    16,
      19,    21,    23,    25,    29,    30,    33,    36,    39,    42,
      46,    49,    52,    56,    60,    66,    68,    70,    72,    74,
      76,    78,    80,    82,    84,    86,    88,    90,    92,    96,
     104,   105,   108,   109,   112,   114,   118,   120,   128,   130,
     134
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      35,     0,    -1,    26,    -1,    33,    26,    -1,    -1,    -1,
      33,    -1,    34,    36,    -1,    -1,    36,    37,    -1,    38,
      -1,    42,    -1,    44,    -1,    19,    39,    33,    -1,    -1,
      39,    40,    -1,    39,    41,    -1,    20,    21,    -1,    20,
      22,    -1,    20,    23,    24,    -1,    25,    15,    -1,    43,
      33,    -1,    16,    17,    18,    -1,    16,    17,    15,    -1,
      45,    46,    47,    48,    33,    -1,     3,    -1,    11,    -1,
      12,    -1,    13,    -1,    14,    -1,    27,    -1,     5,    -1,
       4,    -1,     7,    -1,     6,    -1,     8,    -1,    49,    -1,
      50,    -1,    51,    28,    57,    -1,    51,    28,    57,    28,
      53,    28,    57,    -1,    -1,    52,    55,    -1,    -1,    54,
      55,    -1,    56,    -1,    56,    29,    15,    -1,    27,    -1,
      15,    30,    15,    30,    15,    30,    15,    -1,    15,    -1,
      15,    31,    15,    -1,    27,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   345,   345,   346,   347,   349,   350,   353,   356,   357,
     361,   362,   363,   367,   370,   371,   372,   376,   377,   378,
     382,   386,   390,   391,   396,   400,   404,   405,   406,   407,
     408,   413,   414,   415,   416,   417,   421,   422,   426,   430,
     434,   434,   438,   438,   442,   443,   444,   448,   452,   453,
     454
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "\"use\"", "\"tcp client\"",
  "\"tcp server\"", "\"udp sender\"", "\"udp receiver\"",
  "\"udp connect\"", "\"tcp\"", "\"udp\"", "\"os\"", "\"vma\"", "\"sdp\"",
  "\"sa\"", "\"integer value\"", "\"application id\"", "\"program name\"",
  "\"userdefined id str\"", "\"log statement\"", "\"destination\"",
  "\"ystderr\"", "\"syslog\"", "\"yfile\"", "\"a name\"", "\"min-level\"",
  "\"new line\"", "'*'", "':'", "'/'", "'.'", "'-'", "$accept", "NL",
  "ONL", "config", "statements", "statement", "log_statement", "log_opts",
  "log_dest", "verbosity", "app_id_statement", "app_id",
  "socket_statement", "use", "transport", "role", "tuple", "three_tuple",
  "five_tuple", "address_first", "$@1", "address_second", "$@2", "address",
  "ipv4", "ports", YY_NULL
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,    42,    58,    47,
      46,    45
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    32,    33,    33,    33,    34,    34,    35,    36,    36,
      37,    37,    37,    38,    39,    39,    39,    40,    40,    40,
      41,    42,    43,    43,    44,    45,    46,    46,    46,    46,
      46,    47,    47,    47,    47,    47,    48,    48,    49,    50,
      52,    51,    54,    53,    55,    55,    55,    56,    57,    57,
      57
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     2,     0,     0,     1,     2,     0,     2,
       1,     1,     1,     3,     0,     2,     2,     2,     2,     3,
       2,     2,     3,     3,     5,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     7,
       0,     2,     0,     2,     1,     3,     1,     7,     1,     3,
       1
};

/* YYDEFACT[STATE-NAME] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       4,     2,     6,     8,     0,     3,     7,     1,    25,     0,
      14,     9,    10,    11,     4,    12,     0,     0,     4,    21,
      26,    27,    28,    29,    30,     0,    23,    22,     0,     0,
      13,    15,    16,    32,    31,    34,    33,    35,    40,    17,
      18,     0,    20,     4,    36,    37,     0,     0,    19,    24,
       0,     0,    46,    41,    44,    48,    50,    38,     0,     0,
       0,    42,     0,    45,    49,     0,     0,     0,     0,    43,
       0,    39,     0,    47
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     2,     3,     4,     6,    11,    12,    18,    31,    32,
      13,    14,    15,    16,    25,    38,    43,    44,    45,    46,
      47,    65,    66,    53,    54,    57
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -25
static const yytype_int8 yypact[] =
{
     -24,   -25,   -17,   -25,    12,   -25,    -2,   -25,   -25,    -1,
     -25,   -25,   -25,   -25,   -24,   -25,    -6,    13,    -7,   -17,
     -25,   -25,   -25,   -25,   -25,    19,   -25,   -25,    11,    -4,
     -17,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,
     -25,     6,   -25,   -24,   -25,   -25,    -8,   -12,   -25,   -17,
      -5,     5,   -25,   -25,     7,     8,   -25,     9,    23,    25,
      26,   -25,    14,   -25,   -25,    15,   -12,    27,    -5,   -25,
      16,   -25,    30,   -25
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -25,   -14,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,
     -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,
     -25,   -25,   -25,   -19,   -25,   -20
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      19,     8,     1,    51,    30,    20,    21,    22,    23,     5,
      55,    42,     7,    28,     9,    52,    17,    10,    29,     1,
      50,    24,    56,    33,    34,    35,    36,    37,    26,    49,
      48,    27,    39,    40,    41,    58,    59,    61,    62,    60,
      63,    64,    70,    68,    67,    73,    72,    69,    71
};

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-25)))

#define yytable_value_is_error(Yytable_value) \
  YYID (0)

static const yytype_uint8 yycheck[] =
{
      14,     3,    26,    15,    18,    11,    12,    13,    14,    26,
      15,    15,     0,    20,    16,    27,    17,    19,    25,    26,
      28,    27,    27,     4,     5,     6,     7,     8,    15,    43,
      24,    18,    21,    22,    23,    30,    29,    28,    15,    31,
      15,    15,    15,    28,    30,    15,    30,    66,    68
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    26,    33,    34,    35,    26,    36,     0,     3,    16,
      19,    37,    38,    42,    43,    44,    45,    17,    39,    33,
      11,    12,    13,    14,    27,    46,    15,    18,    20,    25,
      33,    40,    41,     4,     5,     6,     7,     8,    47,    21,
      22,    23,    15,    48,    49,    50,    51,    52,    24,    33,
      28,    15,    27,    55,    56,    15,    27,    57,    30,    29,
      31,    28,    15,    15,    15,    53,    54,    30,    28,    55,
      15,    57,    30,    15
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))

/* Error token number */
#define YYTERROR	1
#define YYERRCODE	256


/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */
#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
        break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  /* coverity[unterminated_case] */
	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = 0;
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULL;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  if (yytoken < 0) return 1;
  yysize0 = yytnamerr (YY_NULL, yytname[yytoken]);
  yysize = yysize0;

  /* There are many possibilities here to consider:
     - Assume YYFAIL is not used.  It's too flawed to consider.  See
       <http://lists.gnu.org/archive/html/bison-patches/2009-12/msg00024.html>
       for details.  YYERROR is fine as it does not invoke this
       function.
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULL, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + (yyformat ? yystrlen (yyformat) : 0);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    /* coverity[var_deref_op] */
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  (void)yymsg;
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
        break;
    }
}




/* The lookahead symbol.  */
int yychar;


#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval YY_INITIAL_VALUE(yyval_default);

/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	/* coverity[leaked_storage] */
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
	/* coverity[leaked_storage] */
      }
# endif
#endif /* no yyoverflow */

      /* coverity[ptr_arith] */
      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 17:
/* Line 1792 of yacc.c  */
/* Line 376 of config_parser.y */
    { __vma_log_set_log_stderr(); }
    break;

  case 18:
/* Line 1792 of yacc.c  */
/* Line 377 of config_parser.y */
    { __vma_log_set_log_syslog(); }
    break;

  case 19:
/* Line 1792 of yacc.c  */
/* Line 378 of config_parser.y */
    { __vma_log_set_log_file((yyvsp[(3) - (3)].sval)); }
    break;

  case 20:
/* Line 1792 of yacc.c  */
/* Line 382 of config_parser.y */
    { __vma_log_set_min_level((yyvsp[(2) - (2)].ival)); }
    break;

  case 22:
/* Line 1792 of yacc.c  */
/* Line 390 of config_parser.y */
    {__vma_add_instance((yyvsp[(2) - (3)].sval), (yyvsp[(3) - (3)].sval));	if ((yyvsp[(2) - (3)].sval)) free((yyvsp[(2) - (3)].sval)); if ((yyvsp[(3) - (3)].sval)) free((yyvsp[(3) - (3)].sval));	}
    break;

  case 23:
/* Line 1792 of yacc.c  */
/* Line 391 of config_parser.y */
    {__vma_add_inst_with_int_uid((yyvsp[(2) - (3)].sval), (yyvsp[(3) - (3)].ival));	if ((yyvsp[(2) - (3)].sval)) free((yyvsp[(2) - (3)].sval));		}
    break;

  case 24:
/* Line 1792 of yacc.c  */
/* Line 396 of config_parser.y */
    { __vma_add_rule(); }
    break;

  case 25:
/* Line 1792 of yacc.c  */
/* Line 400 of config_parser.y */
    { current_conf_type = CONF_RULE; }
    break;

  case 26:
/* Line 1792 of yacc.c  */
/* Line 404 of config_parser.y */
    { __vma_rule.target_transport = TRANS_OS;	}
    break;

  case 27:
/* Line 1792 of yacc.c  */
/* Line 405 of config_parser.y */
    { __vma_rule.target_transport = TRANS_VMA;	}
    break;

  case 28:
/* Line 1792 of yacc.c  */
/* Line 406 of config_parser.y */
    { __vma_rule.target_transport = TRANS_SDP;	}
    break;

  case 29:
/* Line 1792 of yacc.c  */
/* Line 407 of config_parser.y */
    { __vma_rule.target_transport = TRANS_SA;	}
    break;

  case 30:
/* Line 1792 of yacc.c  */
/* Line 408 of config_parser.y */
    { __vma_rule.target_transport = TRANS_ULP;	}
    break;

  case 31:
/* Line 1792 of yacc.c  */
/* Line 413 of config_parser.y */
    { current_role = ROLE_TCP_SERVER; 	__vma_rule.protocol = PROTO_TCP; }
    break;

  case 32:
/* Line 1792 of yacc.c  */
/* Line 414 of config_parser.y */
    { current_role = ROLE_TCP_CLIENT; 	__vma_rule.protocol = PROTO_TCP; }
    break;

  case 33:
/* Line 1792 of yacc.c  */
/* Line 415 of config_parser.y */
    { current_role = ROLE_UDP_RECEIVER; __vma_rule.protocol = PROTO_UDP; }
    break;

  case 34:
/* Line 1792 of yacc.c  */
/* Line 416 of config_parser.y */
    { current_role = ROLE_UDP_SENDER;	__vma_rule.protocol = PROTO_UDP; }
    break;

  case 35:
/* Line 1792 of yacc.c  */
/* Line 417 of config_parser.y */
    { current_role = ROLE_UDP_CONNECT;	__vma_rule.protocol = PROTO_UDP; }
    break;

  case 40:
/* Line 1792 of yacc.c  */
/* Line 434 of config_parser.y */
    { __vma_address_port_rule = &(__vma_rule.first); __vma_rule.use_second = 0; }
    break;

  case 42:
/* Line 1792 of yacc.c  */
/* Line 438 of config_parser.y */
    { __vma_address_port_rule = &(__vma_rule.second); __vma_rule.use_second = 1; }
    break;

  case 44:
/* Line 1792 of yacc.c  */
/* Line 442 of config_parser.y */
    { if (current_conf_type == CONF_RULE) __vma_address_port_rule->match_by_addr = 1; __vma_set_inet_addr_prefix_len(32); }
    break;

  case 45:
/* Line 1792 of yacc.c  */
/* Line 443 of config_parser.y */
    { if (current_conf_type == CONF_RULE) __vma_address_port_rule->match_by_addr = 1; __vma_set_inet_addr_prefix_len((yyvsp[(3) - (3)].ival)); }
    break;

  case 46:
/* Line 1792 of yacc.c  */
/* Line 444 of config_parser.y */
    { if (current_conf_type == CONF_RULE) __vma_address_port_rule->match_by_addr = 0; __vma_set_inet_addr_prefix_len(32); }
    break;

  case 47:
/* Line 1792 of yacc.c  */
/* Line 448 of config_parser.y */
    { __vma_set_ipv4_addr((yyvsp[(1) - (7)].ival),(yyvsp[(3) - (7)].ival),(yyvsp[(5) - (7)].ival),(yyvsp[(7) - (7)].ival)); }
    break;

  case 48:
/* Line 1792 of yacc.c  */
/* Line 452 of config_parser.y */
    { __vma_address_port_rule->match_by_port = 1; __vma_address_port_rule->sport= (yyvsp[(1) - (1)].ival); __vma_address_port_rule->eport= (yyvsp[(1) - (1)].ival); }
    break;

  case 49:
/* Line 1792 of yacc.c  */
/* Line 453 of config_parser.y */
    { __vma_address_port_rule->match_by_port = 1; __vma_address_port_rule->sport= (yyvsp[(1) - (3)].ival); __vma_address_port_rule->eport= (yyvsp[(3) - (3)].ival); }
    break;

  case 50:
/* Line 1792 of yacc.c  */
/* Line 454 of config_parser.y */
    { __vma_address_port_rule->match_by_port = 0; __vma_address_port_rule->sport= 0;  __vma_address_port_rule->eport= 0;  }
    break;


/* Line 1792 of yacc.c  */
/* Line 1893 of config_parser.c */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


/* Line 2055 of yacc.c  */
/* Line 457 of config_parser.y */


int yyerror(const char *msg)
{
	/* replace the $undefined and $end if exists */
	char *orig_msg = (char*)malloc(strlen(msg)+25);
	char *final_msg = (char*)malloc(strlen(msg)+25);

	strcpy(orig_msg, msg);
	
	char *word = strtok(orig_msg, " ");
	final_msg[0] = '\0';
	while (word != NULL) {
		if (!strncmp(word, "$undefined", 10)) {
			strcat(final_msg, "unrecognized-token ");
		} else if (!strncmp(word, "$end",4)) {
			strcat(final_msg, "end-of-file ");
		} else {
			strcat(final_msg, word);
			strcat(final_msg, " ");
		}
		word = strtok(NULL, " ");
	}
	
	__vma_log(9, "Error (line:%ld) : %s\n", __vma_config_line_num, final_msg);
	parse_err = 1;
	
	free(orig_msg);
	free(final_msg);
	return 1;
}

#include <unistd.h>
#include <errno.h>

/* parse apollo route dump file */
int __vma_parse_config_file (const char *fileName) {
	extern FILE * libvma_yyin;
   
	/* open the file */
	if (access(fileName, R_OK)) {
		/*
		 * Let upper layer inform about no access to open file - based on log level
		*/
		return(1);
	}

	/* coverity[toctou] */
	libvma_yyin = fopen(fileName,"r");
	if (!libvma_yyin) {
		printf("libvma Error: Fail to open File:%s\n", fileName);
		return(1);
	}
	__instance_list.head = NULL;
	__instance_list.tail = NULL;
	parse_err = 0;
	__vma_config_line_num = 1;

	/* parse it */
	yyparse();

	fclose(libvma_yyin);
	return(parse_err);
}

int __vma_parse_config_line (const char *line) {
	extern FILE * libvma_yyin;
	
	__vma_rule_push_head = 1;
	
	/* The below casting is valid because we open the stream as read-only. */
	libvma_yyin = fmemopen((void*)line, strlen(line), "r");
	
	if (!libvma_yyin) {
		printf("libvma Error: Fail to parse line:%s\n", line);
		return(1);
	}
	
	parse_err = 0;
	yyparse();
	
	fclose(libvma_yyin);
	
	return(parse_err);
}
