/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison interface for Yacc-like parsers in C
   
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

#ifndef YY_LIBVMA_YY_CONFIG_PARSER_H_INCLUDED
# define YY_LIBVMA_YY_CONFIG_PARSER_H_INCLUDED
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
/* Line 2058 of yacc.c  */
/* Line 306 of config_parser.y */

  int        ival;
  char      *sval;


/* Line 2058 of yacc.c  */
/* Line 115 of config_parser.h */
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

#endif /* !YY_LIBVMA_YY_CONFIG_PARSER_H_INCLUDED  */
