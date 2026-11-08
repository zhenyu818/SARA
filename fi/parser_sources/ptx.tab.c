/* A Bison parser, made by GNU Bison 3.5.1.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

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

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.5.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 2

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         ptx_parse
#define yylex           ptx_lex
#define yyerror         ptx_error
#define yydebug         ptx_debug
#define yynerrs         ptx_nerrs

/* First part of user prologue.  */
#line 30 "ptx.y"

typedef void * yyscan_t;
class ptx_recognizer;
#include "../../libcuda/gpgpu_context.h"

#line 81 "ptx.tab.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_PTX_GENERATED_PTX_TAB_H_INCLUDED
# define YY_PTX_GENERATED_PTX_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int ptx_debug;
#endif
/* "%code requires" blocks.  */
#line 36 "ptx.y"

#include "ptx_integer_literal.h"

#line 128 "ptx.tab.c"

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    STRING = 258,
    OPCODE = 259,
    WMMA_DIRECTIVE = 260,
    LAYOUT = 261,
    CONFIGURATION = 262,
    ALIGN_DIRECTIVE = 263,
    BRANCHTARGETS_DIRECTIVE = 264,
    BYTE_DIRECTIVE = 265,
    CALLPROTOTYPE_DIRECTIVE = 266,
    CALLTARGETS_DIRECTIVE = 267,
    CONST_DIRECTIVE = 268,
    CONSTPTR_DIRECTIVE = 269,
    PTR_DIRECTIVE = 270,
    ENTRY_DIRECTIVE = 271,
    EXTERN_DIRECTIVE = 272,
    FILE_DIRECTIVE = 273,
    FUNC_DIRECTIVE = 274,
    GLOBAL_DIRECTIVE = 275,
    LOCAL_DIRECTIVE = 276,
    LOC_DIRECTIVE = 277,
    MAXNCTAPERSM_DIRECTIVE = 278,
    MAXNNREG_DIRECTIVE = 279,
    MAXNTID_DIRECTIVE = 280,
    MINNCTAPERSM_DIRECTIVE = 281,
    PARAM_DIRECTIVE = 282,
    PRAGMA_DIRECTIVE = 283,
    REG_DIRECTIVE = 284,
    REQNTID_DIRECTIVE = 285,
    SECTION_DIRECTIVE = 286,
    SHARED_DIRECTIVE = 287,
    SREG_DIRECTIVE = 288,
    SSTARR_DIRECTIVE = 289,
    STRUCT_DIRECTIVE = 290,
    SURF_DIRECTIVE = 291,
    TARGET_DIRECTIVE = 292,
    TEX_DIRECTIVE = 293,
    UNION_DIRECTIVE = 294,
    VERSION_DIRECTIVE = 295,
    ADDRESS_SIZE_DIRECTIVE = 296,
    VISIBLE_DIRECTIVE = 297,
    WEAK_DIRECTIVE = 298,
    IDENTIFIER = 299,
    INT_OPERAND = 300,
    FLOAT_OPERAND = 301,
    DOUBLE_OPERAND = 302,
    S8_TYPE = 303,
    S16_TYPE = 304,
    S32_TYPE = 305,
    S64_TYPE = 306,
    U8_TYPE = 307,
    U16_TYPE = 308,
    U32_TYPE = 309,
    U64_TYPE = 310,
    F16_TYPE = 311,
    F32_TYPE = 312,
    F64_TYPE = 313,
    FF64_TYPE = 314,
    B8_TYPE = 315,
    B16_TYPE = 316,
    B32_TYPE = 317,
    B64_TYPE = 318,
    BB64_TYPE = 319,
    BB128_TYPE = 320,
    PRED_TYPE = 321,
    TEXREF_TYPE = 322,
    SAMPLERREF_TYPE = 323,
    SURFREF_TYPE = 324,
    V2_TYPE = 325,
    V3_TYPE = 326,
    V4_TYPE = 327,
    COMMA = 328,
    PRED = 329,
    HALF_OPTION = 330,
    EXTP_OPTION = 331,
    EQ_OPTION = 332,
    NE_OPTION = 333,
    LT_OPTION = 334,
    LE_OPTION = 335,
    GT_OPTION = 336,
    GE_OPTION = 337,
    LO_OPTION = 338,
    LS_OPTION = 339,
    HI_OPTION = 340,
    HS_OPTION = 341,
    EQU_OPTION = 342,
    NEU_OPTION = 343,
    LTU_OPTION = 344,
    LEU_OPTION = 345,
    GTU_OPTION = 346,
    GEU_OPTION = 347,
    NUM_OPTION = 348,
    NAN_OPTION = 349,
    CF_OPTION = 350,
    SF_OPTION = 351,
    NSF_OPTION = 352,
    LEFT_SQUARE_BRACKET = 353,
    RIGHT_SQUARE_BRACKET = 354,
    WIDE_OPTION = 355,
    SPECIAL_REGISTER = 356,
    MINUS = 357,
    PLUS = 358,
    COLON = 359,
    SEMI_COLON = 360,
    EXCLAMATION = 361,
    PIPE = 362,
    RIGHT_BRACE = 363,
    LEFT_BRACE = 364,
    EQUALS = 365,
    PERIOD = 366,
    BACKSLASH = 367,
    DIMENSION_MODIFIER = 368,
    RN_OPTION = 369,
    RZ_OPTION = 370,
    RM_OPTION = 371,
    RP_OPTION = 372,
    RNI_OPTION = 373,
    RZI_OPTION = 374,
    RMI_OPTION = 375,
    RPI_OPTION = 376,
    UNI_OPTION = 377,
    GEOM_MODIFIER_1D = 378,
    GEOM_MODIFIER_2D = 379,
    GEOM_MODIFIER_3D = 380,
    SAT_OPTION = 381,
    FTZ_OPTION = 382,
    NEG_OPTION = 383,
    SYNC_OPTION = 384,
    RED_OPTION = 385,
    ARRIVE_OPTION = 386,
    ATOMIC_POPC = 387,
    ATOMIC_AND = 388,
    ATOMIC_OR = 389,
    ATOMIC_XOR = 390,
    ATOMIC_CAS = 391,
    ATOMIC_EXCH = 392,
    ATOMIC_ADD = 393,
    ATOMIC_INC = 394,
    ATOMIC_DEC = 395,
    ATOMIC_MIN = 396,
    ATOMIC_MAX = 397,
    LEFT_ANGLE_BRACKET = 398,
    RIGHT_ANGLE_BRACKET = 399,
    LEFT_PAREN = 400,
    RIGHT_PAREN = 401,
    APPROX_OPTION = 402,
    FULL_OPTION = 403,
    ANY_OPTION = 404,
    ALL_OPTION = 405,
    BALLOT_OPTION = 406,
    GLOBAL_OPTION = 407,
    CTA_OPTION = 408,
    SYS_OPTION = 409,
    EXIT_OPTION = 410,
    ABS_OPTION = 411,
    TO_OPTION = 412,
    CA_OPTION = 413,
    CG_OPTION = 414,
    CS_OPTION = 415,
    LU_OPTION = 416,
    CV_OPTION = 417,
    WB_OPTION = 418,
    WT_OPTION = 419,
    NC_OPTION = 420,
    UP_OPTION = 421,
    DOWN_OPTION = 422,
    BFLY_OPTION = 423,
    IDX_OPTION = 424,
    PRMT_F4E_MODE = 425,
    PRMT_B4E_MODE = 426,
    PRMT_RC8_MODE = 427,
    PRMT_RC16_MODE = 428,
    PRMT_ECL_MODE = 429,
    PRMT_ECR_MODE = 430
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 46 "ptx.y"

  double double_value;
  float  float_value;
  int    int_value;
  sara_ptx::integer_literal integer_value;
  char * string_value;
  void * ptr_value;

#line 324 "ptx.tab.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int ptx_parse (yyscan_t scanner, ptx_recognizer* recognizer);

#endif /* !YY_PTX_GENERATED_PTX_TAB_H_INCLUDED  */

/* Second part of user prologue.  */
#line 233 "ptx.y"

  	#include "ptx_parser.h"
	#include <stdlib.h>
	#include <string.h>
	#include <math.h>
	void syntax_not_implemented(yyscan_t yyscanner, ptx_recognizer* recognizer);
	int ptx_lex(YYSTYPE * yylval_param, yyscan_t yyscanner, ptx_recognizer* recognizer);
	int ptx_error( yyscan_t yyscanner, ptx_recognizer* recognizer, const char *s );

#line 349 "ptx.tab.c"


#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))

/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

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

#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

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
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
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
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
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
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
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
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   729

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  176
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  73
/* YYNRULES -- Number of rules.  */
#define YYNRULES  309
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  461

#define YYUNDEFTOK  2
#define YYMAXUTOK   430


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
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
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   245,   245,   246,   247,   248,   251,   251,   252,   252,
     252,   255,   259,   260,   263,   264,   267,   267,   267,   268,
     268,   269,   272,   272,   272,   273,   276,   277,   278,   279,
     280,   281,   282,   283,   286,   287,   288,   288,   290,   290,
     291,   291,   293,   294,   295,   297,   298,   299,   300,   302,
     304,   306,   307,   308,   309,   310,   311,   311,   312,   312,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   329,   330,   331,   332,   335,   337,   338,   340,
     341,   353,   354,   357,   358,   360,   361,   362,   363,   364,
     365,   368,   370,   371,   372,   375,   376,   377,   378,   379,
     380,   381,   382,   385,   386,   389,   390,   391,   394,   395,
     396,   397,   398,   399,   400,   401,   402,   403,   404,   405,
     406,   407,   408,   409,   410,   411,   412,   413,   414,   415,
     418,   419,   421,   422,   430,   432,   434,   435,   437,   438,
     439,   441,   442,   443,   445,   445,   446,   447,   448,   449,
     452,   452,   453,   455,   456,   457,   458,   459,   460,   461,
     462,   463,   464,   465,   466,   467,   470,   471,   473,   474,
     475,   476,   477,   478,   479,   480,   481,   482,   483,   484,
     485,   486,   487,   488,   489,   490,   491,   492,   493,   494,
     495,   496,   497,   498,   499,   500,   501,   502,   503,   504,
     505,   506,   507,   508,   509,   510,   511,   512,   513,   514,
     515,   518,   519,   520,   521,   522,   523,   524,   525,   526,
     527,   528,   531,   532,   535,   536,   537,   538,   541,   542,
     543,   544,   547,   548,   549,   550,   551,   552,   553,   554,
     555,   556,   557,   558,   559,   560,   561,   562,   563,   564,
     567,   568,   569,   570,   571,   572,   575,   576,   585,   586,
     588,   589,   590,   591,   592,   593,   594,   595,   596,   597,
     598,   599,   600,   601,   602,   603,   604,   605,   606,   607,
     610,   611,   612,   613,   614,   617,   617,   622,   623,   626,
     627,   628,   629,   630,   633,   634,   635,   636,   637,   638,
     639,   642,   643,   644,   647,   648,   649,   650,   651,   654
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "STRING", "OPCODE", "WMMA_DIRECTIVE",
  "LAYOUT", "CONFIGURATION", "ALIGN_DIRECTIVE", "BRANCHTARGETS_DIRECTIVE",
  "BYTE_DIRECTIVE", "CALLPROTOTYPE_DIRECTIVE", "CALLTARGETS_DIRECTIVE",
  "CONST_DIRECTIVE", "CONSTPTR_DIRECTIVE", "PTR_DIRECTIVE",
  "ENTRY_DIRECTIVE", "EXTERN_DIRECTIVE", "FILE_DIRECTIVE",
  "FUNC_DIRECTIVE", "GLOBAL_DIRECTIVE", "LOCAL_DIRECTIVE", "LOC_DIRECTIVE",
  "MAXNCTAPERSM_DIRECTIVE", "MAXNNREG_DIRECTIVE", "MAXNTID_DIRECTIVE",
  "MINNCTAPERSM_DIRECTIVE", "PARAM_DIRECTIVE", "PRAGMA_DIRECTIVE",
  "REG_DIRECTIVE", "REQNTID_DIRECTIVE", "SECTION_DIRECTIVE",
  "SHARED_DIRECTIVE", "SREG_DIRECTIVE", "SSTARR_DIRECTIVE",
  "STRUCT_DIRECTIVE", "SURF_DIRECTIVE", "TARGET_DIRECTIVE",
  "TEX_DIRECTIVE", "UNION_DIRECTIVE", "VERSION_DIRECTIVE",
  "ADDRESS_SIZE_DIRECTIVE", "VISIBLE_DIRECTIVE", "WEAK_DIRECTIVE",
  "IDENTIFIER", "INT_OPERAND", "FLOAT_OPERAND", "DOUBLE_OPERAND",
  "S8_TYPE", "S16_TYPE", "S32_TYPE", "S64_TYPE", "U8_TYPE", "U16_TYPE",
  "U32_TYPE", "U64_TYPE", "F16_TYPE", "F32_TYPE", "F64_TYPE", "FF64_TYPE",
  "B8_TYPE", "B16_TYPE", "B32_TYPE", "B64_TYPE", "BB64_TYPE", "BB128_TYPE",
  "PRED_TYPE", "TEXREF_TYPE", "SAMPLERREF_TYPE", "SURFREF_TYPE", "V2_TYPE",
  "V3_TYPE", "V4_TYPE", "COMMA", "PRED", "HALF_OPTION", "EXTP_OPTION",
  "EQ_OPTION", "NE_OPTION", "LT_OPTION", "LE_OPTION", "GT_OPTION",
  "GE_OPTION", "LO_OPTION", "LS_OPTION", "HI_OPTION", "HS_OPTION",
  "EQU_OPTION", "NEU_OPTION", "LTU_OPTION", "LEU_OPTION", "GTU_OPTION",
  "GEU_OPTION", "NUM_OPTION", "NAN_OPTION", "CF_OPTION", "SF_OPTION",
  "NSF_OPTION", "LEFT_SQUARE_BRACKET", "RIGHT_SQUARE_BRACKET",
  "WIDE_OPTION", "SPECIAL_REGISTER", "MINUS", "PLUS", "COLON",
  "SEMI_COLON", "EXCLAMATION", "PIPE", "RIGHT_BRACE", "LEFT_BRACE",
  "EQUALS", "PERIOD", "BACKSLASH", "DIMENSION_MODIFIER", "RN_OPTION",
  "RZ_OPTION", "RM_OPTION", "RP_OPTION", "RNI_OPTION", "RZI_OPTION",
  "RMI_OPTION", "RPI_OPTION", "UNI_OPTION", "GEOM_MODIFIER_1D",
  "GEOM_MODIFIER_2D", "GEOM_MODIFIER_3D", "SAT_OPTION", "FTZ_OPTION",
  "NEG_OPTION", "SYNC_OPTION", "RED_OPTION", "ARRIVE_OPTION",
  "ATOMIC_POPC", "ATOMIC_AND", "ATOMIC_OR", "ATOMIC_XOR", "ATOMIC_CAS",
  "ATOMIC_EXCH", "ATOMIC_ADD", "ATOMIC_INC", "ATOMIC_DEC", "ATOMIC_MIN",
  "ATOMIC_MAX", "LEFT_ANGLE_BRACKET", "RIGHT_ANGLE_BRACKET", "LEFT_PAREN",
  "RIGHT_PAREN", "APPROX_OPTION", "FULL_OPTION", "ANY_OPTION",
  "ALL_OPTION", "BALLOT_OPTION", "GLOBAL_OPTION", "CTA_OPTION",
  "SYS_OPTION", "EXIT_OPTION", "ABS_OPTION", "TO_OPTION", "CA_OPTION",
  "CG_OPTION", "CS_OPTION", "LU_OPTION", "CV_OPTION", "WB_OPTION",
  "WT_OPTION", "NC_OPTION", "UP_OPTION", "DOWN_OPTION", "BFLY_OPTION",
  "IDX_OPTION", "PRMT_F4E_MODE", "PRMT_B4E_MODE", "PRMT_RC8_MODE",
  "PRMT_RC16_MODE", "PRMT_ECL_MODE", "PRMT_ECR_MODE", "$accept", "input",
  "function_defn", "$@1", "$@2", "$@3", "block_spec", "block_spec_list",
  "function_decl", "$@4", "$@5", "$@6", "function_ident_param", "$@7",
  "$@8", "function_decl_header", "param_list", "$@9", "param_entry",
  "$@10", "$@11", "ptr_spec", "ptr_space_spec", "ptr_align_spec",
  "statement_block", "statement_list", "$@12", "$@13",
  "directive_statement", "variable_declaration", "variable_spec",
  "identifier_list", "identifier_spec", "var_spec_list", "var_spec",
  "align_spec", "space_spec", "addressable_spec", "type_spec",
  "vector_spec", "scalar_type", "initializer_list", "literal_list",
  "prototype_block", "prototype_decl", "prototype_call", "prototype_param",
  "instruction_statement", "instruction", "$@14", "opcode_spec", "$@15",
  "pred_spec", "option_list", "option", "atomic_operation_spec",
  "rounding_mode", "floating_point_rounding_mode", "integer_rounding_mode",
  "compare_spec", "prmt_spec", "wmma_spec", "operand_list", "operand",
  "vector_operand", "tex_operand", "$@16", "builtin_operand",
  "memory_operand", "twin_operand", "literal_operand",
  "address_expression", "int_operand32", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428,   429,   430
};
# endif

#define YYPACT_NINF (-307)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-153)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -307,   204,  -307,   -15,  -307,    10,  -307,    47,   -15,  -307,
    -307,  -307,   -15,  -307,    68,  -307,  -307,  -307,  -307,  -307,
      30,  -307,    40,   -15,    39,   126,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,    14,   -29,  -307,    52,   117,   657,  -307,  -307,
    -307,  -307,  -307,   265,  -307,  -307,  -307,   101,  -307,   173,
     -15,    75,   115,    87,  -307,  -307,  -307,  -307,  -307,  -307,
      99,   130,  -307,   159,  -307,   -73,   141,   106,  -307,  -307,
    -307,  -307,  -307,   183,   161,   -15,  -307,   191,  -307,   592,
    -307,   -15,   -15,   -15,  -307,   130,    91,    98,  -307,    -9,
     -15,   117,     6,   166,   -15,  -307,   175,   -23,   145,   -25,
     146,   523,    99,  -307,  -307,   172,   -13,   274,  -307,   206,
    -307,    99,  -307,  -307,  -307,   134,   137,  -307,   184,   140,
    -307,  -307,  -307,  -307,     6,  -307,  -307,   -15,   212,   242,
     351,  -307,   114,   243,   185,  -307,    99,  -307,  -307,   284,
    -307,  -307,  -307,    56,    15,   178,    12,   248,   249,    80,
    -307,   221,  -307,  -307,  -307,  -307,  -307,   190,   -15,  -307,
     657,   657,  -307,  -307,  -307,  -307,   188,   -46,  -307,  -307,
     -15,  -307,   291,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,   351,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -307,  -307,  -307,   287,  -307,   -28,  -307,  -307,
    -307,   153,   -15,   256,   257,    55,   203,  -307,  -307,    51,
     102,   -18,  -307,  -307,  -307,   -31,   157,     3,  -307,   231,
     290,   117,   159,    91,  -307,   124,  -307,  -307,   144,  -307,
     163,   233,   263,   -42,  -307,   210,   211,   236,  -307,    46,
      79,  -307,  -307,  -307,   -15,  -307,  -307,  -307,   -39,   213,
     292,  -307,  -307,   -33,  -307,   264,   -15,   152,   117,  -307,
    -307,   -55,  -307,  -307,   331,  -307,   312,   195,   196,   -16,
    -307,  -307,  -307,  -307,  -307,  -307,  -307,   234,  -307,    22,
     271,  -307,   199,    80,  -307,   -15,  -307,  -307,  -307,  -307,
     338,  -307,  -307,  -307,  -307,  -307,   104,   201,   304,   276,
      94,   162,   251,   307,  -307,    80,  -307,  -307,  -307,    91,
     308,   310,   311,   214,    80,  -307,  -307,   100,  -307,  -307,
      29,   285,  -307,  -307,  -307,   216,   286,   289,  -307,  -307,
     313,  -307,   218,   312,   321,   222,    35,    80,   223,   268,
     324,   326,  -307,   228,   270,  -307,   230,   306,  -307,  -307,
     315,   333,   336,   317,   279,   337,  -307,   318,   342,   288,
    -307
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int16 yydefact[] =
{
       2,     0,     1,     0,    95,     0,    26,    89,     0,    29,
      96,    97,     0,    98,     0,    92,    99,    93,   100,   101,
       0,   102,     0,     0,    88,    90,   108,   109,   110,   111,
     112,   113,   114,   115,   116,   117,   118,   119,   120,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   105,   106,
     107,     4,     5,    21,     3,     0,     0,    76,    83,    87,
      85,    94,    86,     0,   103,   309,    91,     0,    32,     0,
       0,     0,    66,    61,    63,    27,    30,    28,    31,    71,
       0,     0,    16,     0,    60,    79,    72,    77,    89,    88,
      90,    84,   104,     0,    67,     0,    70,     0,    62,    58,
       7,     0,     0,     0,    14,     9,     0,    25,    20,     0,
       0,     0,     0,     0,     0,    69,    64,   150,     0,     0,
       0,    56,     0,    51,    53,     0,   149,     0,    13,     0,
      12,     0,    15,    38,    40,     0,     0,    81,     0,     0,
      78,   301,   302,   303,     0,    73,    74,     0,     0,     0,
       0,   142,   153,     0,     0,    50,     0,    54,    52,     0,
      55,    59,   141,   260,     0,   288,     0,     0,     0,     0,
     148,   258,   266,   268,   265,   263,   264,     0,     0,    10,
       0,     0,    17,    23,    82,    80,     0,     0,   132,    75,
       0,    65,     0,   197,   198,   232,   233,   234,   235,   236,
     237,   238,   239,   240,   241,   242,   243,   244,   245,   246,
     247,   248,   249,   178,   224,   225,   226,   227,   228,   229,
     230,   231,   177,   185,   186,   187,   188,   189,   190,   174,
     176,   175,   212,   211,   213,   214,   215,   216,   217,   218,
     219,   220,   221,   191,   192,   179,   180,   181,   182,   183,
     184,   193,   194,   196,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   250,   251,   252,   253,
     254,   255,   170,   168,   151,   166,   195,   171,   222,   223,
     169,   173,   172,   156,   158,   155,   157,   159,   160,   162,
     161,   163,   164,   165,   154,   142,    57,     0,   134,   270,
     272,     0,     0,     0,     0,   304,     0,   308,   287,   262,
       0,     0,   267,   293,   261,     0,     0,     0,   143,     0,
      42,     0,     0,    34,   131,     0,   130,    68,     0,   167,
       0,     0,     0,   304,   301,     0,     0,     0,   269,   274,
     277,   285,   305,   306,     0,   289,   271,   273,   304,     0,
       0,   284,   144,     0,   259,   258,     0,     0,     0,    41,
      18,     0,    35,   133,     0,   256,   138,     0,     0,     0,
     292,   291,   290,   275,   276,   278,   279,     0,   307,     0,
       0,   147,     0,     0,    11,     0,    48,    45,    46,    47,
       0,    44,    39,    36,    24,   257,     0,     0,     0,     0,
     294,     0,     0,     0,   280,     0,   146,    49,    43,     0,
       0,     0,     0,     0,     0,   295,   296,   297,   300,   286,
       0,     0,    37,   140,   139,     0,     0,     0,   298,   299,
       0,   281,     0,   138,     0,     0,     0,     0,     0,     0,
       0,     0,   282,     0,     0,   137,     0,     0,   145,   135,
       0,     0,     0,     0,     0,     0,   136,     0,     0,     0,
     283
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -307,  -307,  -307,  -307,  -307,  -307,   319,  -307,   391,  -307,
    -307,  -307,    71,  -307,  -307,  -307,  -307,  -307,  -306,  -307,
    -307,  -307,  -307,     4,   -59,  -307,  -307,  -307,   -64,  -307,
      49,  -307,  -108,  -307,   340,  -307,  -307,  -142,  -140,  -307,
     332,   281,  -307,  -307,  -307,  -307,    13,   327,   320,  -307,
    -307,  -307,  -307,   174,  -307,  -307,  -307,  -307,  -307,  -307,
    -307,  -307,  -125,  -124,  -162,  -307,  -307,  -307,  -159,  -307,
    -106,   149,    -3
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    51,    80,    81,   131,   104,   105,   120,   106,
     322,    83,   108,   136,   323,    53,   361,   409,   135,   180,
     181,   358,   390,   391,   100,   121,   156,   122,    54,    55,
      56,    86,    87,    57,    58,    59,    60,    61,    62,    63,
      64,   145,   187,   158,   159,   298,   397,   124,   125,   380,
     126,   150,   127,   274,   275,   276,   277,   278,   279,   280,
     281,   282,   354,   355,   172,   173,   377,   174,   175,   335,
     176,   306,   307
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      66,   170,   171,   140,   312,    69,   146,   313,   272,    70,
     273,   163,   141,   142,   143,   -19,   331,   362,   393,   152,
      74,  -152,  -152,  -152,  -152,   109,   349,   325,   400,    65,
      65,   163,   141,   142,   143,   123,    65,    -8,   188,    -8,
      -8,   342,   350,   343,   342,   316,   343,   163,   141,   142,
     143,   141,   142,   143,    67,    75,   309,   157,    76,   305,
      65,   369,   326,   161,   344,   164,    68,    95,   165,   166,
     110,    71,   179,   167,    72,  -152,   168,   351,  -152,  -152,
     310,   153,  -152,  -152,   311,   164,  -152,    73,   165,   166,
     137,   394,   115,   167,   401,   403,   168,   296,   128,   129,
     130,   164,   430,   422,   165,   166,   138,   139,   441,   167,
     310,   148,   168,   381,   311,   144,    82,   332,   133,    79,
     134,   168,  -152,    -6,   163,   141,   142,   143,   341,   373,
     404,   374,   169,   272,   346,   273,   347,   431,   342,   299,
     343,   300,    77,   442,   189,    78,   348,    65,   353,   301,
     364,   365,   313,   101,   301,   102,   103,    84,   344,   302,
     385,    85,   375,   303,   376,   386,   410,   411,   304,   141,
     142,   143,   387,   388,    93,   319,    94,   415,   164,   416,
      96,   165,   166,   428,   389,   429,   167,   327,    97,   168,
      98,   283,   284,   285,   286,   336,   287,   333,   334,   142,
     143,   288,   289,   107,     2,   290,   417,    65,    99,   291,
     292,   293,     3,   359,   111,   402,   112,     4,     5,   363,
       6,     7,     8,     9,    10,    11,    12,   113,   382,   320,
     321,    13,    14,    15,   114,   116,    16,    17,    18,   147,
      19,    20,    21,   -22,    22,    23,    24,    25,   149,   151,
     392,    79,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,   162,   117,   178,
     182,   421,   183,   184,   185,   190,   191,   294,   297,   295,
     427,   308,   314,   315,   317,   318,   324,   328,   330,   338,
     339,   340,   345,   352,   356,   357,   367,   368,   366,   370,
     371,   301,   443,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
      43,    44,    45,    46,    47,   372,   379,   383,   395,   396,
     398,   378,   399,   168,   405,   406,   385,   412,   413,   414,
     419,   420,   423,   384,   424,   425,   192,   436,   432,   434,
     426,   433,   435,   437,     4,   439,   378,   440,   446,   444,
     447,    10,    11,   445,   448,   449,   450,   453,    13,   451,
     454,   457,   407,    16,   456,    18,   459,    19,   452,    21,
     455,   458,    52,   360,   408,    92,   460,    91,   418,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
      47,    48,    49,    50,   132,   186,   193,   194,   195,   196,
     197,   198,   199,   200,   201,   202,   203,   204,   205,   206,
     207,   208,   209,   210,   211,   212,   438,   177,   160,   329,
     337,   213,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   214,   215,   216,   217,   218,
     219,   220,   221,   222,   223,   224,   225,   226,   227,   228,
     229,   230,   231,   232,   233,   234,   235,   236,   237,   238,
     239,   240,   241,   242,     0,     0,     0,     0,   243,   244,
     245,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   117,     0,     0,
       0,     3,     0,     0,     0,     0,     4,     5,     0,     6,
       7,     8,     9,    10,    11,    12,     0,     0,     0,     0,
      13,    14,    15,     0,     0,    16,    17,    18,     0,    19,
      20,    21,     0,    22,    23,    24,    25,   154,     0,     0,
       0,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,   117,   119,     0,     0,
       3,     0,     0,     0,     0,     4,     5,     0,     6,     7,
       8,     9,    10,    11,    12,     0,     0,     0,     0,    13,
      14,    15,     0,     0,    16,    17,    18,     0,    19,    20,
      21,   155,    22,    23,    24,    25,   118,     0,     0,     0,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,     3,   119,     0,     0,     0,
       4,     0,     0,     0,    88,     0,     0,    10,    11,     0,
       0,     0,     0,     0,    13,     0,    15,     0,     0,    16,
      17,    18,     0,    19,     0,    21,     0,     0,     0,    89,
      90,     0,     0,     0,     0,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50
};

static const yytype_int16 yycheck[] =
{
       3,   126,   126,   111,   166,     8,   112,   166,   150,    12,
     150,    44,    45,    46,    47,    44,    44,   323,    73,    44,
      23,    44,    45,    46,    47,    98,    44,    73,    44,    45,
      45,    44,    45,    46,    47,    99,    45,    23,   144,    25,
      26,    83,    73,    85,    83,   169,    85,    44,    45,    46,
      47,    45,    46,    47,    44,    16,    44,   121,    19,    44,
      45,   103,   108,   122,   103,    98,    19,    70,   101,   102,
     143,     3,   131,   106,    44,    98,   109,   108,   101,   102,
      98,   106,   105,   106,   102,    98,   109,    47,   101,   102,
      99,   146,    95,   106,   110,    73,   109,   156,   101,   102,
     103,    98,    73,   409,   101,   102,   109,   110,    73,   106,
      98,   114,   109,   146,   102,   109,   145,   145,    27,   105,
      29,   109,   145,   109,    44,    45,    46,    47,    73,    83,
     108,    85,   145,   275,    83,   275,    85,   108,    83,    83,
      85,    85,    16,   108,   147,    19,    44,    45,   145,    98,
       6,     7,   311,    23,    98,    25,    26,   105,   103,   103,
       8,    44,    83,   107,    85,    13,    62,    63,   112,    45,
      46,    47,    20,    21,    73,   178,     3,    83,    98,    85,
     105,   101,   102,    83,    32,    85,   106,   190,    73,   109,
     103,    77,    78,    79,    80,   301,    82,    44,    45,    46,
      47,    87,    88,    44,     0,    91,    44,    45,   109,    95,
      96,    97,     8,   321,    73,   377,   110,    13,    14,   325,
      16,    17,    18,    19,    20,    21,    22,    44,   353,   180,
     181,    27,    28,    29,    73,    44,    32,    33,    34,    73,
      36,    37,    38,   145,    40,    41,    42,    43,    73,   104,
     358,   105,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,   105,     4,    73,
     146,   405,   145,    99,   144,    73,    44,    44,     4,   104,
     414,   113,    44,    44,    73,   105,   108,     6,    11,   302,
      44,    44,    99,   146,    73,    15,    73,    44,   145,    99,
      99,    98,   437,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    99,    44,    73,     7,    27,
     145,   344,   146,   109,    73,   146,     8,   146,    44,    73,
      99,    44,    44,   356,    44,    44,     5,    44,    73,    73,
     146,   145,    73,   145,    13,    44,   369,   145,    44,   146,
      44,    20,    21,   105,   146,   105,   146,    44,    27,    73,
      44,    44,   385,    32,   105,    34,    44,    36,    73,    38,
      73,    73,     1,   322,   390,    63,   108,    57,   401,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,   105,   144,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      89,    90,    91,    92,    93,    94,   433,   127,   121,   275,
     301,   100,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   114,   115,   116,   117,   118,
     119,   120,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,    -1,    -1,    -1,    -1,   147,   148,
     149,   150,   151,   152,   153,   154,   155,   156,   157,   158,
     159,   160,   161,   162,   163,   164,   165,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     4,    -1,    -1,
      -1,     8,    -1,    -1,    -1,    -1,    13,    14,    -1,    16,
      17,    18,    19,    20,    21,    22,    -1,    -1,    -1,    -1,
      27,    28,    29,    -1,    -1,    32,    33,    34,    -1,    36,
      37,    38,    -1,    40,    41,    42,    43,    44,    -1,    -1,
      -1,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,     4,    74,    -1,    -1,
       8,    -1,    -1,    -1,    -1,    13,    14,    -1,    16,    17,
      18,    19,    20,    21,    22,    -1,    -1,    -1,    -1,    27,
      28,    29,    -1,    -1,    32,    33,    34,    -1,    36,    37,
      38,   108,    40,    41,    42,    43,    44,    -1,    -1,    -1,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,     8,    74,    -1,    -1,    -1,
      13,    -1,    -1,    -1,    17,    -1,    -1,    20,    21,    -1,
      -1,    -1,    -1,    -1,    27,    -1,    29,    -1,    -1,    32,
      33,    34,    -1,    36,    -1,    38,    -1,    -1,    -1,    42,
      43,    -1,    -1,    -1,    -1,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,   177,     0,     8,    13,    14,    16,    17,    18,    19,
      20,    21,    22,    27,    28,    29,    32,    33,    34,    36,
      37,    38,    40,    41,    42,    43,    48,    49,    50,    51,
      52,    53,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,   178,   184,   191,   204,   205,   206,   209,   210,   211,
     212,   213,   214,   215,   216,    45,   248,    44,    19,   248,
     248,     3,    44,    47,   248,    16,    19,    16,    19,   105,
     179,   180,   145,   187,   105,    44,   207,   208,    17,    42,
      43,   210,   216,    73,     3,   248,   105,    73,   103,   109,
     200,    23,    25,    26,   182,   183,   185,    44,   188,    98,
     143,    73,   110,    44,    73,   248,    44,     4,    44,    74,
     184,   201,   203,   204,   223,   224,   226,   228,   248,   248,
     248,   181,   182,    27,    29,   194,   189,    99,   248,   248,
     208,    45,    46,    47,   109,   217,   246,    73,   248,    73,
     227,   104,    44,   106,    44,   108,   202,   204,   219,   220,
     223,   200,   105,    44,    98,   101,   102,   106,   109,   145,
     238,   239,   240,   241,   243,   244,   246,   224,    73,   200,
     195,   196,   146,   145,    99,   144,   217,   218,   246,   248,
      73,    44,     5,    75,    76,    77,    78,    79,    80,    81,
      82,    83,    84,    85,    86,    87,    88,    89,    90,    91,
      92,    93,    94,   100,   114,   115,   116,   117,   118,   119,
     120,   121,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   147,   148,   149,   150,   151,   152,   153,
     154,   155,   156,   157,   158,   159,   160,   161,   162,   163,
     164,   165,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,   213,   214,   229,   230,   231,   232,   233,   234,
     235,   236,   237,    77,    78,    79,    80,    82,    87,    88,
      91,    95,    96,    97,    44,   104,   200,     4,   221,    83,
      85,    98,   103,   107,   112,    44,   247,   248,   113,    44,
      98,   102,   240,   244,    44,    44,   239,    73,   105,   248,
     206,   206,   186,   190,   108,    73,   108,   248,     6,   229,
      11,    44,   145,    44,    45,   245,   246,   247,   248,    44,
      44,    73,    83,    85,   103,    99,    83,    85,    44,    44,
      73,   108,   146,   145,   238,   239,    73,    15,   197,   208,
     188,   192,   194,   246,     6,     7,   145,    73,    44,   103,
      99,    99,    99,    83,    85,    83,    85,   242,   248,    44,
     225,   146,   238,    73,   248,     8,    13,    20,    21,    32,
     198,   199,   208,    73,   146,     7,    27,   222,   145,   146,
      44,   110,   240,    73,   108,    73,   146,   248,   199,   193,
      62,    63,   146,    44,    73,    83,    85,    44,   248,    99,
      44,   239,   194,    44,    44,    44,   146,   239,    83,    85,
      73,   108,    73,   145,    73,    73,    44,   145,   222,    44,
     145,    73,   108,   238,   146,   105,    44,    44,   146,   105,
     146,    73,    73,    44,    44,    73,   105,    44,    73,    44,
     108
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,   176,   177,   177,   177,   177,   179,   178,   180,   181,
     178,   182,   182,   182,   183,   183,   185,   186,   184,   187,
     184,   184,   189,   190,   188,   188,   191,   191,   191,   191,
     191,   191,   191,   191,   192,   192,   193,   192,   195,   194,
     196,   194,   197,   197,   197,   198,   198,   198,   198,   199,
     200,   201,   201,   201,   201,   201,   202,   201,   203,   201,
     204,   204,   204,   204,   204,   204,   204,   204,   204,   204,
     204,   204,   205,   205,   205,   205,   206,   207,   207,   208,
     208,   208,   208,   209,   209,   210,   210,   210,   210,   210,
     210,   211,   212,   212,   212,   213,   213,   213,   213,   213,
     213,   213,   213,   214,   214,   215,   215,   215,   216,   216,
     216,   216,   216,   216,   216,   216,   216,   216,   216,   216,
     216,   216,   216,   216,   216,   216,   216,   216,   216,   216,
     217,   217,   218,   218,   219,   220,   221,   221,   222,   222,
     222,   223,   223,   223,   225,   224,   224,   224,   224,   224,
     227,   226,   226,   228,   228,   228,   228,   228,   228,   228,
     228,   228,   228,   228,   228,   228,   229,   229,   230,   230,
     230,   230,   230,   230,   230,   230,   230,   230,   230,   230,
     230,   230,   230,   230,   230,   230,   230,   230,   230,   230,
     230,   230,   230,   230,   230,   230,   230,   230,   230,   230,
     230,   230,   230,   230,   230,   230,   230,   230,   230,   230,
     230,   231,   231,   231,   231,   231,   231,   231,   231,   231,
     231,   231,   232,   232,   233,   233,   233,   233,   234,   234,
     234,   234,   235,   235,   235,   235,   235,   235,   235,   235,
     235,   235,   235,   235,   235,   235,   235,   235,   235,   235,
     236,   236,   236,   236,   236,   236,   237,   237,   238,   238,
     239,   239,   239,   239,   239,   239,   239,   239,   239,   239,
     239,   239,   239,   239,   239,   239,   239,   239,   239,   239,
     240,   240,   240,   240,   240,   242,   241,   243,   243,   244,
     244,   244,   244,   244,   245,   245,   245,   245,   245,   245,
     245,   246,   246,   246,   247,   247,   247,   247,   247,   248
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     2,     2,     2,     0,     3,     0,     0,
       5,     6,     2,     2,     1,     2,     0,     0,     7,     0,
       3,     1,     0,     0,     6,     1,     1,     2,     2,     1,
       2,     2,     2,     2,     0,     1,     0,     4,     0,     5,
       0,     4,     0,     3,     2,     1,     1,     1,     1,     2,
       3,     1,     2,     1,     2,     2,     0,     3,     0,     2,
       2,     2,     3,     2,     4,     6,     2,     3,     7,     4,
       3,     2,     2,     4,     4,     6,     1,     1,     3,     1,
       4,     3,     4,     1,     2,     1,     1,     1,     1,     1,
       1,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     1,     3,     2,    11,    13,     9,     0,     3,
       3,     2,     2,     3,     0,    11,     6,     5,     2,     1,
       0,     3,     1,     2,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     1,     2,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     3,     4,     1,     3,
       1,     2,     2,     1,     1,     1,     1,     2,     1,     3,
       2,     3,     2,     3,     3,     4,     4,     3,     4,     4,
       5,     7,     9,    17,     3,     0,     6,     2,     1,     3,
       4,     4,     4,     2,     3,     4,     4,     4,     5,     5,
       4,     1,     1,     1,     1,     2,     2,     3,     1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
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
        yyerror (scanner, recognizer, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, scanner, recognizer); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep, yyscan_t scanner, ptx_recognizer* recognizer)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  YYUSE (scanner);
  YYUSE (recognizer);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep, yyscan_t scanner, ptx_recognizer* recognizer)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep, scanner, recognizer);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, int yyrule, yyscan_t scanner, ptx_recognizer* recognizer)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[+yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              , scanner, recognizer);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, scanner, recognizer); \
} while (0)

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
#ifndef YYINITDEPTH
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
#   define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
#  else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
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
static char *
yystpcpy (char *yydest, const char *yysrc)
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
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
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

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
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
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                yy_state_t *yyssp, int yytoken)
{
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Actual size of YYARG. */
  int yycount = 0;
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* There are many possibilities here to consider:
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
      int yyn = yypact[+*yyssp];
      YYPTRDIFF_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
      yysize = yysize0;
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
                  YYPTRDIFF_T yysize1
                    = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
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
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    /* Don't count the "%s"s in the final size, but reserve room for
       the terminator.  */
    YYPTRDIFF_T yysize1 = yysize + (yystrlen (yyformat) - 2 * yycount) + 1;
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
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
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, yyscan_t scanner, ptx_recognizer* recognizer)
{
  YYUSE (yyvaluep);
  YYUSE (scanner);
  YYUSE (recognizer);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (yyscan_t scanner, ptx_recognizer* recognizer)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    yy_state_fast_t yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss;
    yy_state_t *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYPTRDIFF_T yystacksize;

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
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;
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
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
# undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

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
      yychar = yylex (&yylval, scanner, recognizer);
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
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
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
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 6:
#line 251 "ptx.y"
                             { recognizer->set_symtab((yyvsp[0].ptr_value)); recognizer->func_header(".skip"); }
#line 1982 "ptx.tab.c"
    break;

  case 7:
#line 251 "ptx.y"
                                                                                                               { recognizer->end_function(); }
#line 1988 "ptx.tab.c"
    break;

  case 8:
#line 252 "ptx.y"
                        { recognizer->set_symtab((yyvsp[0].ptr_value)); }
#line 1994 "ptx.tab.c"
    break;

  case 9:
#line 252 "ptx.y"
                                                                        { recognizer->func_header(".skip"); }
#line 2000 "ptx.tab.c"
    break;

  case 10:
#line 252 "ptx.y"
                                                                                                                              { recognizer->end_function(); }
#line 2006 "ptx.tab.c"
    break;

  case 11:
#line 255 "ptx.y"
                                                                                    {recognizer->func_header_info_int(".maxntid", (yyvsp[-4].int_value));
										recognizer->func_header_info_int(",", (yyvsp[-2].int_value));
										recognizer->func_header_info_int(",", (yyvsp[0].int_value));
                                                                                recognizer->maxnt_id((yyvsp[-4].int_value), (yyvsp[-2].int_value), (yyvsp[0].int_value));}
#line 2015 "ptx.tab.c"
    break;

  case 12:
#line 259 "ptx.y"
                                               { recognizer->func_header_info_int(".minnctapersm", (yyvsp[0].int_value)); printf("GPGPU-Sim: Warning: .minnctapersm ignored. \n"); }
#line 2021 "ptx.tab.c"
    break;

  case 13:
#line 260 "ptx.y"
                                               { recognizer->func_header_info_int(".maxnctapersm", (yyvsp[0].int_value)); printf("GPGPU-Sim: Warning: .maxnctapersm ignored. \n"); }
#line 2027 "ptx.tab.c"
    break;

  case 16:
#line 267 "ptx.y"
                                               { recognizer->start_function((yyvsp[-1].int_value)); recognizer->func_header_info("(");}
#line 2033 "ptx.tab.c"
    break;

  case 17:
#line 267 "ptx.y"
                                                                                                                                             {recognizer->func_header_info(")");}
#line 2039 "ptx.tab.c"
    break;

  case 18:
#line 267 "ptx.y"
                                                                                                                                                                                                       { (yyval.ptr_value) = recognizer->reset_symtab(); }
#line 2045 "ptx.tab.c"
    break;

  case 19:
#line 268 "ptx.y"
                               { recognizer->start_function((yyvsp[0].int_value)); }
#line 2051 "ptx.tab.c"
    break;

  case 20:
#line 268 "ptx.y"
                                                                                        { (yyval.ptr_value) = recognizer->reset_symtab(); }
#line 2057 "ptx.tab.c"
    break;

  case 21:
#line 269 "ptx.y"
                               { recognizer->start_function((yyvsp[0].int_value)); recognizer->add_function_name(""); recognizer->g_func_decl=0; (yyval.ptr_value) = recognizer->reset_symtab(); }
#line 2063 "ptx.tab.c"
    break;

  case 22:
#line 272 "ptx.y"
                                 { recognizer->add_function_name((yyvsp[0].string_value)); }
#line 2069 "ptx.tab.c"
    break;

  case 23:
#line 272 "ptx.y"
                                                                                   {recognizer->func_header_info("(");}
#line 2075 "ptx.tab.c"
    break;

  case 24:
#line 272 "ptx.y"
                                                                                                                                               { recognizer->g_func_decl=0; recognizer->func_header_info(")"); }
#line 2081 "ptx.tab.c"
    break;

  case 25:
#line 273 "ptx.y"
                     { recognizer->add_function_name((yyvsp[0].string_value)); recognizer->g_func_decl=0; }
#line 2087 "ptx.tab.c"
    break;

  case 26:
#line 276 "ptx.y"
                                      { (yyval.int_value) = 1; recognizer->g_func_decl=1; recognizer->func_header(".entry"); }
#line 2093 "ptx.tab.c"
    break;

  case 27:
#line 277 "ptx.y"
                                            { (yyval.int_value) = 1; recognizer->g_func_decl=1; recognizer->func_header(".entry"); }
#line 2099 "ptx.tab.c"
    break;

  case 28:
#line 278 "ptx.y"
                                         { (yyval.int_value) = 1; recognizer->g_func_decl=1; recognizer->func_header(".entry"); }
#line 2105 "ptx.tab.c"
    break;

  case 29:
#line 279 "ptx.y"
                         { (yyval.int_value) = 0; recognizer->g_func_decl=1; recognizer->func_header(".func"); }
#line 2111 "ptx.tab.c"
    break;

  case 30:
#line 280 "ptx.y"
                                           { (yyval.int_value) = 0; recognizer->g_func_decl=1; recognizer->func_header(".func"); }
#line 2117 "ptx.tab.c"
    break;

  case 31:
#line 281 "ptx.y"
                                        { (yyval.int_value) = 0; recognizer->g_func_decl=1; recognizer->func_header(".func"); }
#line 2123 "ptx.tab.c"
    break;

  case 32:
#line 282 "ptx.y"
                                          { (yyval.int_value) = 2; recognizer->g_func_decl=1; recognizer->func_header(".func"); }
#line 2129 "ptx.tab.c"
    break;

  case 33:
#line 283 "ptx.y"
                                        { (yyval.int_value) = 0; recognizer->g_func_decl=1; recognizer->func_header(".func"); }
#line 2135 "ptx.tab.c"
    break;

  case 35:
#line 287 "ptx.y"
                      { recognizer->add_directive(); }
#line 2141 "ptx.tab.c"
    break;

  case 36:
#line 288 "ptx.y"
                           {recognizer->func_header_info(",");}
#line 2147 "ptx.tab.c"
    break;

  case 37:
#line 288 "ptx.y"
                                                                            { recognizer->add_directive(); }
#line 2153 "ptx.tab.c"
    break;

  case 38:
#line 290 "ptx.y"
                             { recognizer->add_space_spec(param_space_unclassified,0); }
#line 2159 "ptx.tab.c"
    break;

  case 39:
#line 290 "ptx.y"
                                                                                                                                { recognizer->add_function_arg(); }
#line 2165 "ptx.tab.c"
    break;

  case 40:
#line 291 "ptx.y"
                        { recognizer->add_space_spec(reg_space,0); }
#line 2171 "ptx.tab.c"
    break;

  case 41:
#line 291 "ptx.y"
                                                                                                   { recognizer->add_function_arg(); }
#line 2177 "ptx.tab.c"
    break;

  case 45:
#line 297 "ptx.y"
                                 { recognizer->add_ptr_spec(global_space); }
#line 2183 "ptx.tab.c"
    break;

  case 46:
#line 298 "ptx.y"
                                 { recognizer->add_ptr_spec(local_space); }
#line 2189 "ptx.tab.c"
    break;

  case 47:
#line 299 "ptx.y"
                                 { recognizer->add_ptr_spec(shared_space); }
#line 2195 "ptx.tab.c"
    break;

  case 48:
#line 300 "ptx.y"
                                            { recognizer->add_ptr_spec(global_space); }
#line 2201 "ptx.tab.c"
    break;

  case 51:
#line 306 "ptx.y"
                                    { recognizer->add_directive(); }
#line 2207 "ptx.tab.c"
    break;

  case 52:
#line 307 "ptx.y"
                                     {printf("Prototype statement detected. WARNING: this is not supported yet on GPGPU-SIM\n"); }
#line 2213 "ptx.tab.c"
    break;

  case 53:
#line 308 "ptx.y"
                                { recognizer->add_instruction(); }
#line 2219 "ptx.tab.c"
    break;

  case 54:
#line 309 "ptx.y"
                                             { recognizer->add_directive(); }
#line 2225 "ptx.tab.c"
    break;

  case 55:
#line 310 "ptx.y"
                                               { recognizer->add_instruction(); }
#line 2231 "ptx.tab.c"
    break;

  case 56:
#line 311 "ptx.y"
                         {recognizer->start_inst_group();}
#line 2237 "ptx.tab.c"
    break;

  case 57:
#line 311 "ptx.y"
                                                                           {recognizer->end_inst_group();}
#line 2243 "ptx.tab.c"
    break;

  case 58:
#line 312 "ptx.y"
          {recognizer->start_inst_group();}
#line 2249 "ptx.tab.c"
    break;

  case 59:
#line 312 "ptx.y"
                                                            {recognizer->end_inst_group();}
#line 2255 "ptx.tab.c"
    break;

  case 61:
#line 316 "ptx.y"
                                           { recognizer->add_version_info((yyvsp[0].double_value), 0); }
#line 2261 "ptx.tab.c"
    break;

  case 62:
#line 317 "ptx.y"
                                                { recognizer->add_version_info((yyvsp[-1].double_value),1); }
#line 2267 "ptx.tab.c"
    break;

  case 63:
#line 318 "ptx.y"
                                               {/*Do nothing*/}
#line 2273 "ptx.tab.c"
    break;

  case 64:
#line 319 "ptx.y"
                                                       { recognizer->target_header2((yyvsp[-2].string_value),(yyvsp[0].string_value)); }
#line 2279 "ptx.tab.c"
    break;

  case 65:
#line 320 "ptx.y"
                                                                        { recognizer->target_header3((yyvsp[-4].string_value),(yyvsp[-2].string_value),(yyvsp[0].string_value)); }
#line 2285 "ptx.tab.c"
    break;

  case 66:
#line 321 "ptx.y"
                                      { recognizer->target_header((yyvsp[0].string_value)); }
#line 2291 "ptx.tab.c"
    break;

  case 67:
#line 322 "ptx.y"
                                              { recognizer->add_file((yyvsp[-1].int_value),(yyvsp[0].string_value)); }
#line 2297 "ptx.tab.c"
    break;

  case 68:
#line 323 "ptx.y"
                                                                                      { recognizer->add_file((yyvsp[-5].int_value),(yyvsp[-4].string_value)); }
#line 2303 "ptx.tab.c"
    break;

  case 70:
#line 325 "ptx.y"
                                             { recognizer->add_pragma((yyvsp[-1].string_value)); }
#line 2309 "ptx.tab.c"
    break;

  case 71:
#line 326 "ptx.y"
                                   {/*Do nothing*/}
#line 2315 "ptx.tab.c"
    break;

  case 72:
#line 329 "ptx.y"
                                                    { recognizer->add_variables(); }
#line 2321 "ptx.tab.c"
    break;

  case 73:
#line 330 "ptx.y"
                                                                { recognizer->add_variables(); }
#line 2327 "ptx.tab.c"
    break;

  case 74:
#line 331 "ptx.y"
                                                               { recognizer->add_variables(); }
#line 2333 "ptx.tab.c"
    break;

  case 75:
#line 332 "ptx.y"
                                                                             { recognizer->add_constptr((yyvsp[-4].string_value), (yyvsp[-2].string_value), (yyvsp[0].int_value)); }
#line 2339 "ptx.tab.c"
    break;

  case 76:
#line 335 "ptx.y"
                             { recognizer->set_variable_type(); }
#line 2345 "ptx.tab.c"
    break;

  case 79:
#line 340 "ptx.y"
                            { recognizer->add_identifier((yyvsp[0].string_value),0,NON_ARRAY_IDENTIFIER); recognizer->func_header_info((yyvsp[0].string_value));}
#line 2351 "ptx.tab.c"
    break;

  case 80:
#line 341 "ptx.y"
                                                                          { recognizer->func_header_info((yyvsp[-3].string_value)); recognizer->func_header_info_int("<", (yyvsp[-1].int_value)); recognizer->func_header_info(">");
		int i,lbase,l;
		char *id = NULL;
		lbase = strlen((yyvsp[-3].string_value));
		for( i=0; i < (yyvsp[-1].int_value); i++ ) { 
			l = lbase + (int)log10(i+1)+10;
			id = (char*) malloc(l);
			snprintf(id,l,"%s%u",(yyvsp[-3].string_value),i);
			recognizer->add_identifier(id,0,NON_ARRAY_IDENTIFIER);
		}
		free((yyvsp[-3].string_value));
	}
#line 2368 "ptx.tab.c"
    break;

  case 81:
#line 353 "ptx.y"
                                                              { recognizer->add_identifier((yyvsp[-2].string_value),0,ARRAY_IDENTIFIER_NO_DIM); recognizer->func_header_info((yyvsp[-2].string_value)); recognizer->func_header_info("["); recognizer->func_header_info("]");}
#line 2374 "ptx.tab.c"
    break;

  case 82:
#line 354 "ptx.y"
                                                                            { recognizer->add_identifier((yyvsp[-3].string_value),(yyvsp[-1].int_value),ARRAY_IDENTIFIER); recognizer->func_header_info((yyvsp[-3].string_value)); recognizer->func_header_info_int("[",(yyvsp[-1].int_value)); recognizer->func_header_info("]");}
#line 2380 "ptx.tab.c"
    break;

  case 89:
#line 364 "ptx.y"
                           { recognizer->add_extern_spec(); }
#line 2386 "ptx.tab.c"
    break;

  case 91:
#line 368 "ptx.y"
                                          { recognizer->add_alignment_spec((yyvsp[0].int_value)); }
#line 2392 "ptx.tab.c"
    break;

  case 92:
#line 370 "ptx.y"
                          {  recognizer->add_space_spec(reg_space,0); }
#line 2398 "ptx.tab.c"
    break;

  case 93:
#line 371 "ptx.y"
                          {  recognizer->add_space_spec(reg_space,0); }
#line 2404 "ptx.tab.c"
    break;

  case 95:
#line 375 "ptx.y"
                                  {  recognizer->add_space_spec(const_space,(yyvsp[0].int_value)); }
#line 2410 "ptx.tab.c"
    break;

  case 96:
#line 376 "ptx.y"
                                  {  recognizer->add_space_spec(global_space,0); recognizer->mark_instruction_volatile((yyvsp[0].int_value) != 0); }
#line 2416 "ptx.tab.c"
    break;

  case 97:
#line 377 "ptx.y"
                                  {  recognizer->add_space_spec(local_space,0); }
#line 2422 "ptx.tab.c"
    break;

  case 98:
#line 378 "ptx.y"
                                  {  recognizer->add_space_spec(param_space_unclassified,0); }
#line 2428 "ptx.tab.c"
    break;

  case 99:
#line 379 "ptx.y"
                                  {  recognizer->add_space_spec(shared_space,0); }
#line 2434 "ptx.tab.c"
    break;

  case 100:
#line 380 "ptx.y"
                              {  recognizer->add_space_spec(sstarr_space,0); }
#line 2440 "ptx.tab.c"
    break;

  case 101:
#line 381 "ptx.y"
                                  {  recognizer->add_space_spec(surf_space,0); }
#line 2446 "ptx.tab.c"
    break;

  case 102:
#line 382 "ptx.y"
                                  {  recognizer->add_space_spec(tex_space,0); }
#line 2452 "ptx.tab.c"
    break;

  case 105:
#line 389 "ptx.y"
                      {  recognizer->add_option(V2_TYPE); recognizer->func_header_info(".v2");}
#line 2458 "ptx.tab.c"
    break;

  case 106:
#line 390 "ptx.y"
                      {  recognizer->add_option(V3_TYPE); recognizer->func_header_info(".v3");}
#line 2464 "ptx.tab.c"
    break;

  case 107:
#line 391 "ptx.y"
                      {  recognizer->add_option(V4_TYPE); recognizer->func_header_info(".v4");}
#line 2470 "ptx.tab.c"
    break;

  case 108:
#line 394 "ptx.y"
                     { recognizer->add_scalar_type_spec( S8_TYPE ); }
#line 2476 "ptx.tab.c"
    break;

  case 109:
#line 395 "ptx.y"
                     { recognizer->add_scalar_type_spec( S16_TYPE ); }
#line 2482 "ptx.tab.c"
    break;

  case 110:
#line 396 "ptx.y"
                     { recognizer->add_scalar_type_spec( S32_TYPE ); }
#line 2488 "ptx.tab.c"
    break;

  case 111:
#line 397 "ptx.y"
                     { recognizer->add_scalar_type_spec( S64_TYPE ); }
#line 2494 "ptx.tab.c"
    break;

  case 112:
#line 398 "ptx.y"
                     { recognizer->add_scalar_type_spec( U8_TYPE ); }
#line 2500 "ptx.tab.c"
    break;

  case 113:
#line 399 "ptx.y"
                     { recognizer->add_scalar_type_spec( U16_TYPE ); }
#line 2506 "ptx.tab.c"
    break;

  case 114:
#line 400 "ptx.y"
                     { recognizer->add_scalar_type_spec( U32_TYPE ); }
#line 2512 "ptx.tab.c"
    break;

  case 115:
#line 401 "ptx.y"
                     { recognizer->add_scalar_type_spec( U64_TYPE ); }
#line 2518 "ptx.tab.c"
    break;

  case 116:
#line 402 "ptx.y"
                     { recognizer->add_scalar_type_spec( F16_TYPE ); }
#line 2524 "ptx.tab.c"
    break;

  case 117:
#line 403 "ptx.y"
                     { recognizer->add_scalar_type_spec( F32_TYPE ); }
#line 2530 "ptx.tab.c"
    break;

  case 118:
#line 404 "ptx.y"
                     { recognizer->add_scalar_type_spec( F64_TYPE ); }
#line 2536 "ptx.tab.c"
    break;

  case 119:
#line 405 "ptx.y"
                      { recognizer->add_scalar_type_spec( FF64_TYPE ); }
#line 2542 "ptx.tab.c"
    break;

  case 120:
#line 406 "ptx.y"
                     { recognizer->add_scalar_type_spec( B8_TYPE );  }
#line 2548 "ptx.tab.c"
    break;

  case 121:
#line 407 "ptx.y"
                     { recognizer->add_scalar_type_spec( B16_TYPE ); }
#line 2554 "ptx.tab.c"
    break;

  case 122:
#line 408 "ptx.y"
                     { recognizer->add_scalar_type_spec( B32_TYPE ); }
#line 2560 "ptx.tab.c"
    break;

  case 123:
#line 409 "ptx.y"
                     { recognizer->add_scalar_type_spec( B64_TYPE ); }
#line 2566 "ptx.tab.c"
    break;

  case 124:
#line 410 "ptx.y"
                      { recognizer->add_scalar_type_spec( BB64_TYPE ); }
#line 2572 "ptx.tab.c"
    break;

  case 125:
#line 411 "ptx.y"
                       { recognizer->add_scalar_type_spec( BB128_TYPE ); }
#line 2578 "ptx.tab.c"
    break;

  case 126:
#line 412 "ptx.y"
                     { recognizer->add_scalar_type_spec( PRED_TYPE ); }
#line 2584 "ptx.tab.c"
    break;

  case 127:
#line 413 "ptx.y"
                       { recognizer->add_scalar_type_spec( TEXREF_TYPE ); }
#line 2590 "ptx.tab.c"
    break;

  case 128:
#line 414 "ptx.y"
                           { recognizer->add_scalar_type_spec( SAMPLERREF_TYPE ); }
#line 2596 "ptx.tab.c"
    break;

  case 129:
#line 415 "ptx.y"
                        { recognizer->add_scalar_type_spec( SURFREF_TYPE ); }
#line 2602 "ptx.tab.c"
    break;

  case 130:
#line 418 "ptx.y"
                                                      { recognizer->add_array_initializer(); }
#line 2608 "ptx.tab.c"
    break;

  case 131:
#line 419 "ptx.y"
                                                  { syntax_not_implemented(scanner, recognizer); }
#line 2614 "ptx.tab.c"
    break;

  case 142:
#line 442 "ptx.y"
                           { recognizer->add_label((yyvsp[-1].string_value)); }
#line 2620 "ptx.tab.c"
    break;

  case 144:
#line 445 "ptx.y"
                                                        { recognizer->set_return(); }
#line 2626 "ptx.tab.c"
    break;

  case 150:
#line 452 "ptx.y"
                    { recognizer->add_opcode((yyvsp[0].int_value)); }
#line 2632 "ptx.tab.c"
    break;

  case 152:
#line 453 "ptx.y"
                 { recognizer->add_opcode((yyvsp[0].int_value)); }
#line 2638 "ptx.tab.c"
    break;

  case 153:
#line 455 "ptx.y"
                            { recognizer->add_pred((yyvsp[0].string_value),0, -1); }
#line 2644 "ptx.tab.c"
    break;

  case 154:
#line 456 "ptx.y"
                                      { recognizer->add_pred((yyvsp[0].string_value),1, -1); }
#line 2650 "ptx.tab.c"
    break;

  case 155:
#line 457 "ptx.y"
                                     { recognizer->add_pred((yyvsp[-1].string_value),0,1); }
#line 2656 "ptx.tab.c"
    break;

  case 156:
#line 458 "ptx.y"
                                     { recognizer->add_pred((yyvsp[-1].string_value),0,2); }
#line 2662 "ptx.tab.c"
    break;

  case 157:
#line 459 "ptx.y"
                                     { recognizer->add_pred((yyvsp[-1].string_value),0,3); }
#line 2668 "ptx.tab.c"
    break;

  case 158:
#line 460 "ptx.y"
                                     { recognizer->add_pred((yyvsp[-1].string_value),0,5); }
#line 2674 "ptx.tab.c"
    break;

  case 159:
#line 461 "ptx.y"
                                     { recognizer->add_pred((yyvsp[-1].string_value),0,6); }
#line 2680 "ptx.tab.c"
    break;

  case 160:
#line 462 "ptx.y"
                                      { recognizer->add_pred((yyvsp[-1].string_value),0,10); }
#line 2686 "ptx.tab.c"
    break;

  case 161:
#line 463 "ptx.y"
                                      { recognizer->add_pred((yyvsp[-1].string_value),0,12); }
#line 2692 "ptx.tab.c"
    break;

  case 162:
#line 464 "ptx.y"
                                      { recognizer->add_pred((yyvsp[-1].string_value),0,13); }
#line 2698 "ptx.tab.c"
    break;

  case 163:
#line 465 "ptx.y"
                                     { recognizer->add_pred((yyvsp[-1].string_value),0,17); }
#line 2704 "ptx.tab.c"
    break;

  case 164:
#line 466 "ptx.y"
                                     { recognizer->add_pred((yyvsp[-1].string_value),0,19); }
#line 2710 "ptx.tab.c"
    break;

  case 165:
#line 467 "ptx.y"
                                      { recognizer->add_pred((yyvsp[-1].string_value),0,28); }
#line 2716 "ptx.tab.c"
    break;

  case 174:
#line 479 "ptx.y"
                      { recognizer->add_option(SYNC_OPTION); }
#line 2722 "ptx.tab.c"
    break;

  case 175:
#line 480 "ptx.y"
                        { recognizer->add_option(ARRIVE_OPTION); }
#line 2728 "ptx.tab.c"
    break;

  case 176:
#line 481 "ptx.y"
                     { recognizer->add_option(RED_OPTION); }
#line 2734 "ptx.tab.c"
    break;

  case 177:
#line 482 "ptx.y"
                     { recognizer->add_option(UNI_OPTION); }
#line 2740 "ptx.tab.c"
    break;

  case 178:
#line 483 "ptx.y"
                      { recognizer->add_option(WIDE_OPTION); }
#line 2746 "ptx.tab.c"
    break;

  case 179:
#line 484 "ptx.y"
                     { recognizer->add_option(ANY_OPTION); }
#line 2752 "ptx.tab.c"
    break;

  case 180:
#line 485 "ptx.y"
                     { recognizer->add_option(ALL_OPTION); }
#line 2758 "ptx.tab.c"
    break;

  case 181:
#line 486 "ptx.y"
                        { recognizer->add_option(BALLOT_OPTION); }
#line 2764 "ptx.tab.c"
    break;

  case 182:
#line 487 "ptx.y"
                        { recognizer->add_option(GLOBAL_OPTION); }
#line 2770 "ptx.tab.c"
    break;

  case 183:
#line 488 "ptx.y"
                     { recognizer->add_option(CTA_OPTION); }
#line 2776 "ptx.tab.c"
    break;

  case 184:
#line 489 "ptx.y"
                     { recognizer->add_option(SYS_OPTION); }
#line 2782 "ptx.tab.c"
    break;

  case 185:
#line 490 "ptx.y"
                           { recognizer->add_option(GEOM_MODIFIER_1D); }
#line 2788 "ptx.tab.c"
    break;

  case 186:
#line 491 "ptx.y"
                           { recognizer->add_option(GEOM_MODIFIER_2D); }
#line 2794 "ptx.tab.c"
    break;

  case 187:
#line 492 "ptx.y"
                           { recognizer->add_option(GEOM_MODIFIER_3D); }
#line 2800 "ptx.tab.c"
    break;

  case 188:
#line 493 "ptx.y"
                     { recognizer->add_option(SAT_OPTION); }
#line 2806 "ptx.tab.c"
    break;

  case 189:
#line 494 "ptx.y"
                     { recognizer->add_option(FTZ_OPTION); }
#line 2812 "ptx.tab.c"
    break;

  case 190:
#line 495 "ptx.y"
                     { recognizer->add_option(NEG_OPTION); }
#line 2818 "ptx.tab.c"
    break;

  case 191:
#line 496 "ptx.y"
                        { recognizer->add_option(APPROX_OPTION); }
#line 2824 "ptx.tab.c"
    break;

  case 192:
#line 497 "ptx.y"
                      { recognizer->add_option(FULL_OPTION); }
#line 2830 "ptx.tab.c"
    break;

  case 193:
#line 498 "ptx.y"
                      { recognizer->add_option(EXIT_OPTION); }
#line 2836 "ptx.tab.c"
    break;

  case 194:
#line 499 "ptx.y"
                     { recognizer->add_option(ABS_OPTION); }
#line 2842 "ptx.tab.c"
    break;

  case 196:
#line 501 "ptx.y"
                    { recognizer->add_option(TO_OPTION); }
#line 2848 "ptx.tab.c"
    break;

  case 197:
#line 502 "ptx.y"
                      { recognizer->add_option(HALF_OPTION); }
#line 2854 "ptx.tab.c"
    break;

  case 198:
#line 503 "ptx.y"
                      { recognizer->add_option(EXTP_OPTION); }
#line 2860 "ptx.tab.c"
    break;

  case 199:
#line 504 "ptx.y"
                    { recognizer->add_option(CA_OPTION); }
#line 2866 "ptx.tab.c"
    break;

  case 200:
#line 505 "ptx.y"
                    { recognizer->add_option(CG_OPTION); }
#line 2872 "ptx.tab.c"
    break;

  case 201:
#line 506 "ptx.y"
                    { recognizer->add_option(CS_OPTION); }
#line 2878 "ptx.tab.c"
    break;

  case 202:
#line 507 "ptx.y"
                    { recognizer->add_option(LU_OPTION); }
#line 2884 "ptx.tab.c"
    break;

  case 203:
#line 508 "ptx.y"
                    { recognizer->add_option(CV_OPTION); }
#line 2890 "ptx.tab.c"
    break;

  case 204:
#line 509 "ptx.y"
                    { recognizer->add_option(WB_OPTION); }
#line 2896 "ptx.tab.c"
    break;

  case 205:
#line 510 "ptx.y"
                    { recognizer->add_option(WT_OPTION); }
#line 2902 "ptx.tab.c"
    break;

  case 206:
#line 511 "ptx.y"
                    { recognizer->add_option(NC_OPTION); }
#line 2908 "ptx.tab.c"
    break;

  case 207:
#line 512 "ptx.y"
                    { recognizer->add_option(UP_OPTION); }
#line 2914 "ptx.tab.c"
    break;

  case 208:
#line 513 "ptx.y"
                      { recognizer->add_option(DOWN_OPTION); }
#line 2920 "ptx.tab.c"
    break;

  case 209:
#line 514 "ptx.y"
                      { recognizer->add_option(BFLY_OPTION); }
#line 2926 "ptx.tab.c"
    break;

  case 210:
#line 515 "ptx.y"
                     { recognizer->add_option(IDX_OPTION); }
#line 2932 "ptx.tab.c"
    break;

  case 211:
#line 518 "ptx.y"
                                  { recognizer->add_option(ATOMIC_AND); }
#line 2938 "ptx.tab.c"
    break;

  case 212:
#line 519 "ptx.y"
                      { recognizer->add_option(ATOMIC_POPC); }
#line 2944 "ptx.tab.c"
    break;

  case 213:
#line 520 "ptx.y"
                    { recognizer->add_option(ATOMIC_OR); }
#line 2950 "ptx.tab.c"
    break;

  case 214:
#line 521 "ptx.y"
                     { recognizer->add_option(ATOMIC_XOR); }
#line 2956 "ptx.tab.c"
    break;

  case 215:
#line 522 "ptx.y"
                     { recognizer->add_option(ATOMIC_CAS); }
#line 2962 "ptx.tab.c"
    break;

  case 216:
#line 523 "ptx.y"
                      { recognizer->add_option(ATOMIC_EXCH); }
#line 2968 "ptx.tab.c"
    break;

  case 217:
#line 524 "ptx.y"
                     { recognizer->add_option(ATOMIC_ADD); }
#line 2974 "ptx.tab.c"
    break;

  case 218:
#line 525 "ptx.y"
                     { recognizer->add_option(ATOMIC_INC); }
#line 2980 "ptx.tab.c"
    break;

  case 219:
#line 526 "ptx.y"
                     { recognizer->add_option(ATOMIC_DEC); }
#line 2986 "ptx.tab.c"
    break;

  case 220:
#line 527 "ptx.y"
                     { recognizer->add_option(ATOMIC_MIN); }
#line 2992 "ptx.tab.c"
    break;

  case 221:
#line 528 "ptx.y"
                     { recognizer->add_option(ATOMIC_MAX); }
#line 2998 "ptx.tab.c"
    break;

  case 224:
#line 535 "ptx.y"
                                        { recognizer->add_option(RN_OPTION); }
#line 3004 "ptx.tab.c"
    break;

  case 225:
#line 536 "ptx.y"
                    { recognizer->add_option(RZ_OPTION); }
#line 3010 "ptx.tab.c"
    break;

  case 226:
#line 537 "ptx.y"
                    { recognizer->add_option(RM_OPTION); }
#line 3016 "ptx.tab.c"
    break;

  case 227:
#line 538 "ptx.y"
                    { recognizer->add_option(RP_OPTION); }
#line 3022 "ptx.tab.c"
    break;

  case 228:
#line 541 "ptx.y"
                                  { recognizer->add_option(RNI_OPTION); }
#line 3028 "ptx.tab.c"
    break;

  case 229:
#line 542 "ptx.y"
                     { recognizer->add_option(RZI_OPTION); }
#line 3034 "ptx.tab.c"
    break;

  case 230:
#line 543 "ptx.y"
                     { recognizer->add_option(RMI_OPTION); }
#line 3040 "ptx.tab.c"
    break;

  case 231:
#line 544 "ptx.y"
                     { recognizer->add_option(RPI_OPTION); }
#line 3046 "ptx.tab.c"
    break;

  case 232:
#line 547 "ptx.y"
                       { recognizer->add_option(EQ_OPTION); }
#line 3052 "ptx.tab.c"
    break;

  case 233:
#line 548 "ptx.y"
                    { recognizer->add_option(NE_OPTION); }
#line 3058 "ptx.tab.c"
    break;

  case 234:
#line 549 "ptx.y"
                    { recognizer->add_option(LT_OPTION); }
#line 3064 "ptx.tab.c"
    break;

  case 235:
#line 550 "ptx.y"
                    { recognizer->add_option(LE_OPTION); }
#line 3070 "ptx.tab.c"
    break;

  case 236:
#line 551 "ptx.y"
                    { recognizer->add_option(GT_OPTION); }
#line 3076 "ptx.tab.c"
    break;

  case 237:
#line 552 "ptx.y"
                    { recognizer->add_option(GE_OPTION); }
#line 3082 "ptx.tab.c"
    break;

  case 238:
#line 553 "ptx.y"
                    { recognizer->add_option(LO_OPTION); }
#line 3088 "ptx.tab.c"
    break;

  case 239:
#line 554 "ptx.y"
                    { recognizer->add_option(LS_OPTION); }
#line 3094 "ptx.tab.c"
    break;

  case 240:
#line 555 "ptx.y"
                    { recognizer->add_option(HI_OPTION); }
#line 3100 "ptx.tab.c"
    break;

  case 241:
#line 556 "ptx.y"
                     { recognizer->add_option(HS_OPTION); }
#line 3106 "ptx.tab.c"
    break;

  case 242:
#line 557 "ptx.y"
                     { recognizer->add_option(EQU_OPTION); }
#line 3112 "ptx.tab.c"
    break;

  case 243:
#line 558 "ptx.y"
                     { recognizer->add_option(NEU_OPTION); }
#line 3118 "ptx.tab.c"
    break;

  case 244:
#line 559 "ptx.y"
                     { recognizer->add_option(LTU_OPTION); }
#line 3124 "ptx.tab.c"
    break;

  case 245:
#line 560 "ptx.y"
                     { recognizer->add_option(LEU_OPTION); }
#line 3130 "ptx.tab.c"
    break;

  case 246:
#line 561 "ptx.y"
                     { recognizer->add_option(GTU_OPTION); }
#line 3136 "ptx.tab.c"
    break;

  case 247:
#line 562 "ptx.y"
                     { recognizer->add_option(GEU_OPTION); }
#line 3142 "ptx.tab.c"
    break;

  case 248:
#line 563 "ptx.y"
                     { recognizer->add_option(NUM_OPTION); }
#line 3148 "ptx.tab.c"
    break;

  case 249:
#line 564 "ptx.y"
                     { recognizer->add_option(NAN_OPTION); }
#line 3154 "ptx.tab.c"
    break;

  case 250:
#line 567 "ptx.y"
                         { recognizer->add_option( PRMT_F4E_MODE); }
#line 3160 "ptx.tab.c"
    break;

  case 251:
#line 568 "ptx.y"
                         { recognizer->add_option( PRMT_B4E_MODE); }
#line 3166 "ptx.tab.c"
    break;

  case 252:
#line 569 "ptx.y"
                         { recognizer->add_option( PRMT_RC8_MODE); }
#line 3172 "ptx.tab.c"
    break;

  case 253:
#line 570 "ptx.y"
                         { recognizer->add_option( PRMT_RC16_MODE);}
#line 3178 "ptx.tab.c"
    break;

  case 254:
#line 571 "ptx.y"
                         { recognizer->add_option( PRMT_ECL_MODE); }
#line 3184 "ptx.tab.c"
    break;

  case 255:
#line 572 "ptx.y"
                         { recognizer->add_option( PRMT_ECR_MODE); }
#line 3190 "ptx.tab.c"
    break;

  case 256:
#line 575 "ptx.y"
                                              {recognizer->add_space_spec(global_space,0);recognizer->add_ptr_spec(global_space); recognizer->add_wmma_option((yyvsp[-2].int_value));recognizer->add_wmma_option((yyvsp[-1].int_value));recognizer->add_wmma_option((yyvsp[0].int_value));}
#line 3196 "ptx.tab.c"
    break;

  case 257:
#line 576 "ptx.y"
                                                    {recognizer->add_wmma_option((yyvsp[-3].int_value));recognizer->add_wmma_option((yyvsp[-2].int_value));recognizer->add_wmma_option((yyvsp[-1].int_value));recognizer->add_wmma_option((yyvsp[0].int_value));}
#line 3202 "ptx.tab.c"
    break;

  case 260:
#line 588 "ptx.y"
                     { recognizer->add_scalar_operand( (yyvsp[0].string_value) ); }
#line 3208 "ptx.tab.c"
    break;

  case 261:
#line 589 "ptx.y"
                                 { recognizer->add_neg_pred_operand( (yyvsp[0].string_value) ); }
#line 3214 "ptx.tab.c"
    break;

  case 262:
#line 590 "ptx.y"
                            { recognizer->add_scalar_operand( (yyvsp[0].string_value) ); recognizer->change_operand_neg(); }
#line 3220 "ptx.tab.c"
    break;

  case 267:
#line 595 "ptx.y"
                               { recognizer->change_operand_neg(); }
#line 3226 "ptx.tab.c"
    break;

  case 269:
#line 597 "ptx.y"
                                        { recognizer->add_address_operand((yyvsp[-2].string_value),(yyvsp[0].int_value)); }
#line 3232 "ptx.tab.c"
    break;

  case 270:
#line 598 "ptx.y"
                               { recognizer->add_scalar_operand( (yyvsp[-1].string_value) ); recognizer->change_operand_lohi(1);}
#line 3238 "ptx.tab.c"
    break;

  case 271:
#line 599 "ptx.y"
                                     { recognizer->add_scalar_operand( (yyvsp[-1].string_value) ); recognizer->change_operand_lohi(1); recognizer->change_operand_neg();}
#line 3244 "ptx.tab.c"
    break;

  case 272:
#line 600 "ptx.y"
                               { recognizer->add_scalar_operand( (yyvsp[-1].string_value) ); recognizer->change_operand_lohi(2);}
#line 3250 "ptx.tab.c"
    break;

  case 273:
#line 601 "ptx.y"
                                     { recognizer->add_scalar_operand( (yyvsp[-1].string_value) ); recognizer->change_operand_lohi(2); recognizer->change_operand_neg();}
#line 3256 "ptx.tab.c"
    break;

  case 274:
#line 602 "ptx.y"
                                     { recognizer->add_2vector_operand((yyvsp[-2].string_value),(yyvsp[0].string_value)); recognizer->change_double_operand_type(-1);}
#line 3262 "ptx.tab.c"
    break;

  case 275:
#line 603 "ptx.y"
                                               { recognizer->add_2vector_operand((yyvsp[-3].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(-1); recognizer->change_operand_lohi(1);}
#line 3268 "ptx.tab.c"
    break;

  case 276:
#line 604 "ptx.y"
                                               { recognizer->add_2vector_operand((yyvsp[-3].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(-1); recognizer->change_operand_lohi(2);}
#line 3274 "ptx.tab.c"
    break;

  case 277:
#line 605 "ptx.y"
                                          { recognizer->add_2vector_operand((yyvsp[-2].string_value),(yyvsp[0].string_value)); recognizer->change_double_operand_type(-3);}
#line 3280 "ptx.tab.c"
    break;

  case 278:
#line 606 "ptx.y"
                                                    { recognizer->add_2vector_operand((yyvsp[-3].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(-3); recognizer->change_operand_lohi(1);}
#line 3286 "ptx.tab.c"
    break;

  case 279:
#line 607 "ptx.y"
                                                    { recognizer->add_2vector_operand((yyvsp[-3].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(-3); recognizer->change_operand_lohi(2);}
#line 3292 "ptx.tab.c"
    break;

  case 280:
#line 610 "ptx.y"
                                                                   { recognizer->add_2vector_operand((yyvsp[-3].string_value),(yyvsp[-1].string_value)); }
#line 3298 "ptx.tab.c"
    break;

  case 281:
#line 611 "ptx.y"
                                                                                      { recognizer->add_3vector_operand((yyvsp[-5].string_value),(yyvsp[-3].string_value),(yyvsp[-1].string_value)); }
#line 3304 "ptx.tab.c"
    break;

  case 282:
#line 612 "ptx.y"
                                                                                                       { recognizer->add_4vector_operand((yyvsp[-7].string_value),(yyvsp[-5].string_value),(yyvsp[-3].string_value),(yyvsp[-1].string_value)); }
#line 3310 "ptx.tab.c"
    break;

  case 283:
#line 613 "ptx.y"
                                                                                                                                                                           { recognizer->add_8vector_operand((yyvsp[-15].string_value),(yyvsp[-13].string_value),(yyvsp[-11].string_value),(yyvsp[-9].string_value),(yyvsp[-7].string_value),(yyvsp[-5].string_value),(yyvsp[-3].string_value),(yyvsp[-1].string_value)); }
#line 3316 "ptx.tab.c"
    break;

  case 284:
#line 614 "ptx.y"
                                                    { recognizer->add_1vector_operand((yyvsp[-1].string_value)); }
#line 3322 "ptx.tab.c"
    break;

  case 285:
#line 617 "ptx.y"
                                                  { recognizer->add_scalar_operand((yyvsp[-1].string_value)); }
#line 3328 "ptx.tab.c"
    break;

  case 287:
#line 622 "ptx.y"
                                                     { recognizer->add_builtin_operand((yyvsp[-1].int_value),(yyvsp[0].int_value)); }
#line 3334 "ptx.tab.c"
    break;

  case 288:
#line 623 "ptx.y"
                           { recognizer->add_builtin_operand((yyvsp[0].int_value),-1); }
#line 3340 "ptx.tab.c"
    break;

  case 289:
#line 626 "ptx.y"
                                                                             { recognizer->add_memory_operand(); }
#line 3346 "ptx.tab.c"
    break;

  case 290:
#line 627 "ptx.y"
                                                                                 { recognizer->add_memory_operand(); recognizer->change_memory_addr_space((yyvsp[-3].string_value)); }
#line 3352 "ptx.tab.c"
    break;

  case 291:
#line 628 "ptx.y"
                                                                              { recognizer->change_memory_addr_space((yyvsp[-3].string_value)); }
#line 3358 "ptx.tab.c"
    break;

  case 292:
#line 629 "ptx.y"
                                                                           { recognizer->change_memory_addr_space((yyvsp[-3].string_value)); recognizer->add_memory_operand();}
#line 3364 "ptx.tab.c"
    break;

  case 293:
#line 630 "ptx.y"
                               { recognizer->change_operand_neg(); }
#line 3370 "ptx.tab.c"
    break;

  case 294:
#line 633 "ptx.y"
                                          { recognizer->add_double_operand((yyvsp[-2].string_value),(yyvsp[0].string_value)); recognizer->change_double_operand_type(1); }
#line 3376 "ptx.tab.c"
    break;

  case 295:
#line 634 "ptx.y"
                                               { recognizer->add_double_operand((yyvsp[-3].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(1); recognizer->change_operand_lohi(1); }
#line 3382 "ptx.tab.c"
    break;

  case 296:
#line 635 "ptx.y"
                                               { recognizer->add_double_operand((yyvsp[-3].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(1); recognizer->change_operand_lohi(2); }
#line 3388 "ptx.tab.c"
    break;

  case 297:
#line 636 "ptx.y"
                                             { recognizer->add_double_operand((yyvsp[-3].string_value),(yyvsp[0].string_value)); recognizer->change_double_operand_type(2); }
#line 3394 "ptx.tab.c"
    break;

  case 298:
#line 637 "ptx.y"
                                                      { recognizer->add_double_operand((yyvsp[-4].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(2); recognizer->change_operand_lohi(1); }
#line 3400 "ptx.tab.c"
    break;

  case 299:
#line 638 "ptx.y"
                                                      { recognizer->add_double_operand((yyvsp[-4].string_value),(yyvsp[-1].string_value)); recognizer->change_double_operand_type(2); recognizer->change_operand_lohi(2); }
#line 3406 "ptx.tab.c"
    break;

  case 300:
#line 639 "ptx.y"
                                                { recognizer->add_address_operand((yyvsp[-3].string_value),(yyvsp[0].int_value)); recognizer->change_double_operand_type(3); }
#line 3412 "ptx.tab.c"
    break;

  case 301:
#line 642 "ptx.y"
                              { recognizer->add_literal_int((yyvsp[0].integer_value)); }
#line 3418 "ptx.tab.c"
    break;

  case 302:
#line 643 "ptx.y"
                        { recognizer->add_literal_float((yyvsp[0].float_value)); }
#line 3424 "ptx.tab.c"
    break;

  case 303:
#line 644 "ptx.y"
                         { recognizer->add_literal_double((yyvsp[0].double_value)); }
#line 3430 "ptx.tab.c"
    break;

  case 304:
#line 647 "ptx.y"
                               { recognizer->add_address_operand((yyvsp[0].string_value),0); }
#line 3436 "ptx.tab.c"
    break;

  case 305:
#line 648 "ptx.y"
                               { recognizer->add_address_operand((yyvsp[-1].string_value),0); recognizer->change_operand_lohi(1);}
#line 3442 "ptx.tab.c"
    break;

  case 306:
#line 649 "ptx.y"
                               { recognizer->add_address_operand((yyvsp[-1].string_value),0); recognizer->change_operand_lohi(2); }
#line 3448 "ptx.tab.c"
    break;

  case 307:
#line 650 "ptx.y"
                                        { recognizer->add_address_operand((yyvsp[-2].string_value),(yyvsp[0].int_value)); }
#line 3454 "ptx.tab.c"
    break;

  case 308:
#line 651 "ptx.y"
                        { recognizer->add_address_operand2((yyvsp[0].int_value)); }
#line 3460 "ptx.tab.c"
    break;

  case 309:
#line 654 "ptx.y"
                            { (yyval.int_value) = recognizer->literal_int32((yyvsp[0].integer_value)); }
#line 3466 "ptx.tab.c"
    break;


#line 3470 "ptx.tab.c"

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

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (scanner, recognizer, YY_("syntax error"));
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
            yymsg = YY_CAST (char *, YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
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
        yyerror (scanner, recognizer, yymsgp);
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
                      yytoken, &yylval, scanner, recognizer);
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
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
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
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

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
                  yystos[yystate], yyvsp, scanner, recognizer);
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
  yyerror (scanner, recognizer, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, scanner, recognizer);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[+*yyssp], yyvsp, scanner, recognizer);
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
  return yyresult;
}
#line 657 "ptx.y"


void syntax_not_implemented(yyscan_t yyscanner, ptx_recognizer* recognizer)
{
	printf("Parse error (%s): this syntax is not (yet) implemented:\n", recognizer->gpgpu_ctx->g_filename);
	ptx_error(yyscanner, recognizer, NULL);
	abort();
}
