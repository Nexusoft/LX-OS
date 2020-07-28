#ifndef _NEXUS_FORMULA_H_
#define _NEXUS_FORMULA_H_

#include <stdarg.h>
#include <nexus/der.h>
#include <nexus/vector.h>
#include <nexus/hashtable.h>

/*
 * formula.h: Data types and methods for storing, manipulating, and transcoding
 * logical formulas from the Nexus Authorization Logic.
 *
 * This implementation splits formulas into three fairly distinct levels:
 * - term expressions (aka terms) of type string, integer, bytes, principal, list, or set;
 *   terms are built using constants, logical variables, operators, and
 *   user-defined state variables and state functions.
 * - predicate expressions (aka preds) of boolean type;
 *   predictes are build from terms and built-in predicates and operators.
 * - statements (aka formulas) of boolean type;
 *   statements are built from terms, preds, and connectives.
 * - patterns, which are currently just strings, and which match against statements.
 */

/* There are four different ways in which formulas are represented. The first
 * is simple 7-bit clean, ascii, null-terminated, human readable form.  The
 * second is a canonical, binary DER serialization of the syntax tree. The third
 * is a 7-bit clean PEM (i.e. base64 ascii) encoding of the DER representation.
 * The last is an in-memory tree representation with embedded pointers.
 *
 * Keys can be large, and formulas often reference the same key multiple times.
 * In all the flattened representations, we eliminate duplicates (to save space)
 * by replacing them with reference, as follows: Each key is numbered (starting
 * from 0, as the keys are encountered in an in-order traversal of the formula
 * tree).  Each appearance of a key in the formula tree is replaced by the key's
 * number. The keys are written out seperately, after the tree itself, in order
 * of their number. More specifically, we replace the strings and byte arrays
 * found inside der(...) and pem(...) constructors with references like %i.
 *
 *
 * In the in-memory tree representation, separate copies are made for each
 * appearance of a key.
 */

/* 1st Representation: char * (i.e. Human readable pretty printing)
 *
 * The complete grammar for this encoding is defined in <NAL.lex> and <NAL.y>.
 */

/* 2nd representation: Formula * (i.e. DER binary encoding)
 *
 * This serves as a flattened (serialized) encoding of a logical formula. It is
 * canonical (with respect to the formula syntax), and so is used 
 * when signing a formula.  This representation is binary with embedded null
 * bytes, but has no embedded pointers, so can still be copied and stored easily. 
 *
 * This encoding is considered the default, standard encoding of logical
 * formulas.
 */
typedef struct Formula { unsigned char body[0]; } Formula;

/* 3rd representation: char * (i.e. Base-64 PEM encoded DER)
 *
 * This is a somewhat more verbose form of the DER representation, but uses only
 * 7-bit clean ascii characters, and is null terminated. This may be somewhat
 * more convenient than DER for some applications (e.g. it can be passed
 * directly to printf, or embedded directly in an email message).
 *
 * Not available to the kernel (which lacks base64 support).
 */

/* 4th representation: Form * (i.e. the expanded abstract syntax tree)
 *
 * This data type represents the full AST for a logical formula.  This
 * representation has embedded pointers, and so care must be taken when storing,
 * copying, or transporting such objects. 
 *
 * The structure and contents of the logical formula is accessible, and can be
 * manipulated programatically. Form objects are used not only for the top-level
 * elements of the formula grammar (full logical formulas), but also for all
 * other elements of the grammar (predicates, statements, predicate terms, user-
 * and meta-variables, etc.)
 *
 * This encoding is used internally by guards, and is useful wherever logical
 * formulas need to be manipulated or traversed efficiently.
 */
typedef struct form Form;

// Each node of the AST is tagged, and each tag has three components:
//  type: defines the kind of element (term, pred, stmt, or compacted formula)
//  arity: defines how many child nodes (zero, one, two, or three)
//  subtype: defines which particular element (OR, AND, NOT, etc.)
// But note that not all combinations of type, arity, and subtype are legal: the
// complete list of possible tag values is given below.
//
#define F_TYPE_MASK		(0xffff0000)
#define F_ARITY_MASK		(0x00000f00)
#define F_SUBTYPE_MASK		(0x000000ff)

// TYPE field (these first ones are all top-level formulas)
#define F_TYPE_FORM		(0x00010000) // compacted formula
#define F_TYPE_STMT		(0x00030000) // statement
#define F_TYPE_PRED		(0x00070000) // predicate expression

// TYPE field (these next ones are not top-level formulas)
#define F_TYPE_TERM		(0x00100000) // term
#define F_TYPE_LIST		(0x01000000) // list of items
// #define F_TYPE_PATTERN		(0x10000000) // pattern

#define F_ISSTMT(tag) (((tag) & F_TYPE_FORM) == F_TYPE_FORM)
#define F_ISTERM(tag) (((tag) & F_TYPE_MASK) == F_TYPE_TERM)
#define F_ISLIST(tag) (((tag) & F_TYPE_MASK) == F_TYPE_LIST)

// Lists are used in four places:
//  svar(term, term, term)
//	  ===> [apply, svar, [cons, term, [cons, term, [cons, term, stop]]]]
//  cform, %0 = term, %1 = term
//	  ===> [form, cform, [cons, ..., [cons, ..., stop]]]
//  [ term, term, term ]
//	  ===> [list, [cons, ..., [cons, ..., [cons, ..., stop]]]]
//  { term, term, term }
//	  ===> [set, [cons, ..., [cons, ..., [cons, ..., stop]]]]
// These are all represented using the same linked list data structure using
// LIST_CONS and LIST_NONE, both of type F_TYPE_LIST.  In every case, there is
// a sentinel sitting in front of the list that describes what the list is
// being used as: an argument list, a parameter list, a term list, or a term
// set.

// ARITY field
#define F_IS_EMPTY		(0x00000000) // no children
#define F_IS_UNARY		(0x00000100) // one sub-Form (left)
#define F_IS_BINARY		(0x00000200) // two sub-Forms (left, right)
#define F_IS_TERNARY		(0x00000300) // three sub-Forms (left, mid, right)
#define F_IS_DATA		(0x00000400) // contains pointer to data (data)
#define F_IS_VALUE		(0x00000500) // contains a value

#define F_ISUNARY(tag) (((tag) & F_ARITY_MASK) == F_IS_UNARY)
#define F_ISBINARY(tag) (((tag) & F_ARITY_MASK) == F_IS_BINARY)
#define F_ISTERNARY(tag) (((tag) & F_ARITY_MASK) == F_IS_TERNARY)

// SUBTYPES
enum {
  F_SUBTYPE_UNUSED = 0, // unused
  F_SUBTYPE_AND,
  F_SUBTYPE_OR,
  F_SUBTYPE_IMP,
  F_SUBTYPE_NOT,
  F_SUBTYPE_SAYS,
  F_SUBTYPE_SFOR, // also "SFORON" when ternary
  F_SUBTYPE_CSUB,
  F_SUBTYPE_OSUB,
  F_SUBTYPE_INT,
  F_SUBTYPE_STR,
  F_SUBTYPE_BYTES,
  F_SUBTYPE_TLIST,
  F_SUBTYPE_TSET,
  F_SUBTYPE_PEM,
  F_SUBTYPE_DER,
  F_SUBTYPE_CLOSED,
  F_SUBTYPE_OPEN,
  F_SUBTYPE_ISPRIN,
  F_SUBTYPE_ISINT,
  F_SUBTYPE_ISSTR,
  F_SUBTYPE_ISBYTES,
  F_SUBTYPE_ISTLIST,
  F_SUBTYPE_ISTSET,
  F_SUBTYPE_SIZE,
  F_SUBTYPE_TRUE,
  F_SUBTYPE_FALSE,

  F_SUBTYPE_PREF, // data is a string
  F_SUBTYPE_QVAR, // data is a string
  F_SUBTYPE_SVAR, // data is a string

  F_SUBTYPE_IFF,

  F_SUBTYPE_APPLY, // always binary
  F_SUBTYPE_EQ,
  F_SUBTYPE_GT,
  F_SUBTYPE_LT,
  F_SUBTYPE_GE,
  F_SUBTYPE_LE,
  F_SUBTYPE_NE,
  F_SUBTYPE_IN,
  F_SUBTYPE_PLUS,
  F_SUBTYPE_MINUS,
  F_SUBTYPE_DIGRP,
  F_SUBTYPE_CIGRP,
  F_SUBTYPE_UNION,
  F_SUBTYPE_JOIN,

  F_SUBTYPE_COMPACT,
  F_SUBTYPE_ELT, // list element
  F_SUBTYPE_FORALL,
  F_SUBTYPE_EXISTS
};

#define MAKE_TAG(type, arity, subtype) (F_TYPE_##type | F_IS_##arity | F_SUBTYPE_##subtype)

// following are all of the possible tag values
#define F_FORM_COMPACT		MAKE_TAG(FORM, BINARY, COMPACT)	// S, bindinglist

#define F_STMT_AND		MAKE_TAG(STMT, BINARY, AND)	// S and S'
#define F_STMT_OR		MAKE_TAG(STMT, BINARY, OR)	// S or S'
#define F_STMT_IMP		MAKE_TAG(STMT, BINARY, IMP)	// S imp S'
#define F_STMT_IFF		MAKE_TAG(STMT, BINARY, IFF)	// S iff S'
#define F_STMT_NOT		MAKE_TAG(STMT, UNARY, NOT)	// not S
#define F_STMT_TRUE		MAKE_TAG(STMT, EMPTY, TRUE)	// true
#define F_STMT_FALSE		MAKE_TAG(STMT, EMPTY, FALSE)	// false
#define F_STMT_SAYS		MAKE_TAG(STMT, BINARY, SAYS)	// A says S
#define F_STMT_SFOR		MAKE_TAG(STMT, BINARY, SFOR)	// A speaksfor B
#define F_STMT_SFORON		MAKE_TAG(STMT, TERNARY, SFOR)	// A on pat speaksfor B
#define F_STMT_FORALL		MAKE_TAG(STMT, BINARY, FORALL)	// forall $v : S
#define F_STMT_EXISTS		MAKE_TAG(STMT, BINARY, EXISTS)	// exists $v : S
#define F_STMT_PREF		MAKE_TAG(STMT, DATA, PREF)	// stmt-valued parameter reference

#define F_PRED_EQ		MAKE_TAG(PRED, BINARY, EQ)	// x = y (strings, ints, byte arrays)
#define F_PRED_GT		MAKE_TAG(PRED, BINARY, GT)	// x > y (ints)
#define F_PRED_LT		MAKE_TAG(PRED, BINARY, LT)	// x < y (ints)
#define F_PRED_GE		MAKE_TAG(PRED, BINARY, GE)	// x >= y (ints)
#define F_PRED_LE		MAKE_TAG(PRED, BINARY, LE)	// x <= y (ints)
#define F_PRED_NE		MAKE_TAG(PRED, BINARY, NE)	// x != y (strings, ints, byte arrays)
#define F_PRED_IN		MAKE_TAG(PRED, BINARY, IN)	// x in y (strings, ints, byte arrays)
#define F_PRED_CLOSED		MAKE_TAG(PRED, UNARY, CLOSED)	// closed(x)
#define F_PRED_OPEN		MAKE_TAG(PRED, UNARY, OPEN)	// open(x)
#define F_PRED_ISPRIN		MAKE_TAG(PRED, UNARY, ISPRIN)	// prin(x)
#define F_PRED_ISINT		MAKE_TAG(PRED, UNARY, ISINT)	// int(x)
#define F_PRED_ISSTR		MAKE_TAG(PRED, UNARY, ISSTR)	// str(x)
#define F_PRED_ISBYTES		MAKE_TAG(PRED, UNARY, ISBYTES)	// bytes(x)
#define F_PRED_ISTLIST		MAKE_TAG(PRED, UNARY, ISTLIST)  // list(x)
#define F_PRED_ISTSET		MAKE_TAG(PRED, UNARY, ISTSET)   // set(x)

#define F_TERM_APPLY		MAKE_TAG(TERM, BINARY, APPLY)	// svar(termlist)
#define F_TERM_PLUS		MAKE_TAG(TERM, BINARY, PLUS)	// x + y (strings, ints)
#define F_TERM_MINUS		MAKE_TAG(TERM, BINARY, MINUS)	// x - y (ints)
#define F_TERM_SIZE		MAKE_TAG(TERM, UNARY, SIZE)	// size(x)
#define F_TERM_INT		MAKE_TAG(TERM, VALUE, INT)	// integer constant (value is the signed 32-bit integer constant)
#define F_TERM_STR		MAKE_TAG(TERM, DATA, STR)	// string constant (value is the string)
#define F_TERM_BYTES		MAKE_TAG(TERM, DATA, BYTES)	// byte array constant (data is the bytes)
#define F_TERM_UNION		MAKE_TAG(TERM, BINARY, UNION)	// union(x, y) (sets)
#define F_TERM_JOIN		MAKE_TAG(TERM, BINARY, JOIN)	// join(x, y) (lists)
#define F_TERM_SVAR		MAKE_TAG(TERM, DATA, SVAR)	// state variable or state function
#define F_TERM_QVAR		MAKE_TAG(TERM, DATA, QVAR)	// quantified or lambda variable
#define F_TERM_PREF		MAKE_TAG(TERM, DATA, PREF)	// term-valued parameter reference
#define F_TERM_PEM		MAKE_TAG(TERM, UNARY, PEM)	// pem(...)
#define F_TERM_DER		MAKE_TAG(TERM, UNARY, DER)	// der(...)
#define F_TERM_CSUB		MAKE_TAG(TERM, BINARY, CSUB)	// x . y
#define F_TERM_OSUB		MAKE_TAG(TERM, BINARY, OSUB)	// x : y
#define F_TERM_TLIST		MAKE_TAG(TERM, UNARY, TLIST)	// [ termlist ]
#define F_TERM_TSET		MAKE_TAG(TERM, UNARY, TSET)	// { termset }
#define F_TERM_DIGRP		MAKE_TAG(TERM, BINARY, DIGRP)	// [( v : S )]
#define F_TERM_CIGRP		MAKE_TAG(TERM, BINARY, CIGRP)	// [[ v : S ]]

#define F_LIST_NONE		MAKE_TAG(LIST, EMPTY, ELT)	// empty argument list
#define F_LIST_CONS		MAKE_TAG(LIST, BINARY, ELT)	// argument, remainder

struct form {
	int tag;

	// UNARY, BINARY, and TERNARY use the following fields:
	Form *left;
	Form *mid;
	Form *right;

	// DATA use the following fields:
	char *data; // len bytes if len >= 0, else null terminated string
	int len;

	// VALUE uses the following field:
	int value;
};

// create a new formula node manually
// Pointers passed to form_new() and form_newdata() are NOT cloned 
// and will be freed when form_free() is called.
Form *form_new(int tag,
    Form *left,
    Form *mid /* null for UNARY, BINARY */,
    Form *right /* null for UNARY */);
Form *form_newdata(int tag, void * data, int len /* -1 for null-terminated string */);
Form *form_newval(int tag, int value);

// duplicate a Form object (deep copy)
Form *form_dup(Form *f);

// duplicate a Form object, replacing each subterm equal to s with a copy of v
Form *form_repl(Form *f, Form *s, Form *v);
Form *form_repl_all(Form *f, PointerVector *s_list, PointerVector *v_list);

// compare two Form objects for equality
// returns zero if f and g are identical; non-zero otherwise
int form_cmp(Form *f, Form *g);

// free a Form object (recursive free)
void form_free(Form *f);

// translate between AST-based Form and a pretty printed string
// if width == 0, put it all on one line, verbatim
// if width > 0, split into lines every width characters or so
// if width == -1, put it all on line line, but elide boring parts
// if width < -1, split into lines every -width characters or so
char *form_to_pretty(Form *f, int width);

void form_set_elide_mode(int s_compact, int s_min, int s_left, int s_mid, int s_right,
			 int b_compact, int b_min, int b_left, int b_mid, int b_right);

#define form_s(f) (_scr[_nscr++] = form_to_pretty(f, 0)) /* form to pretty, no abbreviation */
#define form_a(f) (_scr[_nscr++] = form_to_pretty(f, -80)) /* form to pretty, abbreviated */
#define form_a0(f) (_scr[_nscr++] = form_to_pretty(f, -1)) /* form to pretty, abbreviated, one line */
#define form_printf(args...) ({ \
    int _nscr = 0; \
    char *_scr[20]; \
    int _ret = printf(args); \
    while (_nscr-- > 0) \
      if (_scr[_nscr]) nxcompat_free(_scr[_nscr]); \
    _ret; }) /* usage: form_printf("... blah %s blah ...", ..., form_s(f), ...); */
#define form_fprintf(args...) ({ \
    int _nscr = 0; \
    char *_scr[20]; \
    int _ret = fprintf(args); \
    while (_nscr-- > 0) \
      if (_scr[_nscr]) nxcompat_free(_scr[_nscr]); \
    _ret; }) /* usage: form_printf("... blah %s blah ...", ..., form_s(f), ...); */

#ifndef nop__NEXUSKERNEL__
// The kernel never needs to parse pretty-printed formulas, and so does not
// implement form_from_pretty(). This is nice, because it saves us from having
// to include complicated bison and flex code in the kernel.
Form *form_from_pretty(const char *pretty);
Form *term_from_pretty(const char *pretty); // same but parses a term instead
Form *form_or_term_from_pretty(const char *pretty); // same but parses either
Form *form_fmt(char *pretty, ...); /* like form_from_pretty */
Form *term_fmt(char *pretty, ...); /* like term_from_pretty */
int form_vscan(Form *f, Form *fmt, va_list args); /* like unify */
int form_scan(Form *f, char *fmt_pretty, ...); /* like form_fmt()/term_fmt() then unify */
int form_scanf(Form *f, Form *fmt, ...); /* like unify */
#endif // __NEXUSKERNEL__

int form_qstr_escape(char *buf, int len, char *str, int justify);

// translate between AST-based Form and a DER serialized buffer
Formula *form_to_der(Form *f);
Form *form_from_der(Formula *der);
int der_msglen(const unsigned char *der);
static inline int Formula_len(Formula *der) { return der_msglen((unsigned char *)der->body); }
#ifdef nop__NEXUSKERNEL__
int der_msglen_u(const char *uder);
#endif // __NEXUSKERNEL__

#ifndef nop__NEXUSKERNEL__
// translate between AST-based Form and a PEM serialized string
char *form_to_pem(Form *f);
Form *form_from_pem(char *pem);

//char *der_to_pem(Formula *form); // just do der_to_pem(form->body);
//Formula *der_from_pem(char *pem); // just do (Formula *)der_from_pem(pem);

#endif // __NEXUSKERNEL__

// check if f is a well-formed, top-level formula; returns non-zero if so
int form_is_proper(Form *f);

// find free quantified variables in a term or statement
struct HashTable *form_free_qvars(Form *f);

// check and return the type of expression f 
int form_check_level(Form *f);

int form_replace_qvar(Form *f, char *qvar, Form *repl);
int form_replace_param(Form *f, char *pref, Form *repl);
int form_set_param_blind(Form *f, char *pref, Form *repl);
int form_unify_params(Form *f, Form *pattern, struct HashTable *map);
int form_replace_all(Form *f, struct HashTable *replacements /* varname -> repl */);

// SignedFormula: a statement S with attached cryptographic signature.
//
// The statement S is always in one of two form:
//  - K says S2
//  - K.subname1...subnameN says S2
// In both cases, key K is the public half of the key that produced the
// signature. After validating the signature, the statement S can be taken at
// face value. This is because the public half always appears as the left-most
// term in the statement that was signed.
//
// (Note: The second form can be thought of as equivalent to (but
// more consise than) signing "K says K.subname1...subnameN says S2" then
// eliminating the extraneous "K says" using a deduction rule. 
typedef struct SignedFormula { unsigned char body[0]; } SignedFormula;

// Functions for producing signed formulas appear elsewhere. E.g. the vkey API
// includes a function for signing formulas with user-level keys, and verifying
// formulas signed by arbitrary keys, and the labelstore API includes a function
// for obtaining formulas (in the form of labels in a labelstore) signed by a
// kernel-level key, and importing formulas signed by arbitrary keys into a
// labelstore.
//
// These functions take an arbitrary formula, and will prepend "K says" if
// needed, to ensure that the signed statement has the correct form.

// kernel: see <nexus/kvkey.h> for:
// SignedFormula *formula_sign(Formula *f, KVKey_nsk *key);

// user: see <nexus/vkey.h> for:
// SignedFormula *formula_sign(Formula *f, VKey *key);
// SignedFormula *form_sign(Form *f, VKey *key);

// check the signature on signedformula; returns 0 on success, <0 on error
int signedform_verify(SignedFormula *der);

// these do not allocate memory: they return pointers to the insides of the argument
Formula *signedform_get_formula(SignedFormula *der);
Form *form_get_speaker_pubkey(Form *f);

int der_pub_encode(unsigned char *buf, int len, unsigned char *modulus, int moduluslen, int algtype);

struct x509_st;
char *der_key_from_cert(struct x509_st *x);
Formula *form_bind_cert_pubkey(struct x509_st *cert);

Form *read_signed_file(char *dir, char *sigfile, SignedFormula **sig_form);

#endif // _NEXUS_FORMULA_H_
