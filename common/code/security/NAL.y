/* NAL.y -- parser for Nexus Authentication Logic */

%{

#define YYSTYPE Form *

#include "NAL.h"

#define YYPARSE_PARAM yyscanner
#define YYLEX_PARAM yyscanner

#define YYERROR_VERBOSE 1
#define yyerror(msg) yyerror_localized(yyscanner, msg, &yylloc, &yyerror_range[0], &yyerror_range[1])
void yyerror_localized(nal_scan_t scanner, char *msg, YYLTYPE *yylloc, YYLTYPE *yyerr0, YYLTYPE *yyerr1) {
	printf("NAL parse error at line %d col %d - %d: '%s'\n",
		yylloc->first_line, yylloc->first_column, yylloc->last_column, msg);
	struct nal_parse_results *fpd = nal_scanner_results(scanner);
	if (fpd && !fpd->errmsg) {
		fpd->errmsg = strdup(msg);
		fpd->errline = yylloc->first_line;
		fpd->errlineend = yylloc->last_line;
		fpd->errcol = yylloc->first_column;
		fpd->errcolend = yylloc->last_column;
	}
}

// declare to suppress gcc undefined warnings
int yylex(YYSTYPE * yylval_param, YYLTYPE * yylloc_param, nal_scan_t yyscanner);

%}

%error-verbose
%locations
%pure-parser
%defines
%debug

%token LPAREN "("
%token RPAREN ")"
%token LBRACE "{"
%token RBRACE "}"
%token LBRACK "["
%token RBRACK "]"
%token LCBRACK "[["
%token RCBRACK "]]"
%token LOBRACK "[("
%token ROBRACK ")]"
%token NOT "not"
%token IMP "imp"
%token OR "or"
%token AND "and"
%token IFF "iff"
%token SAYS "says"
%token SPEAKSFOR "speaksfor"
%token ON "on"
%token FORALL "forall"
%token EXISTS "exists"
%token TRUE "true"
%token FALSE "false"
%token UNION "union"
%token JOIN "join"
%token PEM "pem"
%token DER "der"
%token SIZE "size"
%token ISPRIN "prin"
%token ISINT "int"
%token ISSTR "str"
%token ISLIST "list"
%token ISSET "set"
%token ISBYTES "bytes"
%token CLOSED "closed"
%token OPEN "open"

%token LT "<"
%token GT ">"
%token LE "<="
%token GE ">="
%token EQ "="
%token NE "!="
%token IN "in"
%token COMMA ","
%token PLUS "+"
%token MINUS "-"
%token DOT "."
%token ODOT ":"

%token STRING
%token BYTES
%token INTEGER

%token POSPREF
%token TNAMEDPREF
%token SNAMEDPREF
%token TPRINTFPREF
%token SPRINTFPREF

%token SVAR
%token QVAR

/* These associativity and precedence rules must match those for printing in formula.c
 * Things near the top of the list have low precedence, and get parsed "later".
 * Things near the end of the list have high precedence, and get parsed "earlier".
 * NB: Bison insists that low precedence things come first in the list, which is
 * backwards from the order most tables whould show precedence. "Rank" is the
 * inverse of precedence. Most tables explaining the precedence of C or C++
 * confuse rank for precedence, and wind up explaining the table exactly the
 * wrong way.
 */

/* low precedence, high rank */
%right SAYS FORALL EXISTS GROUP
%nonassoc IFF
%right IMP 
%left OR
%left AND
%right NOT
%nonassoc SPEAKSFOR ON
%nonassoc LT GT LE GE EQ NE
%nonassoc PLUS MINUS IN
%left DOT ODOT
/* high precedence, low rank */

%start strictformula

%%

strictformula:
	fullform {
		struct nal_parse_results *fpd = nal_scanner_results(yyscanner);
		if (fpd) {
		  fpd->f = $$ = $1;
		  /* fpd->errmsg = 0; */
		  /* fpd->errcol = 0; */
		}
	}
;

termlist:
	/* empty */ { $$ = form_new(F_LIST_NONE, 0, 0, 0); }
	| term termlisttail { $$ = form_new(F_LIST_CONS, $1, 0, $2); }
;

termlisttail:
	/* empty */ { $$ = form_new(F_LIST_NONE, 0, 0, 0); }
	| "," term termlisttail { $$ = form_new(F_LIST_CONS, $2, 0, $3); }
;

termpref:
	  POSPREF
	| TNAMEDPREF
	| TPRINTFPREF
;

qvar:
	  termpref
	| QVAR
;

term:
	INTEGER
	| STRING
	| BYTES
	| qvar
	| SVAR
	| SVAR "(" termlist ")" { $$ = form_new(F_TERM_APPLY, $1, 0, $3); }
	| term "." term { $$ = form_new(F_TERM_CSUB, $1, 0, $3); }
	| term ":" term { $$ = form_new(F_TERM_OSUB, $1, 0, $3); }
	| term "+" term { $$ = form_new(F_TERM_PLUS, $1, 0, $3); }
	| term "-" term { $$ = form_new(F_TERM_MINUS, $1, 0, $3); }
	| "union" "(" term "," term ")" { $$ = form_new(F_TERM_UNION, $3, 0, $5); }
	| "join" "(" term "," term ")" { $$ = form_new(F_TERM_JOIN, $3, 0, $5); }
	| "pem" "(" term ")" { $$ = form_new(F_TERM_PEM, $3, 0, 0); }
	| "der" "(" term ")" { $$ = form_new(F_TERM_DER, $3, 0, 0); }
	| "[[" qvar ":" stmt "]]" %prec GROUP { $$ = form_new(F_TERM_CIGRP, $2, 0, $4); }
	| "[(" qvar ":" stmt ")]" %prec GROUP { $$ = form_new(F_TERM_DIGRP, $2, 0, $4); }
	| "size" "(" term ")" { $$ = form_new(F_TERM_SIZE, $3, 0, 0); }
	| "[" termlist "]" { $$ = form_new(F_TERM_TLIST, $2, 0, 0); }
	| "{" termlist "}" { $$ = form_new(F_TERM_TSET, $2, 0, 0); }
	| "(" term ")" { $$ = $2; }
;

pred:
	  term "=" term  { $$ = form_new(F_PRED_EQ, $1, 0, $3); }
	| term "!=" term { $$ = form_new(F_PRED_NE, $1, 0, $3); }
	| term ">" term  { $$ = form_new(F_PRED_GT, $1, 0, $3); }
	| term ">=" term { $$ = form_new(F_PRED_GE, $1, 0, $3); }
	| term "<" term  { $$ = form_new(F_PRED_LT, $1, 0, $3); }
	| term "<=" term { $$ = form_new(F_PRED_LE, $1, 0, $3); }
	| term "in" term { $$ = form_new(F_PRED_IN, $1, 0, $3); }
	| "open" "(" term ")"   { $$ = form_new(F_PRED_OPEN, $3, 0, 0); }
	| "closed" "(" term ")" { $$ = form_new(F_PRED_CLOSED, $3, 0, 0); }
	| "prin" "(" term ")"   { $$ = form_new(F_PRED_ISPRIN, $3, 0, 0); }
	| "int" "(" term ")"    { $$ = form_new(F_PRED_ISINT, $3, 0, 0); }
	| "str" "(" term ")"    { $$ = form_new(F_PRED_ISSTR, $3, 0, 0); }
	| "bytes" "(" term ")"  { $$ = form_new(F_PRED_ISBYTES, $3, 0, 0); }
	| "list" "(" term ")"   { $$ = form_new(F_PRED_ISTLIST, $3, 0, 0); }
	| "set" "(" term ")"    { $$ = form_new(F_PRED_ISTSET, $3, 0, 0); }
;

/* pat:
   STRING
   | termpref
; */

stmtpref:
	SNAMEDPREF
	| SPRINTFPREF
;

stmt:
	stmtpref
	| pred
	| stmt "and" stmt { $$ = form_new(F_STMT_AND, $1, 0, $3); }
	| stmt "or" stmt  { $$ = form_new(F_STMT_OR,  $1, 0, $3); }
	| stmt "imp" stmt { $$ = form_new(F_STMT_IMP, $1, 0, $3); }
	| stmt "iff" stmt { $$ = form_new(F_STMT_IFF, $1, 0, $3); }
	| "not" stmt      { $$ = form_new(F_STMT_NOT, $2, 0, 0); }
	| "true"	  { $$ = form_new(F_STMT_TRUE, 0, 0, 0); }
	| "false"	  { $$ = form_new(F_STMT_FALSE, 0, 0, 0); }
	| term "says" stmt { $$ = form_new(F_STMT_SAYS, $1, 0, $3); }
	| term "speaksfor" term { $$ = form_new(F_STMT_SFOR, $1, 0, $3); }
	/* | term "on" pat "speaksfor" term { $$ = form_new(F_STMT_SFORON, $1, * $3, $5); } */
	| "forall" qvar ":" stmt %prec FORALL { $$ = form_new(F_STMT_FORALL, $2, 0, $4); }
	| "exists" qvar ":" stmt %prec EXISTS { $$ = form_new(F_STMT_EXISTS, $2, 0, $4); }
	| "(" stmt ")"	  { $$ = $2; }
;

form:
	stmt
	| term
;

fullform:
	form paramlist { $$ = form_new(F_FORM_COMPACT, $1, 0, $2); }
;

paramlist:
	/* empty */ { $$ = form_new(F_LIST_NONE, 0, 0, 0); }
	| "," paramval paramlist { $$ = form_new(F_LIST_CONS, $2, 0, $3); }
;

paramval:
	term
	| termpref "=" term  { $$ = form_new(F_PRED_EQ, $1, 0, $3); }
	| stmtpref "=" stmt  { $$ = form_new(F_STMT_IFF, $1, 0, $3); }
;

%%

/** Parse formula or term. 
    Does not free input string */
Form *form_or_term_from_pretty(const char *c) {
	nal_scan_t scanner;
	struct nal_parse_results fpd;
	memset(&fpd, 0, sizeof(struct nal_parse_results));
	nal_create_scanner(&scanner, c, &fpd);
	yyparse(scanner);
	nal_destroy_scanner(scanner);
	if (!fpd.f) {
		int i;
		fprintf(stderr, "error: %s\n", c);
		fprintf(stderr, "------");
		for (i = 0; i < fpd.errcol; i++) fprintf(stderr, "-");
		for ( ; i <= fpd.errcolend; i++) fprintf(stderr, "^");
		fprintf(stderr, "\n  (%s)\n", fpd.errmsg);
		return 0;
	}
	if (fpd.errmsg) {
		// this case could be used to scan a partial string...
		// but just fail for now
		int i;
		fprintf(stderr, "error: %s\n", c);
		fprintf(stderr, "------");
		for (i = 0; i < fpd.errcol; i++) fprintf(stderr, "-");
		for ( ; i <= fpd.errcolend; i++) fprintf(stderr, "^");
		fprintf(stderr, "\n  (%s)\n", fpd.errmsg);
		form_free(fpd.f);
		return 0;
	}
	// normalize by substituting all parameters
	Form *f = fpd.f->left;
	Form *paramlist = fpd.f->right;
	nxcompat_free(fpd.f);
	fpd.f = 0;
	Form *it;
	int i = 0;
	// don't worry about typing here, it would not have gotten past the
	// parser if we tried to put a term where we need a stmt, or vice versa
	for (it = paramlist; it->tag == F_LIST_CONS; it = it->right, i++) {
		Form *param = it->left;
		char *pref;
		Form *repl;
		if (param->tag == F_PRED_EQ && param->left->tag == F_TERM_PREF) {
		    pref = param->left->data;
		    repl = param->right;
		} else if (param->tag == F_STMT_IFF && param->left->tag == F_STMT_PREF) {
		    pref = param->left->data;
		    repl = param->right;
		} else {
		      char prefbuf[20];
		      pref = prefbuf;
		      sprintf(pref, "%%%d", i);
		      repl = param;
		}
		int used = form_replace_param(f, pref, repl); /* use blind replace? nah */
		if (used < 0) {
		      form_free(f);
		      f = NULL;
		      break;
		}
		if (!used) { /* fail if not used? warn for now */
		      fprintf(stderr, "warning: parameter %s is never used\n", pref);
		}
	}
	form_free(paramlist);
	return f;
}

/** Parse formula. 
    Does not free input string */
Form *form_from_pretty(const char *c) {
	Form *f = form_or_term_from_pretty(c);
	if (f && !F_ISSTMT(f->tag)) {
	    fprintf(stderr, "error: expected statement, but found a term\n");
	    form_free(f);
	    return NULL;
	}
	return f;
}

/** Parse term. 
    Does not free input string */
Form *term_from_pretty(const char *c) {
	Form *f = form_or_term_from_pretty(c);
	if (f && F_ISSTMT(f->tag)) {
	    fprintf(stderr, "error: expected term, but found a statement\n");
	    form_free(f);
	    return NULL;
	}
	return f;
}

// return -1 for error, 0 w/ fmt_start=NULL for "not a scanf parameter"
static int get_scanf_param(char *pref, int *idx, char **fmt_start, char **fmt_end) {
  assert(pref[0] == '%');
  if (pref[1] == '%') return 0; // escaped scanf
  char *s = strchr(pref, '{');
  if (!s) return 0; // not scanf
  char *e = strchr(pref, '}');
  if (!e) return -1; // mangled
  int k = 0;
  char *c = pref+1;
  while (*c >= '0' && *c <= '9') k = 10*k + ((*(c++)) - '0');
  if (c != s) return -1; // junk before opening
  if (e[1] != '\0') return -1; // junk after close
  if (e - s < 2) return -1; // nothing between opening and close

  if (s > pref+1) *idx = k;
  *fmt_start = s+1;
  *fmt_end = e;
  return 0;
}

static int form_peek_params(Form *f, int *count /* = 0 */, int *implicit_numbering /* = -1 */, char **fmts) {
  if (!f) return 0;
  if ((f->tag & F_SUBTYPE_MASK) == F_SUBTYPE_PREF && f->len == -1) {
    char *s = NULL, *e = NULL;
    int idx = -1;
    if (get_scanf_param(f->data, &idx, &s, &e)) return -1; // mangled
    if (!s) return 0; // not scanf
    if (idx == -1) { // implicit numbering
      if (*implicit_numbering == 0) return -1; // mismatch numbering schemes
      *implicit_numbering = 1;
      idx = *count;
      *count = *count + 1;
    } else { // explicit numbering
      if (*implicit_numbering == 1) return -1; // mismatch numbering schemes
      *implicit_numbering = 0;
      if (idx+1 > *count) *count = idx+1;
    }
    if (fmts && fmts[idx] && strcmp(fmts[idx], s)) return -1; // conflicting use of arg[idx]
    else if (fmts) fmts[idx] = s;
    if (!strncmp(s, "bytes", 5)) {
      int len = -1;
      if (sscanf(s, "bytes:%d}", &len) == 1) { // format holds length
	if (len < 0) return -1; // mangled
      } else if (!*implicit_numbering && sscanf(s, "bytes:%%%d}", &idx) == 1) {
	if (idx+1 > *count) *count = idx+1; // length is in arg[idx]
      } else if (*implicit_numbering && !strcmp(s, "bytes}")) {
	idx = *count; // length is in arg[count]
	*count = *count + 1;
      } else {
	return -1; // mangled reference
      }
      if (len < 0) { // no explicit length: convert length as a param
	s = "int}";
	if (fmts && fmts[idx] && strcmp(fmts[idx], s)) return -1; // conflicting use of arg[idx]
	else if (fmts) fmts[idx] = s;
      }
    }
    return 0;
  }
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_UNARY:
	if (form_peek_params(f->left, count, implicit_numbering, fmts)) return -1;
	return 0;
    case F_IS_BINARY:
	if (form_peek_params(f->left, count, implicit_numbering, fmts)) return -1;
	if (form_peek_params(f->right, count, implicit_numbering, fmts)) return -1;
	return 0;
    case F_IS_TERNARY:
	if (form_peek_params(f->left, count, implicit_numbering, fmts)) return -1;
	if (form_peek_params(f->mid, count, implicit_numbering, fmts)) return -1;
	if (form_peek_params(f->right, count, implicit_numbering, fmts)) return -1;
	return 0;
    default:
	return 0;
  }
}

static int form_vfmtr(Form *f, Form **cargs, int *idx, int count) {
  if (!f) return 0;
  if ((f->tag & F_SUBTYPE_MASK) == F_SUBTYPE_PREF && f->len == -1) {
    char *s = NULL, *e = NULL;
    if (get_scanf_param(f->data, idx, &s, &e)) return -1; // mangled
    if (!s && f->data[0] == '%' && f->data[1] == '%') {
      // reduce escaping
      s = strdup(f->data + 1);
      nxcompat_free(f->data);
      f->data = s;
      return 0;
    }
    if (!s) return 0; // not scanf
    assert(*idx < count);
    assert(cargs && cargs[*idx]);
    Form *dup = form_dup(cargs[*idx]);
    *idx = *idx + 1;
    if (dup->tag == F_TERM_BYTES) {
      if (!strncmp(s, "bytes}", 6))
	*idx = *idx + 1; // for implicit length
      // other two cases (explicit length param, constant length) don't increment
    }
    nxcompat_free(f->data);
    *f = *dup;
    return 0;
  }
  /* do blind substitution for now: don't worry abouot forall/exists variable capture */
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_UNARY:
	if (form_vfmtr(f->left, cargs, idx, count)) return -1;
	return 0;
    case F_IS_BINARY:
	if (form_vfmtr(f->left, cargs, idx, count)) return -1;
	if (form_vfmtr(f->right, cargs, idx, count)) return -1;
	return 0;
    case F_IS_TERNARY:
	if (form_vfmtr(f->left, cargs, idx, count)) return -1;
	if (form_vfmtr(f->mid, cargs, idx, count)) return -1;
	if (form_vfmtr(f->right, cargs, idx, count)) return -1;
	return 0;
    default:
	return 0;
  }

  return 0;
}

static int form_convert_args(int count, char **fmts, Form **cargs, va_list args) {
  int i, j, len;

  for (i = 0; i < count; i++) {
    char *fmt = fmts[i];
    char *e = strchr(fmt, '}');
    int n = e - fmt;
    assert (n > 0);
    if (!strcmp(fmt, "int}")) {
      int d = va_arg(args, int);
      cargs[i] = form_newval(F_TERM_INT, d);
    } else if (!strcmp(fmt, "str}")) {
      char *s = va_arg(args, char *);
      if (s)
	cargs[i] = form_newdata(F_TERM_STR, strdup(s), -1);
    } else if (sscanf(fmt, "bytes:%d}", &len) == 1) {
      if (len < 0) return -1; // bad length
      char *s = va_arg(args, char *);
      if (len == 0) {
	cargs[i] = form_newdata(F_TERM_BYTES, NULL, 0);
      } else {
	char *m = nxcompat_alloc(len);
	memcpy(m, s, len);
	cargs[i] = form_newdata(F_TERM_BYTES, m, len);
      }
      // len was part of format, so no va_arg() and no parameter input for length
      // assert(++i < count);
      // fmt = fmts[i];
      // assert(!strcmp(fmt, "int}"));
      // len = va_arg(args, int); 
      // cargs[i] = form_newval(F_TERM_INT, len);
    } else if (sscanf(fmt, "bytes:%%%d}", &j) ==1) {
      char *s = va_arg(args, char *);
      // do in a second pass to get length right, but cache the pointer somewhere
      cargs[i] = form_newdata(F_TERM_BYTES, NULL, 0);
      cargs[i]->data = s; // harmless b/c of zero length
    } else if (!strcmp(fmt, "bytes}")) {
      char *s = va_arg(args, char *);
      // must be implict numbering... next arg is length
      assert(++i < count);
      fmt = fmts[i];
      assert(!strcmp(fmt, "int}"));
      len = va_arg(args, int);
      if (len < 0) return -1; // bad length
      if (len == 0) {
	cargs[i-1] = form_newdata(F_TERM_BYTES, NULL, 0);
      } else {
	char *m = nxcompat_alloc(len);
	memcpy(m, s, len);
	cargs[i-1] = form_newdata(F_TERM_BYTES, m, len);
      }
      cargs[i] = form_newval(F_TERM_INT, len);
    } else if (!strcmp(fmt, "term}") || !strcmp(fmt, "Stmt}")) {
      Form *f = va_arg(args, Form *);
      if (!f) return -1;
      cargs[i] = form_dup(f);
    } else if (!strcmp(fmt, "term/der}") || !strcmp(fmt, "Stmt/der")) {
      // todo
      return -1;
    } else if (!strcmp(fmt, "term/pem}") || !strcmp(fmt, "Stmt/pem")) {
      // todo
      return -1;
    } else {
      return -1;
    }
  }
  for (i = 0; i < count; i++) {
    char *fmt = fmts[i];
    if (sscanf(fmt, "bytes:%%%d}", &j) ==1) {
      Form *g = cargs[i];
      assert(g && g->tag == F_TERM_BYTES && g->len == 0);
      char *s = g->data;
      assert(!strcmp(fmts[j], "int}"));
      Form *f = cargs[j];
      assert(f && f->tag == F_TERM_INT);
      len = f->value;
      if (len < 0) return -1;
      if (len == 0) {
	g->data = NULL;
      } else {
	g->data = nxcompat_alloc(len);
	memcpy(g->data, s, len);
      }
    }
  }
  return 0;
}

static int form_vfmt(Form *f, va_list args) {
  // count formats
  int i, err, count = 0, implicit_numbering = -1, idx = 0;
  if (form_peek_params(f, &count, &implicit_numbering, NULL)) {
    fprintf(stderr, "error: form_fmt(): mangled scanf-style parameter\n");
    return -1;
  }
  if (!count)
    return form_vfmtr(f, NULL, &idx, 0); // just removes escaped parameters

  // gather formats
  char **fmts = nxcompat_alloc(count * sizeof(char *));
  memset(fmts, 0, count * sizeof(char *));
  count = 0;
  form_peek_params(f, &count, &implicit_numbering, fmts);

  // convert to args
  Form **cargs = nxcompat_alloc(count * sizeof(Form *));
  memset(cargs, 0, count * sizeof(Form *));
  err = form_convert_args(count, fmts, cargs, args);
  nxcompat_free(fmts);
  if (err) {
    for (i = 0; i < count; i++)
      if (cargs[i]) form_free(cargs[i]);
    nxcompat_free(cargs);
    return err;
  }

  err = form_vfmtr(f, cargs, &idx, count);
  for (i = 0; i < count; i++)
    if (cargs[i]) form_free(cargs[i]);
  nxcompat_free(cargs);

  return err;
}

Form *form_fmt(char *c, ...) { // alternate names: form_format()?, form_scanf()?
  va_list args;
  Form *f = form_from_pretty(c);
  if (!f) return NULL;

  va_start(args, c);
  int err = form_vfmt(f, args);
  va_end(args);
  if (err) {
    form_free(f);
    return NULL;
  }
  return f;
}

Form *term_fmt(char *c, ...) { // alternate names: term_format()?, term_scanf()?
  va_list args;
  Form *f = term_from_pretty(c);
  if (!f) return NULL;

  va_start(args, c);
  int err = form_vfmt(f, args);
  va_end(args);
  if (err) {
    form_free(f);
    return NULL;
  }
  return f;
}

static int form_put_dummies(Form *f, char **dummies, int count, int *idx) {
  if (!f) return 0;
  if ((f->tag & F_SUBTYPE_MASK) == F_SUBTYPE_PREF && f->len == -1) {
    char *s = NULL, *e = NULL;
    if (get_scanf_param(f->data, idx, &s, &e)) return -1; // mangled
    if (!s && f->data[0] == '%' && f->data[1] == '%') {
      // reduce escaping
      s = strdup(f->data + 1);
      nxcompat_free(f->data);
      f->data = s;
      return 0;
    }
    if (!s) return 0; // not scanf
    assert(*idx < count);
    nxcompat_free(f->data);
    f->data = strdup(dummies[*idx]);
    *idx = *idx + 1;
    return 0;
  }
  /* do blind substitution for now: don't worry abouot forall/exists variable capture */
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_UNARY:
	if (form_put_dummies(f->left, dummies, count, idx)) return -1;
	return 0;
    case F_IS_BINARY:
	if (form_put_dummies(f->left, dummies, count, idx)) return -1;
	if (form_put_dummies(f->right, dummies, count, idx)) return -1;
	return 0;
    case F_IS_TERNARY:
	if (form_put_dummies(f->left, dummies, count, idx)) return -1;
	if (form_put_dummies(f->mid, dummies, count, idx)) return -1;
	if (form_put_dummies(f->right, dummies, count, idx)) return -1;
	return 0;
    default:
	return 0;
  }
  return 0;
}

static int form_convert_params(int count, char **fmts, Form **cargs, va_list args) {
  int i, j, len;

  // first pass, figure out lengths and store stomewhere
  for (i = 0; i < count; i++) {
    char *fmt = fmts[i];
    if (sscanf(fmt, "bytes:%%%d}", &j) == 1) {
      Form *g = cargs[i];
      if(!g || g->tag != F_TERM_BYTES) return -1; // unification error
      assert(!strcmp(fmts[j], "int}"));
      Form *h = form_newval(F_TERM_INT, g->len); // cache in cargs placeholder
      if (cargs[j]) {
	if (form_cmp(h, cargs[j])) return -1; // unification error
	form_free(h);
      } else {
	cargs[j] = h;
      }
    }
  }

  for (i = 0; i < count; i++) {
    char *fmt = fmts[i];
    char *e = strchr(fmt, '}');
    int n = e - fmt;
    assert (n > 0);
    Form *f = cargs[i];
    assert(f);
    if (!strcmp(fmt, "int}")) {
      if (f->tag != F_TERM_INT) return -1; // type mismatch
      int *d = va_arg(args, int *);
      *d = f->value;
    } else if (!strcmp(fmt, "str}")) {
      if (f->tag != F_TERM_STR) return -1;
      char **s = va_arg(args, char **); // note: not scanf semantics: uses char** instead
      *s = strdup(f->data);
    } else if (sscanf(fmt, "bytes:%d}", &len) == 1) {
      if (f->tag != F_TERM_BYTES) return -1;
      if (f->len != len) return -1;
      char **s = va_arg(args, char **); // note: uses char**
      if (len == 0) {
	*s = NULL;
      } else {
	char *m = nxcompat_alloc(len);
	memcpy(m, f->data, len);
	*s = m;
      }
      // len was part of format, so no va_arg() and no parameter output for length
      // assert(++i < count);
      // fmt = fmts[i];
      // assert(!strcmp(fmt, "int}"));
      // ... va_arg(args, int) ... 
    } else if (sscanf(fmt, "bytes:%%%d}", &j) ==1) {
      if (f->tag != F_TERM_BYTES) return -1;
      // len was cached in a previous pass to put length right
      char **s = va_arg(args, char **); // note: uses char**
      if (f->len == 0) {
	*s = NULL;
      } else {
	char *m = nxcompat_alloc(f->len);
	memcpy(m, f->data, f->len);
	*s = m;
      }
    } else if (!strcmp(fmt, "bytes}")) {
      if (f->tag != F_TERM_BYTES) return -1;
      char **s = va_arg(args, char **); // note: uses char**
      if (f->len < 0) return -1; // bad length
      if (f->len == 0) {
	*s = NULL;
      } else {
	char *m = nxcompat_alloc(len);
	memcpy(m, f->data, len);
	*s = m;
      }
      // must be implict numbering... next arg is length
      assert(++i < count);
      fmt = fmts[i];
      assert(!strcmp(fmt, "int}"));
      int *d = va_arg(args, int *);
      *d = f->len;
    } else if (!strcmp(fmt, "term}") || !strcmp(fmt, "Stmt}")) {
      Form **g = va_arg(args, Form **);
      *g = form_dup(f);
    } else if (!strcmp(fmt, "term/der}") || !strcmp(fmt, "Stmt/der")) {
      // todo
      return -1;
    } else if (!strcmp(fmt, "term/pem}") || !strcmp(fmt, "Stmt/pem")) {
      // todo
      return -1;
    } else {
      return -1;
    }
  }
  return 0;
}

// vscan is slightly broken: the format can not contain prefs, e.g. '%foo'
int form_vscan(Form *f, Form *fmt, va_list args) {
  // count formats
  int i, err, count = 0, implicit_numbering = -1;
  if (form_peek_params(fmt, &count, &implicit_numbering, NULL)) {
    fprintf(stderr, "error: form_vscan(): mangled scanf-style parameter\n");
    return -1;
  }
  if (!count) {
    // just unify, no extraction
    struct HashTable *map = hash_new_vlen(16, hash_strlen);
    int err = form_unify_params(f, fmt, map);
    hash_destroy(map);
    if (err) return -1;
    return 0;
  }

  // gather formats
  char **fmts = nxcompat_alloc(count * sizeof(char *));
  memset(fmts, 0, count * sizeof(char *));
  count = 0;
  form_peek_params(fmt, &count, &implicit_numbering, fmts);

  // replace with dummy names
  fmt = form_dup(fmt);
  char **dummy = nxcompat_alloc(count * sizeof(char *));
  for (i = 0; i < count; i++) {
    dummy[i] = nxcompat_alloc(40);
    sprintf(dummy[i], "%%xvscandummypref%d", i);
    dummy[i][1] = fmts[i][0]; // get upper and lower for matching form or term
  }

  i = 0;
  form_put_dummies(fmt, dummy, count, &i);

  struct HashTable *map = hash_new_vlen(16, hash_strlen);
  err = form_unify_params(f, fmt, map);
  form_free(fmt);
  if (err) {
    hash_destroy(map);
    nxcompat_free(fmts);
    return -1;
  }

  // grab mappings
  Form **cargs = nxcompat_alloc(count * sizeof(Form *));
  memset(cargs, 0, count * sizeof(Form *));
  for (i = 0; i < count; i++) {
    cargs[i] = hash_findItem(map, dummy[i]);
  }
  hash_destroy(map);

  // check results against formats
  err = form_convert_params(count, fmts, cargs, args);
  nxcompat_free(fmts);
  for (i = 0; i < count; i++)
    if (cargs[i]) form_free(cargs[i]);
  nxcompat_free(cargs);
  return err;
}

int form_scan(Form *f, char *fmt_pretty, ...) {
  va_list args;
  Form *fmt = form_or_term_from_pretty(fmt_pretty);
  if (!fmt) return -1;
  va_start(args, fmt_pretty);
  int err = form_vscan(f, fmt, args);
  va_end(args);
  form_free(fmt);
  return err;
}

int form_scanf(Form *f, Form *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int err = form_vscan(f, fmt, args);
  va_end(args);
  return err;
}


