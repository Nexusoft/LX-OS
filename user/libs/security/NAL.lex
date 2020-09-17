/* NAL.lex -- lexical analyzer for Nexus Authorization Logic */

%{
#define YYSTYPE Form *

#include <nexus/defs.h>
#include <nexus/formula.h>
#include <nexus/base64.h>
#include "NAL.tab.h"
#include "NAL.h"

#define YY_INPUT(buf,result,max_size) \
    result = YY_NULL;

#define YY_USER_ACTION \
  yylloc->first_line = yylloc->last_line = yylineno; \
  yylloc->first_column = yycolumn + 1; \
  yycolumn += yyleng; \
  yylloc->last_column = yycolumn; \

#define YY_EXTRA_TYPE struct nal_parse_results *

#define lex_error(msg) yyerror_localized(yyscanner, msg, yylloc, NULL, NULL)

%}

%option noyywrap never-interactive nodefault yylineno
%option reentrant bison-bridge bison-locations
%option 8bit warn
%option nounistd read
%option fast
%option noyyfree

%option noyyalloc
%option noyyrealloc
%option noyyfree

%x QSTR
%x BYTESDATA

%%

	char *str_buf, *str_ptr;
	int str_len;
	void str_start(void) {
		str_ptr = str_buf = nxcompat_alloc(str_len = 256);
	}
	void str_add(char c) {
		assert(str_ptr <= str_buf + str_len);
		if (str_ptr == str_buf + str_len) {
			str_buf = nxcompat_realloc(str_buf, 2*str_len);
			str_ptr = str_buf + str_len;
			str_len *= 2;
		}
		*str_ptr++ = c;
	}
	void str_cat(char *s) {
		while (*s) str_add(*s++);
	}
	void str_reset(void) {
		str_buf = str_ptr = 0;
		str_len = 0;
	}
	char *str_end(void) {
		str_add('\0');
		char *res = str_buf;
		str_reset();
		str_len = 0;
		return res;
	}

	/* keywords for statements */
"and" { return AND; }
"or" { return OR; }
"imp" { return IMP; }
"iff" { return IFF; }
"not" { return NOT; }
"says" { return SAYS; }
"speaksfor" { return SPEAKSFOR; }
"on" { return ON; }
"true" { return TRUE; }
"false" { return FALSE; }
"forall" { return FORALL; }
"exists" { return EXISTS; }
	/* keywords for predicates */
"=" { return EQ; }
">=" { return GE; }
"<=" { return LE; }
">" { return GT; }
"<" { return LT; }
"!=" { return NE; }
"closed" { return CLOSED; }
"open" { return OPEN; }
	/* keywords for typing predicate */
"prin" { return ISPRIN; }
"int" { return ISINT; }
"in" { return IN; }
"union" { return UNION; }
"join" { return JOIN; }
"str" { return ISSTR; }
"list" { return ISLIST; }
"set" { return ISSET; }
"bytes" { return ISBYTES; }
	/* keywords for principals */
"pem" { return PEM; }
"der" { return DER; }
	/* keywords for terms */
"size" { return SIZE; }
"+" { return PLUS; }
"-" { return MINUS; }

	/* punctuation */
","  { return COMMA; }
"."  { return DOT; }
":"  { return ODOT; }
"("  { return LPAREN; }
")"  { return RPAREN; }
"{"  { return LBRACE; }
"}"  { return RBRACE; }
"["  { return LBRACK; }
"]"  { return RBRACK; }
"[[" { return LCBRACK; }
"]]" { return RCBRACK; }
"[(" { return LOBRACK; }
")]" { return ROBRACK; }


	/* quoted strings */
\" { str_start(); BEGIN(QSTR); }
<QSTR>{
	\" { *yylval = form_newdata(F_TERM_STR, str_end(), -1); BEGIN(INITIAL); return STRING; }
	\n { lex_error("unterminated string constant"); yyterminate(); }
	<<EOF>> { lex_error( "unterminated string constant" ); yyterminate(); }
	\\[0-7]{1,3} {
		int res = strtol(yytext+1, 0, 8);
		if (res > 0xff) {
			lex_error("invalid string escape sequence");
			yyterminate();
		}
		str_add((char)res);
	}
	\\[0-9]+ { lex_error("invalid string escape sequence"); yyterminate(); }
	\\n { str_add('\n'); }
	\\t { str_add('\t'); }
	\\r { str_add('\r'); }
	\\b { str_add('\b'); }
	\\f { str_add('\f'); }
	\\(.|\n) { str_add(yytext[1]); }
	[^\\\n\"]+ { char *y = yytext; while (*y) str_add(*y++); }
	. { lex_error( "invalid character in string constant" ); yyterminate(); }
}

	/* integers */
0[0-7]* { 
	int res = strtol(yytext, 0, 8);
	if (res == INT_MIN && strcmp(yytext, "020000000000")) {
		lex_error("underflow in octal constant");
		yyterminate();
	}
	if (res == INT_MAX && strcmp(yytext, "017777777777")) {
		lex_error("overflow in octal constant");
		yyterminate();
	}
	*yylval = form_newval(F_TERM_INT, res);
	return INTEGER;
}
0x[0-9a-fA-F]* { 
	int res = strtol(yytext, 0, 16);
	if (res == INT_MIN && strcmp(yytext, "0x80000000")) {
		lex_error("underflow in hex constant");
		yyterminate();
	}
	if (res == INT_MAX &&
		(strncmp(yytext, "0x7", 3) || strlen(yytext) != 10 /* || strspn(yytext+3, "fF") != 7 */)) {
		lex_error("overflow in hex constant");
		yyterminate();
	}
	*yylval = form_newval(F_TERM_INT, res);
	return INTEGER;
}

[+-]{0,1}[1-9][0-9]* {
	int res = strtol(yytext, 0, 10);
	if (res == INT_MIN && strcmp(yytext, "-2147483648")) {
		lex_error("underflow in decimal constant");
		yyterminate();
	}
	if (res == INT_MAX && strcmp(yytext, "2147483647")) {
		lex_error("overflow in decimal constant");
		yyterminate();
	}
	*yylval = form_newval(F_TERM_INT, res);
	return INTEGER;
}

	/* byte arrays */
"<<" { str_start(); BEGIN(BYTESDATA); }
<BYTESDATA>{
	">>" { *yylval = form_newdata(F_TERM_BYTES, str_buf, str_ptr - str_buf); str_reset();  BEGIN(INITIAL); return BYTES; }
	<<EOF>> { lex_error( "unterminated byte array constant" ); yyterminate(); }
	[0-9a-fA-F]{2} {
		int res = strtol(yytext, 0, 16);
		str_add((char)res);
	}
	[ \n\t\f\v\r]+ { }
	. { lex_error( "invalid character in byte array constant" ); yyterminate(); }
}

	/* (term-valued) positional parameter references */
%[0-9]+ {
		*yylval = form_newdata(F_TERM_PREF, strdup(yytext), -1);
		return POSPREF;
}

	/* term-valued named parameter references */
%[a-z][0-9a-zA-Z]* {
		*yylval = form_newdata(F_TERM_PREF, strdup(yytext), -1);
		return TNAMEDPREF;
}

	/* term-valued printf-style parameter references */
%+[0-9]*\{[a-z][a-zA-Z:/*%0-9]*\} {
		*yylval = form_newdata(F_TERM_PREF, strdup(yytext), -1);
		return TPRINTFPREF;
}

	/* stmt-valued named parameter references */
%[A-Z][0-9a-zA-Z]* {
		*yylval = form_newdata(F_STMT_PREF, strdup(yytext), -1);
		return SNAMEDPREF;
}
	/* stmt-valued printf-style parameter references */
%+[0-9]*\{[A-Z][a-zA-Z:/*%0-9]*\} {
		*yylval = form_newdata(F_STMT_PREF, strdup(yytext), -1);
		return SPRINTFPREF;
}


	/* quantified logic variables (start with dollar and letter) */
$[a-zA-Z][a-zA-Z0-9]* { *yylval = form_newdata(F_TERM_QVAR, strdup(yytext), -1); return QVAR; }

	/* state variables (start with letter) */
[a-zA-Z][a-zA-Z0-9]* { *yylval = form_newdata(F_TERM_SVAR, strdup(yytext), -1); return SVAR; }

	/* whitespace */
[ \n\t\f\v\r] { }
. { lex_error(yytext);
    struct nal_parse_results *fpd = nal_scanner_results(yyscanner);
    if (fpd)
      fpd->errtok = strdup(yytext);
    yyterminate(); }
<<EOF>> { yyterminate(); }

%%

int nal_create_scanner(nal_scan_t *scanner, const char *c, 
		       struct nal_parse_results *res) {
  int err = yylex_init(scanner);
  if (err) return err;
  yy_scan_string(c, *scanner);
  yyset_extra(res, *scanner);
  yyset_lineno(1, *scanner);
  yyset_column(0, *scanner);
  return 0;
}

struct nal_parse_results *nal_scanner_results(nal_scan_t scanner) {
  return yyget_extra(scanner);
}

int nal_destroy_scanner(nal_scan_t scanner) {
  return yylex_destroy(scanner);
}

void * yyalloc(size_t bytes, void * yyscanner) {
  return nxcompat_alloc(bytes);
}

void * yyrealloc(void * ptr, size_t bytes, void * yyscanner) {
  return nxcompat_realloc(ptr, bytes);
}

void   yyfree (void * ptr, void * yyscanner) {
  if (ptr)
    nxcompat_free(ptr);
}

