%{
#include <string.h>
#include "filter.h"
#include "rpsl.tab.hh"

static int bt(char *t);
extern void yyerror(const char *msg, ...);

int cur_pos = 0;
extern int yylineno;
%}

%option noyywrap
%x ATTR_ARGS

digit   [0-9]
letter  [A-Za-z_]
word    [-0-9A-Za-z_:]

%%

 /* rule types */
"filter:"    { bt(yytext); return FILTER; }
"import:"    { bt(yytext); return IMPORT; }
"export:"    { bt(yytext); return EXPORT; }
 /* global operators */
"and"        { bt(yytext); return AND; }
"or"         { bt(yytext); return OR; }
"not"        { bt(yytext); return NOT; }
"any"        { bt(yytext); return ANY; }
 /* attributes to match or modify */
"pref"       { bt(yytext); return PREF; }
"med"        { bt(yytext); return MED; }
"dpa"        { bt(yytext); return DPA; }
"aspath"     { bt(yytext); return ASPATH; }
"community"  { bt(yytext); return COMMUNITY; }
"next-hop"   { bt(yytext); return NEXT_HOP; }
"cost"       { bt(yytext); return COST; }
 /* methods for the above */
"prepend"    { bt(yytext); return PREPEND; }
".="         { bt(yytext); return DOTEQ; }
"append"     { bt(yytext); return APPEND; }
"delete"     { bt(yytext); return DELETE; }
"contains"   { bt(yytext); return CONTAINS; }
"=="         { bt(yytext); return EQ; }
 /* keywords */
"from"       { bt(yytext); return FROM; }
"to"         { bt(yytext); return TO; }
"action"     { bt(yytext); return ACTION; }
"announce"   { bt(yytext); return ANNOUNCE; }
"accept"     { bt(yytext); return ACCEPT; }
"at"         { bt(yytext); return AT; }
 /* misc */
[-^,()/{}+;=.<>\[\]$*+?~|]  { bt(yytext); return *yytext; }
AS-{word}+   { bt(yytext); yylval.sValue = strndup(yytext, yyleng); return AS_SET; }
AS{digit}+   { bt(yytext); yylval.iValue = atoi(yytext+2); return AS; }
PeerAS       { bt(yytext); return PEER_AS; }
{digit}+\.{digit}+\.{digit}+\.{digit}+ { bt(yytext); char *addr = strndup(yytext, yyleng); inet_aton(addr, &yylval.ipValue); free(addr); return IP_ADDR; }
 /* ints and constants */
{digit}+:{digit}+  { bt(yytext); unsigned int a, b; sscanf(yytext, "%d:%d", &a, &b); yylval.iValue = (a<<16)|b; return INT; }
{digit}+     { bt(yytext); yylval.iValue = atoi(yytext); return INT; }
"no_export"            { bt(yytext); yylval.iValue = NO_EXPORT; return INT; }
"no_advertise"         { bt(yytext); yylval.iValue = NO_ADVERTISE; return INT; }
 /* !! "internet" keyword (rfc2622 p.41) */
 /* regex */
[ \t]+       { bt(yytext); }
\n[ \t+]     { bt(yytext); cur_pos = 1; yylineno++; }

. { bt(yytext); yyerror("unexpected token: \"%s\"", yytext); fpd.errtok = strdup(yytext); yyterminate(); }
<<EOF>> { yyterminate(); }

%%
/* extra */

YY_BUFFER_STATE buf;
void set_input(char *c) {
//printf("12345678901234567890123456789012345678901234567890\n%s\n", c);
buf = yy_scan_string(c);
}

void kill_input() {
	yy_delete_buffer(buf);
}

static int bt(char *t) {
  yylloc.first_line = yylloc.last_line = 1;
  yylloc.first_column = cur_pos + 1;
  cur_pos += strlen(t);
  yylloc.last_column = cur_pos;
  return 0;
}
 

/* int main(int ac, char **av) {
	yylex();
} */
