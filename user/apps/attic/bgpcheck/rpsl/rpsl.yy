%{

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filter.h"
#include "rpsl.tab.hh"

extern int cur_pos, yylineno;
static int yy_success = true;
void yyerror(const char *msg, ...) {
	printf("Syntax error at %d:%d: ", yylineno, yylloc.first_column);
	va_list arg;
	va_start(arg, msg);
	vprintf(msg, arg);
	va_end(arg);
	putchar('\n');
	if (!fpd.errmsg) {
		fpd.errmsg = strdup(msg);
		fpd.errline = yylloc.first_line;
		fpd.errcol = yylloc.first_column;
		fpd.errcolend = yylloc.last_column;
	}
	yy_success = false;
}
extern int yylex(void);

static struct in_addr NO_ADDR = { INADDR_NONE };

%}
%union {
	int iValue;
	char *sValue;
	struct in_addr ipValue;
	Node *nPtr;
	ListNodeBase *nList;
};

%error-verbose
%locations
%defines

%token ANY AND OR AS_SET AS IP_ADDR INT PEER_AS FILTER IMPORT EXPORT
%token FROM TO ACTION ANNOUNCE PREF DPA MED ASPATH COMMUNITY NEXT_HOP COST
%token ACCEPT AT DELETE CONTAINS APPEND PREPEND EQ DOTEQ
%type<iValue> AS INT PEER_AS
%type<sValue> AS_SET
%type<ipValue> IP_ADDR
%type<nList> prefix_set regex_no_or regex_set fromlist tolist actionlist int_list as_list
%type<nPtr> regex wholerule rule filter main_filter filter_ent prefix regex_ent
%type<nPtr> regex_ent_repeatable regex_set_ent import export from_ent to_ent
%type<nPtr> action_ent peering as_expr

%right NOT
%left AND OR '|'
%start wholerule

%%

wholerule:
	rule                      { fpd.f = $$ = $1; }
	;

rule:
	FILTER filter             { $$ = opr(FILTER, 1, $2); }
	| IMPORT import           { $$ = $2; }
	| EXPORT export           { $$ = $2; }
	;

filter:
	ANY                       { $$ = opr(ANY, 0); }
	| main_filter
	;

main_filter:
	filter_ent main_filter         { $$ = opr(OR, 2, $1, $2); }
	| filter_ent AND main_filter   { $$ = opr(AND, 2, $1, $3); }
	| filter_ent OR main_filter    { $$ = opr(OR, 2, $1, $3); }
	| filter_ent
	;

filter_ent:
	'{' prefix_set '}'        { $$ = $2; }
	| as_expr
	| PEER_AS                 { $$ = new ASNode(-1); }
	| '<' regex '>'           { $$ = $2; }
	| NOT filter_ent          { $$ = opr(NOT, 1, $2); }
	| '(' main_filter ')'     { $$ = $2; }
	| COMMUNITY '(' int_list ')'               { $$ = new AttributeMatchNode(COMMUNITY, CONTAINS, $3); }
	| COMMUNITY '.' CONTAINS '(' int_list ')'  { $$ = new AttributeMatchNode(COMMUNITY, CONTAINS, $5); }
	| COMMUNITY EQ '{' int_list '}'            { $$ = new AttributeMatchNode(COMMUNITY, EQ, $4); }
	;

as_expr:
	AS_SET                    { $$ = new ASSetNode($1); free($1); }
	| AS                      { $$ = new ASNode($1); }
	;

prefix_set:
	prefix_set ',' prefix     { $$ = $1; ($$)->add($3); }
	| prefix                  { $$ = new PrefixSetNode; ($$)->add($1); }
	;

int_list:
	int_list ',' INT          { $$ = $1; ($$)->add(new IntNode($3)); }
	| INT                     { $$ = new ListNode; ($$)->add(new IntNode($1)); }
	;

as_list:
	as_list ',' AS            { $$ = $1; ($$)->add(new ASNode($3)); }
	| AS                      { $$ = new PrefixSetNode; ($$)->add(new ASNode($1)); }
	;

prefix:
	IP_ADDR '/' INT                     { $$ = new PrefixNode($1, $3, $3, $3); }
	| IP_ADDR '/' INT '^' '+'           { $$ = new PrefixNode($1, $3, $3, 32); }
	| IP_ADDR '/' INT '^' '-'           { $$ = new PrefixNode($1, $3, $3+1, 32); }
	| IP_ADDR '/' INT '^' INT           { $$ = new PrefixNode($1, $3, $5, $5); }
	| IP_ADDR '/' INT '^' INT '-' INT   { $$ = new PrefixNode($1, $3, $5, $7); }
	;

regex:
	regex '|' regex_no_or           { $$ = opr('|', 2, $1, $3); }
	| regex_no_or                   { $$ = $1; }
	;

regex_no_or:
	regex_no_or regex_ent           { $$ = $1; ($$)->add($2); }
	|                               { $$ = new RegexNode; }
	;

regex_ent:
	regex_ent_repeatable                               { $$ = new RegexEntNode($1, 1, 1); }
	| regex_ent_repeatable '*'                         { $$ = new RegexEntNode($1, 0, INF); }
	| regex_ent_repeatable '+'                         { $$ = new RegexEntNode($1, 1, INF); }
	| regex_ent_repeatable '{' INT '}'                 { $$ = new RegexEntNode($1, $3, $3); }
	| regex_ent_repeatable '{' INT ',' INT '}'         { $$ = new RegexEntNode($1, $3, $5); }
	| regex_ent_repeatable '{' INT ',' '}'             { $$ = new RegexEntNode($1, $3, INF); }
	| regex_ent_repeatable '~' '*'                     { $$ = new RegexEntNode($1, 0, INF, true); }
	| regex_ent_repeatable '~' '+'                     { $$ = new RegexEntNode($1, 1, INF, true); }
	| regex_ent_repeatable '~' '{' INT '}'             { $$ = new RegexEntNode($1, $4, $4, true); }
	| regex_ent_repeatable '~' '{' INT ',' INT '}'     { $$ = new RegexEntNode($1, $4, $6, true); }
	| regex_ent_repeatable '~' '{' INT ',' '}'         { $$ = new RegexEntNode($1, $4, INF, true); }
	| '^'                                              { $$ = opr('^', 0); }
	| '$'                                              { $$ = opr('$', 0); }
	;

regex_ent_repeatable:
	AS_SET                    { $$ = new ASSetNode($1); free($1); }
	| AS                      { $$ = new ASNode($1); }
	| '[' regex_set ']'       { $$ = $2; }
	| '[' '^' regex_set ']'   { $$ = $3; dynamic_cast<RegexASSetNode*>($$)->complement = true; }
	| '(' regex ')'           { $$ = $2; }
	;

regex_set:
	regex_set regex_set_ent   { $$ = $1; ($$)->add($2); }
	|                         { $$ = new RegexASSetNode; }
	;

regex_set_ent:
	AS_SET                    { $$ = new ASSetNode($1); free($1); }
	| AS '-' AS               { $$ = new ASRangeNode(std::pair<int,int>($1, $3)); }
	| AS                      { $$ = new ASNode($1); }
	;

import:
	fromlist ACCEPT filter    { $$ = opr(IMPORT, 2, $1, $3); }
	;

fromlist:
	fromlist from_ent         { $$ = $1; ($$)->add($2); }
	|                         { $$ = new ListNode; }
	;

from_ent:
	FROM peering ACTION actionlist     { $$ = opr(FROM, 2, $2, $4); }
	| FROM peering                     { $$ = opr(FROM, 2, $2, NULL); }
	;

export:
	tolist ANNOUNCE filter    { $$ = opr(EXPORT, 2, $1, $3); }
	;

tolist:
	tolist to_ent             { $$ = $1; ($$)->add($2); }
	|                         { $$ = new ListNode; }
	;

to_ent:
	TO peering ACTION actionlist     { $$ = opr(TO, 2, $2, $4); }
	| TO peering                     { $$ = opr(TO, 2, $2, NULL); }
	;

peering:      // !! are these all the peering specs?
	as_expr                          { $$ = new PeeringNode($1, NO_ADDR, NO_ADDR); }
	| as_expr IP_ADDR                { $$ = new PeeringNode($1, $2, NO_ADDR); }
	| as_expr AT IP_ADDR             { $$ = new PeeringNode($1, NO_ADDR, $3); }
	| as_expr IP_ADDR AT IP_ADDR     { $$ = new PeeringNode($1, $2, $4); }
	;

actionlist:
	actionlist action_ent ';'        { $$ = $1; ($$)->add($2); }
	|                                { $$ = new ListNode; }
	;

action_ent:   // !! MED = igp_cost
	PREF '=' INT                               { $$ = new AttributeActionNode(PREF, '=', list(ListNode, new IntNode($3))); }
	| MED '=' INT                              { $$ = new AttributeActionNode(MED, '=', list(ListNode, new IntNode($3))); }
	| DPA '=' INT                              { $$ = new AttributeActionNode(DPA, '=', list(ListNode, new IntNode($3))); }
	| ASPATH '.' PREPEND '(' as_list ')'       { $$ = new AttributeActionNode(ASPATH, PREPEND, $5); }
	| COMMUNITY '=' '{' int_list '}'           { $$ = new AttributeActionNode(COMMUNITY, '=', $4); }
	| COMMUNITY '=' '{' '}'                    { $$ = new AttributeActionNode(COMMUNITY, '=', NULL); }
	| COMMUNITY DOTEQ '{' int_list '}'         { $$ = new AttributeActionNode(COMMUNITY, APPEND, $4); }
	| COMMUNITY '.' APPEND '(' int_list ')'    { $$ = new AttributeActionNode(COMMUNITY, APPEND, $5); }
	| COMMUNITY '.' DELETE '(' int_list ')'    { $$ = new AttributeActionNode(COMMUNITY, DELETE, $5); }
	| NEXT_HOP '=' IP_ADDR                     { $$ = new AttributeActionNode(NEXT_HOP, '=', list(ListNode, new IPNode($3))); }
	| COST '=' INT                             { $$ = new AttributeActionNode(COST, '=', list(ListNode, new IntNode($3))); }
	;

%%

extern void set_input(char *c);
extern void kill_input();

struct filter_parse_data fpd;

Node *filter_parse(char *c) {
	fpd.f = 0;
	fpd.errmsg = 0;
	set_input(c);
	cur_pos = 0;
	yylineno = 1;
	yy_success = true;
	yyparse();
	kill_input();
	if (fpd.f) {
		if (yy_success)
			return fpd.f;
		else
			delete fpd.f;
	}
	return 0;
}

int main(int argc, char **argv) {
	//form *f = form_parse("[[a]] and [[b]] and x:y says [[c]] and d");
	if (argc != 2) {
		fprintf(stderr, "Usage:\n  %s input-file\n\n", argv[0]);
		return 1;
	}
	FILE *fp = fopen(argv[1], "r");
	if (!fp) {
		perror(argv[1]);
		return 1;
	}
	char rule[16384] = "", line[16384], *p;
	do {
		p = fgets(line, sizeof(line), fp);
		if (p && (line[0] == '+' || line[0] == ' ' || line[0] == '\t'))
			strcat(rule, line);
		else {
			if (rule[0]) {
				printf("==[in]==\n%s========\n", rule);
				Node *f = filter_parse(rule);
				if (f) {
					printf("==[out]==\n");
					//filter_print(f, 1);
					filter_print_pretty(f);  putchar('\n');
					printf("=========\n");
					delete f;
				}
			}
			if (p) strcpy(rule, line);
		}
	} while (p);
	return 0;
}
