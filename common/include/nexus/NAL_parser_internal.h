
#ifndef NEXUS_NAL_INTERNAL
#define NEXUS_NAL_INTERNAL

typedef void* nal_scan_t; // must match yyscan_t in NAL.yy.c

struct nal_parse_results {
	Form *f;
	char *errmsg, *errtok;
	int errline, errlineend;
	int errcol, errcolend;
}; 

int nal_create_scanner(nal_scan_t *scanner, const char *c, 
		       struct nal_parse_results *fpd);
int nal_destroy_scanner(nal_scan_t scanner);
struct nal_parse_results *nal_scanner_results(nal_scan_t scanner);

// if defined, then called from flex code. don't redefine this function
#ifndef YYFPRINTF
int yylex(YYSTYPE * yylval_param, YYLTYPE * yylloc_param, nal_scan_t yyscanner);
#endif

void yyerror_localized(nal_scan_t scanner, char *msg, YYLTYPE *yylloc, YYLTYPE *yyerr0, YYLTYPE *yyerr1);

#endif

