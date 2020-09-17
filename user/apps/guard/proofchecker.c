/** NexusOS: Interactive Proofchecker */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/vector.h>
#include <nexus/formula.h>
#include <nexus/guard-impl.h>

static char *skipws(char *s) { while (s && isspace(*s)) s++; return s; }
static char *rtrim(char *s) { while (s && isspace(*s)) s--; return s; }

/** Main program loop. 
    Accepts a buffer or interactive mode */
char *get_command(struct eval *eval, char *allcode) {
	char buf[1024], *s, *e;
	int slen;

	while (1) {
		// read
		printf("nal:> ");

		s = fgets(buf, 1024, stdin);
		if (!s)
			return NULL;

		slen = strlen(s);

		// trim
		e = s + slen - 1;
		s = skipws(s);
		e = rtrim(e);
		e[1] = 0;

		// skip comments (mostly)
		if (s[0] == '#')
		  continue; 

		// drop trailing ';'
		while (e[0] == ';') {
			(e--)[0] = 0;
			if (e == s)
				continue;
		}

		// recalculate length
		slen = strlen(s);
		if (!slen) 
		        continue;

		if (!strcmp(s, "?") || !strcmp(s, "help")) {
			printf(
				"[commands]\n"
				"   rules:	show all NAL rules\n"
				"   status:	show list of applied rules\n"
				"   stack:	show current stack\n"
				"   exit\n"
				"\n");
			continue;
		} else if (!strcmp(s, "rules")) {
			int i, n = PointerVector_len(&eval->rules_sorted);
			printf(
				"[complex rules]\n\n"
				"   dup            duplicate the judgement on top of the stack\n"
				"   pushdown <n>   push to top judgement down to position <n> on the stack\n"
				"   pullup <n>	   pull the <n>th judgement to the top of the stack\n"
				"   assume <%%S>   push judgement [<%%S>] ==> <%%S> onto stack\n"
				"   impi <%%S>     pop [<%%S>, ...] ==> F then push [...] ==> <%%S> imp F\n"
				"   rename <%%S'>  pop [...] ==> %%S then push [...] ==> <%%S'>, where %%S =a <%%S'>\n"
				"\n"
				"[simple rules]\n\n"
				"   reqall                %%a says %%S, %%a says %%t = %%v / %%a says %%S[%%t/%%v]\n"
				"   reqsome <%%S[h/%%v]>  %%a says %%S[h/%%t], %%a says %%t = %%v / %%a says %%S[h/%%v]\n"
				"   foralli <$v>          %%S / forall $v : %%S\n");
			for (i = 0; i < n; i++) {
			  char *name = PointerVector_nth(&eval->rules_sorted, i);
			  struct _Lemma *lemma = hash_findItem(eval->rules, name);
			  printf("   %s\n", name);
			  printf("       ");
			  int j;
			  for (j = 0; j < lemma->numprems; j++) {
			    if (j != 0) printf(", ");
			    char *s = form_to_pretty(lemma->prems[j], 80);
			    printf("%s", s);
			    nxcompat_free(s);
			  }
			  char *s = form_to_pretty(lemma->concl, 80);
			  printf(" / %s\n", s);
			  nxcompat_free(s);
			}
			continue;
		} else if (!strcmp(s, "stack")) {
		    eval->code = "<interactive input>";
		    printf("  stack: %s\n", allcode);
		    dump_eval_stack(eval);
		    continue;
		} else if (!strcmp(s, "status")) {
		    eval->code = "<interactive input>";
		    printf("  transcript: %s\n", allcode);
		    continue;
		} else if (!strcmp(s, "exit") || !strcmp(s, "quit")) {
		  return NULL;
		} 
		return strdup(s);
	}
}

int main(int argc, char **argv)
{
	PointerVector args;
	struct eval *eval;
	char *allcode, *code;
	int allcode_len, err;
       
	printf("Nexus Interactive Proofchecker\n"
	       "\n"
	       "Do not end statements with semicolons\n"
	       "Enter 'help' for more information\n\n");

	// XXX support input from a file

	eval = eval_create();
	eval->code = "<interactive input>";

	allcode = nxcompat_alloc(allcode_len = 2048);
	allcode[0] = 0;

	// XXX read in arguments
	PointerVector_init(&args, 16, POINTERVECTOR_ORDER_PRESERVING);

	code = get_command(eval, allcode);
	while (code) {

		// evaluate command
		if (eval_run1(eval, code, strlen(code), &args)) {
			printf("[error]\n");
			continue;
		}

		// append to log
		if (strlen(allcode) + strlen(code) + 10 >= allcode_len)
			allcode = nxcompat_realloc(allcode, allcode_len *= 2);
		strcat(allcode, code);
		strcat(allcode, "; \n");
		
		// get next command
		nxcompat_free(code);
		code = get_command(eval, allcode);
	}

	if (strlen(allcode) > 0) 
		printf("[check] proof transcript: \n%s\n", allcode);

	nxcompat_free(allcode);
	return 0;
}

