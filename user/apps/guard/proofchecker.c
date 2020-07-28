/** NexusOS: Interactive Proofchecker */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/vector.h>
#include <nexus/formula.h>

static char *filebuf = NULL;
static char *filep = NULL;
static int filelines = 0;

static char *skipws(char *s) { while (s && isspace(*s)) s++; return s; }
static char *rtrim(char *s) { while (s && isspace(*s)) s--; return s; }

static struct Judge * peek(struct eval *eval) {
	int n = PointerVector_len(&eval->stack);
	if (n <= 0) {
	  printf("error: peek into empty stack\n");
	  return NULL;
	}
	return PointerVector_nth(&eval->stack, n-1);
}

/** Read an entire file into one memory chunk */
static char *readfile(char *filename) {
	printf("reading file: %s\n", filename);
	FILE *f = fopen(filename, "r");
	if (!f) {
	  printf("could not open file '%s'\n", filename);
	  return NULL;
	}
	fseek(f, 0, SEEK_END);
	int size = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buf = nxcompat_alloc(size+3);
	if (fread(buf, size, 1, f) != 1) {
		printf("could not read entire file '%s'\n", filename);
		fclose(f);
		nxcompat_free(buf);
		return NULL;
	}
	fclose(f);
	if (buf[size-1] != '\n') buf[size++] = '\n';
	buf[size] = '\n'; // extra blank line at end to aid in cleanup (see below)
	buf[size+1] = '\0';
	return buf;
}

/** Readline */ 
char *get_nextline(char *buf, int *buflen) {
  if (!buf || *buflen == 0) buf = nxcompat_alloc(*buflen = 2048);
  if (!fgets(buf, *buflen, stdin)) {
    nxcompat_free(buf);
    *buflen = 0;
    return NULL;
  }
  int n = strlen(buf);
  if (n == 0 || buf[n-1] != '\n') {
    // keep reading until we do get a newline
    do {
      if (*buflen - n < 100) {
	*buflen *= 2;
	buf = nxcompat_realloc(buf, *buflen);
      }
      if (!fgets(buf+n, *buflen-n, stdin)) {
	nxcompat_free(buf);
	*buflen = 0;
	return NULL;
      }
      n += strlen(buf+n);
    } while (n == 0 || buf[n-1] != '\n');
  }

  return buf;
}

/** Main program loop. 
    Accepts a buffer or interactive mode */
char *get_command(struct eval *eval, char *allcode) {
	char *buf = NULL;
	int buflen = 0;
	for (;;) {
		char *s;
		if (filebuf) {
		  if (!filep) filep = filebuf;
		  s = filep;
		  filep = index(s, '\n');
		  assert(filep);
		  *filep = '\0';
		  filep++;
		  if (*filep == '\0') {
		    assert(strlen(s) == 0); // last line always blank (see above)
		    filep = NULL;
		    nxcompat_free(filebuf);
		    filebuf = NULL;
		    filelines = 0;
		    continue;
		  }
		  printf("%3d: %s\n", ++filelines, s);
		} else {
		  printf("> "); fflush(stdin);
		  buf = get_nextline(buf, &buflen);
		  if (!buf) return NULL;
		  if (strlen(buf) == 0) continue;
		  s = buf;
		}
		// trim
		s = skipws(s);
		char *e = rtrim(s+strlen(s)-1);
		e[1] = '\0';
		while (s[0] && e[0] == ';') (e--)[0] = '\0'; // drop trailing ';'
		if (!strcmp(s, ""))
			continue;
		else if (s[0] == '#') { // skip comments (mostly)
		  s = skipws(s+1);
		  if (!strncmp(s, "shown", strlen("shown"))) {
		    // annotate proof with comment for debugging/display purposes
		    s = skipws(s + strlen("shown"));
		    Judge *f = peek(eval);
		    if (f) {
		      if (f->comment) nxcompat_free(f->comment);
		      f->comment = strdup(s);
		    }
		  }
		  printf("  # %s\n", s);
		  continue; 
		}
		if (!strcmp(s, "?") || !strcmp(s, "help")) {
			int i, n = PointerVector_len(&eval->rules_sorted);
			printf(
				"[commands]\n"
				"   rules"
				"   status"
				"   exit\n"
				"   < <filename>\n"
				"\n"
				"[rules]\n"
				"   dup               pushdown <n>      pullup <n>\n"
				"   assume <%%S>      impi <%%S>\n"
				"   reqall            reqsome <%%S>\n");
			for (i = 0; i < n; i++) {
			  if (!(i % 3)) printf("\n  ");
			  char *name = PointerVector_nth(&eval->rules_sorted, i);
			  printf(" %-17s", name);
			}
			printf("\n");
			continue;
		} else if (!strcmp(s, "rules")) {
			int i, n = PointerVector_len(&eval->rules_sorted);
			printf(
				"[complex rules]\n\n"
				"   dup\n"
				"       duplicate the judgement on top of the stack\n"
				"   pushdown <n>\n"
				"       push to top judgement down to position <n> on the stack\n"
				"   pullup <n>\n"
			        "       pull the <n>th judgement to the top of the stack\n"
				"   assume <%%S>\n"
			        "       push judgement [<%%S>] ==> <%%S> onto stack\n"
				"   impi <%%S>\n"
			       	"       pop [<%%S>, ...] ==> F then push [...] ==> <%%S> imp F\n"
				"   rename <%%S'>\n"
				"       pop [...] ==> %%S then push [...] ==> <%%S'>, where %%S =a <%%S'>\n"
				"\n"
				"[simple rules]\n\n"
				"   reqall\n"
				"       %%a says %%S, %%a says %%t = %%v / %%a says %%S[%%t/%%v]\n"
				"   reqsome <%%S[h/%%v]>\n"
				"       %%a says %%S[h/%%t], %%a says %%t = %%v / %%a says %%S[h/%%v]\n"
				"   foralli <$v>\n"
				"       %%S / forall $v : %%S\n");
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
		    continue;
		} else if (!strcmp(s, "status")) {
		    eval->code = "<interactive input>";
		    printf("  transcript: %s\n", allcode);
		    continue;
		} else if (!strcmp(s, "exit") || !strcmp(s, "quit")) {
		  return NULL;
		} else if (s[0] == '<') {
		  if (filebuf) {
		    printf("sorry, can't include a file from within a file (yet)\n");
		    continue;
		  }
		  s = skipws(s+1);
		  filebuf = readfile(s);
		  continue;
		}
		return strdup(s);
	}
}

int main(int argc, char **argv)
{
	PointerVector args;
	struct guard *guard;
	char *allcode, *code;
	int allcode_len, err;
       
	printf("Nexus Interactive Proofchecker\n"
	       "Enter 'help' for information\n\n");

	// XXX support input from a file

	guard = guard_create();
	guard->eval.code = "<interactive input>";

	allcode = nxcompat_alloc(allcode_len = 2048);
	allcode[0] = 0;

	// XXX read in arguments
	PointerVector_init(&args, 16, POINTERVECTOR_ORDER_PRESERVING);

	code = get_command(&guard->eval, allcode);
	while (code) {
		err = eval_run1(&guard->eval, code, strlen(code), &args);
		if (err) {
			guard->eval.errors++;
			printf("[check] error (%d so far)\n", guard->eval.errors);
		}
		else {
			if (strlen(allcode) + strlen(code) + 10 >= allcode_len)
				allcode = nxcompat_realloc(allcode, allcode_len *= 2);
			strcat(allcode, code);
			strcat(allcode, "; \n");
		}
		nxcompat_free(code);
		code = get_command(&guard->eval, allcode);
	}

	if (strlen(allcode) > 0) 
		printf("[check] proof transcript: \n%s\n", allcode);

	nxcompat_free(allcode);
	return 0;
}

