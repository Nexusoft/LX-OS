/** NexusOS: benchmark proof evaluation */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>

#include <nexus/test.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/formula.h>
#include <nexus/profiler.h>

extern Judge * guard_check_proof(struct goal *goal, const char *proof);
extern void judge_free(Judge *f);

#define ENABLE_LIBRARY 1
#include "../guard/eval_inner.c"

int
main(int argc, char **argv)
{
	char *name;
	gfunc func;
	long testnum;
	int full;

	printf("Nexus proof evaluation benchmark\n");

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <testnum>\n", argv[0]);
		return 1;
	}

	testnum = strtol(argv[1], NULL, 10);
	if (testnum == LONG_MIN || testnum == LONG_MAX) {
		fprintf(stderr, "Usage: %s <testnum>\n", argv[0]);
		return 1;
	}

	switch (testnum) {
		case 1:	name = "delegation"; 	func = proof_generate_delegation;	full=0;	break;
		case 2:	name = "delegation"; 	func = proof_generate_delegation;	full=1;	break;
		case 3:	name = "negation"; 	func = proof_generate_negation;		full=0;	break;
		case 4:	name = "negation"; 	func = proof_generate_negation;		full=1;	break;
		case 5:	name = "boolean"; 	func = proof_generate_boolean;		full=0;	break;
		case 6:	name = "boolean"; 	func = proof_generate_boolean;		full=1;	break;
		default:
			fprintf(stderr, "Usage: %s <testnum>\n", argv[0]);
			return 1;
	}
	// test delegation
	printf("[eval] Running test %s (%s)\n", name, full ? "FULL" : "EVAL");
	if (test_inner(name, func, full))
		return 1;

	printf("[eval] OK. Completed all tests successfully\n");
	return 0;
}

