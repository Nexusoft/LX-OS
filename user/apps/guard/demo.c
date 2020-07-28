/** NexusOS: NAL fo:w
  rmula playground */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <nexus/guard.h>
#include <nexus/formula.h>

/// maximum input
#define INLEN 512

static Guard *nal_guard;

/** Parse and validate a NAL formula.
    @return 0 on success, -1 on error. */
static int
nal_parse_formula(char *string)
{
	Form * formula;
	char * ostring;

	formula = form_from_pretty(string);
	if (!formula) {
		fprintf(stderr, "[error] string is not a NAL formula\n");
		return -1;
	}

	if (!form_is_proper(formula)) {
		fprintf(stderr, "[error] string is not a proper formula\n");
		return -1;
	}

	ostring = form_to_pretty(formula, 0);
	printf("%s\n", ostring);
	free(ostring);
	return 0;
}

static int 
nal_guard_setgoal(char *string)
{
	if (nal_guard)
		guard_destroy(nal_guard);

	nal_guard = guard_create();
	assert(nal_guard);
	guard_setdebug(nal_guard, GUARD_DEBUG_ALL);

	if (guard_setgoal(nal_guard, form_to_der(form_from_pretty(string)))) {
		fprintf(stderr, "[error] failed to set goal\n");
		guard_destroy(nal_guard);
		nal_guard = NULL;
		return 1;
	}

	return 0;
}

static int
nal_guard_addpolicy(char *string)
{
	if (!nal_guard) {
		fprintf(stderr, "[error] no guard. Set a goal first.\n");
		return 1;
	}

	if (guard_addpolicy(nal_guard, form_to_der(form_from_pretty(string)))) {
		fprintf(stderr, "[error] unknown\n");
		return 1;
	}

	return 0;
}

static int
nal_guard_eval(char *string)
{
	if (!nal_guard) {
		fprintf(stderr, "[error] no guard. Set a goal first.\n");
		return 1;
	}

	if (guard_check(nal_guard, form_from_pretty(string), NULL)) {
		printf("access denied\n");
		return 1;
	}
	else {
		printf("access granted\n");
		return 0;
	}
}

static void
nal_help(void)
{
	printf("NAL playground\n"
	       "\n"
	       "type 'form <formula>' to validate a formula\n"
	       "     'goal <formula>' to set guard goal. Resets the guard\n"
	       "     'prem <formula>' to add a premise to the guard\n"
	       "     'eval <formula>' to have the guard evaluate an action\n"
	       "     'help'           to display this message\n"
	       "     'exit'           to leave\n"
	       "\n");
}

int
main(int argc, char **argv)
{
	char buf[INLEN + 1];
	int len;

	nal_help();
	do {
		// read a line
		fprintf(stderr, "nal: ");
		len = read(0, buf, INLEN);
		if (len < 0) {
			fprintf(stderr, "read error\n");
			return 1;
		}
		buf[--len] = 0; // wipe end of line

		// special case: blank line
		if (len == 0)
			continue;

		if (len < 4) {
			fprintf(stderr, "[error] invalid input: too short\n");
			continue;
		}

		if (!strcmp(buf, "exit"))
			break;
		if (!strcmp(buf, "help"))
			nal_help();
		else if (!memcmp(buf, "form ", 5))
			nal_parse_formula(buf + 5);
		else if (!memcmp(buf, "goal ", 5))
			nal_guard_setgoal(buf + 5);
		else if (!memcmp(buf, "prem ", 5))
			nal_guard_addpolicy(buf + 5);
		else if (!memcmp(buf, "eval ", 5))
			nal_guard_eval(buf + 5);
		else
			fprintf(stderr, "[error] invalid input\n");
	} while (1);
	
	if (nal_guard)
		guard_destroy(nal_guard);

	return 0;
}

