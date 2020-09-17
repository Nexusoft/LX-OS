/** NexusOS: demo the guard: the bureaucrat will not sign off on
    anything before 9 and after 4.47.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/test.h>

#include <nexus/Auth.interface.h>

int
auth_answer(const char *req, int pid)
{
	struct tm *split;
	char *strtime;
	time_t now;
	int working, slen;

	// read number of seconds since 1970
	now = time(NULL);
	if (now == (time_t) -1)
		ReturnError(0, "time()");

	// parse time into days, etc.
	split = localtime(&now);
	if (!split)
		ReturnError(0, "localtime()");
	strtime = asctime(split);
	if (!strtime)
		ReturnError(0, "asctime()");

	// calculate working hours: our bureaucrat works weekend (yeah, he's a prototype).
	working = split->tm_hour < 9 || (split->tm_hour > 16 && split->tm_min > 47) ? 0 : 1;
	
	// pretty print
	slen = strlen(strtime);
	strtime[slen - 1] = 0; // drop \n
	printf("[auth:bureaucrat] (%s): %s \n", strtime, working ? "Yes" : "NO");

	return working;
}

int
main(int argc, char **argv)
{
	return nxguard_auth(default_guard_port, "bureaucrat", NULL);
}

