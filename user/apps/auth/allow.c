/** NexusOS: an authority that allows anything
    used for benchmarking			*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/profiler.h>

#include <nexus/Auth.interface.h>

int
auth_answer(const char *formula, int pid)
{
	return 1;
}
	
int 
main(int argc, char **argv)
{
	nxguard_auth(default_guard_port, "allow", NULL);
	return 0;
}

