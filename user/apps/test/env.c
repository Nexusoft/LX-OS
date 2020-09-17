/** NexusOS: Test that the environment is read in correctly */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/test.h>

static int 
test_syscall(int argc, char **argv)
{
	char **env = &argv[argc + 1];
	int i;
       
// optionally print all environment variables
#if 0
	for (i = 0; env[i]; i++)
		printf("[env] %s\n", env[i]);
#endif

	for (i = 0; env[i]; i++) {
		// PATH should always be in the default path. simple test
		if (!memcmp("PATH", env[i], 4))
			return 0;

	}

	ReturnError(1, "path not found");
}

#define NEWVAR "BLURB"
#define NEWVAL "BLOOB"

static int
test_posix(void)
{
	char *value;

	value = getenv("PATH");
	if (!value)
		ReturnError(1, "getenv #1");

	value = getenv(NEWVAR);
	if (value)
		ReturnError(1, "getenv #2");

	if (setenv(NEWVAR, NEWVAL, 1))
		ReturnError(1, "setenv");

	value = getenv(NEWVAR);
	if (!value || strcmp(value, NEWVAL))
		ReturnError(1, "getenv #3");

	return 0;
}

#include <nexus/ipc.h>
#include <nexus/IPC.interface.h>

int 
main(int argc, char **argv)
{
	if (test_syscall(argc, argv))
		return 1;

	if (test_posix())
		return 1;

	return 0;
}

