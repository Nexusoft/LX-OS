/** NexusOS: chmod library call wrapper */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/test.h>
#include <nexus/guard.h>

int
main(int argc, char **argv)
{
	long mode;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <filepath> <principal> <mode>\n", 
			argv[0]);
		return 1;
	}

	mode = strtol(argv[3], NULL, 10);
	if (mode == LONG_MIN || mode == LONG_MAX)
		ReturnError(1, "unknown mode\n");

	return nxguard_chmod(argv[1], argv[2], mode);
}

