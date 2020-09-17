/** NexusOS: wrapper around chown() library function */

#include <stdlib.h>
#include <stdio.h>

#include <nexus/fs.h>
#include <nexus/fs_path.h>
#include <nexus/test.h>
#include <nexus/guard.h>

int
main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <filepath> <principal>\n", argv[0]);
		exit(1);
	}

	return nxguard_chown(argv[1], argv[2]);
}

