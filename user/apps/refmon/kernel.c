/** NexusOS: control logic to start an in-kernel monitor */

#include <stdio.h>
#include <string.h>

#include <nexus/interpose.h>

int
main(int argc, char **argv)
{
	int refmon_id;

	// check input
	if (argc < 3) {
		fprintf(stderr, "[refmon] Usage: %s <refmon id> <cmd> [args ..]\n", argv[0]);
		return 1;
	}

	refmon_id = strtol(argv[1], NULL, 10);
	if (refmon_id < 0 || refmon_id > 3) {
		fprintf(stderr, "[refmon] unknown monitor\n");
		return 1;
	}

	printf("Nexus kernel reference monitor %d\n\n", refmon_id);
	return nxrefmon_kernel(argv + 2, refmon_id);
}

