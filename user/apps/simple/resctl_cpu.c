/** NexusOS: CPU shard resource controller */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/ipc.h>
#include <nexus/Resource.interface.h>

int
main(int argc, char **argv)
{
	if (ipc_server_run("Resource_CPU") < 0) {
		fprintf(stderr, "Failed to start CPU resource manager\n");
		return 1;
	}

	while (1)
		sleep(60);

	return 0;
}

