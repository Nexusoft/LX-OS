/** NexusOS: a device driver reference monitor for the vlance driver */

#include <stdio.h>

#include <nexus/interpose.h>

#include "../../../common/refmon/vlance.c"

int
main(int argc, char **argv)
{
	char *args[2];
	
	printf("Nexus pcnet32/vlance device driver reference monitor\n\n");

	args[0] = "bin/net.drv";
	args[1] = NULL;
	return nxrefmon(args, nxrefmon_vlance_in, nxrefmon_vlance_out);
}

