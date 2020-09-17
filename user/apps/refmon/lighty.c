/** NexusOS: a reference monitor for lighttpd */

#include <stdio.h>
#include <nexus/interpose.h>

#include "../../../common/refmon/lighty.c"

extern int refmon_lighty_val;

int
main(int argc, char **argv)
{
	char *args[5];
	int do_lighty = 0;
	int do_max = 0;

	printf("Nexus lighttpd reference monitor\n\n");
	if (argc != 1 && argc != 3) {
		fprintf(stderr, "Usage: %s [<lighty|httpd> <min|max>]\n", argv[0]);
		return 1;
	}	

	// parse args
	if (argc == 3) {
		if (!memcmp(argv[1], "lig", 3))
			do_lighty = 1;
		if (!memcmp(argv[2], "max", 3))
			do_max = 1;
	}

	// feedback
	printf("   server = %s\n", do_lighty ? "lighttpd" : "httpd");
	printf("   method = %s\n", do_max ? "max" : "min");

	// setup
	if (do_lighty) {
		args[0] = "bin/lighttpd";
		args[1] = "-D";
		args[2] = "-f";
		args[3] = "/bin/lighttpd.conf";
		args[4] = NULL;
	}
	else {
		printf("Warning: Nexus HTTPD mode\n");
		args[0] = "bin/httpd.app";
		args[1] = NULL;
	}

	if (do_max)
		refmon_lighty_val = AC_ALLOW_NOCACHE;
	else
		refmon_lighty_val = AC_ALLOW_CACHE;

	// start
	return nxrefmon(args, nxrefmon_lighty_in, nxrefmon_lighty_out);
}

