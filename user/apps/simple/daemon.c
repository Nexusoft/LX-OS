/** NexusOS: a general purpose daemon for executing IDL-based services
 
    All IDL services expect one or more threads that block on their
    RecvCall and DoBindAccept calls. Instead of recreating this functionality
    for each service, we have this single daemon that accepts a service type
    as argument.
 */

#include <stdio.h>
#include <string.h>

#include <nexus/ipc.h>
#include <nexus/Thread.interface.h>

static int 
usage(int ac, char **av)
{
	fprintf(stderr, "[daemon] Usage: %s <service name>      to start a server\n"
			"                %s -l                  to list servers", 
		av[0], av[0]);
	return 1;
}

/** Main (duh)
 
    XXX add support for choosing a port (including '0' for arbitrary)
 */
int 
main(int ac, char **av) 
{
  int port;

  if (ac != 2)
	return usage(ac, av);

  if (!strcmp(av[1], "-l")) {
  	ipc_server_list();
	return 0;
  }

  port = ipc_server_run(av[1]);
  if (port < 0) {
	  printf("[daemon] failed to start service [%s]\n", av[1]);
	  return 1;
  }

  printf("[daemon] service [%s] up at port %d\n", av[1], port);

  while (1)
	  Thread_USleep(1000000 * 10);
}

