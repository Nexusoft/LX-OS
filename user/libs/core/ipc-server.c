/** NexusOS: standard server thread support
 
    All userspace servers must run a few call and bind handling
    threads. This file centralizes that boilerplate logic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <nexus/RamFS.interface.h>
#include <nexus/syscall-defs.h>
#include <nexus/sema.h>
#include <nexus/ipc.h>

/** See services[] below */
struct ipc_service {
	const char *name;
	int stdport;		///< reserved portno; 0 if no reserved
	int *port_num;		///< port set by the init() callback
	void (*init)(void);	///< default IDL-generated initialization
	void (*inituser)(void); ///< optional user-generated initialization
	int (*func)(void);	///< RecvCall handler
};

/**
    All name, init and func elements of all struct ipc_service instances will 
    be the same apart from their unique prefix (e.g., RamFS). 
    Unfortunately, in C we cannot use reflection. This is the alternative.

    Set defaultnum to 0 if this service does not have a default reserved number
    (as defined in nexus/syscall-defs.h)

    If you need to run initialization code before starting the server threads,
    use svc_init2
 */
#define SERVICE(svc_name, svc_defaultnum, svc_inituser) \
	{ .name 	= #svc_name,				\
	  .stdport 	= svc_defaultnum,			\
	  .port_num 	= &svc_name##_port_handle,		\
	  .init 	= svc_name##_serverInit,		\
	  .inituser	= svc_inituser,				\
	  .func 	= svc_name##_processNextCommand }

/** List of all known services.
    To add a service to, you only need to add it to this list.

    The last list element MUST have all zero members. */
static struct ipc_service services[] = {
	SERVICE(RamFS, RamFS_reserved_port, RamFS_new_dynamic),
	{}
};

Sema daemon_sema = SEMA_INIT;

/** Function to execute in a separate thread that handles RecvCall() */
static void *
__ipcserver_thread(void *arg) 
{
	int (*func)(void) = arg;

	V_nexus(&daemon_sema);
	while (1)
		func();

	return NULL;
}

/** List all implemented services */
void
ipc_server_list(void)
{
  struct ipc_service *cur;

  // find the service
  for (cur = services; cur->name; cur++)
	  printf("%s\n", cur->name);
}

static struct ipc_service *
ipc_server_find(const char *name)
{
  struct ipc_service *cur;
  int nlen;

  nlen = strlen(name);
  for (cur = services; cur->name; cur++) {
  	if (nlen == strlen(cur->name) && !memcmp(name, cur->name, nlen))
		return cur;
  }

  fprintf(stderr, "[daemon] service %s not found\n", name);
  return NULL;
}

/** Start a server for the service with the given name. 
    @return port number on success, -1 on failure */
int 
ipc_server_run(const char *name)
{
	struct ipc_service *cur;
  	pthread_t t;

	// find the service
	cur = ipc_server_find(name);
	if (!cur)
		return -1;

	// initialize
	if (cur->init)
		cur->init();
	if (cur->inituser)
		cur->inituser();

	// run
	if (pthread_create(&t, NULL, __ipcserver_thread, cur->func))
		fprintf(stderr, "[daemon] Error during fork\n");
	P(&daemon_sema);

	return *cur->port_num;
}

