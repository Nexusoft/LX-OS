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

#include <nexus/ipc.h>
#include <nexus/sema.h>
#include <nexus/syscall-defs.h>

#include <nexus/Debug.interface.h>
#include <nexus/RamFS.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Resource.interface.h>
#include <nexus/Resource_CPU.interface.h>
#include <nexus/GuardStd.interface.h>

/** See services[] below */
struct ipc_service {
	const char *name;
	int *port_num;		///< the (global) portnum that ->init() sets
	void (*init)(void);	///< default IDL-generated initialization
	void (*inituser)(void); ///< optional user-generated initialization
	int (*func)(void);	///< RecvCall handler
	int threadcount;	///< #threads handling requests
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
#define SERVICE(svc_name, svc_inituser, svc_count) 			\
	{ .name 	= #svc_name,					\
	  .port_num 	= &svc_name##_port_handle,			\
	  .init 	= svc_name##_serverInit,			\
	  .inituser	= svc_inituser,					\
	  .func 	= svc_name##_processNextCommand,		\
	  .threadcount	= svc_count }

/** List of all known services.
    To add a service, append it to this list */
static struct ipc_service services[] = {
	SERVICE(RamFS, 		RamFS_new_dynamic, 1),
	SERVICE(Resource_CPU,	Resource_CPU_Init, 1),
	SERVICE(GuardStd,	GuardStd_InitMain, 30),
};

Sema daemon_sema = SEMA_INIT;

/** Function to execute in a separate thread that handles RecvCall() */
static void *
__ipcserver_thread(void *arg) 
{
	int (*func)(void) = arg;

	// WARNING: race between V_nexus and sleep in func
	//          little we can do without changing IDL
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
        int i, port;

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
	for (i = 0; i < cur->threadcount; i++) {
		if (pthread_create(&t, NULL, __ipcserver_thread, cur->func)) {
			fprintf(stderr, "[daemon] Error creating thread (%d, %d)\n", i, cur->threadcount);
			abort();
		}
	}
	
	// wait for all
	for (i = 0; i < cur->threadcount; i++)
		P(&daemon_sema);

	return *cur->port_num;
}

