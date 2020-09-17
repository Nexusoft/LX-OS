/** NexusOS: Labelstore: a process that 
	         1. stores Nexus labels and 
		 2. attests to them as an authority over ipc */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/guard.h>
#include <nexus/formula.h>
#include <nexus/guard-impl.h>

#include <nexus/IPC.interface.h>
#include <nexus/Auth.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/GuardStd.interface.h>

static int port_cred;	// ipc port on which to access labels

/** attest to a NAL statement if it is locally stored 
    will only agree to statements of the form
 
      ``labelstore says S''
 
    where S is locally stored 

    @return 1 if found, 0 if not
 */
int
auth_answer(const char *req, int pid)
{
	Form *form;
	char *der;
	int ret;

	printf("[debug] request: %s\n", req);

	// parse string
	form = form_from_pretty(req);
	if (!form) {
		printf("[labelstore] dropped illegible credential #1\n");
		return 0;
	}
	
	// generate DER standard form
	der = (char *) form_to_der(form);
	if (!der) {
		printf("[labelstore] dropped illegible credential #2\n");
		return 0;
	}
	
	// lookup
	ret = nxguardsvc_cred_chk(der) ? 0 : 1;

	// cleanup
	free(der);
	form_free(form);

	printf("        reply:   %d\n", ret);
	return ret;
}

/** Handle Auth_Answer requests */
static void *
auth_thread(void *unused)
{
	while (1)
		Auth_processNextCommand();

	return NULL;
}

static void *
cred_thread(void *unused)
{
	while (1)
		GuardStd_processNextCommand();

	return NULL;
}

int 
main(int argc, char **argv)
{
	pthread_t thread;

	if (argc != 2) {
		// must call with a name to be used as authority (e.g., 'labelstore')
		fprintf(stderr, "Usage: %s <authname>\n", argv[1]);
		return 1;
	}

	// claim name
	Auth_serverInit();
	if (nxguard_auth_register(default_guard_port, Auth_port_handle, argv[1]))
		ReturnError(1, "[labelstore] could not acquire name");

	// initial credential store 
	// nb: also starts a lot of other services unnecessarily
	if (nxguardsvc_init())
		return 1;

	// start authority thread: listen on authority requests
	pthread_create(&thread, NULL, auth_thread, NULL);

	// start guard thread: listen on credential requests
	GuardStd_serverInit();
	pthread_create(&thread, NULL, cred_thread, NULL);

	printf("[labelstore] up\n"
	       "   insert labels at ipc port %d\n"
	       "   verify labels at authority %s\n"
	       "\n"
	       "press [Enter] to exit\n",
	       GuardStd_port_handle, argv[1]);
	getchar();

	printf("[labelstore] down\n");
	return 0;
}

