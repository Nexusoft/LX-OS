/** Nexus OS: lowlevel IPC functionality testing: a minimal client */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <nexus/init.h>
#include <nexus/ipc.h>
#include <nexus/IPC.interface.h>
#include <nexus/Thread.interface.h>

#define APPNAME "[ipctest-client]"
#define REQUEST "request?"
#define RESLEN 16

int 
main(int argc, char **argv)
{
	struct TransferDesc tdesc[2];
	Connection_Handle conn_handle;
	char result[RESLEN];
	int ret;

	// open connection
	printf("%s attempting to connect to port %d ..\n", APPNAME, 
	       ipctest_reserved_port);
	conn_handle = IPC_DoBind(ipctest_reserved_port);
	if (conn_handle < 0) {
		fprintf(stderr, "%s Error during connect\n", APPNAME);
		return 1;
	}
	printf("%s .. Ok\n", APPNAME);
	
	// prepare the transfer descriptor
	// first holds reply, second our request (XXX why?)
	tdesc[0].access = IPC_WRITE,
	tdesc[0].u.direct.base = (unsigned long) &result;
	tdesc[0].u.direct.length = RESLEN;
	
	// duplicate of IPC_Invoke args 2+3. Needed?
	tdesc[1].access = IPC_READ,
	tdesc[1].u.direct.base = (unsigned long) REQUEST;
	tdesc[1].u.direct.length = strlen(REQUEST) + 1;

	// send the request
	ret = IPC_Invoke(conn_handle, REQUEST, strlen(REQUEST) + 1, tdesc, 2 /* # descs*/ );
	if (ret < 0) {
		fprintf(stderr, "%s Error during transmission\n", APPNAME);
		return 1;
	}

	// process the reply
	printf("%s reply is [%s] (%dB)\n", APPNAME, result, 
	       tdesc[0].u.direct.length);

	// cleanup
	// XXX don't seem to be any cleanup routines?

	return 0;
}

static void 
pre_main(void) 
{
  // don't do poxix file init for this isolated test
  __disable_filesystem = 1; 
}

/** this function will be called before library __init calls */
void (*pre_main_hook)(void) = pre_main;

