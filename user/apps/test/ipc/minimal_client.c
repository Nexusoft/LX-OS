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

// Just sending payload, bu all IPC invocation requests must start with opfield
struct request {
	int operation;		
	char payload[10];
};

int 
main(int argc, char **argv)
{
	struct TransferDesc tdesc[1];
	struct request request;
	char result[RESLEN];
	int ret;

	// open connection
	printf("%s attempting to connect to port %d ..\n", APPNAME, 
	       ipctest_reserved_port);
	
	// prepare the transfer descriptor
	// first holds reply, second our request
	tdesc[0].access = IPC_WRITE,
	tdesc[0].u.direct.base = (unsigned long) &result;
	tdesc[0].u.direct.length = RESLEN;
	
	// prepare request
	request.operation = 666;
	snprintf(request.payload, 8, "%s", REQUEST);
	request.payload[9] = 0;

	// send the request
	ret = IPC_Invoke(ipctest_reserved_port, 
			 (char *) &request, sizeof(request), 
			 tdesc, 1 /* # descs*/ );
	if (ret < 0) {
		fprintf(stderr, "%s Error during transmission\n", APPNAME);
		return 1;
	}

	// process the reply
	printf("%s reply is [%s] (%dB)\n", APPNAME, result, 
	       tdesc[0].u.direct.length);

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

