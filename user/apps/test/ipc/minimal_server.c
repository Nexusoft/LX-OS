/** Nexus OS: lowlevel IPC functionality testing: a minimal server 
 
    Test IPC by first executing this server and then calling the
    accompanying client. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <nexus/init.h>
#include <nexus/ipc.h>
#include <nexus/IPC.interface.h>

#define APPNAME "[ipctest-server]"
#define REPLY "reply!"
#define RXBUFLEN 1024

int 
main(int argc, char **argv)
{
	Port_Handle server_handle;
	Port_Num server_portnum;
	Call_Handle call_handle;
	CallDescriptor cdesc;
	char rxbuf[RXBUFLEN];
	int rxlen;
	int ret = 0;

	if (argc != 1) {
		fprintf(stderr, "%s Usage: %s\n", APPNAME, argv[0]);
		return 1;
	}

	// create the port
	server_portnum = ipctest_reserved_port;
	server_handle = IPC_CreatePort(&server_portnum);
	assert(server_handle == server_portnum);
	printf("%s listening on port %d\n", APPNAME, server_portnum);

	// wait for and process connect request
	if (IPC_DoBindAccept(server_handle) < 0) {
		fprintf(stderr, "%s Error: at bind\n", APPNAME);
		ret = 1;
		goto cleanup;
	}
	printf("%s accepted connection request\n", APPNAME);

	// wait for and process read request
	rxlen = RXBUFLEN;
	call_handle = IPC_RecvCall(server_handle, rxbuf, &rxlen, &cdesc);
	
	// I don't know why this construct is needed. XXX find out
	if (call_handle == 0) {
		fprintf(stderr, "%s Debug: using embedded chan\n", APPNAME);
		call_handle = cdesc.call_handle;
	}
	if (call_handle < 0) {
		fprintf(stderr, "%s request reception failed\n", APPNAME);
		ret = 1;
		goto cleanup;
	}

	printf("%s received message [%s] (%dB). replying\n", 
	       APPNAME, rxbuf, rxlen);

	// reply
	IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START,
		       REPLY, strlen(REPLY) + 1);
	IPC_CallReturn(call_handle);

cleanup:
	if (IPC_DestroyPort(server_handle)) {
		fprintf(stderr, "%s failed to cleanly close port\n", APPNAME);
		ret = 1;
	}

	return ret;
}

static void 
pre_main(void) 
{
  // don't do poxix file init for this isolated test
  __disable_filesystem = 1; 
}

/** this function will be called before library __init calls */
void (*pre_main_hook)(void) = pre_main;
