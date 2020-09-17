/* NexusOS: unidirectional ipc_sendpage test, to test multiprocess alloc/free */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/ipc.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>

#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>

#define NUMTRANSFER 10000
#define PORT 100

static int
do_rx(void)
{
	void *page;
	int i;

	if (IPC_CreatePort(PORT) != PORT)
		ReturnError(1, "acquire port");

	// tell tx-process that we're up
	ipc_send(PORT + 1, &i, sizeof(int));
	
	for (i = 0; i < NUMTRANSFER; i++) {
		if (ipc_recvpage(PORT, &page)) {
			fprintf(stderr, "rx error at %d\n", i);
			ReturnError(1, "rx");
		}

		if (Mem_FreePages((unsigned long) page, 1))
			ReturnError(1, "rx free");
	}

	return 0;
}

/// start child process
static int
start_rx(const char *execpath)
{
	char *argv[3];

	argv[0] = (char *) execpath;
	argv[1] = "--rx";
	argv[2] = NULL;

	nxcall_exec_ex(execpath, argv, NULL, 0);
	return 0;
}

static int
do_tx(void)
{
	void *page;
	int i;

	// wait until rx process is up
	if (IPC_CreatePort(PORT + 1) != PORT + 1)
		ReturnError(1, "acquire tx port");
	ipc_recv(PORT + 1, &i, sizeof(int));

	for (i = 0; i < NUMTRANSFER; i++) {
		page = (void *) Mem_GetPages(1, 0);
		if (page == (void *) -1)
			ReturnError(1, "tx alloc");

		if (ipc_sendpage(PORT, page)) {
			fprintf(stderr, "tx error at %d\n", i);
			ReturnError(1, "tx");
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	// hangs at waitpid() during boot... why?
	test_skip_auto();

	if (argc == 2 && !strcmp(argv[1], "--rx"))
		return do_rx();

	if (start_rx(argv[0]))
		ReturnError(1, "start rx");

	if (do_tx())
		return 1;

	return 0;
}

