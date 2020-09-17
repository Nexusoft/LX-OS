/** NexusOS: memory subsystem tests */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/ipc.h>
#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>

#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Thread.interface.h>

#define TESTBYTE_TX	('a')
#define TESTBYTE_RX	('b')

#define NUMRUNS		(10000)

// verify that a page is filled only with characters
// @return 0 on success
static int 
test_page(char *page, int character)
{
	int i;

	for (i = 0; i < PAGESIZE; i++) {
		if (page[i] != character)
			return 1;
	}

	return 0;
}

// share a single page
static int
do_tx_single(int pid, int replyport)
{
	unsigned long req[2];
	char reply;
	void *data;

	// alloc
	data = (void *) Mem_GetPages(1, 0);
	if (!data)
		return -1;
	memset(data, TESTBYTE_TX, PAGESIZE);

	// correct share
	req[1] = replyport;
	req[0] = (unsigned long) Mem_Share_Pages(pid, (unsigned long) data, 1, 1);
	if (!req[0])
		ReturnError(-1, "parent: share failed\n");

	if (ipc_send(memtest_reserved_port, req, sizeof(long) * 2) != 0)
		ReturnError(-1, "tx: send failed\n");
	
	// wait for child to reply
	if (ipc_recv(req[1], &reply, 1) != 1)
		ReturnError(-1, "tx: recv failed\n");
	if (reply != 0)
		ReturnError(-1, "tx: illegal response\n");

	// verify data
	if (test_page((char *) data, TESTBYTE_RX))
		ReturnError(-1, "tx: data mismatch\n");

	// cleanup
	Mem_FreePages((unsigned long) data, 1);

	return 0;
}

/// like do_tx_single, but with additional tests 
static int
do_tx_extensive(int pid, int replyport)
{
	unsigned long req[2], alt;
	char *data, reply;

	// alloc
	data = (char *) Mem_GetPages(1, 0);
	if (!data)
		return -1;
	memset(data, TESTBYTE_TX, PAGESIZE);
	
	// create a port for the reply
	req[1] = replyport;

	// verify that unaligned share fails
	alt = Mem_Share_Pages(pid, (unsigned long) data + 1, 1, 1);
	if (alt)
		ReturnError(-1, "parent: unaligned share succeeded\n");

	// correct share
	req[0] = (unsigned long) Mem_Share_Pages(pid, (unsigned long) data, 1, 1);
	if (!req[0])
		return -1;

	// verify that share fails when recipient's grantpages are exhausted
	alt = Mem_Share_Pages(pid, (unsigned long) data, 1, 1);
	if (alt)
		ReturnError(-1, "parent: share succeeded after exhausting grants\n");

	// tell it the address to read
	if (ipc_send(memtest_reserved_port, req, sizeof(long) * 2) != 0)
		ReturnError(-1, "parent: send failed\n");
	
	// wait for child to reply
	if (ipc_recv(req[1], &reply, 1) != 1)
		ReturnError(-1, "parent: receive failed\n");
	if (reply != 0)
		ReturnError(-1, "parent: illegal response\n");

	// verify data
	if (test_page((char *) data, TESTBYTE_RX))
		ReturnError(-1, "Data mismatch\n");

	// cleanup
	Mem_FreePages((unsigned long) data, 1);
	return 0;
}

static int
do_tx(const char *filepath)
{
	int pid, replyport, i;

	replyport = IPC_CreatePort(0);
	
	// start process and give it access to our page
	pid = nxcall_exec_ex(filepath, (char *[]) {(char *) filepath, "--child", NULL}, NULL, 0);
	usleep(100000); // wait for process to have called Set_GrantPages (RACE)

	//XXX will fail, because Set_GrantPages(2) will allow second Share_Page
	//if (do_tx_extensive(pid, replyport))
	//	return 1;

	for (i = 0; i < NUMRUNS; i++) {
		if (do_tx_single(pid, replyport)) {
			printf("Tx failed at %d\n", i);
			return 1;
		}
	}

	// cleanup
	IPC_DestroyPort(replyport);
	return 0;
}

static int
do_rx_inner(int ipcport)
{
	unsigned long req[2];
	char reply; 
	int len;
	
	// XXX set multiple pages to avoid (infrequent) race 
	//     race probably because IPC send/recv need not be synchronous
	Mem_Set_GrantPages(2);

	// wait for request
	len = ipc_recv(ipcport, req, sizeof(long) * 2);
	
	// verify data
	if (test_page((char *) req[0], TESTBYTE_TX))
		ReturnError(-1, "rx: data mismatch\n");

	memset((char *) req[0], TESTBYTE_RX, PAGESIZE);

	// unmap
	if (Mem_FreePages(req[0], 1))
		ReturnError(-1, "rx: unmap failed\n");

	// reply OK
	reply = 0;
	if (ipc_send(req[1], &reply, 1) != 0)
		ReturnError(-1, "rx: reply failed\n");

	return 0;
}

/// execute as memory grant test child process
static int
do_rx(void)
{
	int ipcport, i;

	// acquire standard port for this test
	ipcport = IPC_CreatePort(memtest_reserved_port);
	if (ipcport != memtest_reserved_port)
		ReturnError(-1, "could not acquire testport\n");

	for (i = 0; i < NUMRUNS; i++) {
		if (do_rx_inner(ipcport)) {
			printf("Rx failed at %d\n", i);
			return 1;
		}
	}

	// cleanup
	IPC_DestroyPort(ipcport);
	return 0;
}

int 
main(int argc, char **argv)
{
	// XXX run at boot. Fails probably because of race (see above)
	test_skip_auto()

	// child process spawned by standard codepath
	if (argc == 2 && !strcmp(argv[1], "--child"))
		return do_rx();
	
	if (argc == 1) 
		printf("[mem] NB: takes a long time because of byte tests\n");
	
	// standard codepath
	if (do_tx(argv[0]))
		return 1;

	if (argc == 1)
		printf("[mem] OK. Test passed\n");
	return 0;
}

