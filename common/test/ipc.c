/** Nexus OS: test the low-level IPC interfaces 
              same code for user and kernel interfaces (where possible) */

#ifdef __NEXUSKERNEL__
#include <nexus/user_compat.h>
#include <nexus/thread.h>
#include <nexus/synch-inline.h>
#else
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include <nexus/defs.h>
#include <nexus/sema.h>
#include <nexus/test.h>
#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Thread.interface.h>
#endif

#define BUFLEN 50
#define MSG "one small message"

static Sema threadsema;
static int portnum;
static int fail;

// same for both tests
static void
shared_child_init(void)
{
	portnum = IPC_CreatePort(0);
	if (portnum < 0) {
		nxcompat_fprintf(stderr, "Error at create port\n");
#ifdef __NEXUSKERNEL__
		nexuspanic();
#else
		exit(1);
#endif
	}
	V_nexus(&threadsema);
}


#ifdef __NEXUSKERNEL__
int 
#else
void *
#endif
test_ipc_child(void *unused)
{
	char buf[BUFLEN];
	int ret;

	shared_child_init();
	
	ret = IPC_Recv(portnum, buf, BUFLEN);
	if (ret < 0 || memcmp(buf, MSG, strlen(MSG) + 1)) {
		nxcompat_fprintf(stderr, "Error at recv\n");
		goto done;
	}

	fail = 0;

done:
	V_nexus(&threadsema);
	return 0;
}

#ifdef __NEXUSKERNEL__
int 
#else
void *
#endif
test_paged_ipc_child(void *unused)
{
	void *dest;
	char cmp[PAGESIZE];
	
	shared_child_init();

	// wait for and receive data
	if (ipc_recvpage(portnum, &dest)) {
		nxcompat_fprintf(stderr, "recvpage()\n");
		goto done;
	}

	// check alignment
	if (((unsigned long) dest) & (PAGESIZE - 1)) {
		nxcompat_fprintf(stderr, "recvpage alignment\n");
		goto done;
	}

	// check data correctness
	memset(cmp, 'a', PAGESIZE);
	if (memcmp(dest, cmp, PAGESIZE)) {
		nxcompat_fprintf(stderr, "recvpage data\n");
		goto done;
	}
	
	// check mapping permissions
	((char *) dest)[0] = 'b';

	// check deallocator
#ifdef __NEXUSKERNEL__
	Map_free(kernelMap, (unsigned long) dest, 1);
#else
	if (Mem_FreePages((unsigned long) dest, 1)) {
		nxcompat_fprintf(stderr, "recvpage free\n");
		exit(1);
	}
#endif

	fail = 0;

done:
	V_nexus(&threadsema);
	return 0;
}

// same for both tests
static void
shared_parent_init(int ipc)
{
	// initialized
#ifdef __NEXUSKERNEL__
	threadsema = SEMA_INIT_KILLABLE;
#else
	threadsema = SEMA_INIT;
#endif
	fail = 1;

	// start child
#ifdef __NEXUSKERNEL__
	nexusthread_fork(ipc ? test_paged_ipc_child : test_ipc_child, NULL);
#else
	pthread_t t;
	pthread_create(&t, NULL, ipc ? test_paged_ipc_child : test_ipc_child, NULL);
#endif

	// wait for child to signal readiness
	P(&threadsema);	
}

int 
test_ipc(void)
{
	char *buf;
	int blen;

	shared_parent_init(0);

	// send data to child
	blen = strlen(MSG) + 1;
	buf = nxcompat_alloc(blen);
	memcpy(buf, MSG, blen);
	if (IPC_Send(portnum, buf, blen))
		ReturnError(1, "Error at send\n");

	// wait for acknowledgement from child
	P(&threadsema);	

	// fail is a variable set to 0 on success
	return fail;
}

/** paged IPC is not (yet) available within the kernel */
int
test_paged_ipc(void)
{
	void * page;
	
	shared_parent_init(1);

	// allocate
#ifdef __NEXUSKERNEL__
	page = (void *) Map_alloc(kernelMap, 1, 1, 0, vmem_kernel);
#else
	page = (void *) Mem_GetPages(1, 0);
#endif

	// check page invariants
	assert(page != (void *) -1 && page != NULL);
	assert((((unsigned long) page) & (PAGESIZE - 1)) == 0);

	// mark for verification
	memset(page, 'a', PAGESIZE);

	// send
	if (ipc_sendpage(portnum, page))
		ReturnError(1, "Error at send\n");

	P(&threadsema);	
	return fail;
}

#ifndef __NEXUSKERNEL__
int
main(int argc, char **argv)
{
	if (test_ipc())
		return 1;

	if (test_paged_ipc())
		return 1;

	return 0;
}
#endif

