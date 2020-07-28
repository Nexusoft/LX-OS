/** Nexus OS: test the low-level IPC interfaces */

#ifdef __KERNEL__
#include <nexus/user_compat.h>
#include <nexus/thread.h>
#include <nexus/synch-inline.h>
#else
#include <string.h>
#include <pthread.h>

#include <nexus/IPC.interface.h>
#include <nexus/sema.h>
#endif

#define BUFLEN 50
#define MSG "one small message"

static Sema threadsema = SEMA_INIT;
static int portnum;
static int fail = 1;

#ifdef __NEXUSKERNEL__
int 
#else
void *
#endif
test_ipc_rxthread(void *unused)
{
	char buf[BUFLEN];
	int ret;

	portnum = IPC_CreatePort(NULL);
	if (portnum < 0) {
		nxcompat_fprintf(stderr, "Error at create port\n");
		goto done;
	}
	V_nexus(&threadsema);

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

int 
test_ipc(void)
{
	char *buf;
	int blen;

#ifdef __NEXUSKERNEL__
	nexusthread_fork(test_ipc_rxthread, NULL);
#else
	pthread_t t;
	pthread_create(&t, NULL, test_ipc_rxthread, NULL);
#endif

	P(&threadsema);	
	blen = strlen(MSG) + 1;
	buf = nxcompat_alloc(blen);
	memcpy(buf, MSG, blen);
	if (IPC_Send(portnum, buf, blen)) {
		nxcompat_fprintf(stderr, "Error at send\n");
		return fail;
	}

	P(&threadsema);	

	// fail is a variable set to 0 on success
	return fail;
}

#ifndef __NEXUSKERNEL__
int
main(int arc, char **argv)
{
	int ret = test_ipc();

	printf("[%s] %s.\n", argv[0], ret ? "Error" : "Ok");
	return ret;
}
#endif

