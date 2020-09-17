/** NexusOS: stresstest/benchmark IPC with concurrency */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/machine-structs.h>

#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>

//// configuration

#define NUM_SECS	(100)
//#define DO_PAGED

//// definitions

#define BUF_SIZE	(4096)
#define CHECK_SIZE	(10)

static Sema stopsema;
static int dostop;
static int count;

//// function declarations

/** data should be 4 bytes that contain a reply port, 
    followed by characters (rport % 256) */
static int
check_data(char *buf, char character)
{
	int i;

	for (i = sizeof(long); i < CHECK_SIZE; i++) 
		if (buf[i] != character)
			return 1;

	return 0;
}

/** see check_data for info */
static void
fill_data(char *buf, long port)
{
	char character;
	int i;

	memcpy(buf, &port, sizeof(port));
	character = port & 255;

	for (i = sizeof(long); i < BUF_SIZE; i++) 
		buf[i] = character;
}

static void *
do_server(void *_port)
{
#ifdef DO_PAGED
	char *buf;
#else
	char buf[BUF_SIZE];
#endif
	long rport = 0, port = (long) _port;
	int len;

	while (!dostop) {
#ifdef DO_PAGED
		len = IPC_RecvPage(port, (unsigned long) &buf, NULL);
		len = len ? -1 : PAGE_SIZE;
#else
		// recv
		len = IPC_Recv(port, buf, BUF_SIZE);
#endif
		if (len < 0)
			ReturnError((void *) -1, "rx");
		if (len != BUF_SIZE)
			ReturnError((void *) -1, "rx len");

		// verify
		memcpy(&rport, buf, sizeof(long));
		if (check_data(buf, rport & 255))
			ReturnError((void *) -1, "rx data");

		// send
#ifdef DO_PAGED
		if (IPC_SendPage(rport, buf))
#else
		if (IPC_Send(rport, buf, BUF_SIZE))
#endif
			ReturnError((void *) -1, "tx");
	}

#ifndef DO_PAGED
	if (rport)
		IPC_Send(rport, buf, BUF_SIZE);
#endif

	IPC_DestroyPort(port);
	V_nexus(&stopsema);
	return NULL;
}

static void *
do_client(void *_rport)
{
#ifdef DO_PAGED
	char *buf = (void *) Mem_GetPages(1, 0);
#else
	char buf[BUF_SIZE], rbuf[BUF_SIZE];
#endif
	long lport, rport = (long) _rport;
	int len, i;

	lport = IPC_CreatePort(0);
	fill_data(buf, lport);

	while (!dostop) {
		// send
#ifdef DO_PAGED
		if (IPC_SendPage(rport, buf))
#else
		if (IPC_Send(rport, buf, BUF_SIZE))
#endif
			ReturnError((void *) -1, "tx");
		
		// recv
#ifdef DO_PAGED
		len = IPC_RecvPage(lport, (unsigned long) &buf, NULL);
		len = len ? -1 : PAGE_SIZE;
#else
		len = IPC_Recv(lport, rbuf, BUF_SIZE);
#endif
		if (len < 0)
			ReturnError((void *) -1, "rx");
		if (len != BUF_SIZE)
			ReturnError((void *) -1, "rx len");

		// verify
		if (check_data(buf, lport & 255))
			ReturnError((void *) -1, "rx data");

		atomic_addto(&count, 1);
	}

#ifdef DO_PAGED
	Mem_FreePages((unsigned long) buf, 1);
#else
	// send one more request, to unblock servers
	IPC_Send(rport, buf, BUF_SIZE);
#endif

	IPC_DestroyPort(lport);
	V_nexus(&stopsema);
	return NULL;
}

static int
do_test(int num_servers, int clients_per_server)
{
	pthread_t t;
	long port;
	int i, j;

	printf("[test] %d servers + %d clients\n", 
	       num_servers, num_servers * clients_per_server);
	
	stopsema = SEMA_INIT;
	count = 0;

	// start servers + clients
	for (i = 0; i < num_servers; i++) {
		port = IPC_CreatePort(0);
		pthread_create(&t, NULL, do_server, (void *) port);
		for (j = 0; j < clients_per_server; j++)
			pthread_create(&t, NULL, do_client, (void *) port);
	}

	// sleep
	sleep(NUM_SECS);
	dostop = 1;

// ~n - 1 remain blocked
//	for (i = 0; i < num_servers + (num_servers * clients_per_server); i++)
//		P(&stopsema);
	printf("[test] %d packets\n", count * 2 /* request + reply */); 
	return 0;
}

int
main(int argc, char **argv)
{
//	do_test(1, 1);
//	do_test(1, 10);
	do_test(10, 1);

	printf("[ok] all tests succeeded\n");
	return 0;
}

