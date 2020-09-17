/** Measure bitrate for IPC operations: ping-pong test */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/rdtsc.h>

#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>

#define PARENT 0
#define CHILD 1
#define ROUNDTRIPS (1000ULL * 100)
#define CPU_HZ (3000ULL * 1000 * 1000)

#if NXCONFIG_FAST_IPC
#define SEND 		ipc_send
#define RECV 		ipc_recv
#define SND_PAGE	ipc_sendpage
#define RCV_PAGE	ipc_recvpage
#else
#define SEND IPC_Send
#define RECV IPC_Recv
#define SND_PAGE	IPC_SendPage
#define RCV_PAGE	IPC_RecvPage
#endif

static Sema child_done = SEMA_INIT;

static int blen;			///< length of buffer

static int
endpoint(int ports[2], int parent)
{
	uint64_t tstamp = 0;
	char *buf;
	unsigned long long roundtrips;
	double pps;

	buf = malloc(blen);
	
	if (parent) {
		// NB: we send one packet too many
		if (SEND(ports[CHILD], buf, blen))
			ReturnError(1, "send #1");
	} 
	else {
		tstamp = rdtsc64();
	}

	roundtrips = 0;
	while (roundtrips++ < ROUNDTRIPS) {
		if (RECV(ports[parent ? PARENT : CHILD], buf, blen) != blen)
			ReturnError(1, "recv #1");
		if (SEND(ports[parent ? CHILD : PARENT], buf, blen))
			ReturnError(1, "send #2");
	}

	if (!parent) {
		// calculate rate
		tstamp = rdtsc64() - tstamp;
		pps = ((double) roundtrips) / ((double) tstamp / CPU_HZ);
		pps *= 2; // calculate total bandwidth of bidirectional channel
		printf("sec=%.2g cycles=%llu pps~=%.6g Bps~=%.6g (pktlen=%u)\n", 
		       (double) tstamp / CPU_HZ, tstamp, pps, pps * blen, blen);

		// empty queue
		if (RECV(ports[CHILD], buf, blen) != blen)
			ReturnError(1, "recv #2");
	}

	free(buf);
	return 0;
}

/** child endpoint */
static void *
ipc_thread(void * _ports)
{
	endpoint(_ports, 0);
	V_nexus(&child_done);
	return NULL;
}

static int
run_test(int ports[2], int buflen)
{
	pthread_t thread;
	
	blen = buflen;
	pthread_create(&thread, NULL, ipc_thread, ports);
	endpoint(ports, 1);

	P(&child_done);
	return 0;
}

/** very similar to endpoint.
    XXX combine shared parts */
static int
endpoint_paged(int ports[2], int parent, void *page)
{
	uint64_t tstamp = 0;
	unsigned long long roundtrips;
	double pps;

	if (parent) {
		// NB: we send one packet too many
		if (SND_PAGE(ports[CHILD], page))
			ReturnError(1, "send #1");
	} 
	else {
		tstamp = rdtsc64();
	}

	roundtrips = 0;
	while (roundtrips++ < ROUNDTRIPS) {
#if NXCONFIG_FAST_IPC
		if (RCV_PAGE(ports[parent ? PARENT : CHILD], &page))
#else
		if (RCV_PAGE(ports[parent ? PARENT : CHILD], (unsigned long) &page, NULL))
#endif
			ReturnError(1, "recv #2");
		if (SND_PAGE(ports[parent ? CHILD : PARENT], page))
			ReturnError(1, "send #2");
	}

	if (!parent) {
		// calculate rate
		tstamp = rdtsc64() - tstamp;
		pps = ((double) roundtrips) / ((double) tstamp / CPU_HZ);
		pps *= 2; // calculate total bandwidth of bidirectional channel
		printf("sec=%.2g cycles=%llu pps~=%.6g Bps~=%.6g (pagesize==4kB)\n", 
		       (double) tstamp / CPU_HZ, tstamp, pps, pps * PAGESIZE);

		// empty queue
#if NXCONFIG_FAST_IPC
		if (RCV_PAGE(ports[CHILD], &page))
#else
		if (RCV_PAGE(ports[CHILD], (unsigned long) &page, NULL))
#endif
			ReturnError(1, "recv #2");
	
		// only free on the last receiving endpoint!
		Mem_FreePages((unsigned long) page, 1);
	}

	return 0;
}

static void *
ipc_thread_paged(void * _ports)
{
	endpoint_paged(_ports, 0, NULL);
	V_nexus(&child_done);
	return NULL;
}

/** Run a page ping-pong with page-swapping IPC */
static int
run_test_paged(int ports[2])
{
	void * page;
	pthread_t thread;

	page = (void *) Mem_GetPages(1, 0);
	if (page == (void *) -1) {
		fprintf(stderr, "getpages");
		return -1;
	}

	pthread_create(&thread, NULL, ipc_thread_paged, ports);
	endpoint_paged(ports, 1, page);

	P(&child_done);
	return 0;
}

int main(int argc, char **argv)
{
	int ports[2];

	printf("Nexus IPC benchmark utility\n");

	// open IPC endpoints
	ports[0] = IPC_CreatePort(0);
	if (ports[0] < 0)
		ReturnError(1, "create port #1");
	ports[1] = IPC_CreatePort(0);
	if (ports[1] < 0)
		ReturnError(1, "create port #1");

	// run tests for varying payload size
	run_test(ports, 1);
	run_test(ports, PAGESIZE);
	run_test(ports, PAGESIZE << 4);

	// run paged test
	run_test_paged(ports);

	return 0;
}

