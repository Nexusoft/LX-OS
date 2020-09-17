/* NexusOS: Posix client for communication with the echo server */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __NEXUS__
#include <nexus/syscalls.h>
#endif

#include <nexus/profiler.h>

// both in HOST byte order
#define SERVERPORT	8000
//#define SERVERADDR	((192 << 24) + (168 << 16) + ( 188 << 8) + 128)
//#define SERVERADDR	((128 << 24) + (84 << 16) + ( 98 << 8) + 76)
#define SERVERADDR	((10 << 24) + (0 << 16) + (0 << 8) + 8)

#define REPEAT		11
#define NUMSECS		1
#define THREADCOUNT	1
#define MAX_ASYNC	40
#define RESULTFILE	"/tmp/nxdevice.plotdata"

#define MINSIZE		1
#define USE_SIGNALS	1	// without signals, single thread has very high variance

static int sock;
static struct sockaddr_in saddr;

static int dostop = 1;
static int txtotal, rxtotal;

static inline void atomic_addto(int* x, int newval) {
  asm volatile ( "lock addl %1, %0" : "=m" (*x) : "ri" (newval));
}

#if USE_SIGNALS
static void 
alarmhandler(int signal)
{
       if (signal == SIGALRM)
               dostop = 1;
}
#endif

static void *
do_ask(void * _pktlen)
{
	unsigned long pktlen = (unsigned long) _pktlen;
	int txcount, rxcount, ret;
	char payload[1470];
	int i;

	txcount = 0;
	rxcount = 0;

	// ugly polling synchronization method to align start
	while (dostop)
#ifdef __NEXUS__
		thread_yield();
#else
		sched_yield();
#endif

	while (! dostop) {
		for (i = 0; i < MAX_ASYNC; i++) {
			// write
			ret = sendto(sock, payload, pktlen, 0, 
				     (struct sockaddr *) &saddr, 
				     sizeof(saddr));
			if (ret != pktlen) {
				fprintf(stderr, "sendto %d\n", ret);
				return (void *) 1;
			}
			txcount++;
		}

		for (i = 0; i < MAX_ASYNC; i++) {
			// read
			ret = recv(sock, payload, pktlen, 0);
			if (ret != pktlen) {
				// timeout (see setsockopt)
				if (ret == -1 && errno == EWOULDBLOCK)
					break;

				fprintf(stderr, "recv %d\n", ret);
				return (void *) 1;
			}
			rxcount++;
		}

		// account
		atomic_addto(&txtotal, MAX_ASYNC);
		atomic_addto(&rxtotal, MAX_ASYNC);
	}

	return NULL;
}

/** Run multiple times and calculate the median */
int
run_repeat(void)
{
	unsigned long pktlen;
	struct nxmedian_data *med;
	pthread_t t;
	int i, j;

	// forall pktsizes
//	for (pktlen = MINSIZE; pktlen <= 1470; pktlen += 1469) {
	for (pktlen = MINSIZE; pktlen <= 1458; pktlen += 1457) {
		med = nxmedian_alloc(REPEAT);
		
		printf("testing packetsize=%ld\n", pktlen);
		// repeat for median
		for (i = 0; i < REPEAT; i++) {
		
			rxtotal = 0;
			txtotal = 0;

			// start additional threads
#if USE_SIGNALS
			for (j = 1; j < THREADCOUNT; j++)
#else
			for (j = 0; j < THREADCOUNT; j++)
#endif
				pthread_create(&t, NULL, do_ask, (void *) pktlen);


			// run
			dostop = 0;
#if USE_SIGNALS
			alarm(NUMSECS);
			do_ask((void *) pktlen);
#else
			sleep(NUMSECS);
			dostop = 1;
#endif
			nxmedian_set(med, rxtotal / NUMSECS);
			printf("[total] tx=%d rx=%d in %u seconds\n", txtotal, rxtotal, NUMSECS);
		}

		nxmedian_show("", med);
		nxmedian_write(RESULTFILE, pktlen, med);
		nxmedian_free(med);
	}
	return 0;
}

int
main(int argc, char **argv)
{
// doesn't work as is: the very first recv() will return EWOULDBLOCK
// while we want to wait for the first reply.. it should skip only
// on TX overflow in the server (which is infrequent)
#ifdef RECV_TIMEOUT
	struct timeval timeout_tv;
#endif

	printf("UDP Echo client\n\n"
	       "  repeat=%u\n"
	       "  seconds=%u\n"
	       "  threads=%d\n"
	       "  async=%d\n"
	       "  server=%hu.%hu.%hu.%hu:%hu\n\n",
	       REPEAT,
	       NUMSECS,
	       THREADCOUNT,
	       MAX_ASYNC,
	       (SERVERADDR >> 24) & 0xff,
	       (SERVERADDR >> 16) & 0xff,
	       (SERVERADDR >>  8) & 0xff,
	       (SERVERADDR      ) & 0xff,
	       SERVERPORT);

#ifdef __NEXUS__
	printf("XXX Nexus version does not work (never completed)\n");
	return 1;
#endif

	// init
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		fprintf(stderr, "socket()\n");
		return 1; 
	}

#ifdef RECV_TIMEOUT
	timeout_tv.tv_sec = 0;
	timeout_tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, 
		       &timeout_tv, sizeof(timeout_tv))) {
		fprintf(stderr, "setsockopt()\n");
		return 1;
	}
#endif

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(SERVERPORT);
	saddr.sin_addr.s_addr = htonl(SERVERADDR);

#if USE_SIGNALS
	signal(SIGALRM, alarmhandler);
#endif

	return run_repeat();
}

