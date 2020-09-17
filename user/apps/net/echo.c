/** NexusOS: multithreaded UDP echo server that does not rely on lwIP stack */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

#include <nexus/net.h>
#include <nexus/test.h>

#ifdef __NEXUS__
#include <nexus/IPC.interface.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>
#else
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#endif

// configure parallelism
#define NUMTHREAD	4
#define SERVERPORT 	8000		///< host byte order

static int fd;				///< ipcport on nexus
static int pktcount;

static inline int 
atomic_get_and_addto(int* x, int newval) 
{
  __asm__ __volatile__ ( "lock xaddl %1, %0" : "=m" (*x), "+r" (newval));
  return newval;
}

static int
do_init(void)
{
#ifdef __NEXUS__
	fd = IPC_CreatePort(0);
	if (Net_filter_ipport(0, SERVERPORT, fd))
		ReturnError(1, "failed to acquire UDP port");
#else
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (fd < 0)
		ReturnError(1, "failed to open packet socket");
#endif
	return 0;
}

#include "../../../common/net/echo.c"

static void *
do_serve(void *unused)
{
#ifdef __NEXUS__
	char *page;
#else
	struct sockaddr_ll from;
	socklen_t fromlen;
	char page[1500];
#endif
	int len, oldlen = -1;
	int curcnt;

	printf("[thread] %d up\n", (int) pthread_self());
	while (1) {
#ifdef __NEXUS__
		// rx
		if (IPC_RecvPage(fd, (unsigned long) &page, NULL))
#else
		fromlen = sizeof(from);
		len = recvfrom(fd, page, 1500, 0, (struct sockaddr *) &from, &fromlen);
		if (len < 40)
#endif
			ReturnError((void *) 1, "recv()");

#ifdef __NEXUS__
		len = nxnet_page_getlen(page);
#endif
		if (len != oldlen) {
			oldlen = len;
			fprintf(stderr, "size=%d\n", len);
		}
		
		// generate reply
		if (!nxnet_echoreply(page)) {
			fprintf(stderr, "reverse\n");
			continue;
		}

		// update count
		curcnt = atomic_get_and_addto(&pktcount, 1);
		if (!(curcnt % 100000))
			fprintf(stderr, "[count] %u\n", curcnt);

#ifdef __NEXUS__
		// tx
		Net_vrouter_to((unsigned long) page, len);
#else
		if (sendto(fd, page, len, 0, (struct sockaddr *) &from, sizeof(from)) != len)
			ReturnError((void *) 1, "send()");
#endif
	}
	
	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t t;
	int i;

	printf("UDP echo server\n\n"
	       "  port=%d\n"
	       "  threads=%d\n\n", 
	       SERVERPORT,
	       NUMTHREAD);

	if (do_init())
		return 1;

	for (i = 1; i < NUMTHREAD; i++)
		pthread_create(&t, NULL, do_serve, NULL);

#ifdef __NEXUS__
	Thread_SetName("echo.1");
#endif
	do_serve(NULL);
	return 0;
}

