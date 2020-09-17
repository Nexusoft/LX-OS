/** NexusOS: userlevel network stack testing at lwIP low-level API */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>
#include <lwip/netifapi.h>
#include <lwip/sockets.h>

#include <nexus/net.h>
#include <nexus/sema.h>
#include <nexus/profiler.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

#define ReturnError(stmt) do { fprintf(stderr, "%s.%d: %s\n", __FUNCTION__, __LINE__, stmt); return 1; } while (0)
#define SRVPORT 8000
#define CLTPORT 9000

#define PAYLOAD "a"
#define PLEN 1

// this was a mode in lwip:nexusif, where the rxthread was disabled
// has not been committed (but can easily be revived)
#ifdef  HACKED_LWIP_NORXTHREAD
extern int nexusif_no_rxthread;
extern void low_level_rx(void);
#endif

Sema read_block = SEMA_INIT;
static unsigned int ipaddr_local;

/** background processing thread */
static void *
lwip_background(void *unused)
{
	int recur = 0;

	while (1) {
		Thread_USleep(TCP_FAST_INTERVAL * 1000);
		tcp_fasttmr();
		if (++recur % 1)
			tcp_slowtmr();
	}

	return NULL;
}

static void
lwip_udp_recv(void *arg, struct udp_pcb *conn, struct pbuf *p,
	      struct ip_addr *addr, u16_t port)
{
	if (p->len != PLEN || memcmp(p->payload, PAYLOAD, PLEN)) {
		fprintf(stderr, "recv: corrupted packet\n");
		return;
	}

	V_nexus(&read_block);
	pbuf_free(p);
}

static int
lwip_udp_send(struct udp_pcb *client, const char *payload, int plen)
{
	struct pbuf *p;

	p = pbuf_alloc(PBUF_TRANSPORT, plen, PBUF_RAM);
	memcpy(p->payload, payload, plen); 

	if (udp_send(client, p) != ERR_OK) {
		fprintf(stderr, "send: failed\n");
		return 1;
	}
	
	pbuf_free(p);
	return 0;
}

/** @param port in host byte order */
static struct udp_pcb *
lwip_udpserver_init(uint16_t port)
{
	struct udp_pcb *server;
    	
	// setup server
	server = udp_new();
	if (!server) {
		fprintf(stderr, "server: udp_new\n");
		return NULL;
	}

	if (Net_filter_ipport(0, port, nexusif_port)) {
		fprintf(stderr, "server: cannot claim port\n");
		return NULL;
	}

	if (udp_bind(server, IP_ADDR_ANY, port) != ERR_OK) {
		fprintf(stderr, "server: connect\n");
		return NULL;
	}

	return server;
}

/** Initialize a communication endpoint 
    @param port in host byte order */
static struct udp_pcb * 
lwip_udpclient_init(uint16_t port) 
{
	struct udp_pcb *client;
	struct ip_addr dstaddr;

	dstaddr.addr = ipaddr_local;

	client = udp_new();
	if (!client) {
		fprintf(stderr, "client: udp_new\n");
		return NULL;
	}
		
	// need to bind client end as well
	// XXX then integrate client and server
	if (udp_bind(client, IP_ADDR_ANY, port + 1) != ERR_OK) {
		fprintf(stderr, "client: bind\n");
		return NULL;
	}


	if (udp_connect(client, &dstaddr, port) != ERR_OK) {
		fprintf(stderr, "client: connect\n");
		return NULL;
	}

	return client;
}

static int
lwip_udp(uint16_t localport, uint16_t remoteport, int is_server)
{
	struct udp_pcb *client, *server;
	uint64_t profile[2];
	
	server = lwip_udpserver_init(localport);
	if (!server)
		return 1;

	client = lwip_udpclient_init(remoteport);
	if (!client)
		return 1;

	// set callback for recv
	udp_recv(server, lwip_udp_recv, NULL);

	// client? initiate communication
	if (!is_server)
		lwip_udp_send(client, PAYLOAD, PLEN);

	nxprofile_init(profile);
	while (1) {
#ifdef HACKED_LWIP_NORXTHREAD
		low_level_rx();
#else
		// wait for recv to return
		P(&read_block);
#endif

		// send reply
		if (lwip_udp_send(client, PAYLOAD, PLEN))
			break;

		nxprofile_update(profile, "udp");
	}

	return 0;
}

static int
lwip_udpserver(void) 
{
	printf("UDP benchmark using lwip low level (server mode)\n");

	if (lwip_udp(SRVPORT, CLTPORT, 1))
		return 1;
}

static int
lwip_udpclient(void)
{
	printf("UDP benchmark using lwip low level (client mode)\n");

	if (lwip_udp(CLTPORT, SRVPORT, 0))
		return 1;
}

int
main(int argc, char ** argv)
{
	pthread_t thread;

#ifdef HACKED_LWIP_NORXTHREAD
	nexusif_no_rxthread = 1;
#endif
	// warning: race: background thread may be created too late
	// to catch early messages
	nxnet_init_raw(1);
	pthread_create(&thread, NULL, &lwip_background, NULL);

	Net_get_ip(&ipaddr_local, NULL, NULL); 

	if (argc > 1)
		return lwip_udpclient();
	else
		return lwip_udpserver();
}

