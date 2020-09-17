/** NexusOS: UDP pingpong test without lwIP overhead 
 
    start without arguments to act as server
    add an arbitrary argument to start as client */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <nexus/defs.h>
#include <nexus/net.h>
#include <nexus/profiler.h>
#include <nexus/packet_headers.h>
#include <nexus/IPC.interface.h>
#include <nexus/Net.interface.h>

#define SERVER_PORT 9000
#define CLIENT_PORT (SERVER_PORT + 1)

static uint32_t ipaddr;
static char mac[6];
static int is_client;

static char *
alloc_packet(void)
{
	PktEther *eth;
	PktIp  *iph;
	PktUdp *udph;
	char * buf;

	// acquire data
	buf = nxnet_alloc_page();
	if (!buf) {
		fprintf(stderr, "alloc page failed\n");
		exit(1);
	}

	// fill in (minimally required) contents
	memset(buf, 0, 1514);
	eth = (void *) buf;
	memcpy(eth->dstaddr, mac, 6);
	memcpy(eth->srcaddr, mac, 6);
	*((uint16_t *) eth->proto) = htons(0x800);

	iph = (void *) eth + 14;
	*((uint16_t *) iph->len) = sizeof(PktUdp) + sizeof(PktIp);
	iph->proto = IP_PROTO_UDP;
	memcpy(iph->src, &ipaddr, 4);
	memcpy(iph->dst, &ipaddr, 4);

	udph = (void *) buf + 34;
	*((uint16_t *) udph->csum) = 0;
	*((uint16_t *) udph->length) = sizeof(PktUdp);
	if (is_client) {
		*((uint16_t *) udph->srcport) = htons(CLIENT_PORT);
		*((uint16_t *) udph->dstport) = htons(SERVER_PORT);
	}
	else {
		*((uint16_t *) udph->dstport) = htons(CLIENT_PORT);
		*((uint16_t *) udph->srcport) = htons(SERVER_PORT);
	}
	nxnet_page_setlen(buf, sizeof(PktEther) + sizeof(PktIp) + sizeof(PktUdp));
	return buf;
}

int main(int argc, char **argv)
{
	uint64_t profile[2];
	char *buf, *rbuf;
	int port;

	port = IPC_CreatePort(0);
	if (port < 0) {
		fprintf(stderr, "create port failed\n");
		return 1;
	}

	// choose role 
	is_client = (argc > 1) ? 1 : 0;
	printf("Nexus RAWwwww udp test (%s mode)\n", 
	       is_client ? "client" : "server");

	// get network info
	Net_get_mac(mac);
	Net_get_ip(&ipaddr, NULL, NULL);

	// acquire network port
	Net_filter_ipport(0, is_client ? CLIENT_PORT : SERVER_PORT , port);

	nxprofile_init(profile);

	// client ? initiate communication
	if (is_client) {
		buf = alloc_packet();
		if (ipc_sendpage(default_switch_port, buf)) {
			fprintf(stderr, "send failed\n");
			return 1;
		}
	}

	while (1) {
		// recv
		if (ipc_recvpage(port, &rbuf)) {
			fprintf(stderr, "recv failed\n");
			return 1;
		}
		nxnet_free_page(rbuf);

		// send
		buf = alloc_packet();
		if (ipc_sendpage(default_switch_port, buf)) {
			fprintf(stderr, "send failed\n");
			return 1;
		}

		nxprofile_update(profile, "udp");
	}

	return 0;
}


