/** NexusOS: UDP echo application using the lwIP netconn API 
    based on the udpecho example in lwip:contrib */

#include <lwip/api.h>
#include <lwip/sys.h>

#include <nexus/net.h>
#include <nexus/profiler.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

#define MYPORT	6000
#define TXPORT	(MYPORT + 1)
#define MSG 	"hello world\n"

uint64_t profile[2];

int sendside(void)
{
	struct netconn *conn;
	struct netbuf *buf, *sendbuf;
	struct ip_addr addr, laddr;
	char buffer[2000];

	printf("Nexus udp (sender)\n\n");
	printf("Warning: remote IP address is hardcoded\n");

#ifndef NONEXUS
  	/* NEXUS: have to ask filter for port if not using sockets */
  	extern int nexusif_port;
  	Net_filter_ipport(0, TXPORT, nexusif_port);
  	printf("nexus: asked filter for UDP port %d\n", TXPORT);
#endif

	// ip address in network byte order. HARDCODED
	addr.addr = 172 + (16 << 8) + (116 << 16) + (129 << 24);
	laddr.addr = IP_ADDR_ANY;

	conn = netconn_new(NETCONN_UDP);
	LWIP_ASSERT("con != NULL", conn != NULL);
	netconn_bind(conn, &addr, TXPORT);
	printf("[uecho] acquired local port\n");
	netconn_connect(conn, &addr, MYPORT);
	printf("[uecho] connected to remote port\n");

	sendbuf = netbuf_new();
	if (netbuf_ref(sendbuf, MSG, 12) != ERR_OK) {
		printf("netbuf_ref failed\n");
		return 1;
	}
	printf("[uecho] ready\n");

	nxprofile_init(profile);
	while (1) {
		if (netconn_send(conn, sendbuf) == ERR_OK) {
			buf = netconn_recv(conn);
			netbuf_delete(buf);
			nxprofile_update(profile, "udp");
		}
	}

	netconn_delete(conn);
	return 0;
}

int main(int argc, char **argv)
{
	struct netconn *conn;
	struct netbuf *buf;
	struct ip_addr *addr;
	unsigned short port;
	char buffer[2000];
	err_t err;

	nxnet_init();

	if (argc == 2)
		return sendside();

	printf("Nexus udp echo\n\n");
	
	conn = netconn_new(NETCONN_UDP);
	LWIP_ASSERT("con != NULL", conn != NULL);
	netconn_bind(conn, NULL, MYPORT);
	printf("[uecho]  up at port %d\n", MYPORT);

#ifndef NONEXUS
  	/* NEXUS: have to ask filter for port if not using sockets */
  	extern int nexusif_port;
  	Net_filter_ipport(0, MYPORT, nexusif_port);
  	printf("nexus: asked filter for UDP port %d\n", MYPORT);
#endif

	nxprofile_init(profile);
	while (1) {
		buf = netconn_recv(conn);
		if (buf) {
			addr = netbuf_fromaddr(buf);
			port = netbuf_fromport(buf);
			netconn_connect(conn, addr, port);
			netbuf_copy(buf, buffer, buf->p->tot_len);
			buffer[buf->p->tot_len] = '\0';
			netconn_send(conn, buf);
			netbuf_delete(buf);
			nxprofile_update(profile, "udp");
		}
	}

	return 0;
}

