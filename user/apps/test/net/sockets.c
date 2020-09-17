/** NexusOS: a set of UDP/TCP test programs.

    - sink: receive UDP datagrams and calculate rate
    - server: wait for, receive and send UDP
    - client: initilize, send and recv UPD

    server/client can work in synchronous ping-pong mode
    or in flood mode, where the server sends at maximal
    rate after receiving a single packet.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>

#ifdef __NEXUS__

#include <nexus/rdtsc.h>
#include <nexus/net.h>
#include <nexus/profiler.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

#endif 

// Configuration

//#define NO_PINGPONG
#define DO_SELECT
#define DO_PROFILE

//// Warning: only select one of these at a time
//#define DO_UNIX
#define DO_TCP
//#define DO_UDP

// Defitions

#define REPEAT 1
#define MYPORT 7000
#define NUMBATCH 1
#define MSS 1460

#ifndef __NEXUS__
#undef DO_PROFILE
#endif

// Variables


#ifdef DO_UNIX

const char proto[] = "unix tcp";
static struct sockaddr_un 	server;
#define SOCKADDR		struct sockaddr_un

const char sock_filepath[] = "/tmp/sunsock.test";

static void 
init_saddr(void)
{

	memset(&server, 0, sizeof(server));
	server.sun_family = AF_UNIX;
	memcpy(server.sun_path, sock_filepath, sizeof(sock_filepath));
}

#else /* !DO_UNIX */

#ifdef DO_TCP
const char proto[] = "tcp";
#else
const char proto[] = "udp";
#endif

static struct sockaddr_in 	server;
#define SOCKADDR		struct sockaddr_in

static void 
init_saddr(void)
{
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(MYPORT);
	server.sin_addr.s_addr = htonl(INADDR_ANY);
}

#endif /* !DO_UNIX */

// Code

#ifdef DO_PROFILE
static uint64_t profile[2];
#endif

/** Be a sink: receive UDP packets 
    Call with 1B UDP packets for accounting to be correct */
static int __attribute__((unused))
sink_func(void)
{
	char buf;
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket()\n");
		return 1;
	}

	init_saddr();
	if (bind(sock, (struct sockaddr *) &server, sizeof(SOCKADDR)) < 0) {
		fprintf(stderr, "bind()\n");
		return 1;
	}

#ifdef DO_PROFILE
	nxprofile_init(profile);
#endif
	while (1) {
		if (recv(sock, &buf, 1, 0) < 0) {
			printf("[test] recv failed\n");
			break;
		}
#ifdef DO_PROFILE
		nxprofile_update(profile, proto);
#endif
	}

	return 0; // not reached
}

#ifdef DO_SELECT
/** Wait for incoming data using select 
    @return 0 on success, 1 on failure */
static int
select_func(int sock)
{
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	if (select(sock + 1, &readfds, NULL, NULL, NULL) != 1) {
		fprintf(stderr, "select()\n");
		return 1;
	}

	return 0;
}
#endif

static int
socket_func(void)
{
#ifdef DO_UNIX
	return socket(AF_UNIX, SOCK_STREAM, 0);
#elif defined DO_TCP
	return socket(AF_INET, SOCK_STREAM, 0);
#else
	return socket(AF_INET, SOCK_DGRAM, 0);
#endif
}

static void
info_func(void)
{
#ifdef NO_PINGPONG
	printf("Nexus FLOOD test\n");
#else
	printf("Nexus SYNC test\n");
#endif
#ifdef DO_UNIX
	printf("  option UNIX enabled\n");
#elif defined DO_TCP
	printf("  option TCP enabled -- port=%d\n", MYPORT);
#else
	printf("  option UDP enabled -- port=%d\n", MYPORT);
#endif
#ifdef DO_SELECT
	printf("  option DO_SELECT enabled\n");
#endif
	printf("  option BATCHCOUNT %d\n", NUMBATCH);
}

/** Send out UDP packets */
static int 
server_func(void)
{
	SOCKADDR client;
	socklen_t clen;
	char buf[MSS], buf2;
	int sock, i, j;
	int __attribute__((unused)) servsock;

	sock = socket_func();
	if (sock < 0) {
		fprintf(stderr, "socket()\n");
		return 1;
	}

	init_saddr();
	if (bind(sock, (struct sockaddr *) &server, sizeof(SOCKADDR)) < 0) {
		fprintf(stderr, "bind()\n");
		return 1;
	}

#ifndef DO_UDP
	if (listen(sock, 10)) {
		fprintf(stderr, "listen()\n");
		return 1;
	}
#endif

	info_func();

	clen = sizeof(SOCKADDR);
	printf("[test] waiting for client..\n");

#ifndef DO_UDP
	servsock = sock;
	sock = accept(sock, NULL, NULL);
	if (sock < 0) {
		fprintf(stderr, "accept()\n");
		return 1;
	}
#endif

#ifdef DO_SELECT
	if (select_func(sock))
		return 1;
#endif

	if (recvfrom(sock, &buf2, 1, 0, 
		     (struct sockaddr *) &client, &clen) != 1) {
		fprintf(stderr, "recvfrom()\n");
		return 1;
	} 

	for (i = 0; i < MSS; i++)
		buf[i] = 32 + (i % 95); // printable characters 32..126
	
	printf("[test] running..\n");
#ifdef DO_PROFILE
	nxprofile_init(profile);
#endif
	do {
	for (j = 0; j < NUMBATCH; j++)
		if (sendto(sock, buf, MSS, 0, 
			   (struct sockaddr *) &client, clen) < 1) {
			printf("[test] finished transmission\n");
			break;
		}
		
#ifndef NO_PINGPONG
	for (j = 0; j < NUMBATCH; j++)
#ifdef DO_SELECT
		if (select_func(sock))
			break;
#endif
		if (recv(sock, buf, MSS, 0) < 0) {
			printf("[test] recv failed\n");
			break;
		}
#endif
#ifdef DO_PROFILE
	for (j = 0; j < NUMBATCH; j++)
		nxprofile_update(profile, proto);
#endif
	} while (REPEAT);

	close(sock);
#ifndef DO_UDP
	close(servsock);
#endif

	printf("[test] server done\n");
	return 0;
}

/** Attach to another process running the above server 
    @param ip[] in host byteorder */
static int
client_func(unsigned char ip[4])
{
	char buf[MSS];
	int sock, i;

	printf("client mode ");
	
	sock = socket_func();
	if (sock < 0) {
		fprintf(stderr, "socket()\n");
		return 1;
	}

	init_saddr();
#ifndef DO_UNIX
	server.sin_addr.s_addr = htonl(((unsigned long) ip[0] << 24) + 
			               ((unsigned long) ip[1] << 16) + 
				       ((unsigned long) ip[2] << 8) + 
				       ip[3]);
#endif
	if (connect(sock, (struct sockaddr *) &server, sizeof(SOCKADDR)) < 0) {
		fprintf(stderr, "connect ()\n");
		return 1;
	}
	printf("[test] connected\n");
	
	// initiate communication
	buf[0] = 'a';

	for (i = 0; i < NUMBATCH; i++)
		if (send(sock, buf, 1, 0) < 1) {
			printf("[test] transmission failed\n");
			exit(1);
		}

#ifdef DO_PROFILE
	nxprofile_init(profile);
#endif
	do {
		for (i = 0; i < NUMBATCH; i++) {
#ifdef DO_SELECT
			if (select_func(sock))
				return 1;
#endif
			if (recv(sock, buf, MSS, 0) != MSS) {
				printf("[test] reception failed\n");
				exit(1);
			}
		}

#ifndef NO_PINGPONG
		for (i = 0; i < NUMBATCH; i++) {
			if (send(sock, "a", 1, 0) < 1) {
				printf("[test] transmission failed (#2)\n");
				exit(1);
			}
		}
#endif
#ifdef DO_PROFILE
		for (i = 0; i < NUMBATCH; i++)
			nxprofile_update(profile, proto);
#endif
	} while (REPEAT);

	printf("[test] client done\n");
	
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char ip[4];

	// no args ? server
	if (argc == 1)
	       return server_func();

	// sink?
	if (!strcmp(argv[1], "--sink")) {
#ifdef DO_UDP
		return sink_func();
#else
		return 1;
#endif
	}

	// client? 
	if (strcmp(argv[1], "--client")) {
		fprintf(stderr, "usage: %s [--client | --sink]\n", argv[0]);
		return 1;
	}

#ifdef DO_UNIX
	printf("[test] client connecting to %s\n", sock_filepath);
#else
#ifdef __NEXUS__
	Net_get_ip((unsigned int *) ip, NULL, NULL);
#else
	// Linux: hardcoded
	ip[0] = 10;
	ip[1] = 0;
	ip[2] = 0;
	ip[3] = 8;
#endif
	printf("[test] client connecting to %u.%u.%u.%u\n", 
	       ip[0], ip[1], ip[2], ip[3]);
#endif

	// start client	
	return client_func(ip);
}

