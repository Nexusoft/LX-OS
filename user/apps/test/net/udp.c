/** NexusOS: simple UDP test program.

    Wait for a client and start sending at top speed:
    similar to what chargen.c does for TCP.
 
    This implementation avoids select(), because that
    is known to still have issues */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <nexus/net.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

#define MYPORT 6000

static int 
server_func(void)
{
	struct sockaddr_in server, client;
	socklen_t clen;
	char buf[1400], buf2;
	int sock, i;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket()\n");
		return 1;
	}

	memset(&server, 0, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(MYPORT);
	if (bind(sock, &server, sizeof(struct sockaddr_in)) < 0) {
		fprintf(stderr, "bind()\n");
		return 1;
	}

	clen = sizeof(struct sockaddr_in);
	if (recvfrom(sock, &buf2, 1, 0, &client, &clen) != 1) {
		fprintf(stderr, "recvfrom()\n");
		return 1;
	} 

	for (i = 0; i < 1400; i++)
		buf[i] = 32 + (i % 95); // printable characters 32..126
	
	while (1) {
		if (sendto(sock, buf, 1400, 0, &client, clen) < 1) {
			printf("done sending\n");
			break;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	printf("Nexus UDP send test -- up at port %d\n", MYPORT);
	server_func();	
	return 0;
}

