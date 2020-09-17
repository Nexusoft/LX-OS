/** NexusOS: www client to stresstest webserver */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

#define REQUEST		"README"

#define REQLEN	(100)
#define BUFLEN	(4096)

/** Execute a single GET request 
    @param server_ip is in NETWORK byte order */
static int
do_get(const char *request, uint32_t server_ip)
{
	struct sockaddr_in addr, localname;
	char rxbuf[BUFLEN];
	int fd, err, len;

	len = strlen(request);
	fd = socket(PF_INET, SOCK_STREAM, 0);

	// bind
	memset(&localname, 0, sizeof(addr));
	localname.sin_family = AF_INET;
	localname.sin_addr.s_addr = INADDR_ANY;
	localname.sin_port = 0;		// let lwip choose a port
	err = bind(fd, (struct sockaddr *) &localname, sizeof(localname));
	if (err) {
		perror("bind");
		return -1;
	}
printf("bind passed. connecting to %hu.%hu.%hu.%hu\n",
		(server_ip) & 0xff,
		(server_ip >> 8) & 0xff,
		(server_ip >> 16) & 0xff,
		(server_ip >> 24) & 0xff
		);

	// connect
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = server_ip;
	addr.sin_port = htons(80);
  	err = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err) {
		perror("connect");
		return -1;
	}

	// send request
	err = write(fd, request, len);
	if (err != len) {
		if (err < 0)
			perror("write");
		else
			fprintf(stderr, "[tx] %dB. expected %dB\n", err, len);
		return -1;
	}

	// receive response
	//
	// NB: normally have to continue reading until got entire response
	// skipping because (1) we don't have signals that could interrupt and
	//                  (2) buffer is large enough to hold test response
	err = read(fd, rxbuf, BUFLEN);
	if (err < 0) {
		if (err < 0)
			perror("read");
		else
			fprintf(stderr, "[rx] %dB. expected %dB\n", err, 863);
		return -1;
	}

printf("%s [%dB]\n", request, err);
if (err > 0)
	write(1, rxbuf, len);
write(1, "\n", 1);


	// disconnect
	err = close(fd);
	if (err) {
		perror("close");
		return -1;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	char *request, *uri;
	uint32_t address;
	int ad[4];

	if (argc != 1 && argc != 3) {
    		fprintf(stderr, "Usage: %s [ip.ip.ip.ip filepath]\n", argv[0]);
		return 1;
	}

	// (optionally) parse arguments
	if (argc == 3) {
		
		// parse address
		if (sscanf(argv[1], "%d.%d.%d.%d", 
			   &ad[0], &ad[1], &ad[2], &ad[3]) != 4) {
	    		printf("Bad server address: %s\n", argv[1]);
			return 1;
		}
		address = (ad[0] << 24) + (ad[1] << 16) + (ad[2] << 8) + ad[3];
		address = htonl(address);
		uri = argv[2];
	}
	else {
		Net_get_ip(&address, NULL, NULL);
		uri = REQUEST;
	}

	// parse request
	request = malloc(REQLEN + 1);
	snprintf(request, REQLEN, "GET %s HTTP/1.0\r\n\r\n", request);
	
	if (do_get(request, address))
		return 1;

	free(request);
	printf("[ok] test succeeded\n");
	return 0;
}

