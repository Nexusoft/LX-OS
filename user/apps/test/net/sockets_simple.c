/** NexusOS: very simple socket functionality (mostly select) */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <nexus/test.h>

#define MYPORT	(6000)
#define DO_TCP

int
main(int argc, char **argv)
{
	struct sockaddr_in addr;
	fd_set readfds;
	char buf[256];
	int fd, ret;

#ifdef DO_TCP
	fd = socket(PF_INET, SOCK_STREAM, 0);
#else
	fd = socket(PF_INET, SOCK_DGRAM, 0);
#endif
	if (fd < 0)
		ReturnError(1, "socket()");

	// bind
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(MYPORT);
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)))
		ReturnError(1, "bind()");

#ifdef DO_TCP
	if (listen(fd, 1))
		ReturnError(1, "listen()");

	fd = accept(fd, NULL, NULL);
	if (fd < 0)
		ReturnError(1, "accept()");
#endif

	while (1) {
		FD_ZERO(&readfds);
		FD_SET(0, &readfds);
		FD_SET(fd, &readfds);
		printf("wait..\n");
		ret = select(fd + 1, &readfds, NULL, NULL, NULL);
		fprintf(stderr, "  ready descriptors..\n", ret);	
	
		if (FD_ISSET(0, &readfds)) {
			ret = read(0, buf, 255);
			buf[ret < 0 ? 0 : ret] = 0;
			fprintf(stderr, "  .. keyboard read %dB [%s]\n", ret, buf);
		}

		if (FD_ISSET(fd, &readfds)) {
			ret = read(fd, buf, 255);
			buf[ret < 0 ? 0 : ret] = 0;
			fprintf(stderr, "  .. network read %dB [%s]\n", ret, buf);
		}
	}

	return 0;
}

