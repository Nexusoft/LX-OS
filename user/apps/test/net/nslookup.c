/** NexusOS: DNS lookup utility */

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int
main(int argc, char **argv)
{
	struct hostent *host;
	char *ipstr;
	int i = 0;


	if (argc == 1)
		host = gethostbyname("www.cs.cornell.edu");
	else
		host = gethostbyname(argv[1]);

	if (!host) {
		fprintf(stderr, "[dns] lookup failed\n");
		return 1;
	}

	printf("[dns] %s :\n", host->h_name);
	while (host->h_addr_list[i]) {
		ipstr = inet_ntoa(*(struct in_addr*) host->h_addr_list[i]);
		printf("\t\t%s", ipstr);
		i++;
	}

	return 0;
}

