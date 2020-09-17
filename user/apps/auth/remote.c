/** NexusOS: demo the guard: 
  	     - log to a remore servuce or 
	     - ask a remote service for permission

	     WARNING: communication is with netcat over INSERCURE channel. 
	     This is just a demo.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/test.h>

#include <nexus/Auth.interface.h>

/// define to run as standalone process instead of authority
//#define TESTDIRECT

#define SERVER_PORT_LOG 1234
#define SERVER_PORT_ASK 1235

static int sock;
static int ask;

/** Send the request to a server in plain text and give the credential */
static int
authfunc_log(const char *req)
{
	char buf[81];
	int len, ret;

	if (snprintf(buf, 79, "authority: %s\n", req) == 79) {
		// hard limit at good ol' IBM punchard width
		buf[79] = '\n';		
		buf[80] = 0;
	}
	
	// allow if transmission succeeded
	len = strlen(buf) + 1;
	ret = send(sock, buf, len, 0);
	if (ret == len) {
		printf("[auth] logged request\n");
		return 1;
	}
	else {
		printf("[auth] failed to log access (%d != %d)\n", ret, len);
		return 0;
	}
}

/** Like authfunc_log, but ask the server whether to give the credential.
    The server is expected to return "yes". All else is interpreted as "no". 
    The reply is not case-sensitive.
 */
static int
authfunc_ask(const char *req)
{
	char buf[81];
	int len, forbid = 0;

	authfunc_log(req);
	do {
		len = recv(sock, buf, 80, 0);
		
		// len should never be as many as 80 characters. 
		// flush the buffer and fail
		if (len == 80)
			forbid = 1;

		// remove trailing endline 
		if (buf[len - 1] == '\n') 
			len--;
	
	} while (len == 80);	

	if (forbid || len != 3)
		return 0;

	buf[3] = 0;
	return strcasecmp(buf, "yes") ? 0 : 1;
}

/** Callback called from Auth.svc with each Auth_Answer call */
int auth_answer(const char *req, int pid)
{
	if (ask)
		return authfunc_ask(req);
	else
		return authfunc_log(req);
}

/** Wrapper to test the functions independent from the guard */
static void __attribute__((unused))
run_direct(int do_ask)
{
#define DOTEST 5

	char buf;
	int ret, i;

	printf("[test] running direct %s test\n"
	       "       your next %d [enters] will emulate a check\n", 
	       do_ask ? "ask" : "log", DOTEST);
	
	for (i = 0; i < DOTEST; i++) {
		while ((buf = getchar()) != '\n' && buf != EOF) {}

		// call the function
		if (do_ask)
			ret = authfunc_ask("may I?");
		else
			ret = authfunc_log("may I?");

		printf("I may %s\n", ret ? "" : "NOT");
	}

	printk("[test] done\n");
}

static void __attribute__((noreturn))
usage(const char *filepath)
{
	fprintf(stderr, "Usage: %s <log|ask> <ipv4 address>\n", filepath);
	exit(1);
}

static int
net_open(int argc, char **argv, int ask)
{
	struct sockaddr_in servaddr;
	uint32_t server_ip;	// little endian
	unsigned int s1, s2, s3, s4;
	
	// parse host
	if (sscanf(argv[2], "%u.%u.%u.%u", &s1, &s2, &s3, &s4) != 4)
		usage(argv[0]);
	if (s1 > 255 || s2 > 255 || s3 > 255 || s4 > 255)
		usage(argv[0]);
	server_ip = (s1 << 24) + (s2 << 16) + (s3 << 8) + s4;

	// connect to server
	
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (!sock)
		ReturnError(1, "socket()");

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(ask ? SERVER_PORT_ASK : SERVER_PORT_LOG);
	servaddr.sin_addr.s_addr = htonl(server_ip);

	if (connect(sock, (void *) &servaddr, sizeof(servaddr)))
		ReturnError(1, "connect()");

	printf("[auth] up. connected to %s.%d\n", 
	       argv[2], ntohs(servaddr.sin_port));
	return 0;
}

#define MSG_HI		"\n[authority] connect\n"
#define MSG_BYE		"\n[authority] disconnect\n\n"

int
main(int argc, char **argv)
{
	int ret;

	if (argc != 3)
		usage(argv[0]);

	// parse authority type parameter
	if (!strcmp(argv[1], "ask"))
		ask = 1;
	else if (strcmp(argv[1], "log"))
		usage(argv[0]);
	else
		ask = 0;

	if (net_open(argc, argv, ask))
		return 1;

	send(sock, MSG_HI, strlen(MSG_HI) + 1, 0);

#ifndef TESTDIRECT
	ret = nxguard_auth(default_guard_port, argv[1], NULL);
#else
	run_direct(ask);
	ret = 0;
#endif

	send(sock, MSG_BYE, strlen(MSG_BYE) + 1, 0);
	
	if (close(sock))
		ReturnError(1, "close()");
	
	return ret;
}

