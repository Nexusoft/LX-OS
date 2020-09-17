/** NexusOS: Test select() */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/ipc.h>
#include <nexus/sema.h>
#include <nexus/transfer.h>
#include <nexus/nexuscalls.h>

#include <nexus/IPC.interface.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

static unsigned int ip;

static void *
testsub_ipcsend(void *_port)
{
	long port = (long) _port;
	char x = IPC_READ;

	usleep(1000);
	if (IPC_Send(port, &x, 1))
		ReturnError((void *) 1, "send()");
		
	return NULL;
}

static int
testsub_ipcwait(long *ports, char *res, int len)
{
	pthread_t thread;
	void *ret;

	pthread_create(&thread, NULL, testsub_ipcsend, (void *) ports[len - 1]);

	if (IPC_Wait(ports, res, len) != 1)
		ReturnError(1, "wait #2");

	if (res[len - 1] != 1)
		ReturnError(1, "wait #2");

	// apparent not implemented: 
	//
	// pthread_join(thread, &ret);
	//if (ret)
	//	ReturnError(1, "send thread");

	return 0;
}

// test a single port
static int
test_ipcwait_single(void)
{
	long ports[1];
	char res[1];
	int ret;

	ports[0] = IPC_CreatePort(0);
	res[0] = IPC_READ;

	ret = testsub_ipcwait(ports, res, 1);
	
	IPC_DestroyPort(ports[0]);
	
	return ret;
}

// test a set of ports
static int
test_ipcwait_pair(void)
{
	long ports[2];
	char res[2];
	int ret;

	ports[0] = IPC_CreatePort(0);
	ports[1] = IPC_CreatePort(0);
	res[0] = IPC_READ;
	res[1] = IPC_READ;

	ret = testsub_ipcwait(ports, res, 2);
	
	IPC_DestroyPort(ports[1]);
	IPC_DestroyPort(ports[0]);
	
	return ret;
}

static Sema socksema = SEMA_INIT;

static int
testsub_unixinit(int client)
{
	struct sockaddr_un addr;
	int fd;

	// create socket
	fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		ReturnError(1, "socket");

	// connect
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	memcpy(addr.sun_path, "tmp/test.sock", 14);
	
	if (client) {
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)))
			ReturnError(1, "connect");
	}
	else {
		if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)))
			ReturnError(1, "bind");
	}

	return fd;
}

static void *
testsub_unixsend(void *unused)
{
	int fd, ret;

	fd = testsub_unixinit(1);
	if (fd < 0)
		return (void *) -1;

	P(&socksema);
	ret = write(fd, &fd, 1);
	if (ret != 1)
		ReturnError((void *) 1, "write unix");

	if (close(fd))
		ReturnError((void *) 1, "close");

	return NULL;
}

// test ipcwait for type unixsock
static int
test_unixsock(void)
{
	struct sockaddr_un addr;
	pthread_t thread;
	long ports[1];
	char res[1], data[2];
	int fd;

	fd = testsub_unixinit(0);
	if (fd < 0)
		return 1;

	// start child
	pthread_create(&thread, NULL, testsub_unixsend, NULL);

	// wait for data
	ports[0] = nxfile_port(fd);
	res[0] = IPC_READ;

	if (ports[0] < 0)
		ReturnError(1, "nxfile_port");

	V_nexus(&socksema);
	if (IPC_Wait(ports, res, 1) != 1)
		ReturnError(1, "poll unix");

	if (res[0] != 1)
		ReturnError(1, "poll unix: wrong result");

	if (read(fd, &data, 2) != 1)
		ReturnError(1, "poll unix: read");
	
	if (close(fd))
		ReturnError(1, "close");

	return 0;
}

// test ipcwait for type stdin
static int
test_stdin(void)
{
	long ports[1];
	char res[1];

	ports[0] = nxfile_port(0);
	res[0] = IPC_READ;
	
	if (ports[0] < 0)
		ReturnError(1, "nxfile_port");

	printf("Press any key to continue\n");
	if (IPC_Wait(ports, res, 1) != 1)
		ReturnError(1, "poll stdin");

	if (res[0] != 1)
		ReturnError(1, "poll stdin: wrong result");

	return 0;
}

static int
testsub_netinit(int client)
{
	struct sockaddr_in addr;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		ReturnError(-1, "net socket");


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(45454);

	if (client) {
		addr.sin_addr.s_addr = ip;
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)))
			ReturnError(-1, "net connect");
	}
	else {
		addr.sin_addr.s_addr = INADDR_ANY;
		if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)))
			ReturnError(-1, "net connect");
	}

	return fd;
}

static void *
testsub_netsend(void *unused)
{
	int fd;

	fd = testsub_netinit(1);
	if (fd < 0)
		return (void *) -1;

	if (send(fd, &fd, 1, 0) != 1)
		ReturnError((void *) -1, "net send");

	close(fd);

	return NULL;
}

// test ipcwait for type network
// slightly harder than unixsock: wait on multiple (types of) sockets at once
static int
test_net(void)
{
	pthread_t thread;
	long ports[2];
	char res[2];
	int fd;

	fd = testsub_netinit(0);
	if (fd == 0)
		return 0;
	else if (fd < 0)
		return 1;

	// start child
	pthread_create(&thread, NULL, testsub_netsend, NULL);

	// wait for data
	ports[0] = nxfile_port(0);
	ports[1] = nxfile_port(fd);
	memset(res, IPC_READ, 2);

	if (ports[1] < 0)
		ReturnError(1, "net nxfile_port");

	if (IPC_Wait(ports, res, 2) != 1)
		ReturnError(1, "net wait");

	if (res[0] != 0 || res[1] != 1)
		ReturnError(1, "net wrong result");

	if (close(fd))
		ReturnError(1, "net close");

	return 0;
}

static int
testsub_select_sock(int fd, int fd2, void *(*sendfunc)(void *))
{
	pthread_t thread;
	fd_set readfds;
	int i, ret, maxfd;

	if (fd == -1)
		ReturnError(1, "select: no sock");

	// prepare select
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	if (fd2 != -1)
		FD_SET(fd2, &readfds);

	// start child
	pthread_create(&thread, NULL, sendfunc, NULL);

	// wait for data
	maxfd = (fd > fd2) ? fd + 1 : fd2 + 1;
	ret = select(maxfd, &readfds, NULL, NULL, NULL);
	if (ret != 1)
		ReturnError(1, "select select");

	// verify output
	for (i = 0; i < maxfd; i++) {
		if (i == fd || i == fd2) {
			if (!FD_ISSET(fd, &readfds))
				ReturnError(1, "select: incorrectly NOT set\n");
		}
		else {
			if (FD_ISSET(i, &readfds))
				ReturnError(1, "select: incorrectly set\n");
		}
		       
	}

	if (close(fd))
		ReturnError(1, "select: close unixsock");

	return 0;
}

// test select with single type
static int
test_select_unixsock(int other)
{
	int fd;

	fd = testsub_unixinit(0);
	if (fd < 0)
		return 1;

	V_nexus(&socksema);
	return testsub_select_sock(fd, other, testsub_unixsend);
}

// test select with special single type: networking
static int
test_select_netsock(void)
{
	int fd;

	fd = testsub_netinit(0);
	if (fd == 0)
		return 0;
	else if (fd < 0)
		return 1;

	return testsub_select_sock(fd, -1, testsub_netsend);
}

int
main(int argc, char **argv)
{
	if (test_ipcwait_single())
		return 1;

	if (test_ipcwait_pair())
		return 1;

	// only if not auto, run interactive test (requires keyboard input)
	if (!nxtest_isauto(argc, argv)) {
		if (test_stdin())
			return 1;
	}

	if (test_unixsock())
		return 1;

#if 0
	if (test_select_unixsock(-1 /* single fd */))
		return 1;

	if (test_select_unixsock(0 /* two fds: with stdin */))
		return 1;
#endif

	// only test networking if we have a real IP
	// localhost does not use the IPC layer and therefore cannot be polled
	Net_get_ip(&ip, NULL, NULL);
	if (ip != htonl((127 << 24) + 1)) {
			if (test_net())
				return 1;

			if (test_select_netsock())
				return 1;
	}

	if (!nxtest_isauto(argc, argv))
		printf("[OK]\n");
	
	return 0;
}

