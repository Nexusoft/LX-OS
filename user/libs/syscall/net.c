/** NexusOS: Network stack implementation.
 
    The TCP/IP stack is implemented in liblwip. This file contains
    glue code to connect it to Nexus sockets. There are two parts
 
    1) a GenericFS wrapper around lwIP socket calls. Really dull boilerplate.
    2) an init function to start the network stack thread
 */

#include <stdio.h>
#include <string.h>

#include <lwip/init.h>
#include <lwip/opt.h>
#include <lwip/sys.h>
#include <lwip/mem.h>
#include <lwip/tcpip.h>

// see below for explanation
//#include <lwip/sockets.h>

#include <nexus/net.h>
#include <nexus/sema.h>
#include <nexus/rdtsc.h>
#include <nexus/transfer.h>
#include <nexus/Net.interface.h>

#include "io.private.h"

////////  lwip sockets declarations  ////////

#define F_SETFL 4
#define O_NONBLOCK 	04000
#define FIONREAD 	0x541b

#define LWIP_FIONBIO     	0x8004667e 	/* set/clear non-blocking i/o */
#define LWIP_FIONREAD		0x4004667f	/* retrieve read queuelen */

#define LWIP_MSG_PEEK		0x01
#define LWIP_MSG_DONTWAIT	0x08

// we cannot include lwip/sockets.h and at the same time use uclibc includes
// WARNING: fragile
void lwip_socket_init(void);
int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_shutdown(int s, int how);
int lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen);
int lwip_close(int s);
int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
int lwip_recv(int s, void *mem, size_t len, int flags);
int lwip_read(int s, void *mem, size_t len);
int lwip_recvfrom(int s, void *mem, size_t len, int flags,
                  struct sockaddr *from, socklen_t *fromlen);
int lwip_send(int s, const void *dataptr, size_t size, int flags);
int lwip_sendto(int s, const void *dataptr, size_t size, int flags,
                const struct sockaddr *to, socklen_t tolen);
int lwip_socket(int domain, int type, int protocol);
int lwip_write(int s, const void *dataptr, size_t size);
int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
                struct timeval *timeout);
int lwip_ioctl(int s, long cmd, void *argp);

struct sockaddr_in {
  u8_t sin_family;
  u16_t sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
};


////////  genericfs shared between TCP and UDP  ////////

static int
sock_unsupported(GenericDescriptor *d, const char *optname, int i)
{
	printf("[sockets] unimplemented function %s called\n", __FUNCTION__);
	return -1;
}

static int 
sock_socket(GenericDescriptor *d, int domain, int type, int protocol)
{
	nxnet_init();
	d->private = (void *) lwip_socket(domain, type, protocol);
	if (d->private < 0)
		return -1;

	d->type = type;
	return 0; // genericfs:socket deviates from convention
}

static int 
sock_getsockname(GenericDescriptor *d, struct sockaddr *name, 
		 socklen_t *namelen)
{
	return lwip_getsockname((long) d->private, name, namelen);
}

static int 
sock_setsockopt(GenericDescriptor *d, int level, int optname,  
		const void *optval, socklen_t optlen)
{
	// since each process has a private stack, 
	// SO_REUSEADDR always succeeds between processes
	if (level == SOL_SOCKET && optname == SO_REUSEADDR)
		return 0;

	return lwip_setsockopt((long) d->private, level, optname, optval, optlen);
}

static int
sock_destroy(GenericDescriptor *d)
{
	// NOOP
	return 0;
}

static int 
sock_bind(GenericDescriptor *d, const struct sockaddr *my_addr, 
	  socklen_t addrlen)
{
	const struct sockaddr_in *in = (const struct sockaddr_in *) my_addr;
	struct sockaddr_in in2;
	int localport;

	if (!nexusif_port) {
		fprintf(stderr, "network stack not initialized\n");
		return -1;
	}
	if (d->port) {
		fprintf(stderr, "port %d: subsequent bind attempt blocked\n", d->port);
		return -1;
	}

	// ask for ownership of the port from the kernel
	localport = ntohs(((struct sockaddr_in *)my_addr)->sin_port);
	localport = Net_port_get(localport);
	if (localport == -1) {
		fprintf(stderr, "port already in use\n");
		return -1;
	}
	((struct sockaddr_in *)my_addr)->sin_port = htons((short) localport);

	// acquire a port
	if (lwip_bind((long) d->private, my_addr, addrlen))
		return -1;

	// if this is an automatically assigned port, ask for the number 
	if (ntohs(in->sin_port) == 0) {
		if (lwip_getsockname((long) d->private, 
				     (struct sockaddr *) &in2, &addrlen)) {
			fprintf(stderr, "port error in getsockname\n");
			return -1;
		}
		localport = ntohs(in2.sin_port);
	}
	else
		localport = ntohs(in->sin_port);

	// ask the kernel for all packets destined to our port
	Net_filter_ipport(d->type == SOCK_STREAM ? 1 : 0, 
			  localport, nexusif_port); 

	d->port = localport;
	return 0;
}

/** Connect is a bit more complex than you would expect: because we need to
    add the local port to the in-kernel packet filter, we call bind before
    calling connect. The filter must know the port before we call 
    lwip_connect, because that initiates communication (for TCP). */
static int 
sock_connect(GenericDescriptor *d, const struct sockaddr *serv_addr, 
	     socklen_t addrlen)
{
	struct sockaddr_in localname;
	socklen_t lnamelen;

	if (!d->port) {
		// bind
		localname.sin_family = AF_INET;
		localname.sin_addr.s_addr = INADDR_ANY;
		localname.sin_port = 0;		// let lwip choose a port
		if (sock_bind(d, (struct sockaddr *) &localname, sizeof(localname)))
			return -1;
	}

	// connect to remote port
	if (lwip_connect((long) d->private, serv_addr, addrlen))
		return -1;
	
	return 0;
}	

static int 
sock_listen(GenericDescriptor *d, int backlog)
{
	return lwip_listen((long) d->private, backlog);
}

static int 
sock_accept(GenericDescriptor *d, struct sockaddr *addr, socklen_t *addrlen, 
	    void **new_priv)
{
	*new_priv = (void *) lwip_accept((long) d->private, addr, addrlen);
	return 0;
}

static ssize_t 
sock_recvfrom(GenericDescriptor *d, void *buf, size_t len, int flags, 
	      struct sockaddr *from, socklen_t *fromlen)
{
	int ret;
	ret = lwip_recvfrom((long) d->private, buf, len, flags, from, fromlen);
	return ret;
}

/** Sendto is a bit more complex than you would expect. If called on an 
    unconnected connectionless socket, the network stack binds an address
    automatically. We do that here. */
static ssize_t 
sock_sendto(GenericDescriptor *d, const void *buf, size_t len, int flags,
            const struct sockaddr *to, socklen_t tolen)
{
	struct sockaddr_in localname;
	int ret;

	if (!d->port && d->type == SOCK_DGRAM) {
		// bind
		localname.sin_family = AF_INET;
		localname.sin_addr.s_addr = INADDR_ANY;
		localname.sin_port = 0;		// let lwip choose a port
		if (sock_bind(d, (struct sockaddr *) &localname, sizeof(localname)))
			return -1;
	}
	
	ret = lwip_sendto((long) d->private, buf, len, flags, to, tolen);
	return ret;
}

/** Nexus specific poll. See the GenericDescriptor_ops comments */
static int 
sock_poll(GenericDescriptor *d, int directions)
{
	extern int lwip_poll(int fd);
#if 0
	return directions & lwip_poll((long) d->private);
#else
	fd_set readfds;
	fd_set writefds;
	struct timeval tv;
	int ret;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	if (directions & IPC_READ)
		FD_SET((long) d->private, &readfds);
	if (directions & IPC_WRITE)
		FD_SET((long) d->private, &writefds);

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	ret = lwip_select(1 + (long) d->private, &readfds, &writefds, NULL, &tv);

	if (ret) {
	
		ret = 0;
		if (FD_ISSET((long) d->private, &readfds))
			ret |= 1;
		if (FD_ISSET((long) d->private, &writefds))
			ret |= 2;
	}

	return directions & ret;
#endif
}

static int
sock_port(GenericDescriptor *d)
{
	struct sockaddr_in addr;
	socklen_t alen;

// peer discovery is useful, but kills the port if used on an unconnected port
// (a weird lwip implementation artifact)
#if 0
	// cannot poll on localhost. instead: return 'invalid' port
	alen = sizeof(addr);
	if (lwip_getpeername((long) d->private, (struct sockaddr *) &addr, &alen)) {
		fprintf(stderr, "nxdebug: getpeername failed in net:port()\n");
		return -1;
	}

	if (((ntohs(addr.sin_addr.s_addr) >> 24) == 127)) {
		fprintf(stderr, "nxdebug: net:port() identified localhost\n");
		return -1;
	}
#endif

	return nexusif_port;
}

//// Posix I/O calls that are not socket specific

static ssize_t 
sock_read(GenericDescriptor *d, void *buf, size_t count)
{
	int ret;
	ret = lwip_read((long) d->private, buf, count);
	return ret;
}

static ssize_t 
sock_write(GenericDescriptor *d, const void *buf, size_t count)
{
	int ret;
	ret = lwip_write((long) d->private, buf, count);
	return ret;
}

static int 
sock_close(GenericDescriptor *d)
{
	return lwip_close((long) d->private);
}

static int
sock_fcntl(GenericDescriptor *d, int cmd, long arg) 
{
	if (cmd == F_SETFL) {
		uint32_t nonblock;

		nonblock = (arg & O_NONBLOCK) ? 1 : 0;
		lwip_ioctl((long) d->private, LWIP_FIONBIO, &nonblock);
	}
	return 0;
}

static int 
sock_ioctl(GenericDescriptor *d, int flag, void *data)
{
	uint16_t fiondata;

	if (flag == FIONREAD) {
		*(unsigned long *) data = lwip_ioctl((long) d->private, LWIP_FIONREAD, &fiondata);
		return 0;
	}
	
	fprintf(stderr, "NXDEBUG: unhandled ioctl on socket %d 0x%x\n", (int) d->private, flag);
	return 0;
}

////////  genericfs socket implementation   ////////

GenericDescriptor_operations socket_ops = {
	.name = 	"net",
	.unsupported = 	sock_unsupported,
	.poll_on_select = 1,

	.socket = 	sock_socket,
	.close = 	sock_close,
	.destroy = 	sock_destroy,

	.read =		sock_read,
	.write =	sock_write,
	.recvfrom = 	sock_recvfrom,
	.sendto = 	sock_sendto,

	.bind = 	sock_bind,
	.connect =	sock_connect,
	.listen =	sock_listen,
	.accept = 	sock_accept,

	.poll =		sock_poll,
	.port = 	sock_port,

	.fcntl = 	sock_fcntl,
	.ioctl = 	sock_ioctl,
	.getsockname = 	sock_getsockname,
	.setsockopt = 	sock_setsockopt,
};

////////  calls that are NOT multiplexed through genericfs_operations ////////

int 
nxlibc_syscall_shutdown(int sockfd, int how)
{
	GenericDescriptor *d;
	
	d = nxdesc_find(sockfd);
        if (!d) {
		errno = EINVAL;
		return -1;	
	}

	return lwip_shutdown(sockfd, how);
}

int 
nxlibc_syscall_getpeername(int sockfd, struct sockaddr *addr, 
			   socklen_t *addrlen)
{
	GenericDescriptor *d;
	
	d = nxdesc_find(sockfd);
        if (!d) {
		errno = EINVAL;
		return -1;	
	}

	fprintf(stderr, "warning: lwip_getpeername called\n");

	// warning: this will cause a chronic connection error if used on
	// unconnected sockets (e.g., a UDP server)
	return lwip_getpeername(sockfd, addr, addrlen);
}

int
nxlibc_syscall_getsockopt(int sockfd, int level, int optname,
			  void *optval, socklen_t *optlen)
{
	GenericDescriptor *d;
	
	d = nxdesc_find(sockfd);
        if (!d) {
		errno = EINVAL;
		return -1;	
	}

	return lwip_getsockopt(sockfd, level, optname, optval, optlen);
}

int 
nxlibc_syscall_socketcall(int call, unsigned long *args)
{

/* Various socketcall numbers 
   copied verbatim from uClibc/libc/inet/socketcalls.c 
   WARNING: fragile */
#define SYS_SOCKET      1
#define SYS_BIND        2
#define SYS_CONNECT     3
#define SYS_LISTEN      4
#define SYS_ACCEPT      5
#define SYS_GETSOCKNAME 6
#define SYS_GETPEERNAME 7
#define SYS_SOCKETPAIR  8
#define SYS_SEND        9
#define SYS_RECV        10
#define SYS_SENDTO      11
#define SYS_RECVFROM    12
#define SYS_SHUTDOWN    13
#define SYS_SETSOCKOPT  14
#define SYS_GETSOCKOPT  15
#define SYS_SENDMSG     16
#define SYS_RECVMSG     17

	switch (call) {
	case SYS_SOCKET:	
	case SYS_SHUTDOWN:	return (long) nxlibc_syscall_shutdown((int) args[0], (int) args[1]);
	case SYS_SETSOCKOPT:	return (long) nxlibc_syscall_getsockopt((int) args[0], (int) args[1], 
									(int) args[2], (void *) args[3], 
									(socklen_t*) args[4]);
	case SYS_GETPEERNAME:	return (long) nxlibc_syscall_getpeername((int) args[0], 
									 (void *) args[1],
									 (socklen_t *) args[2]);
	}

	fprintf(stderr, "NXLIBC ERROR: socketcall %d not implemented\n",
		call);

	return -EINVAL;
}

//////// lowlevel lwip initialization ////////

err_t loopif_init(struct netif *netif);
err_t nexusif_init(struct netif *netif);

err_t ethernet_input(struct pbuf *p, struct netif *netif);
err_t tcpip_input(struct pbuf *p, struct netif *netif);

static struct netif loopif;
static struct netif nexusif;

void tcpinit_done(void *arg)
{
	Sema *sema = arg;
	V_nexus(sema);
}

/** Setup the network stack.
    By default, lwip runs in dual-threaded mode, 
    where the TCP/IP stack has its own thread 
 
    @param set lowlevel_api to nonzero to force singlethreaded mode.
           in that case, sockets and lwip netconn APIs will not work propery 
  	   XXX NOTE that the timer threads are disabled, 
	       so TCP retransmission, DHCP, ... does not work 
	       not sure about ARP
 */
void
nxnet_init_raw(int lowlevel_api)
{
	static int initialized;

	struct ip_addr ipaddr, netmask, gw;
	Sema tcpinit_sema = SEMA_INIT;
	pthread_t thread;
	int msecs;

	// only initialize once
	if (atomic_test_and_set(&initialized))
		return;

	Net_get_ip((unsigned int *) &ipaddr.addr, 
		   (unsigned int *) &netmask.addr, 
		   (unsigned int *) &gw.addr); 

	if (!lowlevel_api) {
		// initialize and start network stack
		tcpip_init(tcpinit_done, &tcpinit_sema);
		P(&tcpinit_sema);
		
		// register nexus interface as device driver
		netifapi_netif_add(&nexusif, &ipaddr, &netmask, &gw, NULL, 
				   nexusif_init, tcpip_input);
		netifapi_netif_set_up(&nexusif);
	}
	else {
		lwip_init();
		
		// register nexus interface as device driver
		netif_add(&nexusif, &ipaddr, &netmask, &gw, NULL, 
		          nexusif_init, ethernet_input);
		netif_set_up(&nexusif);
	}

	// register loopback interface
   	IP4_ADDR(&ipaddr, 127, 0, 0, 1);
    	IP4_ADDR(&netmask, 255, 0, 0, 0);
	IP4_ADDR(&gw, 0, 0, 0, 0);
	
	if (!lowlevel_api) {
		netifapi_netif_add(&loopif, &ipaddr, &netmask, &gw, NULL, 
				   loopif_init, tcpip_input);
		netifapi_netif_set_up(&loopif);

		netifapi_netif_set_default(&nexusif);
		lwip_socket_init();
	}
	else {
		netif_add(&loopif, &ipaddr, &netmask, &gw, NULL, 
		          loopif_init, ip_input);
		netif_set_up(&loopif);
		netif_set_default(&nexusif);
	}
	
	// accept all ARP replies
	Net_filter_arp(nexusif_port, 0);
}

void 
nxnet_init(void)
{
	nxnet_init_raw(0);
}

