/** NexusOS: Network stack implementation.
 
    The TCP/IP stack is implemented in liblwip. This file contains
    glue code to connect it to Nexus sockets. There are two parts
 
    1) a GenericFS wrapper around lwIP socket calls. Really dull boilerplate.
    2) an init function to start the network stack thread */

#include <stdio.h>
#include <string.h>

#include <lwip/opt.h>
#include <lwip/sys.h>
#include <lwip/mem.h>
#include <lwip/tcpip.h>

// see below for explanation
//#include <lwip/sockets.h>

#include <nexus/sema.h>
#include <nexus/net.h>
#include <nexus/Net.interface.h>

#include "io.private.h"

////////  lwip sockets declarations  ////////

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
	unsigned short localport;

	// acquire a port
	if (lwip_bind((long) d->private, my_addr, addrlen))
		return -1;

	// if this is an automatically assigned port, ask for the number 
	if (ntohs(in->sin_port) == 0) {
		if (lwip_getsockname((long) d->private, 
				     (struct sockaddr *) &in2, &addrlen))
			return -1;

		localport = ntohs(in2.sin_port);
	}
	else
		localport = ntohs(in->sin_port);

	// ask the kernel for all packets destined to our port
	Net_filter_ipport(d->type == SOCK_STREAM ? 1 : 0, 
			  localport, nexusif_port); 

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

	// bind
	localname.sin_family = AF_INET;
	localname.sin_addr.s_addr = INADDR_ANY;
	localname.sin_port = 0;		// let lwip choose a port
	if (sock_bind(d, &localname, sizeof(localname)))
		return -1;

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
	int ret = lwip_recvfrom((long) d->private, buf, len, flags, from, fromlen);
	return ret;
}

static ssize_t 
sock_sendto(GenericDescriptor *d, const void *buf, size_t len, int flags,
            const struct sockaddr *to, socklen_t tolen)
{
	return lwip_sendto((long) d->private, buf, len, flags, to, tolen);
}

/** Nexus specific poll. See the GenericDescriptor_ops comments */
static int 
sock_poll(GenericDescriptor *d, short events, short *revents)
{
	printf("[sockets] unimplemented function poll called\n");
	return -1;
}

//// Posix I/O calls that are not socket specific

static ssize_t 
sock_read(GenericDescriptor *d, void *buf, size_t count)
{
	return lwip_read((long) d->private, buf, count);
}

static ssize_t 
sock_write(GenericDescriptor *d, const void *buf, size_t count)
{
	return lwip_write((long) d->private, buf, count);
}

static int 
sock_close(GenericDescriptor *d)
{
	return lwip_close((long) d->private);
}

static int 
sock_ioctl(GenericDescriptor *d, int flag, void *data)
{
	return lwip_ioctl((long) d->private, flag, data);
}

// XXX add shutdown 

// XXX add getpeername

// XXX add getsockopt

// XXX add writev

// XXX add readv

////////  genericfs socket implementation   ////////

GenericDescriptor_operations socket_ops = {
	.unsupported = 	sock_unsupported,

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

	._poll =	sock_poll,

	.ioctl = 	sock_ioctl,
	.getsockname = 	sock_getsockname,
	.setsockopt = 	sock_setsockopt,
};

////////  genericfs UDP implementation   ////////

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
    This runs lwip in mulithreaded mode, where the stack has its own thread */
void
nxnet_init(void)
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

	// initialize and start network stack
	tcpip_init(tcpinit_done, &tcpinit_sema);
	P(&tcpinit_sema);

	// register nexus interface as device driver
	netifapi_netif_add(&nexusif, &ipaddr, &netmask, &gw, NULL, 
			   nexusif_init, tcpip_input);
	netifapi_netif_set_up(&nexusif);

// NB: enabling the loopback device broke my UDP test. XXX fix
	// register loopback interface
   	IP4_ADDR(&ipaddr, 127, 0, 0, 1);
    	IP4_ADDR(&netmask, 255, 0, 0, 0);
	IP4_ADDR(&gw, 0, 0, 0, 0);
	
	netifapi_netif_add(&loopif, &ipaddr, &netmask, &gw, NULL, 
			   loopif_init, tcpip_input);
	netifapi_netif_set_up(&loopif);

	netifapi_netif_set_default(&nexusif);
	lwip_socket_init();
	
	// accept all ARP replies
	Net_filter_arp(nexusif_port, 0);
}

