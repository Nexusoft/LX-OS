/** NexusOS: Unix Domain Sockets over Nexus IPC 
    Does not differentiate between SOCK_STREAM and SOCK_DGRAM 
 
    WARN: SOCK_DGRAM was tagged on, most probably not standard compliant
   */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <nexus/ipc.h>
#include <nexus/transfer.h>
#include <nexus/IPC.interface.h>

#include "io.private.h"

// ugly hack: send a magic 'end' packet to close a connection
// XXX update IPC to support 0 packets
#define MAGIC_END "__NXSOCK_END__"
#define FIONREAD 	0x541b

enum nxlocalsock_type { sock_undef, sock_accept, sock_data };

struct nxlocalsock {

	// local and remote ipc ports
	int port;
	int rport;
	int proto;

	// number of clients to queue at accept
	enum nxlocalsock_type type;
	int max_backlog;

	// filesystem presence
	char path[208];
	int filefd;
};

static int 
nxlocalsock_socket(GenericDescriptor *d, int domain, int type, int protocol)
{
	struct nxlocalsock *sock;

	// validate input
	if (type != SOCK_DGRAM && type != SOCK_STREAM) {
		errno = EINVAL;
		return -1;
	}

	// initialize structure
	sock = calloc(1, sizeof(*sock));
	sock->port = -1;
	sock->filefd = -1;
	sock->type = sock_undef;
	sock->proto = type;

	d->private = sock;
	return 0; // genericfs:socket convention
}

static int
nxlocalsock_destroy(GenericDescriptor *d)
{
	struct nxlocalsock *sock = d->private;
	free(sock);
	return 0;
}

static void
__nxlocalsock_close(struct nxlocalsock *sock)
{
	// cleanup filesystem changes
	if (sock->filefd >= 0) {
		close(sock->filefd);
		sock->filefd = -1;
		// unlink inode ?
	}

	if (sock->port >= 0)
		IPC_DestroyPort(sock->port);
	sock->type = sock_undef;
}

static int
nxlocalsock_close(GenericDescriptor *d)
{
	struct nxlocalsock *sock = d->private;
	int ret = 0;

	if (sock->filefd >= 0 && close(sock->filefd))
		ret = 1; // errno will have been set by filesys

	if (sock->proto == SOCK_STREAM && sock->type == sock_data) {
		// tell other end that we've disconnected
		IPC_Send(sock->rport, (void *) MAGIC_END, sizeof(MAGIC_END));
	} 
	else if (sock->type == sock_accept) {
		// XXX: drop all waiting connections gracefully
	}

	__nxlocalsock_close(sock);
	return ret;
}

static int
nxlocalsock_bind(GenericDescriptor *d, const struct sockaddr *saddr, socklen_t slen)
{
	const struct sockaddr_un *sun = (void *) saddr;
	struct nxlocalsock *sock = d->private;

	// validate input
	// NB: python returns smaller than struct sockaddr_un
	if (slen > sizeof(struct sockaddr_un) ||
	    strnlen(sun->sun_path, 208) == 208)	{
		errno = EINVAL;
		return -1;
	}
		
	// try to claim filepath
	sock->filefd = open(sun->sun_path, O_CREAT | O_RDWR, 0644);
	if (sock->filefd < 0) {
		errno = EADDRINUSE;
		return -1;
	}

	// open ipc port
	sock->port = IPC_CreatePort(0);
	strcpy(sock->path, sun->sun_path);

	// allow other end to find us through the filepath
	if (write(sock->filefd, &sock->port, sizeof(int)) != sizeof(int)) {
		IPC_DestroyPort(sock->port);
		return -1; // errno will have been set by filesys
	}

	if (sock->proto == SOCK_STREAM)
		sock->type = sock_accept;
	else
		sock->type = sock_data;
	return 0;
}

static int
nxlocalsock_connect(GenericDescriptor *d, const struct sockaddr *saddr, 
		    socklen_t slen)
{
	const struct sockaddr_un *sun = (void *) saddr;
	struct nxlocalsock *sock = d->private;

	// validate input
	if (/* slen != sizeof(struct sockaddr_un ) || <-- not always respected */
	    strnlen(sun->sun_path, 208) == 208)	{
		fprintf(stderr, "[unixsock] connect: path\n");
		errno = EINVAL;
		return -1;
	}
	
	// connect to server
	sock->filefd = open(sun->sun_path, O_WRONLY);
	if (sock->filefd < 0) {
		errno = ECONNREFUSED;
		return -1;
	}
	
	// find out accept() ipc port
	if (read(sock->filefd, &sock->rport, sizeof(int)) != sizeof(int)) {
		errno = ENETUNREACH;
		fprintf(stderr, "[unixsock] connect: read ipc port\n");
		return -1;
	}

	if (sock->proto == SOCK_STREAM) {
		
		// acquire port
		sock->port = IPC_CreatePort(0);

		// exchange data ports
		if (IPC_Send(sock->rport, &sock->port, sizeof(int)) ||
		    IPC_Recv(sock->port, &sock->rport, sizeof(int)) != sizeof(int)) {
			// warning: dangling state may remain on other end
			IPC_DestroyPort(sock->port);
			errno = ENETUNREACH;
			fprintf(stderr, "[unixsock] connect: port exchange #1\n");
			return -1;
		}

		if (sock->rport == -1) {
			IPC_DestroyPort(sock->port);
			errno = EAGAIN;
			fprintf(stderr, "[unixsock] connect: port exchange #2\n");
			return -1;
		}
	}

	sock->type = sock_data;

	return 0;
}

static int 
nxlocalsock_listen(GenericDescriptor *d, int len)
{
	struct nxlocalsock *sock = d->private;
	
	sock->max_backlog = len;
	return 0;
} 

static int 
nxlocalsock_accept(GenericDescriptor *d, struct sockaddr *sa, 
		   socklen_t *sa_len, void **new_priv) 
{
	struct nxlocalsock *sock = d->private;
	struct nxlocalsock *child;
	int childport, clientport; 

	do {
		// wait for request
		IPC_Recv(sock->port, &clientport, sizeof(int));

// XXX support graceful dropping of backlog
#if 0
		// drop if number of clients exceed allowed
		if (IPC_QueueLen(fd) > max_backlog) {
			childfd = -1;
			IPC_Send(clientfd, &childfd, sizeof(int));
		}
		else
#endif
			break;
	} while (1);

	// tell client that we accept
	childport = IPC_CreatePort(0);
	IPC_Send(clientport, &childport, sizeof(int));

	// fill in (optional) metadata field
	if (sa && *sa_len >= sizeof(struct sockaddr_un)) {
		struct sockaddr_un *sun = (void *) sa;

		sun->sun_family = AF_UNIX;
		sun->sun_path[0] = 0;	// client has no filepath.
		*sa_len = sizeof(struct sockaddr_un);
	}

	// create child structure
	child = calloc(1, sizeof(*child));
	child->type = sock_data;
	child->port = childport;
	child->rport = clientport;
	child->filefd = -1;
	*new_priv = child;

	return 0; // genericfs:accept deviates from accept convention
}

////////  Data Transfer  ////////

static ssize_t 
nxlocalsock_read(GenericDescriptor *d, void *buf, size_t count)
{
	struct nxlocalsock *sock = d->private;
	int ret;

	assert(sock); // debug XXX remove
	if (sock->type != sock_data)
		return -1;

	ret = ipc_recv(sock->port, buf, count);

	// special case: close connection
	if (ret == sizeof(MAGIC_END) && 
	    !memcmp(buf, MAGIC_END, sizeof(MAGIC_END) + 1)) {
		__nxlocalsock_close(sock);
		return 0; // EOF
	}
	
	return ret;
}

static ssize_t 
nxlocalsock_write(GenericDescriptor *d, const void *buf, size_t count)
{
	struct nxlocalsock *sock = d->private;
	int ret;

	// input validation
	if (sock->type != sock_data) {
		fprintf(stderr, "[unix] write blocked: wrong type\n");
		errno = EBADF;
		return -1;
	}

	if (count > IPC_MAXSIZE) 
		count = IPC_MAXSIZE;

	ret = ipc_send(sock->rport, (void *) buf, count);
       
	return ret ? -1 : count;
}

static ssize_t 
nxlocalsock_recvfrom(GenericDescriptor *d, void *buf, size_t len, int flags, 
	             struct sockaddr *from, socklen_t *fromlen)
{
	// do not support filling in metadata
	if (fromlen)
		*fromlen = 0;

	if (flags)
		fprintf(stderr, "warning: unixsock called with 0x%x\n", flags);

	return nxlocalsock_read(d, buf, len);
}

static ssize_t 
nxlocalsock_sendto(GenericDescriptor *d, const void *buf, size_t len, int flags,
            	   const struct sockaddr *to, socklen_t tolen)
{
	if (flags)
		fprintf(stderr, "warning: unixsock called with 0x%x\n", flags);

	return nxlocalsock_write(d, buf, len);
}

static int
nxlocalsock_port(GenericDescriptor *d)
{
	struct nxlocalsock *sock = d->private;

	return sock->port;
}

static int 
nxlocalsock_fcntl(GenericDescriptor *d, int cmd, long arg)
{
	printf("[unixsock] unimplemented fcntl %d called. Aborting\n", cmd);
	abort();
}

static int 
nxlocalsock_ioctl(GenericDescriptor *d, int flag, void *data)
{
	struct nxlocalsock *sock = d->private;
	
	if (flag == FIONREAD) {
		*(unsigned long *) data = IPC_Available(sock->port);
		return 0;
	}
	
	printf("[unixsock] unimplemented ioctl %d called. Aborting\n", flag);
	abort();
}

static int
nxlocalsock_poll(GenericDescriptor *d, int dir)
{
	struct nxlocalsock *sock = d->private;
	
	return IPC_Poll(sock->port, dir);
}

static int
nxlocalsock_unsupported(GenericDescriptor *d, const char *optname, int i)
{
	printf("[unixsock] unimplemented function %s called\n", __FUNCTION__);
	return -1;
}

GenericDescriptor_operations nxlocalsock_ops = {
	.name =		"unixsock",
	.unsupported = 	nxlocalsock_unsupported,

	.socket = 	nxlocalsock_socket,
	.close = 	nxlocalsock_close,
	.destroy = 	nxlocalsock_destroy,

	.read =		nxlocalsock_read,
	.write =	nxlocalsock_write,
	.recvfrom = 	nxlocalsock_recvfrom,
	.sendto = 	nxlocalsock_sendto,

	.bind = 	nxlocalsock_bind,
	.connect =	nxlocalsock_connect,
	.listen =	nxlocalsock_listen,
	.accept = 	nxlocalsock_accept,

	.fcntl = 	nxlocalsock_fcntl,
	.ioctl = 	nxlocalsock_ioctl,
	
	.port = 	nxlocalsock_port,
	.poll = 	nxlocalsock_poll,
};

