#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "containers.h"
#include "mainloop.h"
#include "socklib.h"

#define BGP_PORT  179
#define HOLD_TIME 2 /* sec */
#define MY_AS     42

typedef struct {
	int fd, pos, handle;
} Client;

typedef struct {
	unsigned char pfx_len, pfx[4], next_hop[4], origin, path_len;
	unsigned short path[0];
} __attribute__ ((__packed__)) RVRec;

static void usage(const char *prog);
static void listen_callback(int lfd, IOCondition cond, void *data);
static void rw_callback(int lfd, IOCondition cond, void *data);
static void keepalive_callback(void *data);
static void send_open(int fd);
static void send_update(int fd, const RVRec *rv);
static void send_hold(int fd);
static void send_hold_glue(void *key, void *value, void *data);

static char *rt_map;
static off_t rt_len;
static GHashTable *clients;
int main(int argc, char **argv) {
	if (argc != 2) usage(argv[0]);

	const char *fn = argv[1];
	int rt_fd = open(fn, O_RDONLY);
	if (rt_fd == -1) { perror(fn); exit(1); }
	struct stat st;
	fstat(rt_fd, &st);
	rt_len = st.st_size;
	rt_map = mmap(NULL, rt_len, PROT_READ, MAP_SHARED, rt_fd, 0);
	if ((int)rt_map == -1) { perror("mmap"); exit(1); }
	fprintf(stderr, "%s mapped at %p, %ld bytes\n", fn, rt_map, rt_len);

	int lfd = sock_listen(BGP_PORT);
	if (lfd == -1) exit(1);
	mainloop_add_input(lfd, IO_READ, listen_callback, NULL);

	clients = g_hash_table_new(g_direct_hash, g_direct_equal);
	mainloop_add_timer(HOLD_TIME*1000, keepalive_callback, NULL);

	mainloop_run();
	return 0;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage:\n  %s short-routing-table\n", prog);
	exit(1);
}

static void listen_callback(int lfd, IOCondition cond, void *data) {
	g_assert(cond == IO_READ);
	g_assert(data == NULL);
	struct sockaddr_in sock;
	socklen_t slen = sizeof(sock);

	int fd = accept(lfd, (struct sockaddr*)&sock, &slen);
	if (fd == -1) { perror("accept"); exit(1); }
	fprintf(stderr, "Got a connection from %s:%d [fd=%d]\n",
		inet_ntoa(sock.sin_addr), ntohs(sock.sin_port), fd);

	Client *cl = g_new(Client, 1);
	cl->fd = fd;
	cl->pos = 0;
	cl->handle = mainloop_add_input(fd, IO_READ|IO_WRITE, rw_callback, cl);
	g_hash_table_insert(clients, cl, cl);
	send_open(fd);
}

static void rw_callback(int fd, IOCondition cond, void *data) {
	Client *cl = (Client*)data;
	g_assert(fd == cl->fd);
	if (cond & IO_WRITE) {
		g_assert(cl->pos < rt_len);
		const RVRec *rv = (const RVRec*)(rt_map + cl->pos);
		send_update(fd, rv);
		cl->pos += 11+2*rv->path_len;
		if (cl->pos == rt_len) {
			fprintf(stderr, "Finished sending to fd=%d.\n", fd);
			mainloop_remove_input(cl->handle);
			cl->handle = mainloop_add_input(fd, IO_READ, rw_callback, cl);
		}
	}
	if (cond & IO_READ) {
		char buf[4096];
		int n = read(fd, buf, sizeof(buf));
		if (n == -1) {
			if (errno == ECONNRESET)   /* just another EOF */
				n = 0;
			else {
				perror("read"); exit(1);
			}
		}
		if (n == 0) {
			fprintf(stderr, "fd=%d EOF.\n", fd);
			close(fd);
			cl->fd = -1;
			mainloop_remove_input(cl->handle);
			g_free(cl);
			g_hash_table_remove(clients, cl);
		}
		else fprintf(stderr, "Read %d bytes from fd=%d.\n", n, fd);
	}
}

static void keepalive_callback(void *data) {
	g_hash_table_foreach(clients, send_hold_glue, data);
}

static void send_hold_glue(void *key, void *value, void *data) {
	g_assert(key == value);
	const Client *cl = (Client*)key;
	send_hold(cl->fd);
}

static void send_open(int fd) {
	static const char buf[] = {
		/* marker: 16 bytes */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		/* length: 2 bytes = ... */
		0, 29,
		/* type: 1 byte = 1 (OPEN) */
		1,
		/* version: 1 byte = 4 */
		4,
		/* my AS: 2 bytes */
		(MY_AS>>8) & 0xFF,   MY_AS & 0xFF,
		/* hold time: 2 bytes */
		(HOLD_TIME>>8) & 0xFF,   HOLD_TIME & 0xFF,
		/* BGP ID (my IP): 4 bytes */
		128, 84, 227, 43,
		/* opt param len: 1 byte = 0 */
		0
	};

	g_assert(fd >= 0);
	write(fd, buf, sizeof(buf));
}

static void send_update(int fd, const RVRec *rv) {
	if (rv->path_len == 0) return;

	static unsigned char buf[4096] = {
		/* marker: 16 bytes */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		/* length: 2 bytes = ... */
		-1, -1,
		/* type: 1 byte = 2 (UPDATE) */
		2,
		/* withdrawn routes length: 2 bytes = 0 */
		0, 0,
		/* total path attribute length: 2 bytes */
		/* path attributes (variable) */
		/* NLRI (variable) */
	};
	unsigned char *bufp = buf + 21;  /* points to path attribute length */

	/* path attribute length (2 bytes) */
	int path_attr_len = 4 + 5 + (rv->path_len+1)*2;
	*(bufp++) = (path_attr_len>>8) & 0xFF;
	*(bufp++) = path_attr_len & 0xFF;
	/* origin attribute (4 bytes) */
	*(bufp++) = 0x40;  /* attr flags: transitive */
	*(bufp++) = 1;     /* attr type: origin */
	*(bufp++) = 1;     /* attr length */
	switch (rv->origin) {    /* attr value */
		case 'i':  *(bufp++) = 0;  break;
		case 'e':  *(bufp++) = 1;  break;
		case '?':  *(bufp++) = 2;  break;
		default:
			fprintf(stderr, "Invalid origin code: '%c' (%d)\n",
				rv->origin, rv->origin);
			exit(1); 
	}
	/* path attribute (5+(rv->path_len+1)*2 bytes) */
	*(bufp++) = 0x40;  /* attr flags: transitive */
	*(bufp++) = 2;     /* attr type: path */
	*(bufp++) = 2+(rv->path_len+1)*2;    /* attr length */
	*(bufp++) = 2;   /* path type: AS_SEQUENCE */
	*(bufp++) = rv->path_len+1;   /* path length */
	*(bufp++) = (MY_AS >> 8) & 0xFF;   /* path entry (high byte) */
	*(bufp++) = MY_AS & 0xFF;          /* path entry (low byte) */
	int i;
	for (i=0; i<rv->path_len; i++) {
		*(bufp++) = (rv->path[i] >> 8) & 0xFF;   /* path entry (high byte) */
		*(bufp++) = rv->path[i] & 0xFF;          /* path entry (low byte) */
	}

	/* NLRI: 1 + (pfx_len+7)/8 bytes */
	*(bufp++) = rv->pfx_len;   /* prefix length, in bits */
	for (i=0; i<(rv->pfx_len+7)/8; i++)
		*(bufp++) = rv->pfx[i];  /* prefix byte */

	int msg_len = bufp-buf;
	buf[16] = (msg_len>>8) & 0xFF;
	buf[17] = msg_len & 0xFF;

	g_assert(fd >= 0);
	g_assert(rv->pfx_len > 0);
	g_assert(rv->pfx_len <= 32);
	g_assert(rv->path_len >= 1);
	write(fd, buf, msg_len);
#if 0
	char buf[4096], *p;
	p = buf + sprintf(buf, "%d.%d.%d.%d/%d -> %d.%d.%d.%d origin=%c path = {",
		rv->pfx[0], rv->pfx[1], rv->pfx[2], rv->pfx[3], rv->pfx_len,
		rv->next_hop[0], rv->next_hop[1], rv->next_hop[2], rv->next_hop[3],
		rv->origin);
	int i;
	for (i=0; i<rv->path_len; i++)
		p += sprintf(p, " %d", rv->path[i]);
	p += sprintf(p, " }\n");
	write(fd, buf, p-buf);
#endif
}

static void send_hold(int fd) {
	static const char buf[] = {
		/* marker: 16 bytes */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		/* length: 2 bytes = ... */
		0, 19,
		/* type: 1 byte = 4 (KEEPALIVE) */
		4
	};

	g_assert(fd >= 0);
	write(fd, buf, sizeof(buf));
}
