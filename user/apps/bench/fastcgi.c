/** NexusOS: fastcgi backend stresstest 
             (hacked together from httpd.c code) */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/machine-structs.h>
#include <nexus/Thread.interface.h>

#define NUM_THREADS	(1)
#define NUM_SECS	(100)

//#define SOCKNAME	"size"
#define SOCKNAME	"file"

////// Definitions

#define FASTCGI_MAXCALL 	(100)		//< must correspond to fcgi.py
#define FCGI_VERSION_1 		1
#define FCGI_HEADER_LEN		8

// request types
#define FCGI_BEGIN_REQUEST	1
#define FCGI_END_REQUEST 	3
#define FCGI_PARAMS 		4
#define FCGI_STDIN		5
#define FCGI_STDOUT		6
#define FCGI_STDERR		7
#define FCGI_DATA		8

struct fcgi_header {
	uint8_t  version;
	uint8_t  type;
	uint16_t request;
	uint16_t len;
	uint8_t  padding;
	uint8_t  reserved;
};

// begin request: role values
#define FCGI_RESPONDER	1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER	3

//begin request: flag values
#define FCGI_KEEP_CONN	1

struct fcgi_beginreq {
	struct fcgi_header header;
	struct {
		uint16_t role;
		uint8_t flags;
		uint8_t reserved[5];
	} body;
};

// end request: proto_status values
#define FCGI_REQUEST_COMPLETE	0
#define FCGI_CANT_MPX_CONN	1
#define FCGI_OVERLOADED		2
#define FCGI_UNKNOWN_ROLE	3

struct fcgi_endreq_body {
	uint32_t app_status;
	uint8_t proto_status;
	uint8_t reserved[3];
};

struct fcgi_endreq {
	struct fcgi_header header;
	struct fcgi_endreq_body body;
};

/// 'bitmap' of used call numbers
//  using a char per entry is expensive, but simple to code
static char fcgi_calltable[FASTCGI_MAXCALL];

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif


////// Implementation

/// acquire a request id
//  note that id 0 is reserved for management traffic (and thus off limits)
//  NOT threadsafe
static int
fcgi_callno_get(void)
{
	static int last;  ///< optimization: last found element
	int i;

	i = last;
	do {
		// wrap
		if (i == FASTCGI_MAXCALL)
			i = 0;

		// found
		if (!fcgi_calltable[i]) {
			fcgi_calltable[i] = 1;
			last = i;
			return i + 1; // never return 0, see function info 
		}

		i++;
	} while (i != last);

	fprintf(stderr, "ERR: out of calls.\n");
	abort();
}

static void
fcgi_callno_put(int callno)
{
	fcgi_calltable[callno - 1] = 0;
}

const char *http_headers[] = { 	
	"SERVER_NAME", 		"www",
	"SERVER_PORT", 		"80",
	"SERVER_PROTOCOL", 	"HTTP/1.0",
	"REQUEST_METHOD",	"GET",
	"REQUEST_URI",		"/100",
	NULL
};

#define MAX_REQUEST_URI_LEN 	127

/// Write a length field and increase location pointer
//  Fieldlength depends on string length
static char *
fastcgi_param_setlen(const char *param, int plen, char *location)
{
	if (plen < 128) {
		* ((uint8_t *) location) = plen;
		return location + 1;
	} 
	else {
		*((uint32_t *) location) = plen;
		return location + 4;
	}
}

/// Append a parameter
static int
fastcgi_param_set(const char *pname, const char *pvalue, char *start)
{
	char *location;
	int clen, nlen;

	// write field headers
	clen = strlen(pname);
	nlen = strlen(pvalue);
	location = start;
	location = fastcgi_param_setlen(pname, clen, location);
	location = fastcgi_param_setlen(pvalue, nlen, location);

	// write name and value
	memcpy(location, pname, clen);
	memcpy(location + clen, pvalue, nlen);
	return location + clen + nlen - start;
}

static char *
fastcgi_params_hardcoded(int *plen_ptr)
{
	const char **hcur, **hnext;
	char *params, *pcur;
	int params_len, len, clen, off;

	// calculate length
	len = 0; 
	for (hcur = http_headers; *hcur; hcur++) {
		clen = strlen(*hcur);
		len += clen + (clen < 128 ? 1 : 4); // length + len field (1 or 4 bytes)
	}

	// allocate
	params_len = len;
	params = malloc(1000);
	pcur = params;

	// fill in
	for (hcur = http_headers; *hcur; hcur += 2) {
		hnext = hcur + 1;
		off = fastcgi_param_set(*hcur, *hnext, pcur);
		pcur += off;
	}

	*plen_ptr = params_len;
	return params;
}

/// Generate FastCGI parameter message
//  Reuses hardcoded params and only updates REQUEST_URI
static const char *
fastcgi_params(int *len)
{
	const char header_contlen[] = "CONTENT_LENGTH";
	
	static char *params;
	static int paramslen;
	char *cur;
	int ulen, off;

	if (params)
		free(params);
	
	params = fastcgi_params_hardcoded(&paramslen);
	off = paramslen;
	
	params[off] = 0;
	*len = off;

	return params;
}	

/// Send a request.
//
//  NB: this uses an optimization to get around a TCP flow control issue:
//    Even though we have 3 messages, send 2 requests to avoid delayed ACKs.
//    (every other packet is subject to a delayed ACK)
//  This is no longer required with Unix domain sockets as backend
//
// @return 0 on error, or the request id
static char *
fastcgi_buildrequest(int *rlen)
{
	static struct fcgi_beginreq breq = {
		.header = {
			.version = FCGI_VERSION_1,
			.type = FCGI_BEGIN_REQUEST,
		},
		.body.role = (FCGI_RESPONDER) << 8,
		.body.flags = FCGI_KEEP_CONN,
	};
	static struct fcgi_header paramhdr = {
		.version = FCGI_VERSION_1,
		.type = FCGI_PARAMS,
	};
	static struct fcgi_header stdin_hdr  = {
		.version = FCGI_VERSION_1,
		.type = FCGI_STDIN,
	};

        const char *_params;
	char *buf;
	int reqno, off, parlen, unused, initialized;

	buf = malloc(1460);

	//// packet 1 -- fastcgi message 1 : begin request
	breq.header.len = htons(FCGI_HEADER_LEN);
	reqno = fcgi_callno_get();
	breq.header.request = htons(reqno);
	memcpy(buf, &breq, sizeof(breq));
	off = sizeof(breq);

	//// packet 1 -- fastcgi message 2 : send parameters
	// fill in header fields
	_params = fastcgi_params(&parlen);
	paramhdr.len = htons(parlen);
	paramhdr.request = htons(reqno);

	// append params to begin header in single packet buffer
	memcpy(buf + off, &paramhdr, sizeof(paramhdr));
	off += sizeof(paramhdr);
	memcpy(buf + off, _params, parlen);
	off += parlen;
	assert(off < 1460);

	(*rlen) = off;
	return buf;
}

static int
fastcgi_connect(const char *filepath)
{
  struct sockaddr_un addr;
  int fd; 
  int __attribute__((unused)) optval;

  fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
  	fprintf(stderr, "fastcgi socket()\n");
	return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = PF_UNIX;
  memcpy(addr.sun_path, filepath, strlen(filepath));

  if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
  	fprintf(stderr, "fastcgi connect()\n");
	  close(fd);
	  return -1;
  }

  return fd;
}

static int
fastcgi_send(int fd, char *static_request, int rlen) 
{
	struct fcgi_beginreq *breq;
	struct fcgi_header *paramhdr;
	struct fcgi_header paramend_hdr;
	char request[1460];
	int reqno;

	// copy to private version
	assert(rlen <= 1460);
	assert(static_request);
	memcpy(request, static_request, rlen);
	
	// update call identifier
	reqno = fcgi_callno_get();
	breq = (void *) request;
	breq->header.request = htons(reqno);
	
	paramhdr = (void *) (request + sizeof(*breq));
	paramhdr->request = htons(reqno);

	if (write(fd, request, rlen) != rlen) {
		fprintf(stderr, "fastcgi write()\n");
		return 0;
	}

	// second packet
	memset(&paramend_hdr, 0, sizeof(paramend_hdr));
	paramend_hdr.version = FCGI_VERSION_1;
	paramend_hdr.type = FCGI_PARAMS;
	paramend_hdr.len = 0;
	paramend_hdr.request = htons(reqno);

	write(fd, &paramend_hdr, sizeof(paramend_hdr));
	return reqno;
}

/// handle FASTCGI_STDOUT messages: actually receive and return data
static int
fastcgi_recv_stdout(int fd, int plen)
{
	char buf[1460];
	int off, cur;

	// read initial data
	off = 0;
	do {
		// read into buffer. a bit ugly to integrate status line
		cur = read(fd, buf, min(sizeof(buf), plen - off));
		if (cur < 0) {
			fprintf(stderr, "read() out at %dB\n", off);
			return 1;
		}

		if (memcmp(buf, "HTTP", 4)) {
			fprintf(stderr, "[rx] corrupt data. Concurrency?\n");
			return 1;
		}

		off += cur;
	} while (cur && off < plen);
	
	return 0;
}

/// handle FASTCGI_END_REQUEST messages
static int fastcgi_recv_end(int fd, struct fcgi_header *head)
{
	struct fcgi_endreq_body body;
	uint16_t res;
	int cur;

	// parse header
	assert(head->len == htons(sizeof(body)));
	fcgi_callno_put(ntohs(head->request));

	// read body
	cur = read(fd, &body, sizeof(body));
	if (cur != sizeof(body)) {
		fprintf(stderr, "read() end (%d)\n", cur);
		return 1;
	}
	
	// parse result
	res = body.proto_status;
	if (res != FCGI_REQUEST_COMPLETE) {
		if (res == FCGI_CANT_MPX_CONN) 
			fprintf(stderr,"fastcgi multiplexing is DISABLED\n");
		else
			fprintf(stderr, "result end (%d)\n", res);
		return 1;
	}

	return 0;
}
/// receive reply
// WARNING: grave simplification: we only allow [STDOUT]* [END_REQUEST]
static int
fastcgi_recvreply(int fd)
{
	struct fcgi_header head;
	char buf[1460];
	int off, cur, plen, unused;

	do {
		// read header
		if (read(fd, &head, sizeof(head)) != sizeof(head)) {
			fprintf(stderr, "read head\n");
			return 1;
		}
		plen = ntohs(head.len);

		// receive response for web client
		switch(head.type) {
		case FCGI_STDOUT:
			if (plen && fastcgi_recv_stdout(fd, plen))
				return 1;
		break;
		case FCGI_END_REQUEST:
			if (fastcgi_recv_end(fd, &head))
				return 1;
		break;
		case FCGI_STDERR:
			fprintf(stderr, "STDERR : \n");
			// empty queue
			off = 0;
			do {
				cur = read(fd, buf, min(sizeof(buf), head.len - off));
				off += cur;
				if (cur > 0)
					unused = write(2, buf, cur);
			} while (cur > 0 && off < plen);
		break;
		default:
			fprintf(stderr, "unknown fcgi reply %d\n", head.type);
			// empty queue
			off = 0;
			do {
				cur = read(fd, buf, min(sizeof(buf), head.len - off));
				off += cur;
			} while (cur > 0 && off < plen);
		}

		// eat padding
		if (head.padding) {

			// stupid safety test
			if (head.padding > sizeof(buf)) {
				fprintf(stderr, "illegal padding %d\n", head.padding);
				return 1;
			}
			unused = read(fd, buf, head.padding);
		}

	} while (head.type != FCGI_END_REQUEST);

	return 0;
}


//// main code

static int stop = 0;
static int count;
static int fd;
static char *static_request;
static int static_rlen;

static int
do_single(int fd)
{
  int reqno;

  reqno = fastcgi_send(fd, static_request, static_rlen);
  if (reqno < 0)
	  ReturnError(1, "tx");

  if (fastcgi_recvreply(fd))
	  ReturnError(1, "rx");

  return 0;
}

static void *
do_worker(void *unused)
{
	// send requests (at max rate)
	while (!stop) {
		if (do_single(fd))
			break;
		atomic_get_and_addto(&count, 1);
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t t;
	int i;

	Thread_SetName("bench_fastcgi");

	// build request
	static_request = fastcgi_buildrequest(&static_rlen);
	if (!static_request)
		ReturnError(1, "build");

	// connect
	fd = fastcgi_connect("/tmp/" SOCKNAME ".fastcgi.sock");
	if (fd < 0)
		ReturnError(1, "connect");

	// start threads
	for (i = 0; i < NUM_THREADS; i++)
		pthread_create(&t, NULL, do_worker, NULL);

	//for (i = 0; i < NUM_SECS; i++) {
	while (1) {
		sleep(1);
		fprintf(stderr, "%8d req/s\n", swap(&count, 0));
	}
	stop = 0;

	// disconnect
	if (close(fd))
		ReturnError(1, "disconnect");

	printf("[ok] done\n");
	return 0;
}

