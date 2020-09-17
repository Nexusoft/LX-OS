/** NexusOS: minimal webserver */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <nexus/rdtsc.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>
#ifdef __NEXUS__
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>
#endif

// Options

//#define USE_STATICREPLY
//#define REUSE_FILE
//#define USE_SELECT
//#define USE_FASTCGI
//#define USE_FASTCGI_UNIX
//#define USE_POST
//#define USE_COOKIE
//#define USE_DECRYPT
#define USE_HASH

#define FASTCGI_MAXCALL 	(100)		//< must correspond to fcgi.py
#ifdef __NEXUS__
#define HTTPD_HOME 		"/bin"
#else
#define HTTPD_HOME		"build/boot/bin"
#endif
#define HTTPD_SOCK_HOME		"/tmp"
#define COOKIELEN		(512)
#define MAX_REQUEST_SIZE	(1 << 20)	//< whole request, including POST
#define MAX_PARAMLEN		(14000)

#ifdef USE_FASTCGI
#ifdef USE_FASTCGI_UNIX
#define 	MAX_PORTS 4
static int 	ports[MAX_PORTS];
#else
#define 	FASTCGI_PORT	(6000)
static int 	fastcgi_fd;
#endif
#endif

// Variables

const char ok[] = "HTTP/1.0 200 OK\n";
const char err404_format[] =
	"\r\n\r\n<html><head>\n"
	"<title>404 Not Found</title>\n"
	"</head><body>\n"
	"<h1>Not Found</h1>\n"
	"<p>The requested URL was not found on this server.</p>\n"
	"<hr>\n"
	"</body></html>\r\n\r\n";
const char err500_format[] =
	"\r\n\r\n<html><head>\n"
	"<title>500 Internal Server Error</title>\n"
	"</head><body>\n"
	"<h1>500 Internal Server Error. Oh boy..</h1>\n"
	"<hr>\n"
	"</body></html>\r\n\r\n";

// Various support

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifdef __NEXUS__
/// return local IP address in NETWORK byte order
unsigned long localaddr(void)
{
	unsigned int ip;

	Net_get_ip(&ip, NULL, NULL);
	return ip;
}
#else
unsigned long localaddr(void)
{
	return htonl((127 << 24) + 1);
}
#endif

// Code

static void 
reply_404(int client_fd) 
{
  send(client_fd, ok, sizeof(ok) - 1, 0);
  send(client_fd, err404_format, sizeof(err404_format) - 1, 0);
}

static void __attribute__((unused))
reply_500(int client_fd)
{
  send(client_fd, ok, sizeof(ok) - 1, 0);
  send(client_fd, err500_format, sizeof(err500_format) - 1, 0);
}

// FastCGI

#ifdef USE_FASTCGI

#define FCGI_HEADER_LEN 	8
#define FCGI_VERSION_1 		1

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
	NULL
// generated on demand: REQUEST_URI
// optional: QUERY_STRING, PATH_INFO, SCRIPT_NAME, HTTP_COOKIE
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
	params = malloc(MAX_PARAMLEN);
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
fastcgi_params(const char *uri, int postlen, const char *cookie, int *len)
{
	const char header_requri[] = "REQUEST_URI";
	const char header_contlen[] = "CONTENT_LENGTH";
	const char header_querystr[] = "QUERY_STRING";
	const char header_cookiestr[] = "HTTP_COOKIE";
	const char header_method[] = "REQUEST_METHOD";
	
	static char *params;
	static int paramslen;
	char *cur;
	int ulen, off;

	if (params)
		free(params);
	
	params = fastcgi_params_hardcoded(&paramslen);
	off = paramslen;
	
	// append REQUEST_URI
	ulen = strlen(uri);
	if (ulen > MAX_REQUEST_URI_LEN) {
		uri = "/unknown";
		ulen = strlen(uri);
	}
	fastcgi_param_set(header_requri, uri, params + off);
	off += sizeof(header_requri) - 1 + ulen + /* field headers */ 2;

#ifdef USE_POST
	// (optionally) append CONTENT_LENGTH
	if (postlen) {
		char lenstr[10];

		snprintf(lenstr, 9, "%d", postlen);
		off += fastcgi_param_set(header_contlen, lenstr, params + off);
		off += fastcgi_param_set(header_method, "POST", params + off);
		fprintf(stderr, "NXDEBUG    POSTDATA header %dB\n", postlen);
	}
	else
#endif
		off += fastcgi_param_set(header_method, "GET", params + off);
	
	// (optionally) append QUERY_STRING
	cur = strchr(uri, '?');
	if (cur) {
		cur += 1;
		off += fastcgi_param_set(header_querystr, cur, params + off);
	}

#ifdef USE_COOKIE
	// (optionally) append HTTP_COOKIE
	if (cookie) {
		off += fastcgi_param_set(header_cookiestr, cookie, params + off);
	}
#endif

	// buffer overflowed. XXX avoid this in a proper fashion
	if (off > MAX_PARAMLEN) {
		fprintf(stderr, "Buffer overflow\n");
		abort();
	}
		
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
static int
fastcgi_sendrequest(const char *uri, int fcgi_fd, 
		    int postlen, const char *postdata, 
		    const char *cookie)
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
	static struct fcgi_header paramend_hdr = {
		.version = FCGI_VERSION_1,
		.type = FCGI_PARAMS,
		.len = 0
	};

        const char *_params;
	char buf[1460];
	int request, off, parlen, unused;

	//// packet 1 -- fastcgi message 1 : begin request
	breq.header.len = htons(FCGI_HEADER_LEN);
	request = fcgi_callno_get();
	breq.header.request = htons(request);
	memcpy(buf, &breq, sizeof(breq));
	off = sizeof(breq);

	//// packet 1 -- fastcgi message 2 : send parameters
	// fill in header fields
	_params = fastcgi_params(uri, postlen, cookie, &parlen);
	paramhdr.len = htons(parlen);
	paramhdr.request = htons(request);
	if (sizeof(breq) + sizeof(paramhdr) + parlen > 1460) {
		fprintf(stderr, "fastcgi request too long\n");
		return 0;
	}

	// append params to begin header in single packet buffer
	memcpy(buf + off, &paramhdr, sizeof(paramhdr));
	off += sizeof(paramhdr);
	memcpy(buf + off, _params, parlen);
	off += parlen;
	assert(off < 1460 /* buflen */);

	// write single packet to network
	if (write(fcgi_fd, buf, off) != off) {
		fprintf(stderr, "fastcgi write()\n");
		return 0;
	}

#ifdef USE_POST
	//// packet 2 -- postdata as STDIN + fastcgi message 3
	if (postlen) {

#ifndef USE_FASTCGI_UNIX
		if (postlen > 1000) {
			fprintf(stderr, "large POST not supported with TCP\n");
			return 0;
		}
#endif
		stdin_hdr.len = htons(postlen);

		// combine header and footer to minimize communication, if fits
		if (postlen < 1460 - sizeof(stdin_hdr)) {
			
			// serialize
			off = 0;
			memcpy(buf, &stdin_hdr, sizeof(stdin_hdr));
			off += sizeof(stdin_hdr);
			memcpy(buf + off, postdata, postlen);
			off += postlen;

			unused = write(fcgi_fd, buf, off);
		fprintf(stderr, "NXDEBUG    POSTDATA data %dB (fd=%d)\n", off, fcgi_fd);
		}
		else {
			unused = write(fcgi_fd, &stdin_hdr, sizeof(stdin_hdr));
		fprintf(stderr, "NXDEBUG    POSTDATA stdin hdr %dB\n", sizeof(stdin_hdr));
			unused = write(fcgi_fd, postdata, postlen);
		fprintf(stderr, "NXDEBUG    POSTDATA data %dB (fd=%d)\n", postlen, fcgi_fd);
		}
	}
	
	//// fastcgi message 3: empty params to start the request
#endif
	paramend_hdr.request = htons(request);
	unused = write(fcgi_fd, &paramend_hdr, sizeof(paramend_hdr));

	return request;
}

/// handle FASTCGI_STDOUT messages: actually receive and return data
static int
fastcgi_recv_stdout(int client_fd, int fcgi_fd, int plen)
{
	char buf[1460];
	int off, cur;

	// read initial data
	off = 0;
	do {
		// read into buffer. a bit ugly to integrate status line
		cur = read(fcgi_fd, buf, min(sizeof(buf), plen - off));
		if (cur < 0) {
			fprintf(stderr, "read() out at %dB\n", off);
			return 1;
		}

		// XXX support looping write
		if (write(client_fd, buf, cur) != cur) {
			fprintf(stderr, "write() out at %dB\n", off);
			return 1;
		}
		off += cur;
	} while (cur && off < plen);

	return 0;
}

/// handle FASTCGI_END_REQUEST messages
static int fastcgi_recv_end(int fcgi_fd, struct fcgi_header *head)
{
	struct fcgi_endreq_body body;
	uint16_t res;
	int cur;

	// parse header
	assert(head->len == htons(sizeof(body)));
	fcgi_callno_put(ntohs(head->request));

	// read body
	cur = read(fcgi_fd, &body, sizeof(body));
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
fastcgi_recvreply(int client_fd, int fcgi_fd, int request)
{
	struct fcgi_header head;
	char buf[1460];
	int off, cur, plen, unused;

	do {
		// read header
		if (read(fcgi_fd, &head, sizeof(head)) != sizeof(head)) {
			fprintf(stderr, "read head\n");
			return 1;
		}
		plen = ntohs(head.len);

		// receive response for web client
		switch(head.type) {
		case FCGI_STDOUT:
			if (plen && fastcgi_recv_stdout(client_fd, fcgi_fd, plen))
				return 1;
		break;
		case FCGI_END_REQUEST:
			if (fastcgi_recv_end(fcgi_fd, &head))
				return 1;
		break;
		case FCGI_STDERR:
			fprintf(stderr, "STDERR : \n");
			// empty queue
			off = 0;
			do {
				cur = read(fcgi_fd, buf, min(sizeof(buf), head.len - off));
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
				cur = read(fcgi_fd, buf, min(sizeof(buf), head.len - off));
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
			unused = read(fcgi_fd, buf, head.padding);
		}

	} while (head.type != FCGI_END_REQUEST);

	return 0;
}

/** Reply using FastCGI 
    @param postlen is 0 for a GET request, or the length of postdata
 */
static void
reply_fastcgi(int client_fd, int fcgi_fd, const char *uri, 
	      int postlen, const char *postdata, const char *cookie)
{
  int request;

  request = fastcgi_sendrequest(uri, fcgi_fd, postlen, postdata, cookie);
  if (!request) {
	  reply_500(client_fd);
	  return;
  }
  fastcgi_recvreply(client_fd, fcgi_fd, request);
}

static int
#ifdef USE_FASTCGI_UNIX
fastcgi_connect(const char *filepath)
#else
fastcgi_connect(uint16_t port)
#endif
{
#ifdef USE_FASTCGI_UNIX
  struct sockaddr_un addr;
#else
  struct sockaddr_in addr;
#endif
  int fcgi_fd; 
  int __attribute__((unused)) optval;

#ifdef USE_FASTCGI_UNIX
  fcgi_fd = socket(PF_UNIX, SOCK_STREAM, 0);
#else
  fcgi_fd = socket(PF_INET, SOCK_STREAM, 0);
#endif
  if (fcgi_fd < 0) {
  	fprintf(stderr, "fastcgi socket()\n");
	return -1;
  }

#ifndef USE_FASTCGI_UNIX
  // Serialized send-response causes 250ms ACK delay on each second request
  // disabling Nagle and sending 2 packets ensures that we get immediate ACKs.
  optval = 1;
  if (setsockopt(fcgi_fd, IPPROTO_TCP, TCP_NODELAY, 
			(char *) &optval, sizeof(int))) {
  	fprintf(stderr, "fastcgi setsockopt()\n");
	return -1;
  }
#endif

  memset(&addr, 0, sizeof(addr));
#ifdef USE_FASTCGI_UNIX
  addr.sun_family = PF_UNIX;
  memcpy(addr.sun_path, filepath, strlen(filepath));
#else
  addr.sin_family = PF_INET;
  addr.sin_addr.s_addr = localaddr();
  addr.sin_port = htons(port);
#endif

  if (connect(fcgi_fd, (struct sockaddr *) &addr, sizeof(addr))) {
  	fprintf(stderr, "fastcgi connect()\n");
	  close(fcgi_fd);
	  return -1;
  }

  return fcgi_fd;
}

/** Lookup a fastcgi backed by (hardcoded) URI
    @return -1 if not a fastcgi URI or a filedescriptor to the backend */
static int 
fastcgi_demux(const char *uri)
{
#ifdef USE_FASTCGI_UNIX
	const char * filepath;
	int idx;

#if 0
	// demultiplex and find fastcgi backend
	if (!memcmp(uri, "/admin", 6)) {
		filepath = HTTPD_SOCK_HOME "/admin.fastcgi.sock";
		idx = 1;
	}
	else 
#endif
	if (!memcmp(uri, "/pysize", 5)) {
		filepath = HTTPD_SOCK_HOME "/size.fastcgi.sock";
		idx = 2;
	}
	else 
	if (!memcmp(uri, "/pyfile", 5)) {
		filepath = HTTPD_SOCK_HOME "/file.fastcgi.sock";
		idx = 2;
	}
	else
		return -1;
#if 0
	else if (!memcmp(uri, "/uploadtest", 11)) {
		filepath = HTTPD_SOCK_HOME "/upload.fastcgi.sock";
		idx = 2;
	}
	else {
		filepath = HTTPD_SOCK_HOME "/fastcgi.sock";
		idx = 0;
	}
	//printf("[info] using socket %s for url %s\n", filepath, uri);
#endif

	// open connection if not already opened
	assert(idx < MAX_PORTS);
	if (ports[idx] <= 0) 
		ports[idx] = fastcgi_connect(filepath);

	if (ports[idx] == -1)
		fprintf(stderr, "not connected to %s\n", filepath);

	return ports[idx];
#else
	// WARNING: demux is not supported with TCP
	if (memcmp(uri, "/fast", 5)) 
		return -1;

	if (fastcgi_fd <= 0)
		fastcgi_fd = fastcgi_connect(FASTCGI_PORT);
	
	return fastcgi_fd;
#endif
}

static void
fastcgi_disconnect_all(void)
{
#ifdef USE_FASTCGI_UNIX
	int i;

	for (i = 0; i < MAX_PORTS; i++) {
		  if (ports[i] > 0 && close(ports[i]))
			fprintf(stderr, "fastcgi close error\n");
	}
#else
	if (fastcgi_fd && close(fastcgi_fd))
		fprintf(stderr, "fastcgi close error\n");
#endif
}

#endif /* USE_FASTCGI */

// File Handling

/// (poor) MIME type resolver
static const char *
file_type(const char *uri)
{
	const char *type;
	int ulen;

	ulen = strlen(uri);
	if (!memcmp(uri + ulen - 5, ".html", 5))
		type = "text/html";
	else if (!memcmp(uri + ulen - 4, ".htm", 4))
		type = "text/html";
	else
		type = "text/plain";
	
	return type;
}

static void 
reply_file(int client_fd, const char *uri) 
{
  static char *open_filepath;
  static int file_fd;
  static struct stat open_stat;
  static int total;

  struct stat file_stat;
  char *buf, namebuf[255];
  int tmp_fd, len, off, done, written, wcur, lock_idx;
#if defined USE_DECRYPT || defined USE_HASH
  long flags;
#endif

  // create filepath from uri
  if (uri[0] == '/')
	uri++;
  if (uri[0] == 0)
        uri = "index.html";
  sprintf(namebuf, "%s/%s", HTTPD_HOME, uri);

  // open file
  if (!open_filepath || strcmp(open_filepath, namebuf)) {
	tmp_fd = open(namebuf, O_RDONLY);
	if (tmp_fd < 0) {
		printf("no such file (%s)\n", namebuf);
		reply_404(client_fd);
		return;
	}

#ifdef USE_HASH
	if (sscanf(namebuf, HTTPD_HOME "/bench.%d.html", &lock_idx) == 1) {
		switch (lock_idx) {
			case 100:	lock_idx = 2; break;
			case 1000:	lock_idx = 3; break;
			case 10000:	lock_idx = 4; break;
			case 100000:	lock_idx = 5; break;
			case 1000000:	lock_idx = 6; break;
			default:	lock_idx = 1;
		}
		flags = ((primary_lockbox_port) << 16) | lock_idx;
		if (fcntl(tmp_fd, F_SIGNED, flags)) {
			printf("enable hash verification failed\n");
			reply_404(client_fd);
			return;
		}
	}
#endif
#ifdef USE_DECRYPT
	flags = ((primary_lockbox_port) << 16) | 1;
	if (fcntl(tmp_fd, F_SETENC, flags)) {
		printf("enable decryption failed\n");
		reply_404(client_fd);
		return;
	}
#endif
  	if (open_filepath) {
		free(open_filepath);
		close(file_fd);
	}
	open_filepath = strdup(namebuf);
	file_fd = tmp_fd;

	if (fstat(file_fd, &open_stat)) {
		printf("fstat()\n");
		abort();
	}
	total = open_stat.st_size;
	//printf("opened file %s [%dB]\n", open_filepath, total);
  }

  buf = malloc(total + 1000);
  lseek(file_fd, 0, SEEK_SET);
  
  // write header
  off = sizeof(ok) - 1;
  memcpy(buf, ok, off);
  off += sprintf(buf + off, 
		 "Content-Length: %d\n"
		 "Content-Type: %s\r\n\r\n", 
		 total, file_type(uri));

  // read file
  done = 0;
  do {
	  len = read(file_fd, buf + off, total);
	  if (len < 0) {
	      printf("read()\n");
	      reply_404(client_fd);
	      return;
	  }
	  off += len;
	  if (off) {
		// write until done
		written = 0;
		wcur = 1;
		while (written < off && wcur > 0) {
			wcur = send(client_fd, buf + written, off - written, 0);
			if (wcur < 0) {
				printf("write()\n");
				reply_404(client_fd); // could get ugly if not 1st fragment
			}
			written += wcur;
		}
	  }
	  
	  done += written;
	  off = 0; // offset from start of buffer is only used once: for the header
  } while (len && done < total);
  free(buf);

#ifndef REUSE_FILE
  close(file_fd);
  free(open_filepath);
  open_filepath = NULL;
#endif

}

static char *recv_buf;

static void * __attribute__((unused))
reply(void * _client_fd)
{
    char uri[512], *cur;
    long client_fd = (long) _client_fd;
    int len, clen, cookielen;
#ifdef USE_COOKIE
    char *cookiestart, cookie[COOKIELEN];
    const char clenstr[] = "Content-Length:";
    int off;
#endif
#ifdef USE_FASTCGI
    int fcgi_fd;
#endif

    // recv
    len = recv(client_fd, recv_buf, MAX_REQUEST_SIZE, 0);
    if (len < 5) {
      fprintf(stderr, "read header error\n");
      goto cleanup_err;
    }
   
    // parse GET
    if (sscanf(recv_buf, "GET %500s ", uri) != 1) {

#ifdef USE_POST
      // parse POST
      if (sscanf(recv_buf, "POST %500s ", uri) != 1) {
#endif
	fprintf(stderr, "unknown request %s\n", recv_buf);
        goto cleanup_err;
#ifdef USE_POST
      }

      // find content length
      cur = strstr(recv_buf, clenstr);
      if (!cur) {
      	fprintf(stderr, "POST without Content-Length\n");
	goto cleanup_err;
      }

      clen = strtol(cur + sizeof(clenstr) - 1, NULL, 10);
      if (clen == LONG_MIN || clen == LONG_MAX) {
      	fprintf(stderr, "POST: failed to parse Content-Length\n");
	goto cleanup_err;
      }

      // find start of payload
      cur = strstr(cur, "\r\n\r\n");
      if (!cur) {
      	fprintf(stderr, "POST: failed to find body\n");
	goto cleanup_err;
      }
      cur += 4;

      if (clen >= MAX_REQUEST_SIZE - 4096 /* other headers <= pagesize */ ) {
        fprintf(stderr, "POST: exceeds supported bounds\n");
	goto cleanup_err;
      }

      fprintf(stderr, "NXDEBUG %dB postdata\n", clen);
#endif
    }
    else {
      cur = NULL;
      clen = 0;
    }

#ifdef USE_COOKIE
    // Extract all cookies from optional 
    // "Cookie: <NAME>=<VALUE>[;<NAME>=<VALUE>]*" field
    // We support multiple such field (not sure if that is required)
    cookiestart = strstr(recv_buf, "Cookie: ");
    cookielen = 0;
    while (cookiestart &&  
           ((unsigned long ) (cookiestart - recv_buf)) < len && 
	   cookielen < COOKIELEN) {

	// add cookie to semicolon-separated list
    	cookiestart += 8;
	off = strcspn(cookiestart, "\n"); 
	if (off > 0 && cookielen + off < COOKIELEN) {
		memcpy(cookie + cookielen, cookiestart, off);
		cookielen += off;
		cookie[cookielen] = 0;
	}
    	cookiestart = strstr(cookiestart, "Cookie: ");
    }
#else
    cookielen = 0;
#endif

    // send
#ifdef USE_FASTCGI
    fcgi_fd = fastcgi_demux(uri);
    if (fcgi_fd >= 0)
      reply_fastcgi(client_fd, fcgi_fd, uri, clen, cur, 
		    cookielen ? cookie : NULL);
    else 
#endif
    {
      if (clen) {
      	fprintf(stderr, "POST method not allowed in static requests\n");
	goto cleanup_err;
      }
      reply_file(client_fd, uri);
    }

    // close
    if (close(client_fd)) {
      fprintf(stderr, "close error\n");
    }

    return NULL;

cleanup_err:
    close(client_fd);
    return (void *) -1;
}

int 
main(int argc, char **argv) 
{
#ifdef USE_SELECT
  fd_set readfds;
#endif
  struct sockaddr_in addr;
  int server_fd;
  long client_fd;
  int __attribute__((unused)) optval;

#ifdef __NEXUS__
  Thread_SetName("httpd.main");
#endif

  server_fd = socket(PF_INET, SOCK_STREAM, 0);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = 0;
  addr.sin_port = htons(80);

  if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr))) {
    fprintf(stderr, "bind error\n");
    return 1;
  }

#ifndef __NEXUS__
  optval = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, 
			(char *) &optval, sizeof(int))) {
  	fprintf(stderr, "server setsockopt() reuse address\n");
	return -1;
  }
#endif

  if (listen(server_fd, 10) != 0) {
    fprintf(stderr, "listen error\n");
    return 1;
  }

  printf("Nexus webserver\n");
#ifdef REUSE_FILE
  printf("  option REUSE_FILE enabled\n");
#endif
#ifdef USE_SELECT
  printf("  option USE_SELECT enabled\n");
#endif
#ifdef USE_FASTCGI
  printf("  option USE_FASTCGI enabled\n");
#ifdef USE_FASTCGI_UNIX
  printf("    option FASTCGI_UNIX enabled\n");
  printf("    socket directory %s\n", HTTPD_SOCK_HOME);
#else
  printf("    option FASTCGI_TCP enabled\n");
#endif
#else
  printf("  option USE_FASTCGI DISABLED!\n");
#endif
#ifdef USE_DECRYPT
  printf("  option USE_DECRYPT enabled\n");
#endif
#ifdef USE_HASH
  printf("  option USE_HASH enabled\n");
#endif
  printf("  data directory %s\n", HTTPD_HOME);

  recv_buf = malloc(MAX_REQUEST_SIZE);	// nb: not deallocated

  while(1) {
#ifdef USE_SELECT
    // select
    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);
    if (select(server_fd + 1, &readfds, NULL, NULL, NULL) != 1) {
      fprintf(stderr, "select error\n");
      continue;
    }
#endif

    // accept
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
      fprintf(stderr, "accept error\n");
      continue;
    }

#ifdef USE_STATICREPLY
    {
      char response[] = "HTTP/1.0 200 OK\r\n"
//      		        "Content-Length: 7\n"
      		        "Content-Type: text/plain\r\n\r\n"
      		        "hello\n";

      if (recv(client_fd, recv_buf, MAX_REQUEST_SIZE, 0) < 0) {
	      fprintf(stderr, "receive failed\n");
	      goto close_it;
      }
      if (send(client_fd, response, sizeof(response), 0) != sizeof(response)) {
	      fprintf(stderr, "send failed\n");
      }

close_it:
      close(client_fd);
    }
#else
    reply((void *) client_fd);
#endif
  }

  fprintf(stderr, "[httpd] stopped serving\n");

#ifdef USE_FASTCGI
  fastcgi_disconnect_all();
#endif

  return 0;
}

