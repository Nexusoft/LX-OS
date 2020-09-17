/** NexusOS: a server that can spawn child servers with increased privileges 
    This is a blueprint for such services as sendmail, where only trusted
    authenticated child processes may access private user data. The idea is
    that a client attaches to a central server at a known port (say, 8000),
    asks it for a private server on another port, sends its key and performs
    some communication.
 
    This is a really really simple proof of concept. For one, it lacks
    - a secure channel to communicate keys
    - a challenge response scheme to guard against replay attacks
    - it is susceptible to DoS by malicious clients

    The server implements a simple textual client/server protocol over TCP,
    some bastardization of HTTP 1.0

    It recognizes these commands:

    "LOGIN <num>"
    	spawns a new server on another port for the given user
	
	returns "200 OK" on success


    "KEY <pem-encoded RSA privkey>"
    	tells the server to insert credential 
	"pem(key) says process:$pid speaksfore pem(key)"
	in effect giving access to all resources accessible by the key

	returns "200 OK" on success

	NB: generate the required key with
	
		openssl genrsa -out <privkey.pem> 2048


    "READ <file> <off> <len>"
    	read at most 1024 bytes from a (possibly protected) file

	returns "200 OK <data>" on success


    "WRITE <file> <off> <len> <data>"
        write at most 1024 bytes to a (possibly protected) file
	XXX not yet implemented

	returns "200 OK" on success


    XXX set_use_key combines options do_init? and use_crypto? : ugly and confusing
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <nexus/rdtsc.h>

#ifdef __NEXUS__
#include <nexus/fs.h>
#include <nexus/ipc.h>
#include <nexus/log.h>
#include <nexus/guard.h>
#include <nexus/formula.h>
#include <nexus/nexuscalls.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Net.interface.h>
#endif

#define RXBUFLEN	(2000)
#define PORT_DEFAULT	(8000)
#define FILEPATH	"/tmp/spawndata.txt"

// XXX cleanup set_use_key crap
#define KEY_PARENT_PLAIN 	0
#define KEY_CHILD_ENC		1
#define KEY_PARENT_ENC		2
#define KEY_CHILD_PLAIN		3

const char privkey[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpQIBAAKCAQEAo/5vg3C2aQrrJNSPGb+XW5e4B7SpPfeWWdC4/t+FxPtAXf1p\n"
"J/2y52u2Fs71w5aCM4cVXYg4DeErjYGlTq+z7HESCIRfLtbRcR+pycG2nu1by1q0\n"
"4C4AaeN3PFGg8sIlxVtjQoPlWcrekUB4SSx0dhb0D5UHVPZBhhmBKxeCTFgCUrFH\n"
"qxcDTt653O/3+B+icYkg3nL+lNqVqj0YXGqXHcmRbhTdrpEeWJ3bYSCMDPGArlDQ\n"
"kfNLJNgPbtcNtr3ATyAyj9uAT6micejEjkXzDXFe2jDxeMDudPzRGX4BbzJZiLsi\n"
"F8r0YuaTZ93TTYSTlqH9+w2NiruvCl4fvf2SXwIDAQABAoIBAQCH4ghGUftjGF/0\n"
"mYelHyJsC0+6WtCs/tx+uTrAPTebG1CfUJ10PHuj05UCWyQ6lxh1V6W1ZWyE26F5\n"
"1AXEKEQeUyZNFlnD9s1+PW0zNqZ6E1SvMA6VfqhrFMY0nbKN0572Y53gfGdqunUm\n"
"x9OjVgl929EIpER5+r4aPkHQEd+uHx65Z2vURvsQTTOLjIAc+qFXt1E2NWR7aQf1\n"
"nKUDIgqhrii+seE52kN9YroZ33YUjKNIFhC7Ae6AZh8zrL40Udht2TZfkMq97xoy\n"
"NyQZayfCFcYIkM2ne89Iny3i5iFx0wsbAt8lk85UcIeOd40/dPjv4dZ2bYydDqlL\n"
"khzvhKmBAoGBANO4H5u8XqrWVCpuNH3vwSdNDaeuv0cfQgaNQB04WN+58TqP+d5/\n"
"4tyyRvXpcjxmQMPHMy/2drtRBI/++E9WGfGkJKuZMD9nZuYi5AEl1kM8/A08e6YJ\n"
"xusfN8wLns26npptqpjHCBgJaZBnsXJXA7bS4XCWIReI2QtSM/ClOFMfAoGBAMZL\n"
"ACZdLnXhyVdX1uuPVyFDUfDbJzMFk8qIp62AmKZbzbFE/LU3Z48yXe64BNP2WVrK\n"
"Uu2QJUUIoMKCFObn6701Jox69eXsPE3/Xn5cHxEgIJL/NbmYe9YRAAauJLoHoZQc\n"
"dJZEqh7fKaKEoCAUgj8a+1B19zzVlqv8tpxdxBjBAoGAJ1q0VWiAWFUatABkNXyZ\n"
"dMq33RF4cKn4xer/ne7ZZkzT8ETO93LiIo/o7NEF8QA4zat7clDn5Q28QV/tnCGv\n"
"FOGkB1mkRETeNa0KoMP9veXaHEO/4C81EINvBbirPiaQULhN27QzZvRo8PS1YUGX\n"
"aSZtzVW6tPs1DQusp/CuNZUCgYEAkxYtHUf/X5fFBtH0bTUdV2IdVQDq+dDISPLH\n"
"Fk8ObFAqqrTWkwFvAuxEev/rLONOcqcjjm5fBu8YeE+Pe5xK5EWZu5i18AAk12J2\n"
"0Fo6/TQMlZ1TV8FBEo/3qfzg51EjzL6yyIhUfKPiuVeRg1pTJsY35v4qD+kLY7YI\n"
"KsLu48ECgYEAvo0xQ8ATblFxwonEXMezBdYX+y5ia99nLqAiOIIBBK5aeIxuYJ+P\n"
"Rj0D2NEX23lOD/8RpoujSqydgXnGcIgSH5E56+x0kDvneXCfH1KUupQdto+g+EM4\n"
"cPBzELk+2PZXy11JOv5+2n9ZLM2AsnLQ7qdd2CllX6VgqfaHOFPP1l8=\n"
"-----END RSA PRIVATE KEY-----\n";

////////////////    Server    ////////////////

#ifdef __NEXUS__
static char *execpath;

// socket to wait on for a child to become active 
static int childsock;
static struct sockaddr_un childconn = {
	.sun_family = AF_UNIX,
	.sun_path = "/tmp/spawn.sock",	
};

static int do_stop;

/** Create a new instance on a specific port 
    @param port a port in HOST byteorder
    @return 0 on success, or failure 
 
    Note that the function cannot tell whether the child managed
    to acquire the chosen port (exclusively) */
static int
server_do_spawn(int port, int use_key)
{
	char call[100];
	char *args[4];
	int pid, pid2, ret;

	// input validation
	if (port < 1024 || port > (1 << 16) - 1) {
		fprintf(stderr, "login: port out of bounds\n");
		return 1;
	}

	// start child
	sprintf(call, "%s -p %d %d", execpath, port, 
		use_key ? KEY_CHILD_ENC : KEY_CHILD_PLAIN);
	pid = nxcall_exec(call);
	if (pid < 0) {
		fprintf(stderr, "exec\n");
		return 1;
	}

	// wait until child is ready
	// nb: this version is unsafe in that it can be interposed by others
	ret = read(childsock, &pid2, sizeof(int));
	if (ret != sizeof(int)) {
		fprintf(stderr, "child wait (%d)\n", ret);
		return 1;
	}

	return 0;
}

/** Insert a credential that says the process 'speaksfor' the key,
    in other words, that it has all the rights conferred by the key. */
static int
server_do_key(const char *pemkey)
{
	struct nxguard_object file_obj;
	FSID file;
	Form *form;
	RSA *rsakey;
	char *buf, *pubkey, *cred;

	nxlog_write_ex(2, "key %s\n", pemkey);
	
	// pre: get file id
	file = nxcall_fsid_byname(FILEPATH);
	if (!FSID_isFile(file)) {
		fprintf(stderr, "file lookup\n");
		return -1;
	}

	// 1: import key
	rsakey = rsakey_private_import(pemkey);
	if (!rsakey) {
		fprintf(stderr, "key import\n");
		return 1;
	}
	pubkey = rsakey_public_export(rsakey);
	if (!pubkey) {
		fprintf(stderr, "key export\n");
		return 1;
	}

	// 2: create credential 
// BROKEN: formula code (form_..) is no longer supported (see #if 0 below)
#if 0 
	buf = malloc(2000);
	sprintf(buf, "process.%d speaksfor pem(%%{bytes:%d})", getpid(), PUBKEY_LEN);
	form = form_fmt(buf, pubkey);
	cred = form_to_pretty(form, 0);
	if (nxguard_cred_add(cred, rsakey)) {
		fprintf(stderr, "cred insert\n");		
		return 1;
	}
	free(cred);
	free(form);

	// 3: create proof 
	sprintf(buf, "pem(%%{bytes:%d}) says process.%d speaksfor pem(%%{bytes:%d})", 
		PUBKEY_LEN, getpid(), PUBKEY_LEN);
	form = form_fmt(buf, pubkey, pubkey);
	cred = form_to_pretty(form, 0);
	sprintf(buf, "assume process.%d says read=1;\n"
		       "assume %s;\n"
		       "delegate;\n"
		       "sfor read=1;\n"
		       "impe;\n",
		       getpid(), cred);

	if (nxguard_proof_set(SYS_FS_Read_CMD, &file_obj, buf)) {
		fprintf(stderr, "proof set\n");		
		return 1;
	}
	free(cred);
	free(form);
#else
	buf = malloc(2000);
	// XXX shouldn't this read "assume .."?
	sprintf(buf, "pem(%%{bytes:%d}) says process.%d speaksfor pem(%%{bytes:%d})", 
		PUBKEY_LEN, getpid(), PUBKEY_LEN);
	
	if (nxguard_proof_set(SYS_FS_Read_CMD, &file_obj, buf)) {
		fprintf(stderr, "proof set\n");		
		return 1;
	}
	if (nxguard_cred_add(/*unsafe*/ strstr(cred, "process"), rsakey)) {
		fprintf(stderr, "cred insert\n");		
		return 1;
	}
#endif
	free(buf);

	// cleanup
	free(pubkey);
	rsakey_destroy(rsakey);
	return 0;
}

static int
server_do_read(const char *filepath, int off, int len, char *buf)
{
	const char header[] = "200 OK ";
	int fd, wlen;

	//printf("read [%s] <%d,%d>\n", filepath, off, len);

	if (len > 1024)
		goto error_403;

	// open file
	fd = open(filepath, O_RDONLY);
	if (fd < 0)
		goto error_403;
	if (lseek(fd, off, SEEK_SET) != off)
		goto error_403;

	// read (single fragment)
	memcpy(buf, header, sizeof(header) - 1);
	wlen = read(fd, buf + sizeof(header) - 1, len);
	if (wlen < 0) {
		fprintf(stderr, "%s: read\n", __FUNCTION__);
		goto error_500;
	}

	// close file
	if (close(fd)) {
		fprintf(stderr, "%s: close\n", __FUNCTION__);
		goto error_500;
	}

	return sizeof(header) - 1 + wlen;

error_404:
	return sprintf(buf, "404 Not Found") + 1; 
error_500:
	return sprintf(buf, "500 Internal Server Error") + 1; 
error_403:
	return sprintf(buf, "403 Forbidden") + 1; 
}

/** Demultiplex a request, handle it and overwrite buf with the reply 
    @return the length of the reply */
static int
server_demux(char *buf, int len, int set_use_key)
{
	char param[51];
	int fd, plen, wlen, off, ret, port;

	// spawn a new instance
	if (sscanf(buf, "LOGIN %d", &port) == 1) {
		//printf("login [%d]\n", port);
		assert(set_use_key == KEY_PARENT_PLAIN || set_use_key == KEY_PARENT_ENC);
		if (!server_do_spawn(port, (set_use_key == KEY_PARENT_ENC) ? 1 : 0)) 
			return sprintf(buf, "200 OK") + 1;
		return sprintf(buf, "500 Internal Server Error") + 1; 
	}

	// close server
	if (!memcmp(buf, "LOGOUT ", 7)) {
		do_stop = 1;
		return sprintf(buf, "200 OK") + 1;
	}
	
	// key insertion
	if (sscanf(buf, "KEY -----%s", param) == 1) {
		if (!server_do_key(buf + 4)) {
			//printf("rsakey [%s] (valid)\n", param);
			return sprintf(buf, "200 OK") + 1;
		}
		else {
			//printf("rsakey [%s][%dB] (invalid)\n", param, plen);
			return sprintf(buf, "400 Bad Request") + 1;
		}
	}

	// read
	if (sscanf(buf, "READ %50s %d %d", param, &off, &len) == 3) {
		return server_do_read(param, off, len, buf);
	}

	// write
	if (sscanf(buf, "WRITE %50s %d %d", param, &off, &len) == 3) {
		printf("write [%s] <%d,%d>\n", param, off, len);
		// XXX find extents of data
		// XXX implement
		goto error_500;
	}

	fprintf(stderr, "unknown [%s]\n", buf);
error_500:
	return sprintf(buf, "500 Internal Server Error") + 1; 
}

/** Set proof to access file. Optionally set goal on file */
static int
server_init_key(void)
{
	struct nxguard_object file_obj;
	FSID file;
	Form *form;
	RSA *rsakey;
	char *pubkey, *goal;

	// create file object
	file = nxcall_fsid_byname(FILEPATH);
	if (!FSID_isFile(file)) {
		fprintf(stderr, "file lookup\n");
		return -1;
	}
	file_obj.fsid = file;
	
	// generate the key that owns the file
	// XXX normally, should use the client supplied key
	//     but normally, we create files following WRITE network request
	rsakey = rsakey_private_import(privkey);
	if (!rsakey) {
		fprintf(stderr, "localkey import\n");
		return -1;
	}
	pubkey = rsakey_public_export(rsakey);

	// create goal
	// XXX we are going to show that process speaksfor key
	//     should delegate one further and show that it speaksfor file 
	//     if following earlier NAL custom
	goal = malloc(2000);
	sprintf(goal, "pem(%%{bytes:%d}) says read=1", PUBKEY_LEN);
// BROKEN: XXX FIX without using form_fmt
#if 0
	form = form_fmt(goal, pubkey);
	free(goal);
#else
	fprintf(stderr, "XXX reenable embedded PEM key support. will probably FAIL\n");
#endif

	// set goal
	if (nxguard_goal_set_str(SYS_FS_Read_CMD, &file_obj, goal)) {
		fprintf(stderr, "goal set\n");		
		return 1;
	}

	// cleanup
	free(goal);
	free(pubkey);
	rsakey_destroy(rsakey);

	return 0;
}

/** Open a channel for children to notify us on.
    They will send a message when they're up */
static int
server_init_tunparent(void)
{
	childsock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (childsock < 0) {
		fprintf(stderr, "socket() childconn\n");
		return 1;
	}

	if (bind(childsock, &childconn, sizeof(struct sockaddr_un)) < 0) {
		fprintf(stderr, "bind() childconn\n");
		return 1;
	}
	
	return 0;
}

/** Tell parent that we're up */
static int
server_init_tunchild(void)
{
	int pid;

	childsock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (childsock < 0) {
		fprintf(stderr, "socket() childconn\n");
		return 1;
	}

	if (connect(childsock, &childconn, sizeof(struct sockaddr_un)) < 0) {
		fprintf(stderr, "bind() childconn\n");
		return 1;
	}
	
	pid = getpid();
	if (write(childsock, &pid, sizeof(int)) != sizeof(int)) {
		fprintf(stderr, "write() childconn");
		return 1;
	}

	close(childsock);

	return 0;
}

/** Standard init. Create datafile */
static int
server_init(int set_use_key)
{
	int fd, i;

	// do nothing if no init (regardless of whether key or not)
	if (set_use_key == KEY_CHILD_PLAIN || set_use_key == KEY_CHILD_ENC) 
		return 0;

	// create datafile
	fd = open(FILEPATH, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		fprintf(stderr, "file create failed\n");
		return -1;
	}

	// fill
	for (i = 0; i < 100; i++)
		write(fd, "AAAA.BBBB.CCCC", 14);

	// close file
	close(fd);

	// set file access control
	if (set_use_key == KEY_PARENT_ENC)
		server_init_key();

	return 0;
}

/** Listen on a port and handle requests 
    @param port the network port in HOST byteorder */
static int
server(int port, int set_use_key)
{
	struct sockaddr_in server;
	char *buf;	
	int sock, len, connsock;

	RAND_add(privkey, sizeof(privkey) - 1, 1000);	// WARNING: NOT random at all 
	
	if (server_init(set_use_key)) 
		return 1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket()\n");
		return 1;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, &server, sizeof(struct sockaddr_in)) < 0) {
		fprintf(stderr, "bind()\n");
		return 1;
	}

	if (listen(sock, 10)) {
		fprintf(stderr, "listen()\n");
		return 1;
	}

	// default server creates channel for children to talk on
	if (set_use_key == KEY_PARENT_PLAIN || set_use_key == KEY_PARENT_ENC) {
		if (server_init_tunparent()) 
			return 1;
	}
	else {
		if (server_init_tunchild())
			return 1;
	}

	buf = malloc(RXBUFLEN);	// large enough to hold a 2K RSA privkey
	
	nxlog_write("up at port %d\n", port);
	printf("server up at port %d\n", port);
	while (!do_stop) {
		nxlog_write_ex(1, "wait\n");
		connsock = accept(sock, NULL, NULL);
		if (connsock < 0) {
			fprintf(stderr, "accept()\n");
			return -1;
		}

		nxlog_write_ex(1, "new client\n");
		len = recv(connsock, buf, RXBUFLEN, 0);
		if (len <= 0) {
			fprintf(stderr, "rx\n");
			break;
		}

		nxlog_write_ex(3, "rx %s\n", buf);
		len = server_demux(buf, len, set_use_key);
		if (len > 0) {
			len = send(connsock, buf, len, 0);
			if (len <= 0) {
				fprintf(stderr, "tx\n");
				break;
			}
		}

		if (close(connsock)) {
			fprintf(stderr, "close\n");
			return -1;
		}
	}
	free(buf);

	if (close(sock)) {
		fprintf(stderr, "close()\n");
		return 1;
	}

	return len < 0 ? 1 : 0;
}	
#endif /* __NEXUS__ */


////////////////    Client    ////////////////

static int
do_client(int port, const char *req)
{
	static unsigned int ipaddr;
	struct sockaddr_in server;
	char buf[RXBUFLEN];	// large enough to hold a 2K RSA privkey
	int sock, len, rlen;
  
	// open connection
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket()\n");
		return -1;
	}

#ifdef __NEXUS__
	// get local ip address
	if (!ipaddr)
		Net_get_ip(&ipaddr, NULL, NULL);
#else
	ipaddr = (10 << 24) + 102;
#endif

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = htonl(ipaddr);

	if (connect(sock, (struct sockaddr *) &server, 
		    sizeof(struct sockaddr_in)) < 0) {
		fprintf(stderr, "connect()\n");
		return -1;
	}

	// send request
	rlen = strlen(req);
	if (send(sock, req, rlen, 0) != rlen) {
		fprintf(stderr, "send()\n");
		return -1;
	}

	// recv reply
	// XXX support multiple fragments (loop)
	len = recv(sock, buf, RXBUFLEN, 0);
	if (len < 0) {
		fprintf(stderr, "recv()\n");
		return -1;
	}

	// close connection
	if (close(sock)) {
		fprintf(stderr, "close()\n");
		return -1;
	}

	return strtol(buf, NULL, 10);
}

static int
client(int port, int do_key, int num_read)
{
	char req[RXBUFLEN];
	uint64_t tdiff;
	int i;

	tdiff = rdtsc64();

	// start private process
	sprintf(req, "LOGIN %d\n", port);
	if (do_client(PORT_DEFAULT, req) != 200) {
		fprintf(stderr, "login failed\n");
		return 1;
	}

	// insert secret
	if (do_key) {
		const char key_header[] = "KEY ";
		
		// create key request
		memcpy(req, key_header, sizeof(key_header) - 1);
		memcpy(req + sizeof(key_header) - 1, privkey, sizeof(privkey));
		
		if (do_client(port, req) != 200) {
			fprintf(stderr, "key failed\n");
			return 1;
		}
	}

	// carry out common file operations
	for (i = 0; i < num_read; i++) {
		// test KEY call
		if (do_client(port, "READ " FILEPATH " 0 1000") != 200) {
			fprintf(stderr, "read (%d) failed\n", i);
			return 1;
		}
	}

#if 0
	// close session
	if (do_client(port, "LOGOUT ") != 200) {
		fprintf(stderr, "close failed\n");
		return 1;
	}
#endif

	tdiff = rdtsc64() - tdiff;

	// WARNING: Hz HARDCODED for Core2 T7100
	printf("%d %llu\n", i, tdiff/2000100);
	return 0;
}


////////////////    Shared    ////////////////

static void __attribute__((noreturn))
usage(const char *filepath)
{
	printf("usage: %s -p <portnum> <setkey>\n"
	       "       %s -c <portnum> <usekey> <numread>\n"
	       "\n" 
	       "       where portnum is the server TCP port\n"
	       "	     setkey is [0|1|2|3] and decides whether to \n"
	       "               0: do not use key, create file\n"
	       "               1: use existing key goal\n"
	       "               2: set and use key goal \n"
	       "               3: do not use key, do not create file\n"
	       "             usekey is [0|1] and toggles whether to send the rsa key\n"
	       "             numread specifies the number of read requests per connection\n",
	       filepath, filepath);
	exit(1);
}

int 
main(int argc, char **argv)
{
#ifdef __NEXUS__
	char name[20];
#endif
	int port, do_key, num_read, ret;
	
#ifdef __NEXUS__
	nxlog_disable = 1;	// for benchmarking
#endif

	// validate input
	if (argc < 4 || argc > 5)
		usage(argv[0]);

	// parse port number
	port = strtol(argv[2], NULL, 10);
	if (port < 1024 || port > (1 << 16) - 1) {
		fprintf(stderr, "illegal port number\n");
		return 1;
	}

	// parse key field
	do_key = strtol(argv[3], NULL, 10);
	if (do_key < 0 || do_key > 3) {  // nb: lets client with 2 slip through
		fprintf(stderr, "key value out of bounds\n");
		return 1;
	}
	
	// client
	if (argc == 5) {
		num_read = strtol(argv[4], NULL, 10);
		if (num_read < 0 || num_read > 1000) {
			fprintf(stderr, "session length out of bounds\n");
		}

		//printf("Client port=%d key=%s reads=%d\n", 
		//	port, do_key ? "ON" : "OFF", num_read);
		return client(port, do_key, num_read);
	}

#ifdef __NEXUS__
	sprintf(name, "spawn.%d", port);
	nxlog_open(name);
	nxlog_level = 100;

	execpath = argv[0];
	ret = server(port, do_key);

	nxlog_close();
#else
	fprintf(stderr, "Server mode only supported on Nexus\n");
	ret = 1;
#endif
	return ret;
}

