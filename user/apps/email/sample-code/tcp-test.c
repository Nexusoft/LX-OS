#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define LOCAL_ADDR 0

const char *from = "The Nexus <ashieh@cs.cornell.edu>";
const char *localdomain = "sbox2.cs.cornell.edu";
const char *from_addr = "nexus@cs.cornell.edu";
const char server_addr[4] = { 128, 84, 223, 124};

void tcp_test_server(void);
void tcp_test_client(int, char *, int);
void tcp_send_email(char *recipients[], int num_recipients, char *cert, char *body);

void start_tcp_test(void) {
#define CLIENT_PORT (1179)
#if 0
	tcp_test_server();
#endif
	// CLIENT TEST

#if 0
	// ssh test
	tcp_test_client(22, NULL, 0);
#endif
#if 0
	// simple http test
	const char *fetch = "GET /bsg.avi\r\n";
	//const char *fetch = "GET /bsg-head.avi\r\n";
	//const char *fetch = "GET /ashieh-pkglist.txt\r\n";
	//const char *fetch = "GET /ashieh-pkglist.txt\r\n";
	tcp_test_client(80, fetch, strlen(fetch));
#endif
#if 1
	char *recipients[] = 
		{ "ashieh@cs.cornell.edu" };
	char *body = 
"Hello world.";
	tcp_send_email(recipients, sizeof(recipients) / sizeof(recipients[0]), NULL, body);
#endif
}

#if 0
typedef __u32 socklen_t;
extern int socket(int domain, int type, int protocol);
extern int bind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
extern int listen(int sockfd, int backlog);
extern int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int recv(int sockfd, void *buf, size_t len, int flags);
extern int connect(int  sockfd,  const struct sockaddr *serv_addr, 
		   socklen_t addrlen);
extern ssize_t send(int sockfd, void *buf, size_t len, int flags);
#endif

void tcp_test_server(void) {
	printk("tcp test server\n");
	// Set up a listen socket
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	printk("got socket %d\n", fd);

	printk("1\n");
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = LOCAL_ADDR;
	printk("2\n");
	addr.sin_port = htons(25);
	printk("pre bind\n");
	int err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	printk("bind of %d returned %d\n", fd, err);
	err = listen(fd, 4);
	printk("listen of %d returned %d\n", fd, err);

	int acceptfd;
	while(1) {
		struct sockaddr_in acceptaddr;
		int addrlen = sizeof(struct sockaddr_in);
		acceptfd = accept(fd, (struct sockaddr*)&acceptaddr, &addrlen);
		if(acceptfd > 0) {
			printk("accepted %d=> %X:%d", acceptfd, 
			       acceptaddr.sin_addr.s_addr, 
			       ntohs(acceptaddr.sin_port));
			break;
		}
	}
	while(1) {
#define BUFLEN (16384)
		static char buf[BUFLEN+1];
		int len = recv(acceptfd, buf, BUFLEN, 0);
		if(len > 0) {
			printk("got %d from api\n", len);
			buf[len] = '\0';
			printk("data: %s\n", buf);
		} else {
			//sleep(10);
		}
	}
}

void tcp_test_client(int destport, char *buf, int buflen) {
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	int err;
	extern void save(char *buf, int len);

	printk("got socket %d\n", fd);

	addr.sin_addr.s_addr = LOCAL_ADDR;
	addr.sin_port = htons(CLIENT_PORT);
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));

	struct sockaddr_in dest;
	// char server_addr[4] = { 128, 84, 98, 19};
	char server_addr[4] = { 128, 84, 223, 124};
	dest.sin_family = AF_INET;
	memcpy(&dest.sin_addr.s_addr, server_addr, 4);
	dest.sin_port = htons(destport);

	printk("ready to start\n");
	wait();
	printk("starting\n");
	err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
	printk("connect of %d returned %d\n", fd, err);

	if(buf != NULL) {
#if 0
		int res = send(fd, buf, buflen, 0);
		printk("send(%d) => %d\n", buflen, res);
#else // multiple parts
		int res = send(fd, buf, buflen / 2, 0);
		printk("send() => %d\n", res);
		res = send(fd, buf + buflen / 2, buflen - buflen / 2, 0);
		printk("send() => %d\n", res);
#endif
	}
	int total = 0;
	int csum = 0;
	int sleep_count = 0;
	int final = 0;
	while(1) {
#define BUFLEN (16384)
		static char buf[BUFLEN+1];
		int len = recv(fd, buf, BUFLEN, 0);
		if(len > 0) {
			sleep_count = 0;
			//printk("got %d from api (%d)\n", len, total);
			buf[len] = '\0';
			total += len;
#ifdef SAVE
			save(buf, len);
#else
			//printk("%s", buf);
			int i;
#if 0
			for(i=0; i < len; i++) {
				csum += buf[i];
			}
#endif
			static int lastTotal = 0;
			if(total - lastTotal > 50000000) {
				printk("total=%d, csum=%d\n", total, csum);
#if 0
				Stat_print(&delack0);
				Stat_print(&delack1);
				Stat_print(&sendack);
				Stat_print(&timerdelta);
				HistStat_print(&sendackcaller);
#endif
				lastTotal = total;
			}
#endif
		} else {
			printk("sleeping?");
			sleep(1);
			if(sleep_count++ > 10 && !final) {
				printk("total=%d, csum=%d\n", total, csum);
				final = 1;
			}
		}
		// XXX: the following call screws up the receive thread
		// sleep(1);
	}
}

enum SMTP_Class {
	SMTP_FULL,
	SMTP_INTERMEDIATE
};

void wait_for_smtp_ok(int fd, enum SMTP_Class class) {
	char buf[4096], pos = 0;
	char classchar;
	switch(class) {
	case SMTP_FULL:
		classchar = '2';
		break;
	case SMTP_INTERMEDIATE:
		classchar = '3';
		break;
	}
	while(1) {
		int len = recv(fd, buf+pos, 4096 - pos, 0);
		if(len <= 0) continue;
		pos += len;
		// Scan what we've seen
		buf[pos] = 0;
		if(buf[0] == classchar) {
			int i;
			for(i=0; i < pos-1; i++) {
				if(buf[i] == '\r' && buf[i+1] == '\n') {
					buf[i] = '\0';
					// printk("got %s\n", buf);
					goto done;
				}
			}
		}
	}
 done:
	return;
}

void send_smtp_command(int fd, char *cmd, int len, enum SMTP_Class messageclass) {
	send(fd, cmd, len, 0);
	send(fd, "\r\n", 2, 0);
	wait_for_smtp_ok(fd, messageclass);
}

void tcp_send_email(char *recipients[], int num_recipients, char *cert, char *body) {
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	int err;
	extern void save(char *buf, int len);

	printk("got socket %d\n", fd);

	addr.sin_addr.s_addr = LOCAL_ADDR;
	addr.sin_port = htons(CLIENT_PORT);
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	memcpy(&dest.sin_addr.s_addr, server_addr, 4);
	dest.sin_port = htons(25);

	err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
	printk("connect of %d returned %d\n", fd, err);

	// Start SMTP processing
	wait_for_smtp_ok(fd, SMTP_FULL);
	static char cmdbuf[4096];
	static char tobuf[4096];
	static char bodybuf[2048];
	sprintf(cmdbuf, "HELO %s", localdomain);
	send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);

	sprintf(cmdbuf, "MAIL FROM: <%s>", from_addr);
	send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);
	
	int i;
	for(i=0; i < num_recipients; i++) {
		sprintf(cmdbuf, "RCPT TO: <%s>", recipients[i]);
		send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);
	}
	int j = 0;
	for(i=0, j=0; i < strlen(body) + 1; i++, j++) {
		if(body[i] != '\n') {
			bodybuf[j] = body[i];
		} else {
			bodybuf[j++] = '\r';
			bodybuf[j] = '\n';
		}
	}
	sprintf(cmdbuf, "DATA");
	send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_INTERMEDIATE);

	tobuf[0] = 0;
	for(i=0; i < num_recipients; i++) {
		sprintf(tobuf + strlen(tobuf), "%s%s", recipients[i],
			i != num_recipients - 1 ? ", " : "");
	}
	sprintf(cmdbuf, 
"From: %s
User-Agent: Nexus
X-Nexus-Certificate: none
To: %s
Subject: A test message
",
		from, tobuf);
	send(fd, cmdbuf, strlen(cmdbuf), 0);
	send(fd, bodybuf, strlen(bodybuf), 0);
	send(fd, "\r\n.\r\n", 5, 0);
}

int main() {
	start_tcp_test();
}
