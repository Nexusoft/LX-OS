/* vim: set sw=2 ts=8: */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include "include/nbgp/bgp.h"
#include "../../../include/util/common.h"

typedef struct pf_dump_header_t {
  unsigned int timestamp;
  unsigned short type;
  unsigned short subtype;
  unsigned int len;
} pf_dump_header;

typedef struct pf_common_header_t {
  unsigned short ras;
  unsigned short las;
  unsigned short iid;
  unsigned short afi;
  struct in_addr rpeerip;
  struct in_addr lpeerip;
} pf_common_header;

typedef struct pf_client_list_t {
  struct pf_client_list_t *next;
  int sock;
  struct sockaddr_in addr;
  socklen_t addrlen;
} pf_client_list;

typedef struct BGP_OPEN_MSG_t {
  char marker[16];
  unsigned short len;
  unsigned char type;
  unsigned char version;
  unsigned short asid;
  unsigned short holdtime;
  unsigned int bgpident;
  unsigned char optlen;
} BGP_OPEN_MSG;

typedef struct BGP_KEEPALIVE_MSG_t {
  char marker[16];
  unsigned short len;
  unsigned char type;
} BGP_KEEPALIVE_MSG;

int alive = 1;

static void sig_int_handler(int interrupt){
  alive = 0;
}

static void handle_new_connection(int servfd, pf_client_list **clientsp);
static int handle_pluto_packet(int sock, pf_client_list *clients);
static void print_buffer(char *buffer, int len);
static int resolve(const char *server, struct in_addr *addr);
static void usage(const char *prog);

static time_t last_packet;
static BGP_OPEN_MSG open_msg;
static BGP_KEEPALIVE_MSG keepalive_msg;
int main(int argc, char **argv){
  char buffer[4096];
  struct sockaddr_in addr, saddr;
  int sock, serv;
  int state = 0, read_len;
  int in_a_packet = 0;
  char rval;
  char request[] = "GET /bgp_update/binary HTTP/1.0\r\n\r\n";
  pf_client_list *clients = NULL, *curr, *last;
  fd_set readfds, writefds, exceptfds;
  struct timeval timeout;
  int c;
  int listen_port = 1179;

  while ((c = getopt(argc, argv, "p:")) != -1) {
    switch (c) {
      case 'p':  listen_port = atoi(optarg);  break;
      default:   usage(argv[0]);
    }
  }
  if (argc-optind != 1) usage(argv[0]);

  //figure out who we're connecting to
  const char *pluto_host = argv[optind];

  bzero((char *)&addr, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;

	if (resolve(pluto_host, &addr.sin_addr) == -1) {
		printf("Resolution failure for host \"%s\"\n", pluto_host);
		exit(1);
	}
	printf("host found: %s\n", inet_ntoa(addr.sin_addr));
  addr.sin_port = htons(9995); //default pluto port #

  sock = socket(AF_INET, SOCK_STREAM, 0);

  if(sock < 0){
    printf("Error: Unable to initialize socket\n");
    exit(1);
  }

  fprintf(stderr, "Connecting...\n");

  if(connect(sock, (const struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0){
    perror("Error: Unable to connect to host");
    exit(1);
  }

  printf("Writing request\n");
  if(write(sock, request, strlen(request)) < 0){
    printf("Error writing request\n");
  }

  //ignore the headers
  while(state < 4){
    read(sock, &rval, 1);

    //    if((rval != '\n')&&(rval != '\r')){
    //      printf("read: %c\n", rval);
    //    } else {
    //      if(rval == '\n'){00 1D 01 04 00 2A 00
    //	printf("newline\n");
    //      } else {
    //	printf("return\n");
    //      }
    //    }

    if(rval == ((state%2)?'\n':'\r')){
      state++;
    } else {
      if(rval == '\r'){
	state = 1;
      } else {
	state = 0;
      }
    }
  }

/*   printf("waiting for packets\n"); */
/*   if(read(sock, &dump_header, sizeof(pf_dump_header)) > 0){ */
/*     printf("Got packet: %d (%d bytes)\n", ntohs(dump_header.type), ntohl(dump_header.len)); */
/*     printf("%08x %08x %08x\n", ntohl(dump_header.timestamp), ((unsigned int)ntohs(dump_header.type) << 16) | ntohs(dump_header.subtype), ntohl(dump_header.len)); */
/*   } */
  printf("Creating BGP Server\n");
  serv = socket(AF_INET, SOCK_STREAM, 0);

  if(serv < 0){
    perror("Error: Unable to initialize server socket");
    exit(1);
  }

  int one = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
  perror("warning: setsockopt");

  bzero((char *)&saddr, sizeof(struct sockaddr_in));
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(listen_port);
  saddr.sin_family = AF_INET;

  if(bind(serv, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0){
    perror("Error: Unable to bind socket");
    exit(1);
  }

  if(listen(serv, 10) < 0){
    perror("Error: Unable to configure server socket for listening");
    exit(1);
  }

  memset(&open_msg.marker, 255, 16);
  open_msg.len = htons(16+13);
  open_msg.type = 1;//OPEN
  open_msg.version = 4;
  open_msg.asid = 0;//learn it later
  open_msg.holdtime = htons(10);//seconds, 3 is the minimum
  open_msg.bgpident = htonl((128<<24)|(84<<16)|(223<<8)|101); //clamp.cs
  open_msg.optlen = 0;

  print_buffer((char *)&open_msg, ntohs(open_msg.len));

  memset(&keepalive_msg.marker, 255, 16);
  keepalive_msg.len = htons(16+3);
  keepalive_msg.type = 4;//KEEPALIVE

  print_buffer((char *)&keepalive_msg, ntohs(keepalive_msg.len));

  printf("Starting main event loop\n");
  last_packet = time(NULL);

  signal(2, &sig_int_handler);
  signal(1, &sig_int_handler);
  signal(3, &sig_int_handler);

  while(alive){
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(sock, &readfds);
    FD_SET(serv, &readfds);

    curr = clients;
    int maxfd = MAX(sock, serv);
    while(curr != NULL){
      FD_SET(curr->sock, &readfds);
      maxfd = MAX(maxfd, curr->sock);
      curr = curr->next;
    }

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if(select(maxfd+1, &readfds, &writefds, &exceptfds, &timeout) < 0){
      perror("An error occurred in select");
      exit(1);
    }

    if(FD_ISSET(serv, &readfds)) {
      handle_new_connection(serv, &clients);
    }
    if(FD_ISSET(sock, &readfds))
      in_a_packet = handle_pluto_packet(sock, clients);
    //send a keepalive if time's up and we're not in the middle of another packet
    if(last_packet < time(NULL)-2 && !in_a_packet) {
      //printf("Sending keepalive\n");
      for(curr = clients; curr != NULL; curr = curr->next){
	if(write(curr->sock, &keepalive_msg, ntohs(keepalive_msg.len)) < 0){
	  perror("An error occurred writing to a BGP stream");
	  exit(1);
	}
      }
      last_packet = time(NULL);
    }
    //check to see if anyone's closed on us
    last = NULL;
    for(curr = clients; curr != NULL; curr = curr->next){
      if(FD_ISSET((curr->sock), &readfds)){
	printf("Trying to read\n");
	if(((read_len = read(curr->sock, buffer, sizeof(buffer))) < 1) && (errno != EIO)){
	  //it's closed
	  perror("Closed connection");
	  if(last == NULL){
	    clients = clients->next;
	  } else {
	    last = curr->next;
	  }
	  close(curr->sock);
	  free(curr);
    	  printf("Successfully cleared the thing from the list\n");
	  break;
	} else {
	  if(buffer[18] != 0x04){
	    print_buffer(buffer, read_len);
	  }
	  printf("Dumped %d bytes from client\n", read_len);
	}
      }
      last = curr;
    }
  }
  printf("Shutting down...\n");
  close(serv);
  close(sock);
  for(curr = clients; curr != NULL; curr = curr->next){
    close(curr->sock);
  }
  printf("Goodbye\n");

  return 0;
}

static void handle_new_connection(int servfd, pf_client_list **clientsp) {
  pf_client_list *curr = (pf_client_list*)malloc(sizeof(pf_client_list));
  if(!curr){
    fprintf(stderr, "accept: out of memory\n");
    exit(1);
  }
  curr->addrlen = sizeof(struct sockaddr_in);
  curr->sock = accept(servfd, (struct sockaddr *)&(curr->addr), &(curr->addrlen));
  printf("Accepted connection! ip=%s:%d\n", inet_ntoa(curr->addr.sin_addr), htons(curr->addr.sin_port));
  if(curr->sock < 0){
    perror("An error occurred in accept");
    exit(1);
  }

  if(fcntl(curr->sock, F_SETFL, O_NONBLOCK) < 0){
    perror("An error occurred switching the accepted socket to nonblocking mode");
    exit(1);
  }

  //send the OPEN message
  if(write(curr->sock, &open_msg, ntohs(open_msg.len)) < 0){
    perror("An error occurred writing the OPEN message");
    exit(1);
  }
  //send the KEEPALIVE message
  if(write(curr->sock, &keepalive_msg, ntohs(keepalive_msg.len)) < 0){
    perror("An error occurred writing the KEEPALIVE message");
    exit(1);
  }
  curr->next = *clientsp;
  *clientsp = curr;
}

/* returns true if we're in the middle of a packet */
static int handle_pluto_packet(int sock, pf_client_list *clients) {
  static unsigned int dump_len = 0, common_len = 0;
  static pf_dump_header dump_header;
  static pf_common_header common_header;
  static int packet_len_left = 1, read_len;
  char buffer[4096];
  if(dump_len < sizeof(pf_dump_header)){
    read_len = read(sock, &(((char *)&dump_header)[dump_len]), sizeof(pf_dump_header) - dump_len);
    if(read_len < 0){
      perror("An error occurred reading from the BGP stream");
      exit(1);
    }
    dump_len += read_len;
  } 
  if((dump_len >= sizeof(pf_dump_header) && (common_len < sizeof(pf_common_header)))) {
    read_len = read(sock, &(((char *)&common_header)[common_len]), sizeof(pf_common_header) - common_len);
    if(read_len < 0){
      perror("An error occurred reading from the BGP stream");
      exit(1);
    }
    common_len += read_len;
    if(common_len >= sizeof(pf_common_header)){
      packet_len_left = ntohl(dump_header.len) - sizeof(pf_common_header);
      if (open_msg.asid == 0) open_msg.asid = common_header.ras;
      printf("%d: %s(as=%d) -> ",
      	ntohl(dump_header.timestamp),
	inet_ntoa(common_header.rpeerip),
	ntohs(common_header.ras));
      printf("%s(as=%d)\n",
	inet_ntoa(common_header.lpeerip),
	ntohs(common_header.las));
    }
  }
  if((dump_len >= sizeof(pf_dump_header) && (common_len >= sizeof(pf_common_header))) && (packet_len_left > 0)) {
    read_len = read(sock, buffer, packet_len_left);
    if(read_len < 0){
      perror("An error occurred reading from the BGP stream");
      exit(1);
    }
    pf_client_list *curr;
    for(curr = clients; curr != NULL; curr = curr->next){
      if(write(curr->sock, buffer, read_len) < 0){
	perror("An error occurred writing to a BGP stream");
	exit(1);
      }
    }
    packet_len_left -= read_len;
  }
  if(packet_len_left <= 0){
    //printf("Finished packet\n");
    dump_len = 0;
    common_len = 0;
    packet_len_left = 1;
    last_packet = time(NULL);
  }

  return dump_len >= sizeof(pf_dump_header) && common_len >= sizeof(pf_common_header);
}

static int resolve(const char *server, struct in_addr *addr) {
	struct hostent *hent;

	if (inet_aton(server, addr) != 0) return 0;
	hent = gethostbyname(server);
	if (!hent) {
		herror(server);
		return -1;
	}
	memcpy(addr, hent->h_addr_list[0], sizeof(*addr));
	return 0;
}

static void print_buffer(char *buffer, int len){
  int i;
  for(i = 0; i < len; i += 8){

    if(len - i > 7){
      printf("%03x) %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX\n", i, 	 
	     buffer[i], 
	     buffer[i+1], 
	     buffer[i+2], 
	     buffer[i+3], 
	     buffer[i+4], 
	     buffer[i+5], 
	     buffer[i+6], 
	     buffer[i+7]);
    } else {
      printf("%03x)", i);
      for(; i < len; i ++){
	printf(" %02hhX", buffer[i]);
      }
      printf("\n");
    }
  }
}

static void usage(const char *prog) {
  printf("Usage:\n  %s [-p listen-port] plutohost\n", prog);
  exit(1);
}
