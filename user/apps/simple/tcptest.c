#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <netinet/in.h>

char dest_addr_tmp[4] = { 128, 84, 223, 104 };
int dest_addr;
int raw_socket;

struct sockaddr_in to_addr;

void tcphdr_init(struct tcphdr *th, unsigned short source, unsigned short dest, int seq, int ack_seq) {
  memset(th, 0, sizeof(*th));

  th->source = htons(source);
  th->dest = htons(dest);
  th->seq = htonl(seq);
  th->ack_seq = htonl(ack_seq);

  th->doff = sizeof(*th) / 4;
}

int sendpkt(char *pdat, int plen) {
  // XXX This code does not properly compute TCP checksum
  return sendto(raw_socket, pdat, plen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));

}

void sendTriplet(int srcport, int dstport) {
  char pdat[1514];
  int plen;
  struct tcphdr *th = (struct tcphdr *)pdat;
  tcphdr_init(th, srcport, dstport, 0, 0);
  plen = sizeof(*th);

  printf("syn to %d\n", dstport);
  th->syn = 1; th->rst = 0; th->ack = 0;
  sendpkt(pdat, plen);

  printf("synack to %d\n", dstport);
  // can receive syn/ack
  th->syn = 1; th->rst = 0; th->ack = 1;
  sendpkt(pdat, plen);

  printf("ack to %d\n", dstport);
  // cannot receive other packets
  th->syn = 0; th->rst = 0; th->ack = 1;
  sendpkt(pdat, plen);

  printf("rst to %d\n", dstport);
  th->syn = 0; th->rst = 1; th->ack = 1;
  sendpkt(pdat, plen);
}

int main(int argc, char **argv) {
  dest_addr = *(int *)dest_addr_tmp;
  to_addr = ((struct sockaddr_in) {
	       .sin_port = 0, .sin_addr = { .s_addr = dest_addr }
		 });

  int first_port = 80;
  if(argc > 1) {
    first_port = atoi(argv[1]);
    printf("first port is %d\n", first_port);
  }

  raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
#if 0
  int flag = 1;
  setsockopt(raw_socket, SOL_IP, IP_HDRINCL, flag, sizeof(flag));
#endif

  printf("=== About to test reserveEndpoint(), send to 80");
  getchar();

  // can receive syn
  printf("port 1025\n");
  sendTriplet(1025, first_port);

  printf("port 1026\n");
  sendTriplet(1026, first_port);

  printf("=== about to test packets sent to 82 (unreserved)\n");
  getchar();

  sendTriplet(1025, 82);
  return 0;
}
