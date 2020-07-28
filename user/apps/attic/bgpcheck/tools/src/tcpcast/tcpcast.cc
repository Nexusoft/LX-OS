#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//quick little hack that simulates one side of a TCP conversation 

#pragma pack(push, 1)
struct ipheader {
 unsigned char ip_hl:4, ip_v:4; /* this means that each member is 4 bits */
 unsigned char ip_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off;
 unsigned char ip_ttl;
 unsigned char ip_p;
 unsigned short int ip_sum;
 unsigned int ip_src;
 unsigned int ip_dst;
}; /* total ip header length: 20 bytes (=160 bits) */

struct tcpheader {
 unsigned short int th_sport;
 unsigned short int th_dport;
 unsigned int th_seq;
 unsigned int th_ack;
 unsigned char th_x2:4, th_off:4;
 unsigned char th_flags;
 unsigned short int th_win;
 unsigned short int th_sum;
 unsigned short int th_urp;
}; /* total tcp header length: 20 bytes (=160 bits) */
#pragma pack(pop)


unsigned short		/* this function generates header checksums */
csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}


int main(int argc, char **argv){
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  char buffer[8192]; /* single packets are usually not bigger than 8192 bytes */
  ipheader *ip = (ipheader *)(buffer);
  tcpheader *tcp = (tcpheader *)(buffer + sizeof(ipheader));
  char *payload = (buffer + sizeof(ipheader) + sizeof(tcpheader));
  int len;
  FILE *data = fopen(argv[1], "r");
  
  int id = 400;

  int one = 1;
  struct sockaddr_in sin;
  /* the sockaddr_in containing the dest. address is used
     in sendto() to determine the datagrams path */

  const int *val = &one;
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    printf ("Warning: Cannot set HDRINCL!\n");

  sin.sin_family = AF_INET;
  sin.sin_port = htons (179);/* you byte-order >1byte header values to network
			      byte order (not needed on big endian machines) */
  sin.sin_addr.s_addr = inet_addr ("10.254.254.6");

  memset (buffer, 0, 8192);	/* zero out the buffer */

  while((len = fread(payload, 1024, 1, data)) > 0){

    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof (ipheader) + sizeof (tcpheader) + len);
    ip->ip_id = htonl(54321);
    ip->ip_off = 0;
    ip->ip_ttl = 255;
    ip->ip_p = 6;
    ip->ip_sum = 0; //calculate later
    ip->ip_src = inet_addr("10.254.254.3");
    ip->ip_dst = inet_addr("10.254.254.6");
    tcp->th_sport = htons(1234);
    tcp->th_dport = htons(179);
    tcp->th_seq = htonl(id);
    id += len;
    tcp->th_ack = 0;
    tcp->th_x2 = 0;
    tcp->th_off = 5;
    tcp->th_flags =0;
    tcp->th_win = htons(10000);
    tcp->th_sum = 0;

    ip->ip_sum = csum ((unsigned short *)buffer, ntohs(ip->ip_len) >> 1);
    
    sendto (s,		/* our socket */
	    buffer,	/* the buffer containing headers and data */
	    ntohs(ip->ip_len),	/* total length of our datagram */
	    0,		/* routing flags, normally always 0 */
	    (struct sockaddr *) &sin,	/* socket addr, just like in */
	    sizeof (sin));		/* a normal send() */
  }
    
  return 0;
}
