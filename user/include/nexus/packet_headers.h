#ifndef _PACKET_HEADERS_H_
#define _PACKET_HEADERS_H_

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define NEXUS_IP_DEFAULT_TTL 0x3c

#define MAXUDPLEN 1600

typedef struct PktUdp PktUdp;
struct PktUdp {
  char srcport[2];
  char dstport[2];
  char length[2];
  char csum[2];
};
typedef struct PktIp PktIp;
struct PktIp {
  char vihl;
  char tos;
  char len[2];
  char id[2];
  char flagfrag[2];
  char ttl;
  char proto;
  char hdrcsum[2];
  char src[4];
  char dst[4];
};
typedef struct PktEther PktEther;
struct PktEther {
  char dstaddr[6];
  char srcaddr[6];
  char proto[2];
};

#endif // _PACKET_HEADERS_H_
