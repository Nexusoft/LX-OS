#ifndef __NEXUSNET_H__
#define __NEXUSNET_H__

#include <nexus/queue.h>
#include <nexus/synch.h>
#include <nexus/ipc.h> // for Port_Num

struct PktEther {
  char dstaddr[6];
  char srcaddr[6];
  union {
  	char proto[2];
	uint16_t h_proto;
  };
} __attribute__((packed));

#define PACKETSLOPATEND 10

#define ETHER_PROTO_IP    0x0800
#define ETHER_PROTO_ARP   0x0806

/* ARP protocol opcodes. */
#define ARP_OP_REQUEST   1               /* ARP request.  */
#define ARP_OP_REPLY     2               /* ARP reply.  */

/* ARP protocol HARDWARE identifiers. */
#define ARP_HDR_ETHER    1               /* Ethernet 10/100Mbps.  */

typedef struct {
    uint16_t ar_hrd;          		/* Format of hardware address.  */
    uint16_t ar_pro;          		/* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    uint16_t ar_op;           		/* ARP opcode (command).  */
} __attribute__ ((packed)) ARP_Header;

typedef struct {
    unsigned char ar_sha[6]; /* Sender hardware address.  */
    uint32_t ar_sip;            /* Sender IP address.  */
    unsigned char ar_tha[6]; /* Target hardware address.  */
    uint32_t ar_tip;            /* Target IP address.  */
} __attribute__ ((packed)) ARP_Ethernet;

typedef struct PktIcmp {
	unsigned char type;
	unsigned char code;
	char csum[2];
	char id[2];
	char seqno[2];
} __attribute__((packed)) PktIcmp;

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

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define NEXUS_IP_DEFAULT_TTL 0x3c

struct PktUdp {
  char srcport[2];
  char dstport[2];
  char length[2];
  char csum[2];
} __attribute__((packed));

#define UDP_PROTO_TEST	6534	// nexus kernel network selftest port

typedef struct PktTcp PktTcp;
struct PktTcp {
  char srcport[2];
  char dstport[2];
  char seqno[4];
  char ackno[4];
  uint16_t data_off:4;
  uint16_t reserved:3;
  uint16_t ecn:3;
  uint16_t control:6;
  char wnd[2];
  char csum[2];
  char urgent[2];
} __attribute__((packed));

struct PktBootp {
	char op;
	char htype;
	char hlen;
	char hops;
	char xid[4];
	char secs[2];
	char flags[2];
	char ciaddr[4];
	char yiaddr[4];
	char siaddr[4];
	char giaddr[4];
	char chaddr[16];
	char server_hostname[64];
	char boot_filename[128];
	char dhcp_option_cookie[4]; // this and following are optional?
	char dhcp_option_tags[308]; // arbitrary length?
} __attribute__((packed));

//////// page management (pages are the method of transport)

void * nxnet_alloc_page(void);
void   nxnet_free_page(void *page);

void 	       nxnet_page_setlen(void *page, unsigned short len);
unsigned short nxnet_page_getlen(void *page);

//////// skbuff extensions

struct sk_buff * alloc_skb(unsigned int size, int gfp_mask);
void free_skb(struct sk_buff * skb);

void * nxnet_init_skb(void *, unsigned long);
struct sk_buff *skb_allocate(int datasize);
struct sk_buff *skb_alloc_indirect(Page *page, int offset, int datasize);
void skb_destroy(struct sk_buff *skb);


//////// virtual router (encapsulates switch and filter)

void nxnet_vrouter_to(char *page, int plen);
void nxnet_vrouter_out(int port, char *page, int plen);
int  nxnet_vrouter_from(int port, char **page, char **paddr, int *proto);

//////// filter (sends packets to correct destination(s))

int nxnet_filter_rx(void *pkt, int plen);
int nxnet_filter_test(void);
int nxnet_filter_add(uint16_t offset, uint16_t len, const char *mask0, 
		     const char *mask1, int portnum);
int nxnet_filter_add_ipport(uint16_t ipport, int portnum, int do_tcp);
int nxnet_filter_add_arp(int portnum, int is_request);
int nxnet_filter_add_ipproto(int portnum, char protocol);


//////// device driver interface

int nxnet_dev_rx(struct sk_buff *skb);
int nxnet_dev_rx_int(struct sk_buff *skb);
int nxnet_dev_init(const char *mac, 
		   int hw_checksum, int hw_calc_pseudo,
	           int (*llfunc)(struct sk_buff *, void *), 
		   void *lldev);

//////// switch interface

void nxnet_switch_tx(char *pkt, int plen);
void nxnet_switch_add(const char *mac, int port_num);
int nxnet_switch_init(void);

//////// debug 

void nxnet_pktinfo(const void *ptr, int caller_id);
void nxnet_pktinfo_macaddr(const void *mac);
void nxnet_pktinfo_ipaddr(const uint32_t ip);

//////// internal. don't use these

extern char default_mac_address[6];
extern int default_nic_port;
extern unsigned int my_ipaddress;
extern unsigned int my_gateway;
extern unsigned int my_netmask;
unsigned int switch_packetcount;

#endif

