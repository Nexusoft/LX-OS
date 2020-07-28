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

struct PktTftp {
  char opcode[2];
} __attribute__((packed));

enum TftpRequestCode {
  TFTP_OPCODE_READREQUEST=1,
  TFTP_OPCODE_WRITEREQUEST=2,
  TFTP_OPCODE_DATA=3,
  TFTP_OPCODE_ACK=4,
  TFTP_OPCODE_ERROR=5,
  TFTP_OPCODE_OACK=6,
};

enum TftpErrorCode {
  TFTP_ERRUNDEFINED,
  TFTP_FILENOTFOUND,
  TFTP_ACCESSVIOLATION,
  TFTP_DISKFULL,
  TFTP_ILLEGAL,
  TFTP_UNKNOWNID,
  TFTP_FILEEXISTS,
  TFTP_NOSUCHUSER,
};

#define BOOTP_OPTION_PAD		(0x00)
#define BOOTP_OPTION_SUBNET_MASK	(0x01)
#define BOOTP_OPTION_ROUTER 	(0x03)
#define BOOTP_OPTION_END		(0xff)
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


#define ACK_CALLBACK_PASS 0
#define ACK_CALLBACK_DROP 1
typedef int (*ack_callback_function)(char *data, int len, void *param);

#define TFTP_PORT 69

struct Port {
  int inuse;
  Queue *recvq;
  Sema  *recvsema;
  ack_callback_function ack_callback;
  void *ack_callback_param;
};

extern Port_Num default_ip_nic;
extern Port_Num default_ip_switch;

//////// skbuff extensions

struct sk_buff *skb_allocate(int datasize);
struct sk_buff *skb_alloc_indirect(Page *page, int offset, int datasize);
void skb_destroy(struct sk_buff *skb);

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
	           void (*llfunc)(struct sk_buff *, void *), 
		   void *lldev);

//////// switch interface

void nxnet_switch_tx(char *pkt, int plen);
void nxnet_switch_add(const char *mac, int port_num);
int nxnet_switch_init(void);

//////// testing

int nxnet_test_rx(const void *pkt, int plen);
int nxnet_test(void);

//////// support routines 

void nxnet_pktinfo(const void *ptr, int caller_id);
void nxnet_pktinfo_macaddr(const void *mac);
void nxnet_pktinfo_ipaddr(const uint32_t ip);

static void putshort(char *ptr, unsigned short val) {
	ptr[0] = val >> 8;
	ptr[1] = val;
}

unsigned short getshort(unsigned char *ptr);

char *getmyip(void);
char *getserverip(void);

void set_server(char *server);

int set_l2sec_key(unsigned char *new_key, int key_len);

//////// internal. don't use these

extern char default_mac_address[6];
extern int default_nic_port;
extern char myip[4];
extern unsigned int my_ipaddress;
extern unsigned int my_gateway;
extern unsigned int my_netmask;
unsigned char serverip[4];
unsigned char server_mac[6];
unsigned int switch_packetcount;

#endif

