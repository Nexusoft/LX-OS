/* Nexus OS
   network packet type and handlers.
   The nexus's equivalent of sk_buff (?)
   
NetComp reflection schema:
/ports/[port #]/NetComp/type
/ports/[port #]/NetComp/name

/ports/[port #]/plugs/[plug #]/type
/ports/[port #]/plugs/[plug #]/name

For switch plugs
/ports/[port #]/plugs/[plug #]/external = (1) if this is the default external plug

*/

#ifndef _NETCOMP_H_
#define _NETCOMP_H_

#include <nexus/IPC.interface.h>
#include <nexus/transfer.h>
#include <nexus/dlist.h>

#include <linux/types.h>
#ifdef __NEXUSKERNEL__
#include <nexus/ipd.h>
#else
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#endif

/** user/kernel compatibility ****/

#ifndef __NEXUSKERNEL__
#define barrier() __asm__ __volatile__("": : :"memory")
#define CallHandle_to_Port_Num(I, CH) CallHandle_to_Port_Num(CH)
#define CallHandle_to_IPC_Msg(I, CH) CallHandle_to_IPC_Msg(CH)
#define nexuspanic() 							\
	do {								\
		nxcompat_fprintf(stderr, "NEXUSPANIC at %s.%d\n", 	\
			__FUNCTION__, __LINE__);			\
		exit(1);						\
	} while(0)

/* Ugh. for some reason, the V operation is defined as V_nexus
   in userspace. I'm not sure this is still necessary. */
#define V(sema) V_nexus(sema)

#endif

/** macros ****/

#define NETCOMP_PACKET_DESCNUM (1)
#define NETCOMP_PORT_NUM_INVALID (-1)

#define NETCOMP_TYPE_PLAIN (0x0)
#define NETCOMP_TYPE_NEXT_HOP (0x1)

/** structures ****/

typedef struct {
  unsigned char type;
  union {
    struct {
      uint32_t ip;
    } next_hop;
  } data;
} __attribute__((packed)) NetComp_Packet_Header;

typedef struct {
  dlist_head link;
  Call_Handle call_handle;
  int desc_num;
  struct TransferDesc data_desc; /* desc num 1 */
  int msg_data_len;
  char msg_data[0];
} NetComp_Packet;

typedef int NetComp_Port_Num;

/** functions ****/

void NetComp_init(void);

NetComp_Packet *NetComp_Packet_new(Call_Handle call_handle);
void NetComp_Packet_destroy(NetComp_Packet *pkt, int done);

int NetComp_IPC_from_buf(Connection_Handle conn_handle, char *data, int len);
int NetComp_IPC_from_skb(Connection_Handle conn_handle, struct sk_buff *skb);
#ifdef __NEXUSKERNEL__
int NetComp_IPC_from_ubuf(Connection_Handle conn_handle, Map *m, 
			  char *user_data, int len);
#endif

int NetComp_Packet_extract(NetComp_Packet *packet, int offset, void *dest, int len);
void NetComp_Packet_clean_header(NetComp_Packet *pkt);
void NetComp_Packet_set_nexthop(NetComp_Packet *pkt, unsigned int next_hop_ip);

int NetComp_Packet_handoff(NetComp_Packet *packet, Connection_Handle target);
int NetComp_Packet_handoff_copy(NetComp_Packet *packet, Connection_Handle target);
struct sk_buff *NetComp_Packet_to_skb(NetComp_Packet *pkt);
struct sk_buff *NetComp_Packet_to_skb_keep(NetComp_Packet *pkt);

int NetComp_Packet_get_len(NetComp_Packet *pkt);

#ifdef __NEXUSKERNEL__
int NetComp_Packet_extract_to_map(IPD *packet_ipd, NetComp_Packet *packet, 
				  int offset, Map *target_map, 
				  char *dest, int len);
struct IPD *create_netcomp_ipd(const char *name);
#else
struct IEvent_Call_Info;
int NetComp_get_default_ip_switch(void);
#endif // __NEXUSKERNEL__

/** static inline functions ****/

static inline NetComp_Packet_Header *
NetComp_Packet_get_header(NetComp_Packet *pkt) {
  return (NetComp_Packet_Header *) pkt->msg_data;
}

/** network defines ****/
/*  Replacement for header structs. Will eventually replace those in net.h 
    TODO: throw away one of the two */


#define ETH_ADDR_LEN (6)

typedef struct {
  unsigned char addr[ETH_ADDR_LEN];
}  __attribute__((packed)) MAC_Address;

typedef struct {
   uint32_t addr;
}  __attribute__((packed)) IP_Address;

#define IP_ADDRESS_ALL_BROADCAST (0xffffffff)
#define IP_ADDRESS_GENERIC_BROADCAST(IP,MASK) (((IP) & (MASK)) | ~(MASK))
#define MAC_ADDRESS_BROADCAST ((MAC_Address) { .addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }})
#define MAC_ADDRESS_NONE ((MAC_Address) { .addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }})

static inline int MAC_Address_eq(MAC_Address a0, MAC_Address a1) {
  return memcmp(a0.addr, a1.addr, ETH_ADDR_LEN) == 0;
}

static inline int MAC_Address_is_broadcast(MAC_Address a) {
  MAC_Address bcast = MAC_ADDRESS_BROADCAST;
  return MAC_Address_eq(a, bcast);
}

int MAC_Address_is_local(MAC_Address addr, int num_addrs, MAC_Address *local_addrs);
static inline MAC_Address MAC_Address_from_char(unsigned char *dat) {
  MAC_Address rv;
  memcpy(rv.addr, dat, sizeof(rv.addr));
  return rv;
}
void MAC_Address_print(MAC_Address addr);
static inline void MAC_Address_print_from_char(unsigned char *dat) {
  MAC_Address_print(MAC_Address_from_char(dat));
}

#define NET_OFFSET_OF(STRUCT,FIELD) ((int)(&((STRUCT *)0)->FIELD))
#define NET_SIZE_OF(STRUCT,FIELD) (sizeof(((STRUCT *)0)->FIELD))

typedef struct {
  unsigned char dst[ETH_ADDR_LEN];
  unsigned char src[ETH_ADDR_LEN];
  unsigned short protocol;
} __attribute__((packed)) Ethernet_Header;

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/

typedef struct {
  // xxx check endianness
  uint8_t	ihl:4,
    version:4;
  uint8_t	tos;
  uint16_t	tot_len;
  uint16_t	id;
  uint16_t	frag_off;
  uint8_t	ttl;
  uint8_t	protocol;
  uint16_t	check;
  uint32_t	saddr;
  uint32_t	daddr;
} __attribute__((packed)) IP_Header;

void IP_Address_print(uint32_t addr);

#define IP_ADDR_LEN (4)
#define IPADDR_BROADCAST (0xFFFFFFFF)

#endif // _NETCOMP_H_

