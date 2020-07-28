#ifndef _PACKET_ENTRY_H_
#define _PACKET_ENTRY_H_

#include <linux/netfilter.h>
#include <libipq.h>

struct PacketEntry {
  ipq_packet_msg_t ipq_info;
  int actual_len;
  unsigned int ip_src, ip_dst;
  unsigned short ip_id;
  unsigned short tcp_hash;
} __attribute__ ((packed));

#endif  //  _PACKET_ENTRY_H_
