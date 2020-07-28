#ifndef BURST_H_SHIELD
#define BURST_H_SHIELD

#pragma pack(push, 1)

struct BGP_Header {
  char marker[16];
  unsigned short len;
  unsigned char type;
};

#define BGP_HEADER_SIZE 19

struct BGP_Open {
  unsigned char version;
  unsigned short asid;
  unsigned short holdtime;
  unsigned int bgpident;
  unsigned char optlen;
};

#define BGP_OPEN_SIZE 10

struct BGP_Update {
  unsigned short withdrawn_len;
  unsigned short attr_len;
  unsigned char origin_fl;
  unsigned char origin_type;
  unsigned char origin_len;
  unsigned char origin;
  unsigned char nexthop_fl;
  unsigned char nexthop_type;
  unsigned char nexthop_len;
  unsigned int nexthop;
  unsigned char path_fl;
  unsigned char path_type;
  unsigned char path_len;
  unsigned char path_segment;
  unsigned char path_segment_len;
};

#define BGP_UPDATE_SIZE 20

struct Advertisement {
  unsigned int prefix;
  unsigned char plen;
  unsigned int nexthop;
  int metric;
  int originflags;
  std::vector<unsigned short> path;
};

#pragma pack(pop)

#endif
