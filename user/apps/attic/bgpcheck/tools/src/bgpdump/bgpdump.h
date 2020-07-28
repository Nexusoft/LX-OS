#ifndef BGPDUMP_H_SHIELD
#define BGPDUMP_H_SHIELD

struct Endpoint {
	in_addr addr;
	unsigned short port;
};

struct Flow {
	Endpoint from, to;
	bool operator< (const Flow &other) const {
		return memcmp(this, &other, sizeof(*this)) < 0;
	}
};

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


struct BGP_Update_Announce {
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
  
  unsigned char community_fl;
  unsigned char community_type;
  unsigned char community_len;
  unsigned int community;
  
  unsigned char path_fl;
  unsigned char path_type;
  unsigned char path_len;
  unsigned char path_segment;
  unsigned char path_segment_len;
};


#define BGP_UPDATE_SIZE 27

struct Advertisement {
  unsigned int prefix;
  unsigned char plen;
  unsigned int nexthop;
  unsigned int destination;
  int metric;
  int originflags;
  std::vector<unsigned short> path;
  int type;
  unsigned int community;
  int time;
  Advertisement() { path.reserve(20); }
};

#pragma pack(pop)

#define ad_list std::vector<Advertisement>
#define ad_db std::map<unsigned int, ad_list *>
#endif
