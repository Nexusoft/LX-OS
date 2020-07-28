#include <iostream>
#include <ext/hash_map>
#include <assert.h>
#include <arpa/inet.h>

extern "C" {
#include "../../../include/nbgp/bgp.h"
}

typedef unsigned char	u_char;
typedef unsigned int	u_int;
typedef unsigned short	u_short;
typedef unsigned long	u_long;

//yoinked these enums and the msg_hdr struct from MRTd's io.h
enum MRT_MSG_TYPES {
   MSG_NULL,
   MSG_START,			/* sender is starting up */
   MSG_DIE,			/* receiver should shut down */
   MSG_I_AM_DEAD,		/* sender is shutting down */
   MSG_PEER_DOWN,		/* sender's peer is down */
   MSG_PROTOCOL_BGP,		/* msg is a BGP packet */
   MSG_PROTOCOL_RIP,		/* msg is a RIP packet */
   MSG_PROTOCOL_IDRP,		/* msg is an IDRP packet */
   MSG_PROTOCOL_RIPNG,		/* msg is a RIPNG packet */
   MSG_PROTOCOL_BGP4PLUS,	/* msg is a BGP4+ packet */
   MSG_PROTOCOL_BGP4PLUS_01,	/* msg is a BGP4+ (draft 01) packet */
   MSG_PROTOCOL_OSPF,		/* msg is an OSPF packet */
   MSG_TABLE_DUMP		/* routing table dump */
};

enum MRT_MSG_BGP_TYPES {
   MSG_BGP_NULL,
   MSG_BGP_UPDATE,	/* raw update packet (contains both with and ann) */
   MSG_BGP_PREF_UPDATE, /* tlv preferences followed by raw update */
   MSG_BGP_STATE_CHANGE,/* state change */
   MSG_BGP_SYNC,	/* sync point with dump */
   MSG_BGP_OPEN,
   MSG_BGP_NOTIFY,
   MSG_BGP_KEEPALIVE
};

#pragma pack(push, 1)
struct mrt_msg_hdr {
   u_int tstamp;		/* timestamp */
   u_short type;		/* msg type, one of MRT_MSG_TYPES */
   u_short subtype;		/* msg subtype, protocol-specific */
   u_int length;		/* length of data */
};

//this one's mine
struct bgp_msg_hdr {
  u_char marker[16];
  u_short length;
  u_char type;
};

struct mrt_dump_hdr {
  unsigned short view;
  unsigned short seq_no;
  unsigned int addr;
  unsigned char mask;
  unsigned char status;
  unsigned int originated;
  unsigned int peer_ip;
  unsigned short peer_as;
  unsigned short attrlen;
};

#pragma pack(pop)

int RIB_ENTRY_ENCODINGS = 0;

struct RIB_Entry {
  unsigned int addr;
  unsigned char mask;
  
  RIB_Entry(unsigned int _addr, unsigned char _mask) : addr(ntohl(_addr)), mask(_mask) {assert(mask <= 32);}
  
  int bgp_len(){
    return 1 + (mask + 7)/8;
  }
  void encode_bgp(FILE *f){
    int i;
    unsigned char c;
    RIB_ENTRY_ENCODINGS++;
    assert(fwrite(&mask, sizeof(char), 1, f) == 1);
    for(i = 0; i < (mask + 7)/8; i++){
      c = (addr >> ((3-i)*8)) & 0xff;
      assert(fwrite(&c, sizeof(char), 1, f) == 1);
    }
  }
};

int MRT_MAX_SIZE = 0;

struct RIB_AddrSet {
  std::vector<RIB_Entry> entries;
  struct Attrs {
    int len;
    char *data;
  };
  Attrs attrs;
  unsigned int peer;
  
  RIB_AddrSet(Attrs _attrs, unsigned int _peer) : entries(), attrs(_attrs), peer(_peer) {}
  
  int entry_size(unsigned int start, unsigned int stop){
    unsigned int tot = 0, i;
    std::vector<RIB_Entry>::iterator entry;
    for(entry = entries.begin(), i = 0; (entry != entries.end())&&(i < stop); entry++, i++){
      if((i >= start)&&(i < stop)){
        tot += entry->bgp_len();
      }
    }
    return tot;
  }
  
  void encode_body(FILE *f, unsigned int start, unsigned int stop){
    unsigned short tmp = 0, i;
    std::vector<RIB_Entry>::iterator entry;
    assert(fwrite(&tmp, sizeof(unsigned short), 1, f) == 1);
    tmp = htons(attrs.len);
    assert(fwrite(&tmp, sizeof(unsigned short), 1, f) == 1);
    assert(fwrite(attrs.data, sizeof(char), attrs.len, f) == (unsigned int)attrs.len);
    for(entry = entries.begin(), i = 0; (entry != entries.end())&&(i < stop); entry++, i++){
      if((i >= start)&&(i < stop)){
        entry->encode_bgp(f);
      }
    }
  }
  
#define PREFIXES_PER_MSG 500

  void encode_mrt(FILE *f){ 
    unsigned int set;
    //XXX this is a hacked version of the MRT format.  
    //I'm including a copy of the IP address the "packet" is bound for
    mrt_msg_hdr header;
    header.tstamp = 0;
    header.type = htons(MSG_PROTOCOL_BGP);
    header.subtype = htons(MSG_BGP_UPDATE);
    for(set = 0; set < entries.size(); set += PREFIXES_PER_MSG){
      header.length = htonl(mrt_len(set, set+PREFIXES_PER_MSG));
      assert(fwrite(&header, sizeof(mrt_msg_hdr), 1, f) == 1);
      assert(fwrite(&peer, sizeof(unsigned int), 1, f) == 1);
      encode_body(f, set, set+PREFIXES_PER_MSG);
    }
  }
  
  void encode_bgp(FILE *f){
    unsigned int set;
    int i; unsigned char c = 0xff; unsigned short len;
    
    for(set = 0; set < entries.size(); set += PREFIXES_PER_MSG){
      for(i = 0; i < 16; i++){
        assert(fwrite(&c, sizeof(char), 1, f) == 1);
      }
      len = htons(bgp_len(set, set+PREFIXES_PER_MSG));
      fwrite(&len, sizeof(short), 1, f);
      c = 2;
      fwrite(&c, sizeof(char), 1, f);
      encode_body(f, set, set+PREFIXES_PER_MSG);
    }
  }

  int bgp_len(int start, int stop){
    return sizeof(bgp_msg_hdr) + attrs.len + 4 + entry_size(start, stop);
  }
  int mrt_len(int start, int stop){
    int ret = 4 + attrs.len + 4 + entry_size(start, stop);
    if(ret > MRT_MAX_SIZE){ MRT_MAX_SIZE = ret; }
    return ret;
  }
  
  struct HASH {
    size_t operator()(const RIB_AddrSet::Attrs &a) const {
      size_t ret = 0;
      int i;
      for(i = 0; i < a.len; i++){
        ret = a.data[i] ^ ((ret << 1) | ((ret >> 31) & 0x01));
      }
      return ret;
    }
  };
  struct EQUALS {
    int operator()(const RIB_AddrSet::Attrs &a, const RIB_AddrSet::Attrs & b) const {
      return (a.len == b.len) && (memcmp(a.data, b.data, a.len) == 0);
    }
  };
};



typedef __gnu_cxx::hash_map<RIB_AddrSet::Attrs,
                      RIB_AddrSet *,
                      RIB_AddrSet::HASH,
                      RIB_AddrSet::EQUALS> RIB;

RIB bgp_rib;
int entries = 0;

void create_rib_entry(unsigned int addr, unsigned char mask, unsigned int peer, char *attr, int attrlen){
  RIB_AddrSet *entry;
  RIB_AddrSet::Attrs attrs = {attrlen, attr};
  RIB::iterator old_entry;
  
  old_entry = bgp_rib.find(attrs);
  if(old_entry != bgp_rib.end()){
    old_entry->second->entries.push_back(RIB_Entry(addr, mask));
    delete attr;
  } else {
    entry = new RIB_AddrSet(attrs, peer);
    bgp_rib[entry->attrs] = entry;
    entry->entries.push_back(RIB_Entry(addr, mask));
    entries ++;
  }
}

int mrt_load_dump(mrt_msg_hdr *msg_header, FILE *f, int direction){
  mrt_dump_hdr header;
  char *attrs;
  
  if(fread(&header, sizeof(mrt_dump_hdr), 1, f) < 1){
    return 0;
  }
  
  header.attrlen = ntohs(header.attrlen);
  
  assert(msg_header->length == sizeof(mrt_dump_hdr) + header.attrlen);
  
  attrs = new char[header.attrlen];
  if(fread(attrs, sizeof(char), header.attrlen, f) < header.attrlen){
    delete attrs;
    assert(0);
    return 0;
  }
  
  create_rib_entry(header.addr, header.mask, header.peer_ip, attrs, header.attrlen); //takes control of attrs
  
  return 1;
}

void mrt_reader(FILE *f){
  mrt_msg_hdr msg_header;
  int abort = 0;
  int tot = 0;
  
  while((!feof(f)) && (!abort)){
    if(fread(&msg_header, sizeof(mrt_msg_hdr), 1, f) < 1){
      break;
    }
    //printf("Reading {%8x, %d:%d, %d bytes} (%d)\n", (unsigned int)msg_header.tstamp, msg_header.type, msg_header.subtype, msg_header.length, (int)sizeof(mrt_msg_hdr));
    msg_header.tstamp = ntohl(msg_header.tstamp);
    msg_header.type = ntohs(msg_header.type);
    msg_header.subtype = ntohs(msg_header.subtype);
    msg_header.length = ntohl(msg_header.length);
    
    tot++;
    if(tot % 100000 == 0){
      printf("%d complete (%d unique entries)\n", tot, entries);
    }
    //printf("Reading {%8x, %d:%d, %d bytes}\n", (unsigned int)msg_header.tstamp, msg_header.type, msg_header.subtype, msg_header.length);
    switch(msg_header.type){
      case MSG_NULL:
        //discard;
        while(msg_header.length > 0){
          fgetc(f);
          msg_header.length--;
        }
        break;
      case MSG_TABLE_DUMP:
        switch(msg_header.subtype){
          case 1: //IPV4
            if(!mrt_load_dump(&msg_header, f, 0)) abort = 1;
            break;
          case 2: //IPV6
          default: 
            printf("Error: can't understand {%8x, %d:%d, %d bytes}\n", (unsigned int)msg_header.tstamp, msg_header.type, msg_header.subtype, msg_header.length);
            assert(0);
        }
        break;
      case MSG_PROTOCOL_BGP:
        switch(msg_header.subtype){
          case MSG_BGP_UPDATE:
            default:
            printf("Error: can't understand {%8x, %d:%d, %d bytes}\n", (unsigned int)msg_header.tstamp, msg_header.type, msg_header.subtype, msg_header.length);
            assert(0);
        }
        break;
      default:
        printf("Error: can't understand {%8x, %d:%d, %d bytes}\n", (unsigned int)msg_header.tstamp, msg_header.type, msg_header.subtype, msg_header.length);
        assert(0);
    }
  }
}

void mrt_writer(FILE *f){
  RIB::iterator i;
  int tot = 0;
  
  for(i = bgp_rib.begin(); i != bgp_rib.end(); ++i){
    tot++;
    if(tot % 10000 == 0){
      printf("%d written (%d prefixes; max packet size: %ld)\n", tot, RIB_ENTRY_ENCODINGS, (long)(MRT_MAX_SIZE + sizeof(mrt_msg_hdr)));
    }
    i->second->encode_mrt(f);
  }
}

int main(int argc, char **argv){
  FILE *fin, *fout = NULL;
  assert(argc >= 1);
  fin = fopen(argv[1], "r");
  if(argc >= 2){
    fout = fopen(argv[2], "w");
  }
  if(fin){
    mrt_reader(fin);
  }
  if(fout){
    mrt_writer(fout);
  }
  return 0;
}
