#ifndef GRASSROOTS_UTIL_H_SHIELD
#define GRASSROOTS_UTIL_H_SHIELD

#include "../../../include/nbgp/grassroots.h"

struct Prefix {
  unsigned int prefix;
  int prefixlen;
  bool operator<(const Prefix &y) const {
    if(y.prefix == prefix){
      if(y.prefixlen == prefixlen){
        return 0;
      } else {
        return prefixlen < y.prefixlen;
      }
    } else {
      return prefix < y.prefix;
    }
  }
  int getbit(int depth){
    assert(prefixlen  <= 32);
    if(depth >= prefixlen){
//      printf("depth reached: %d/%d\n", depth, prefixlen);
      return -1;
    } else {
//      printf("At depth %d\n", depth);
    }
    return (ntohl(prefix) >> (31 - depth)) & 0x01;
  }
};
typedef unsigned int AS;
struct ASInfo {
  std::vector<Prefix> properties;
  Grassroots::KEY *key;
};

extern std::map<AS,ASInfo> as_claims;

struct PrefixTrie {
  PrefixTrie(){
    parent = next[0] = next[1] = NULL;
    addr = 0;
    depth = 0;
  }
  ~PrefixTrie(){
    if(next[0]){ delete next[0]; }
    if(next[1]){ delete next[1]; }
  }
  
  PrefixTrie *next[2];
  PrefixTrie *parent;
  std::vector<AS> owners;
  std::vector<Grassroots::Delegation *> credentials;
  std::vector<Grassroots::RawData *> enc_credentials;
  Grassroots::IP_ADDR addr;
  Grassroots::IP_MASKLEN depth;
  
  void put(Prefix &p, AS &owner) 
    { put(p, owner, 0, NULL); }
  void put(Prefix &p, AS &owner, Grassroots::RawData *enc_cred) 
    { put(p, owner, 0, enc_cred); }
    
  PrefixTrie *get(Prefix &p) 
    { return get(p, 0); }
  
  Grassroots::RawData *get_enc_cred(AS source);
    
  void buildCredentialTree(Grassroots *grassroots_db)
    { buildCredentialTree(NULL, NULL, grassroots_db); }
  
  void exportCredentialTree(FILE *f, Grassroots *grassroots_db);

 private:
  PrefixTrie(PrefixTrie *_parent, int bit){
    next[0] = next[1] = NULL;
    parent = _parent;
    depth = parent->depth+1;
    addr = (bit << (32-depth)) | parent->addr;
  }
  void put(Prefix &p, AS &owner, int depth, Grassroots::RawData *enc_cred);
  PrefixTrie *get(Prefix &p, int depth);
  void buildCredentialTree(Grassroots::Delegation *parent_creds, Grassroots::KEY *owner, Grassroots *grassroots_db);
};

PrefixTrie *load_prefix_trie(FILE *f);

#endif

