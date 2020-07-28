#ifndef _FIB_UPDATE_PROTOCOL_HH_
#define _FIB_UPDATE_PROTOCOL_HH_

#include <vector>
#include <string>
#include <iostream>
#include <nq/netquery.h>
#include <nq/attribute.hh>
#include <nq/net_elements.hh>

struct Interface;

struct ForwardingEntry {
  int32_t ip_prefix_len;
  uint32_t ip_prefix;
  Interface *interface;

  static inline uint32_t prefix_mask(int prefix_len) {
    return (0xffffffff << (32 - prefix_len));
  }

  ForwardingEntry() {
    ip_prefix_len = 0;
    ip_prefix = 0;
    interface = NULL;
  }
  ForwardingEntry(int32_t plen, uint32_t p, Interface *i) :
    ip_prefix_len(plen), interface(i)
  {
    if(ip_prefix_len > 32) {
      throw "Invalid prefix len";
    } else {
      ip_prefix = p & prefix_mask(ip_prefix_len);
    }
  }

private:
  unsigned long long as_64() const{
    return (((unsigned long long )ip_prefix) << 32) |
      (((unsigned long long )ip_prefix_len));
  }
public:
  bool operator<(const ForwardingEntry &f) const {
#if 0
    if(ip_prefix == f.ip_prefix) {
      // std::cerr << "multicast forwarding tables not supported!\n";
    }
    return ip_prefix < f.ip_prefix;
#else
    return as_64() < f.as_64();
#endif
  }

  bool operator==(const ForwardingEntry &f) const {
    return 
      ip_prefix_len == f.ip_prefix_len &&
      ip_prefix == f.ip_prefix &&
      interface == f.interface;
  }

  bool match(uint32_t ip) const {
    return (ip & prefix_mask(ip_prefix_len)) == ip_prefix;
  }
};

struct ForwardingTable : std::vector<ForwardingEntry> {
  Interface *lookup(uint32_t ip) {
    int match_len = 0;
    ForwardingEntry *e = NULL;
    for(iterator i = this->begin(); i != this->end(); i++) {
      if(i->match(ip) && match_len < i->ip_prefix_len) {
	match_len = i->ip_prefix_len;
	e = &*i;
      }
    }
    if(e == NULL) {
      return NULL;
    } else {
      return e->interface;
    }
  }
};
typedef struct ForwardingTable FIBUpdates;

struct SimRouter;

struct Interface {
  SimRouter &owner;
  int if_num;
  Interface *peer_interface;

  // Keep track of the intended peer for this interface
  int peer_router_id;

  ExtRef<T_Interface> tspace_interface;

  Interface(SimRouter &o, int num, int p_id);
  ~Interface() { }

  T_Interface *tspace_get();
};

enum FIBUpdate_MsgType {
  LOADSPEC, UPDATEFIB, COMMITALL,
};

// protocol: int type, packet

struct FIBUpdate_Request {
  FIBUpdate_MsgType type;
  int seqnum;
  FIBUpdate_Request(FIBUpdate_MsgType t, int seq) : type(t), seqnum(seq) { }
  FIBUpdate_Request() { } // nop

};
struct LoadSpec {
  char topo_fname[128];
  // char pop_fname[128];
};

struct FIBUpdateTID {
  struct ForwardingEntry entry;
  NQ_Tuple tid;
  FIBUpdateTID() { /* leave uninitialized */ }
  FIBUpdateTID(const struct ForwardingEntry *ent);
};

struct UpdateSpec {
  int router_id;
  int num_adds;
  int num_dels;
  // [+ {ForwardingEntry, TID}]
  // [- {ForwardingEntry, TID} ]
};

struct FIBUpdate_Result {
  int seqnum;
  int result;
};

// result is always a int length byte

//int FIBUpdate_listen(const std::string &sock_location);
int FIBUpdate_init_sock(const std::string &sock_location);
int FIBUpdate_connect(const std::string &sock_location);
//int FIBUpdate_start_server_thread(const std::string &sock_location);

int FIBUpdate_recv_all(int s, void *dest, int len, bool block = true);
int FIBUpdate_respond(int sock, int result, int seqnum);

int FIBUpdate_issue_LoadSpec(const std::string &topo_fname);
int FIBUpdate_issue_Update(int router_id, const FIBUpdates &additions, const FIBUpdates &deletions, bool wait);

int FIBUpdate_issue_CommitAll(void);

extern int fib_sock;

#endif
