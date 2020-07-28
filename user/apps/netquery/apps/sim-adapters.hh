#include <iostream>

#include "eventqueue.hh"

template<class I, class J >
struct ChainWrapper {
  I a;
  J b;
  ChainWrapper(const I &_a, const J &_b) : a(_a), b(_b) { }
  void fail(ostream &os, double curr_time) {
    a.fail(os, curr_time);
    b.fail(os, curr_time);
  }
  void set_router(SimRouter *r) {
    a.set_router(r);
    b.set_router(r);
  }
#if 0
  // This one is more general, but the one below restricts grouping to
  // less complex variants
  bool operator() (std::ostream &os, double curr_time) {
    if(a(os, curr_time)) {
      return b(os, curr_time);
    } else {
      b.fail(os, curr_time);
      return false;
    }
  }
#endif
  void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
    if(a(os, event_entry)) {
      b(os, event_entry);
    } else {
      b.fail(os, event_entry.curr_time);
    }
  }
};

struct NullWrapper {
  void fail(std::ostream &os, double curr_time) { /* do nothing */ }
  void set_router(SimRouter *r) { /* do nothing */  }
  bool operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
    return true;
  }
};

struct CheckIPWrapper : NullWrapper {
  uint32_t ip_loc;
  uint32_t event_ip; // set dynamically
  CheckIPWrapper(uint32_t loc) : 
    ip_loc(loc) { }

  void set_router(SimRouter *r);

  bool operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
    if(event_ip == ip_loc) {
      // os << "CheckIPSuccess(=>" << event_ip << ")";
      return true;
    } else {
      os << "CheckIPFail()";
      std::cerr << "CheckIP wrapper: wrong ip address! " << event_ip << " " << ip_loc << "\n";
      return false;
    }
  }
};

struct ReliableStreamWrapper : NullWrapper {
  size_t msg_size;
  ReliableStreamWrapper(size_t sz) : msg_size(sz) { }
  bool operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
    os << "Reliable(size=" << msg_size << ") ";
    return true;
  }
};

template<class I, class J>
ChainWrapper<I,J> Chain(const I &_a, const J &_b) {
  return ChainWrapper<I,J>(_a,_b);
}

template <class T>
ChainWrapper<ReliableStreamWrapper, T> ReliableStream(const T &c) {
  return Chain(ReliableStreamWrapper(c.size()), c);
}

template <class T>
ChainWrapper<CheckIPWrapper, T> CheckIP(uint32_t ip_loc, const T &c) {
  return Chain(CheckIPWrapper(ip_loc), c);
}

