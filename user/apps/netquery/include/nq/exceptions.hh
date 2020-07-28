#ifndef _NQ_EXCEPTIONS_H_
#define _NQ_EXCEPTIONS_H_
#include <string>
#include <sstream>
#include <nq/netquery.h>

/////////////////////////////
/// NetQuery exceptions
/////////////////////////////

struct NQ_Exception {
  std::string msg;
  inline NQ_Exception(const std::string &m = "Empty message") : 
    msg(m) { }
};

std::ostream &operator<<(std::ostream &os, const NQ_Exception &e);

struct NQ_Transaction_Exception : NQ_Exception {
  NQ_Transaction transaction_id;
  inline NQ_Transaction_Exception(const NQ_Transaction &t, const std::string &m = "") : 
    transaction_id(t) {
    std::stringstream msg_buf("");
    msg_buf << "Transaction Exception " << t << "\"" << m << "\"\n";
    msg = msg_buf.str();
    std::cerr << "Looping because of transaction exception\n";
    while(1) sleep(10);
  }
};

struct NQ_CommitFailed_Exception : NQ_Transaction_Exception {
  inline NQ_CommitFailed_Exception(const NQ_Transaction &t, const std::string &m = "") : 
    NQ_Transaction_Exception(t, m) { }
};

struct NQ_AbortFailed_Exception : NQ_Transaction_Exception {
  inline NQ_AbortFailed_Exception(const NQ_Transaction &t, const std::string &m = "") : 
    NQ_Transaction_Exception(t, m) { }
};

struct NQ_Unimplemented_Exception : NQ_Exception {
  inline NQ_Unimplemented_Exception(const std::string &s) : NQ_Exception(s) { }
};

#ifdef __NEXUS__
extern "C" { void breakpoint(void); }
#endif
struct NQ_Access_Exception : NQ_Exception {
  inline NQ_Access_Exception(const std::string &s) : NQ_Exception(s) { 
  }
};

struct NQ_API_Exception : NQ_Exception {
  inline NQ_API_Exception(const std::string &s) : NQ_Exception(s) { }
};

struct NQ_Schema_Exception : NQ_Exception {
  inline NQ_Schema_Exception(const std::string &s) : NQ_Exception(s) { }
};

struct NQ_Trust_Exception : NQ_Exception {
  inline NQ_Trust_Exception(const std::string &s) : NQ_Exception(s) { 
  }
};

#endif // _NQ_EXCEPTIONS_H_
