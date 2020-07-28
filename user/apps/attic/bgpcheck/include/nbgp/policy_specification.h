#ifndef POLICY_SPEC_H_SHIELD
#define POLICY_SPEC_H_SHIELD

#include <vector>

#include "../nbgp/bgpcheck.h"

struct Policy_Question {
    bc_adverts::iterator incoming;
    bgp_packet *outgoing;

    unsigned int prefix;
    unsigned short p_len;
    
    unsigned int dest_ip;
    unsigned short dest_as;
};

class Policy_Specification {
 public:
  Policy_Specification();
  virtual ~Policy_Specification();
  
  virtual short ask(Policy_Question *q);
  
 private:
};

class Policy_Grouping {
 public:
  Policy_Grouping();
  ~Policy_Grouping();
  
  void add(Policy_Specification *spec);  
  short ask(Policy_Question *q);
  
 private:
  std::vector<Policy_Specification *> specs;
};

#endif
