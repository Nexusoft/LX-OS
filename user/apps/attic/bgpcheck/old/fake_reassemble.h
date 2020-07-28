#ifndef FAKE_REASSEMBLE_H_SHIELD
#define FAKE_REASSEMBLE_H_SHIELD

#include "runtime.h"

class Reassemble_Faker : public Runtime_Handler {
 public:
  Reassemble_Faker(Minipipe *pipe, unsigned int src_ip, int src_port);

  void handle_minipipe(Minipipe *pipe, Runtime *runtime);
  void handle_sockready(Minisocket *sock, Runtime *runtime);

 private:
  Minipipe *outpipe;
  unsigned int ip;
  unsigned short port;
};

#endif
