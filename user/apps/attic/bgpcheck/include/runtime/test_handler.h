#ifndef TEST_HANDLER_H_SHIELD
#define TEST_HANDLER_H_SHIELD

#include "../runtime/runtime.h"
#include "../nbgp/bgpcheck.h"

class Test_Handler : public Runtime_Handler {
public: 
  Test_Handler(BC_Checker *checker_l, Minipipe *pipe_l, int waittime);
  ~Test_Handler();

  virtual int handle_periodic(Runtime *runtime);

private:
  BC_Checker *checker;
  Minipipe *pipe;
  int timeout;
};

#endif
