#include <iostream>
#include "../include/runtime/test_handler.h"

Test_Handler::Test_Handler(BC_Checker *checker_l, Minipipe *pipe_l, int waittime) : 
  Runtime_Handler(waittime, NULL) 
{ 
  checker = checker_l; 
  pipe = pipe_l; 
  timeout = waittime;

#ifdef TEST_HANDLER_PROFILE  
  Profile_Enable(1);
#endif
}

Test_Handler::~Test_Handler() {};

int Test_Handler::handle_periodic(Runtime *runtime) {
#ifdef TEST_HANDLER_PROFILE  
  char *data = (char *)malloc(16000000);
  int len;
#endif
  
  printf("DEBUG: %ds into test\n", timeout);
  //printf("DEBUG: Database size: %d bytes\n", checker->calculate_size());
  printf("DEBUG: Max buffer size: %d bytes\n", pipe->get_maxsize());
  
#ifdef TEST_HANDLER_PROFILE  
  Profile_Enable(0);
  len = Profile_ReadSamples((unsigned int *)data);
  
  printf("DEBUG: Dumping profiler data (%d bytes)\n", len);
  
//  assert((f = open("nbgp-profile.dat", O_WRONLY|O_CREAT, 0)) >= 0);
//  assert(write(f, data, len) >= 0);
//  assert(close(f) >= 0);
  writefile("nbgp-profile.dat", data, len);
  
  printf("DEBUG:Done writing\n");
#endif
  
//  return SIZECHECK_WAITTIME * 1000;
  return 0;
}
