extern "C" {
  #include <nexus/sema.h>
}
#include "../include/util/nexussync.h"

Semaphore::Semaphore(int count){
  sema = sema_new();
  sema_initialize((Sema *)sema, count);
}
Semaphore::~Semaphore(){
  sema_destroy((Sema *)sema);
}

void Semaphore::up(){
  V_nexus((Sema *)sema);
}
void Semaphore::down(){
  P((Sema *)sema);
}
