#ifndef SEC_STORAGE_H_SHIELD
#define SEC_STORAGE_H_SHIELD

extern "C" {
#include "apps/wpss/rwpss.h"
}

class Nexus_Secure_Storage {
 public:
  Nexus_Secure_Storage(char *fname, int size);
  ~Nexus_Secure_Storage();
  
  int read(void *data, int cnt);
  void write(void *data, int cnt);
  void sync();
  int reset();
  void destroy();
  
  int ateof();
  int valid();
  
 private:
  WPSS *store;
  unsigned char *buff;
  int size;
  int *eof;
  int ptr;
};

#endif
