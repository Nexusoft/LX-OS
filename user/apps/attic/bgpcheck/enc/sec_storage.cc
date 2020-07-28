#include <iostream>
#include <fcntl.h>
extern "C" {
#include <nexus/timing.h>
#include <nexus/policy.h>
#include "../include/enc/sec_storage.h"
}

Nexus_Secure_Storage::Nexus_Secure_Storage(char *fname, int _size) :
  store(NULL), buff(NULL), size(_size), eof(NULL), ptr(0)
{
  int fd = open(fname, O_RDWR);
  
  if(fd < 0){
    fd = open(fname, O_CREAT|O_WRONLY|O_TRUNC);
    if(fd < 0){
      return;
    }
    
    store = rw_wpss_create(fd, &buff, size+sizeof(int), fname, 
                           POLITE_REQUESTORS_ONLY, POLITE_REQUESTORS_ONLY, POLITE_REQUESTORS_ONLY,
                           PRETTY_PLEASE, WPSS_W, 500, 0);
    eof = (int *)buff;
    *eof = 0;
  } else {
    store = rw_wpss_retrieve(fd, fname, PRETTY_PLEASE, &buff, 0, size+sizeof(int));
  }
  
  eof = (int *)buff;
  buff += sizeof(int);
}
Nexus_Secure_Storage::~Nexus_Secure_Storage(){
  if(store){
    rw_wpss_free(store);
  }
}

int Nexus_Secure_Storage::read(void *data, int cnt){
  assert(store);
  assert(eof);
  if(ptr+cnt > *eof){
    cnt = (*eof)-ptr;
  }
  memcpy(data, buff+ptr, cnt);
  ptr+=cnt;
  
  return cnt;
}
void Nexus_Secure_Storage::write(void *data, int cnt){
  assert(store);
  assert(ptr+cnt < size);
  memcpy(buff+ptr, data, cnt);
  ptr+=cnt;
  assert(eof);
  *eof = ptr;
}
void Nexus_Secure_Storage::sync(){
  assert(store);
  rw_wpss_archive(store, PRETTY_PLEASE);
}
int Nexus_Secure_Storage::reset(){
  ptr = 0;
  return 0;
}
void Nexus_Secure_Storage::destroy(){
  assert(store);
  rw_wpss_destroy(store, PRETTY_PLEASE);
  store = NULL;
}

int Nexus_Secure_Storage::ateof(){
  return *eof == ptr;
}

int Nexus_Secure_Storage::valid(){
  return store != NULL;
}
