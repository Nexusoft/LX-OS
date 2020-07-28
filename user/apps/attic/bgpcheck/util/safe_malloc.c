#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "../include/util/safe_malloc.h"
#include <assert.h>

static int safely_malloced = 0;

void *safe_malloc(size_t size){
  void *ret;

  // strictly speaking, not a bug... but is there a reason we need to alloc this much
  assert(size < 30*1024*1024); 

  safely_malloced ++;

//  assert(safely_malloced < 10000);

  ret = malloc(size);
  return ret;
}

void safe_free(void *val){
  safely_malloced --;
  free(val);
}
