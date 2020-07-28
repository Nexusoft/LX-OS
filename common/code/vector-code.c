
// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

// vector of pointers
void PointerVector_init(PointerVector *target, int initial_size, int flags) {
  target->flags = flags;
  target->max_size = 0;
  target->count = 0;
  
  target->resize_ctx = NULL;
  target->resize_hook = NULL;
  target->data_buff = NULL;
  target->firstpage = NULL;
  
  PointerVector_resize(target, initial_size);
}

void PointerVector_dealloc(PointerVector *target) {
  int cnt = PointerVector_Size2PageCount(target->max_size);
  int x;
  if(target->firstpage){
#ifdef __NEXUSKERNEL__
    gfree(target->firstpage);
#else
    free(target->firstpage);
#endif
  }
  
  if(target->data_buff){
    for(x = 0; x < cnt; x++){
#ifdef __NEXUSKERNEL__
      gfree(target->data_buff[x]);
#else
      free(target->data_buff[x]);
#endif
    }
#ifdef __NEXUSKERNEL__
    gfree(target->data_buff);
#else
    free(target->data_buff);
#endif
  }
}
