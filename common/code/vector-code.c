
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
  int cnt;
  int x;

  if (target->firstpage) {
    nxcompat_free(target->firstpage);
    target->firstpage = NULL;
  }
  
  cnt = PointerVector_Size2PageCount(target->max_size);
  if (target->data_buff) {
    for(x = 0; x < cnt; x++)
      nxcompat_free(target->data_buff[x]);
    nxcompat_free(target->data_buff);
    target->data_buff = NULL;
  }
  
}

void PointerVector_resize(PointerVector *target, int new_size) {
  //printf("resizing: %d(%d) -> %d(%d)\n", target->max_size, PointerVector_Size2PageCount(target->max_size), new_size, PointerVector_Size2PageCount(new_size));
    
  if(new_size > POINTERVECTOR_ENTRIES_PER_PAGE){
    int new_pages = PointerVector_Size2PageCount(new_size);
    int old_pages= PointerVector_Size2PageCount(target->max_size);
    
    if(old_pages < new_pages){
      void ***tmp = (void ***)nxcompat_alloc(new_pages * sizeof(void **));
      if(target->max_size <= POINTERVECTOR_ENTRIES_PER_PAGE){
        tmp[0] = nxcompat_alloc(POINTERVECTOR_ENTRIES_PER_PAGE * sizeof(void *));
        if(target->flags & POINTERVECTOR_AUTO_ZERO) {
          memset(tmp[0], 0, POINTERVECTOR_ENTRIES_PER_PAGE * sizeof(void *));
        }
        if(target->firstpage){
          memcpy(tmp[0], target->firstpage, target->max_size * sizeof(void *));
          nxcompat_free(target->firstpage);
          target->firstpage = NULL;
        }
      } else {
        memcpy(tmp, target->data_buff, sizeof(void **) * old_pages);
      }
      
      for(; old_pages < new_pages; old_pages++){
        tmp[old_pages] = nxcompat_alloc(POINTERVECTOR_ENTRIES_PER_PAGE * sizeof(void *));
        if(target->flags & POINTERVECTOR_AUTO_ZERO) {
          memset(tmp[old_pages], 0, POINTERVECTOR_ENTRIES_PER_PAGE * sizeof(void *));
        }
      }
      
      if(target->data_buff)
        nxcompat_free(target->data_buff);
      target->data_buff = tmp;
    }
    
    if(target->max_size < new_size){
      target->max_size = new_size;
    } else {
      return;
    }
  } else { // if(new_size > POINTERVECTOR_ENTRIES_PER_PAGE)
    if(target->max_size > new_size) return;
    void **tmp = nxcompat_alloc(new_size * sizeof(void *));
    if(target->firstpage != NULL){
      memcpy(tmp, target->firstpage, sizeof(void *) * target->max_size);
      nxcompat_free(target->firstpage);
    }
    if(target->flags & POINTERVECTOR_AUTO_ZERO) {
      memset((&(tmp[target->max_size])), 0, sizeof(void *) * (new_size - target->max_size));
    }
    target->firstpage = tmp;
    target->max_size = new_size;
  }
  
  if(target->resize_hook != NULL) {
    target->resize_hook(target, new_size, target->resize_ctx);
  }
}

