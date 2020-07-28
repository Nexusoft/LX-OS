#ifndef NQ_GC_MALLOC_H_SHIELD
#define NQ_GC_MALLOC_H_SHIELD

#ifdef __NEXUS__
#define NO_GC_MALLOC
#endif

#ifndef NO_GC_MALLOC
#include <gc/gc.h>
#endif

#ifdef __cplusplus
#if 0
void* operator new(size_t n) {
  extern int new_count;
  new_count += n;
  void *rv = malloc(n + sizeof(int));
  *(int *)rv = n;
  return (char *)rv + sizeof(int);
}

void operator delete(void* p) {
  extern int delete_count;
  delete_count += *(int*)((char *)p - sizeof(int));
  free((char *)p - sizeof(int));
}
#endif

static void print_alloc_count(void) {
  extern int new_count;
  extern int delete_count;
  extern int malloc_count;
  extern int free_count;
  printf("new = %d, delete = %d, delta = %d\nmalloc = %d, free = %d, delta = %d\n", new_count, delete_count, new_count - delete_count,
         malloc_count, free_count, malloc_count - free_count);
}
#endif

#endif
