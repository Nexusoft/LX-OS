#ifndef LINUX
#error This is a copy of nexus/vector.h used for use on linux, and is not needed under nexus.
#endif

#ifndef _NEXUS_VECTOR_H_
#define _NEXUS_VECTOR_H_

#ifdef __KERNEL__
#include <nexus/defs.h>
#else
#include <stdint.h>
#include <assert.h>
#include <string.h>
#endif

typedef struct PointerVector {
  int order_preserving;
  int max_size;
  int count;
  void **data;
} PointerVector;

static inline void PointerVector_setOrderPreserving(PointerVector *target,
		int order_preserving) {
	target->order_preserving = order_preserving;
}

static inline int PointerVector_len(PointerVector *target) {
  return target->count;
}
static inline void *PointerVector_nth(PointerVector *target, int n) {
  return target->data[n];
}

static inline void PointerVector_resize(PointerVector *target, int new_size) {
    // xxx should be a realloc, but it doesn't exist in the kernel
  assert(new_size > target->max_size);
#ifdef __KERNEL__
  void **tmp = galloc(new_size * sizeof(void *));
#else
  void **tmp = malloc(new_size * sizeof(void *));
#endif
  memcpy(tmp, target->data, target->max_size * sizeof(void *));
#ifdef __KERNEL__
  gfree(target->data);
#else
  free(target->data);
#endif
  
  target->data = tmp;
  target->max_size = new_size;
}

static inline void PointerVector_append(PointerVector *target, void *value) {
  if(target->count == target->max_size) {
    int new_size= target->max_size * 2;
    PointerVector_resize(target, new_size);
  }
  target->data[target->count++] = value;
}

static inline void PointerVector_append(PointerVector *target, void *value) {
  if(target->count == target->max_size) {
    int new_size= target->max_size * 2;
    PointerVector_resize(target, new_size);
  }
  target->data[target->count++] = value;
}

static inline void PointerVector_insertAt(PointerVector *target, void *value, int i) {
	int j;
  if(target->count == target->max_size) {
    int new_size= target->max_size * 2;
    PointerVector_resize(target, new_size);
  }
  for (j = target->count; j > i; j--)
		target->data[j] = target->data[j-1];
  target->data[i] = value;
	target->count++;
}

static inline void * PointerVector_deleteAt(PointerVector *target, int n) {
  void *elem = target->data[n];
  if(target->order_preserving) {
    int i;
    for(i=n+1; i < target->count; i++) {
      target->data[i - 1] = target->data[i];
    }
  } else {
    target->data[n] = target->data[target->count - 1];
  }
  target->count--;
  return elem;
}


static inline void PointerVector_init(PointerVector *target, int initial_size, int order_preserving) {
  target->order_preserving = order_preserving;
  target->max_size = initial_size;
  target->count = 0;
  target->data = malloc(sizeof(void*) * target->max_size);
}

static inline void PointerVector_dealloc(PointerVector *target) {
  free(target->data);
}



#endif
