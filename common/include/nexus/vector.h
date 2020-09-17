/** NexusOS: a resizable array of pointers */

#ifndef _NEXUS_VECTOR_H_
#define _NEXUS_VECTOR_H_

#include <nexus/defs.h>
#ifdef __NEXUSKERNEL__
#include <linux/stddef.h>
#else
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#endif

//we can technically fit 1024/page, but let's give malloc some space for its own stuff.
// - Oliver
#define POINTERVECTOR_ENTRIES_PER_PAGE 950
#define POINTERVECTOR_ORDER_PRESERVING (0x1)
#define POINTERVECTOR_AUTO_ZERO (0x2)

#define PointerVector_Size2PageCount(size) (((size) + POINTERVECTOR_ENTRIES_PER_PAGE - 1) / POINTERVECTOR_ENTRIES_PER_PAGE)
#define PointerVector_Entry2Page(entry) ((entry) / POINTERVECTOR_ENTRIES_PER_PAGE)

struct PointerVector;
typedef void (*PointerVectorResize)(struct PointerVector *vector, int new_size, void *ctx);

struct PointerVector {
  int flags;

  int max_size;
  int count;
  void ***data_buff;
  void **firstpage;

  PointerVectorResize resize_hook;
  void *resize_ctx;
};

typedef struct PointerVector PointerVector;

void PointerVector_init(PointerVector *target, int initial_size, int flags);

static inline void 
PointerVector_setOrderPreserving(PointerVector *target, int order_preserving) 
{
  if (order_preserving)
    target->flags |= POINTERVECTOR_ORDER_PRESERVING;
  else
    target->flags &= ~POINTERVECTOR_ORDER_PRESERVING;
}

static inline void 
PointerVector_setResizeHook(PointerVector *target, 
			    PointerVectorResize resize_hook, void *resize_ctx) 
{
  target->resize_hook = resize_hook;
  target->resize_ctx = resize_ctx;
}

void PointerVector_dealloc(PointerVector *target);

static inline void 
PointerVector_truncate(PointerVector *target) 
{
  target->count = 0;
}

static inline int 
PointerVector_len(PointerVector *target) 
{
  return target->count;
}

static inline int 
PointerVector_size(PointerVector *target) 
{
  return target->max_size;
}

static inline void *PointerVector_nth(PointerVector *target, int n) {
  if(target->firstpage){
    return target->firstpage[n];
  } else {
    return target->data_buff[PointerVector_Entry2Page(n)][n%POINTERVECTOR_ENTRIES_PER_PAGE];
  }
}

static inline void PointerVector_set_nth(PointerVector *target, int n, void *new_val) {
  if(target->firstpage){
    target->firstpage[n] = new_val;
  } else {
    target->data_buff[PointerVector_Entry2Page(n)][n%POINTERVECTOR_ENTRIES_PER_PAGE] = new_val;
  }
}

void PointerVector_resize(PointerVector *target, int new_size);

static inline void PointerVector_insertAt(PointerVector *target, void *value, int i) {
	int j;
  if(target->count == target->max_size) {
    int new_size= target->max_size * 2;
    PointerVector_resize(target, new_size);
  }
  for (j = target->count; j > i; j--){
    PointerVector_set_nth(target, j, PointerVector_nth(target, j-1));
  }
  PointerVector_set_nth(target, i, value);
	target->count++;
}

static inline void * PointerVector_deleteAt(PointerVector *target, int n) {
  void *elim = PointerVector_nth(target, n);
  if(target->flags & POINTERVECTOR_ORDER_PRESERVING) {
    int i;
    for(i=n+1; i < target->count; i++) {
      PointerVector_set_nth(target, i-1, PointerVector_nth(target, i));
    }
  } else {
    PointerVector_set_nth(target, n, PointerVector_nth(target, target->count-1));
  }
  if(target->flags & POINTERVECTOR_AUTO_ZERO) {
    PointerVector_set_nth(target, target->count-1, NULL);
  }
  target->count--;
  return elim;
}

/** Insert a value at an arbitrary location */
static inline void 
PointerVector_append(PointerVector *target, void *value) {
  if (target->count == target->max_size)
    PointerVector_resize(target, target->max_size << 1);

  PointerVector_set_nth(target, target->count, value);
  target->count++;
}

/** Lookup a value 
 
    @param cmp should be a function that returns 0 if no match, 1 if it is */
static inline void *
PointerVector_iterate(PointerVector *list, 
		      int (*match)(void *entry, void* arg), void *arg)
{
      void * entry;
      int i, n;
      
      n = PointerVector_len(list);
      for (i = 0; i < n; i++) {
	entry = PointerVector_nth(list, i);
	if (match(entry, arg))
		return entry;
      }
      return NULL;
}


/** Remove a value by its value */
static inline void 
PointerVector_delete(PointerVector *target, void *value) {
  int i, len;

  len = PointerVector_len(target);
  for (i = 0; i < len; i++) {
    if (PointerVector_nth(target, i) == value) {
      PointerVector_deleteAt(target, i);
      return;
    }
  }
}

#endif

