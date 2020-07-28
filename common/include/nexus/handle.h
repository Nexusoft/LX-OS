/** NexusOS: A datastructure that supports add, get and del.
	
	     The interface is similar to a hashtable. 
	     Keys are of type int, Values of void*
	     Semantics: duplicate keys are NOT allowed

	     The implementation combines a bitmap and vector,
	     i.e., this is not a hashtable. */

#ifndef _HANDLE_H_
#define _HANDLE_H_

#include <nexus/vector.h>
#include <nexus/bitmap.h>

// same as in user/../ipc.h
// luckily both are the same
#ifndef INVALID_HANDLE
#define INVALID_HANDLE (-1)

// all handles can have the same values: natural numbers and INVALID_HANDLE
static int 
__Handle_Valid(int handle, const char *func, int line)
{
	if (handle >= 0)
		return 1;

	if (handle != INVALID_HANDLE)
		nxcompat_printf("Illegal handle %d at %s:%d. Bug?\n", 
				handle, func, line);

	return 0;
}

#define Handle_Valid(handle) __Handle_Valid(handle, __FUNCTION__, __LINE__)
#endif

struct HandleTable {
  PointerVector vector;
  BigFastBitmap bitmap;
};

typedef int Handle;

/**** Table construction ********/

HandleTable *HandleTable_new(int initial_size);
void HandleTable_destroy(HandleTable *table);

void HandleTable_init(HandleTable *table, int initial_size);
void HandleTable_dealloc(HandleTable *table);

/**** Data insertion and deletion ********/

Handle HandleTable_add_ext(HandleTable *table, void *val, Handle requested_handle);

static inline Handle 
HandleTable_add(HandleTable *table, void *val) {
  return HandleTable_add_ext(table, val, -1);
}

static inline void 
HandleTable_set(HandleTable *table, Handle h, void *val) {
  assert((unsigned int) h < (unsigned int)PointerVector_size(&table->vector));
  assert(PointerVector_nth(&table->vector, h) == NULL);
  PointerVector_set_nth(&table->vector, h, val);
}

void HandleTable_delete(HandleTable *table, Handle h);

/**** Data lookup ********/

static inline void *HandleTable_find(HandleTable *table, Handle h) {
  if (unlikely((unsigned long) h >= (unsigned long) PointerVector_size(&table->vector))) {
    nxcompat_printf("handle %d out of range (%d)\n", h, PointerVector_size(&table->vector));
    return NULL;
  }
  return PointerVector_nth(&table->vector, h);
}

typedef void (*HandleTable_IterateFunc)(Handle h, void *item, void *arg);
void HandleTable_iterate(HandleTable *table, HandleTable_IterateFunc f, void *arg);

/**** Kernel specific variants of above ********/
#ifdef __NEXUSKERNEL__
Handle HandleTable_add_noint(HandleTable *table, void *val);
void * HandleTable_find_noint(HandleTable *table, Handle handle);
void HandleTable_delete_noint(HandleTable *table, Handle handle);
#endif

#endif // _HANDLE_H_

