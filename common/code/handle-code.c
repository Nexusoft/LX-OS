/** NexusOS: A datastructure that supports add, get and del.
  	     see headerfile handle.h for more information */

static void 
__HandleTable_resize(struct PointerVector *vector, int new_size, void *ctx)
{
  // simple algorithm: allocate a new one, high level copy of old one
  HandleTable *table = (HandleTable *) ctx;
  BigFastBitmap *old_map = &table->bitmap;
  BigFastBitmap new_map;
  BigFastBitmap_init(&new_map, new_size);
  //  nxcompat_printf("new bitmap size %d\n", new_size);

  int i;
  for(i=0; i < old_map->max_len; i++) {
    if(BigFastBitmap_test(old_map, i)) {
      BigFastBitmap_set(&new_map, i);
    }
  }
  BigFastBitmap_dealloc(old_map);
  BigFastBitmap_copy(old_map, &new_map);
}

/** initialize an allocated handle table. 
   @param initial_size sets the initial number of elements in the table */
inline void 
HandleTable_init(HandleTable *table, int initial_size) 
{
  // NOT order-preserving
  PointerVector_init(&table->vector, initial_size, POINTERVECTOR_AUTO_ZERO);
  PointerVector_setResizeHook(&table->vector, __HandleTable_resize, table);

  BigFastBitmap_init(&table->bitmap, initial_size);
}

/** allocate and initialize a handle table */
HandleTable *HandleTable_new(int initial_size) 
{
  HandleTable *rv = galloc(sizeof(HandleTable));
  HandleTable_init(rv, initial_size);
  return rv;
}

/** inverse of HandleTable_init. */
inline void HandleTable_dealloc(HandleTable *table) 
{
  PointerVector_dealloc(&table->vector);
  BigFastBitmap_dealloc(&table->bitmap);
}

/** inverse of HandleTable_new. */
void HandleTable_destroy(HandleTable *table) 
{
  HandleTable_dealloc(table);
  gfree(table);
}

/** iterator */
void HandleTable_iterate(HandleTable *table, HandleTable_IterateFunc f, void *arg) {
  int i;
  for(i=0; i < PointerVector_size(&table->vector); i++) {
    void *val = HandleTable_find(table, i);
    if(val != NULL) {
      f(i, val, arg);
    }
  }
}

/** insert an item 
 
    does not allow duplicates. will spin if a duplicate add is requested */
Handle HandleTable_add_ext(HandleTable *table, void *val, Handle requested_handle) {
  int limit = 0;
  Handle location;
  if(requested_handle < 0) {
    while(1) {
      location = BigFastBitmap_ffz(&table->bitmap);
      if(location >= 0) {
	break;
      }
      // should work after 1 resizing
      assert(limit < 1);
      // Need more space!
      PointerVector_resize(&table->vector, PointerVector_size(&table->vector) * 2);
      limit++;
    }
  } else {
    if(requested_handle >= PointerVector_size(&table->vector)) {
      PointerVector_resize(&table->vector, requested_handle * 2);
    }
    location = requested_handle;
  }

  if(unlikely(PointerVector_nth(&table->vector, location) != NULL)) {
    long val = (long) PointerVector_nth(&table->vector, location);
    nxcompat_printf("not null @ %d (is %p) %d, ", location, (void *) val, requested_handle);
    nxcompat_printf("size %d %d\n", table->bitmap.max_len, PointerVector_size(&table->vector));
    //nexusthread_dump_regs_stack(nexusthread_self());
    // check for mismatch
    int i;
    for(i=0; i < PointerVector_size(&table->vector); i++) {
      int first = 1;
      if(!!BigFastBitmap_test(&table->bitmap, i) ^ !!(int)PointerVector_nth(&table->vector, i)) {
	nxcompat_printf("[%d](%d,%d)", i, 
		   BigFastBitmap_test(&table->bitmap, i),
		   (int)PointerVector_nth(&table->vector, i));
	if(first) {
	  nxcompat_printf("<%p>", &(table->vector.data_buff[PointerVector_Entry2Page(i)][i%POINTERVECTOR_ENTRIES_PER_PAGE]));
	  first = 0;
	}
      }
    }
    nxcompat_printf("looping\n"); while(1);
  }
  assert(PointerVector_nth(&table->vector, location) == NULL);
  BigFastBitmap_set(&table->bitmap, location);
  PointerVector_set_nth(&table->vector, location, val);
  return location;
}

/** remove an item */
void HandleTable_delete(HandleTable *table, Handle h) {
  PointerVector_set_nth(&table->vector, h, NULL);
  BigFastBitmap_clear(&table->bitmap, h);
}

#ifdef __NEXUSKERNEL__
Handle 
HandleTable_add_noint(HandleTable *table, void *val) 
{
  Handle handle;

  int level = disable_preemption();
  handle = HandleTable_add(table, val);
  restore_preemption(level);

  return handle;
}

void * 
HandleTable_find_noint(HandleTable *table, Handle handle)
{
  void * rv;
  int level;
  
  level = disable_preemption();
  rv = HandleTable_find(table, handle);
  restore_preemption(level);

  return rv;
}

void 
HandleTable_delete_noint(HandleTable *table, Handle handle) 
{
  int level = disable_preemption();
  HandleTable_delete(table, handle);
  restore_preemption(level);
}
#endif

