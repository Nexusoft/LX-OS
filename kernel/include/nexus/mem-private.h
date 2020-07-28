#ifndef __MEM_PRIVATE_H__
#define __MEM_PRIVATE_H__

#include <nexus/mem.h>
#include <nexus/queue.h>
#include <nexus/vector.h>

/* A map is just a series of virtual to physical mappings in sorted order */
struct Map {
  Page *pdbr;		
  int refcnt;
  int active_thread_count;
  int is_reaped;
  struct SegmentHashInfo segInfo;
  MapType type;
  
  int numpgs; // keep track of number of physical pages in each map

  // list of all pt pages. for dealloc only
  Queue *pagetables;

  // Note: this list is a superset of all possible vaddrs 
  // No effort is made to remove duplicates, or maintain consistency
  // with the actual map. It's purely used to optimize map free
  PointerVector allocated_vaddrs;


  IPD *owner;	// only set for Xen
  int clean_anon_pages; // if set to true, iterate through frame table on deallocation to deallocate all pages that belong to owner

};


#endif 
