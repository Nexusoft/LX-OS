#ifndef __MEM_PRIVATE_H__
#define __MEM_PRIVATE_H__

#include <nexus/mem.h>
#include <nexus/queue.h>
#include <nexus/vector.h>

/** A map is just a series of virtual to physical mappings */
struct Map {
  Page *pdbr;		
  int numpgs; 			///< pages in the map

  // process owning a page. note that with page sharing, attributing is hard 
  IPD *owner;			

  // accounting. debug XXX remove
  unsigned long account_brk_add;
  unsigned long account_brk_del;
  unsigned long account_mmap_add;
  unsigned long account_mmap_del;
  unsigned long account_mmap_send;
  unsigned long account_mmap_recv;
  unsigned long account_lost;

  /// allocation hints for various disjoint vmemory regions
  //  initialized to the start of the region and updated during alloc
  struct {
    unsigned long brk;	
    unsigned long mmap;
    unsigned long dev;
    unsigned long kernel;
  } hint;
};


#endif 
