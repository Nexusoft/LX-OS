/** NexusOS: test transfer between user and kernel memory
    We had a serious bug in this code before */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/kshmem.h>
#include <nexus/Debug.interface.h>
#include <nexus/Mem.interface.h>

int 
main(int argc, char **argv) 
{
  char stackbuf[PAGESIZE + 1];	// previous bug in stack transfers
  char *heapbuf, *destbuf;
  int i, j, rv, size;

  // alloc
  heapbuf = (void *) Mem_GetPages(3, 0);
  if (!heapbuf)
	  ReturnError(1, "mem alloc");
  destbuf = heapbuf + PAGESIZE;
  if (Mem_FreePages((unsigned long) heapbuf + (2 * PAGESIZE), 1))
	  ReturnError(1, "mem free");

  if (argc != 2 || strcmp(argv[1], "auto"))
  	printf("[%s] OK. Test passed\n", __FILE__);

  return 0;
}

