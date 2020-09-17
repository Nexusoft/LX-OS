
/* This file implements client-side nfs caching/buffering, i.e. it serves to
 * aggregate read and write requests to the nfs server.
 *
 * We maintain a variable number pages, indexed by the code in fs_fh.c. Each
 * page can be:
 *  unused -- not being used
 *  clean -- contains data (roughtly) consistent with the disk
 *  dirty -- contains data not yet sent to server
 *  written -- data was sent to server, but not yet committed at server
 *  failed -- an attempt was made to commit written data, but failed
 *
 * Each page is at most 4k bytes, and is aligned on 4k file boundaries, but may
 * only contain partial data (e.g., in the case of writes without reads). For
 * simplicity, we do not allow non-contiguous partial data within a page (e.g,
 * writing only the beginning and end of a page, but not the middle).
 *
 * todo: try to keep the number of pages in the range [MAX/2, MAX] if possible, but
 * don't bother being particularly aggressive.
 *
 * todo: use a sorted list of pages with a hint -- much better for sequential
 * access. Or use a sorted, circular list, and rotate it as needed.
 */

/*
int cache_flush(struct nfs_page *page) {
  if (page->state == 2) {
    int len = nfs_write(..., 0);
    page->state = 3;
  }
  return 0
}
*/

#include "nfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nexus/util.h> // for min
#define LOCAL_DEBUG_LEVEL DEBUG_LEVEL_WARN
#include <nexus/debug.h>
#include <assert.h>

#define PAGE_SIZE 4096

int num_pages_cached = 0;
int max_cache_pages = (1 << 25) / PAGE_SIZE; // 32 MB worth of file cache

/** print cache pressure on changes 
    @param change: the number of added or deleted pages */
static void cache_update_size(int change)
{
	int old;

	old = num_pages_cached;
	num_pages_cached += change;

	// show output if a MB boundary is crossed (8: 2^20 / 2^PAGE_SIZE)
	if (old >> 8 != num_pages_cached >> 8)
		printf("[nfs] cached %d MB\n", (num_pages_cached << 12) >> 20);
}

#ifdef NFS_CACHEWRITES
/** Write a dirty page back to server */
static int commit_page(struct nfs_page *page) {
  int len, len2;

  // dirty page?
  if (page->state != 2)
    return 0;

  len = page->vend - page->vstart;
  len2 = nfs_write(page->node, page->pgoff + page->vstart, page->data + page->vstart, len);
  if (len2 == -1) { 
    return -1;
  }

  page->state = 1;
  return 1;
}

/** write an entire file back to the server */
int cache_commit(struct nfs_node *node) {
  struct nfs_page *pg;
  int n = 0;

  for (pg = node->pages; pg; pg = pg->next) {
    printf("[nfs] commit %s <%d,%d>\n", node->name, pg->pgoff + pg->vstart, pg->pgoff + pg->vend);
    n += commit_page(pg);
    assert(pg->state == 1); // clean
  }
  return n;
}
#endif

static void cache_discard_page(struct nfs_page *pg)
{
    free(pg->data);
    free(pg);
    cache_update_size(-1);
}

/** free pages */
int cache_discard(struct nfs_node *node) {
  struct nfs_page *pg;
  int n = 0;
  
  for (pg = node->pages; pg; pg = pg->next) {
    cache_discard_page(pg);
    n++;
  }
  node->pages = NULL;

  return n;
}

/** flush and free pages */
int cache_free(struct nfs_node *node) {
  int n = 0;

#ifdef NFS_CACHEWRITES
  n = cache_commit(node);
#endif
  cache_discard(node);
  return n;
}

static struct nfs_page *cache_page(void) {
  struct nfs_page *pg;
  
  if (num_pages_cached >= max_cache_pages)
    fh_evict_cache();
  
  pg = calloc(1, sizeof(struct nfs_page));
  pg->data = malloc(PAGE_SIZE);
  return pg;
}

/** Lookup a cached page in the node's list of pages */
static struct nfs_page *find_page(struct nfs_node *node, int pgoff) {
  struct nfs_page *page;
 
  // XXX make lookup faster. this is terribly slow

  page = node->pages;
  while (page) {
    if (page->pgoff == pgoff)
      return page;

    page = page->next;
  }
  return NULL;
}

static int fill_page(struct nfs_page *page) {
    int readlen = nfs_read(page->node, page->pgoff, page->data);
    if (readlen <= 0) {
      dprintf(WARN, " fill_page failed\n");
      free(page->data);
      free(page);
      return -1;
    }
    assert(readlen);
    page->vstart = 0;
    page->vend = readlen;
    return readlen;
}

char *cache_read(struct nfs_node *node, int file_position, int *readlen) {
  struct nfs_page *page;
  int pgoff, vstart, vend;

  // calculate bounds
  pgoff = file_position & (~(PAGE_SIZE-1));
  vstart = file_position & (PAGE_SIZE-1);
  vend = min((u64) vstart + *readlen, (u64) PAGE_SIZE - 1);

  // lookup page
  page = find_page(node, pgoff);
  if (page && page->vstart <= vstart) {
    if (!file_position)
      printf("[nfs] read %s (cache)\n", node->name);

    *readlen = min(*readlen, page->vend - vstart);
    return page->data + vstart;
  }

  if (page) {
    // page only has partial overlap. flush
    // commit_page(page);
    assert(page->state == 1);
    assert(page->node == node);
    assert(page->pgoff == pgoff);
  } else {
    // no such page -- allocate
    page = cache_page();
    cache_update_size(1);
    page->node = node;
    page->pgoff = pgoff;
    page->state = 1;
    page->next = node->pages;
    node->pages = page;
    cache_update_size(1);
  }

  if (fill_page(page) <= 0)
    return NULL;
 
  *readlen = min(*readlen, vend - vstart + 1);

  if (!file_position)
    printf("[nfs] read %s (network) (%lldB)\n", node->name, node->size);

  return page->data + vstart;
}

// NFS currently does not cache on write (write-back)
#ifdef NFS_CACHEWRITES

// WARNING: communicated between cache_startwrite and cache_endwrite
// writing is therefore clearly NOT multithread safe
static struct nfs_page *page_new;
static struct nfs_page *page_old;

/** Write is bounded per page*/
char *cache_startwrite(struct nfs_node *node, int file_position, int *writelen) {
  struct nfs_page *page;
  int pgoff, vstart, vend;

  // calculate bounds
  pgoff = file_position & (~(PAGE_SIZE-1));
  vstart = file_position & (PAGE_SIZE-1);
  vend = min((u64) vstart + *writelen, (u64) PAGE_SIZE - 1);
  *writelen = vend - vstart /*+ 1*/;

  // free page that should have been, but was not, used in cache_endwrite
  // should never happen (?).
  if (page_new) {
    printf("[nfs] ERR: lingering page\n");
    exit(1);
  }

  // overwrite/extend existing page
  page = find_page(node, pgoff);
  if (page && page->vstart <= vend && page->vend >= vstart) {
    *writelen = vend - vstart /*+ 1*/;
    page_old = page;
    return page->data + vstart;
  }

  // we have a partial page with data not contiguous with new range 
  // -- flush and make new page 
  if (page) {
    commit_page(page);
    assert(page->state == 1);
    page_old = page;
  } 
  // no such page -- allocate
  else {
    page = cache_page();
    page->node = node;
    page->pgoff = pgoff;
    page_new = page;
  }

  return page->data + vstart;
}


void cache_endwrite(struct nfs_node *node, int file_position, int writelen) {
  int pgoff = file_position & (~(PAGE_SIZE-1));
  int vstart = file_position - pgoff;
  struct nfs_page *page;
  
  // new page? insert page at start of pagecache list
  if (page_new) {
    printf("endwrite: npage=%d <%d,%d>\n", pgoff, vstart, vstart + writelen - 1);
    page = page_new;
    page_new = NULL;
    assert(page);
    assert(page->node == node);
    assert(page->pgoff == pgoff);
    page->vstart = vstart;
    page->vend = vstart + writelen - 1;
    page->next = node->pages;
    node->pages = page;
    cache_update_size(1);
  } 
  // existing page? update boundaries
  else {
    printf("endwrite: opage=%d <%d,%d>\n", pgoff, vstart, vstart + writelen - 1);
    page = page_old;
    page_old = NULL;
    assert(page);
    assert(page->node == node);
    assert(page->pgoff == pgoff);
    page->vstart = min(vstart, page->vstart);
    page->vend = max(page->vstart + writelen - 1, page->vend);
  }
  
  if (page->vend >= PAGE_SIZE) {
  	printf("ERR: vend > PAGE_SIZE : vstart=%d vend=%d wlen=%d\n", page->vstart, page->vend, writelen);
	exit(1);
  }
  
  page->state = 2; // dirty
  node->size = max(node->size, (u64) page->pgoff + page->vend);
  commit_page(page);
}
#endif

