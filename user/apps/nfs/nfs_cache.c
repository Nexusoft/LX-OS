
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

int num_pages_cached = 0;
int max_cache_pages = 64*1024*1024 / 4096; // 64 MB worth of file cache

static int commit_page(struct nfs_page *page) {
  if (page->state == 2) {
    int len = page->vend - page->vstart;
    dprintf(INFO, "cache: flushing %d bytes at %d\n", len, page->pgoff + page->vstart);
    int len2 = nfs_write(page->node, page->pgoff + page->vstart, page->data + page->vstart, len, 1);
    assert(len == len2);
    page->state = 1;
    return 1;
  }
  return 0;
}

int cache_free(struct nfs_node *node) {
  struct nfs_page *pg, **pages = &node->pages;
  int n = 0;
  while ((pg = *pages)) {
    *pages = pg->next;
    n += commit_page(pg);
    assert(pg->state == 1); // clean
    free(pg->data);
    pg->data = NULL;
    free(pg);
    num_pages_cached--;
  }
  return n;
}

int cache_discard(struct nfs_node *node) {
  struct nfs_page *pg, **pages = &node->pages;
  int n = 0;
  while ((pg = *pages)) {
    *pages = pg->next;
    free(pg->data);
    pg->data = NULL;
    free(pg);
    num_pages_cached--;
    n++;
  }
  return n;
}


int cache_commit(struct nfs_node *node) {
  struct nfs_page *pg;
  int n = 0;
  for (pg = node->pages; pg; pg = pg->next) {
    n += commit_page(pg);
    assert(pg->state == 1); // clean
  }
  return n;
}

static struct nfs_page *cache_page(void) {
  if (num_pages_cached >= max_cache_pages)
    fh_evict_cache();
  struct nfs_page *pg = malloc(sizeof(struct nfs_page));
  memset(pg, 0, sizeof(struct nfs_page));
  pg->data = malloc(4096);
  return pg;
}

static struct nfs_page *find_page(struct nfs_node *node, int pgoff) {
  dprintf(INFO, " %d? ", pgoff);
  struct nfs_page **ppg;
  for (ppg = &node->pages; *ppg && (*ppg)->pgoff != pgoff; ppg = &(*ppg)->next) {
    dprintf(INFO, " %d ", (*ppg)->pgoff);
  }
  if (*ppg) {
    dprintf(INFO, " hit %d ", (*ppg)->pgoff);
  }
  /* static int die = 0;
  if (die++ > 100 && die % 10 == 0) {
    usleep(6000000);
  } */
  if (*ppg && node->pages != *ppg) {
    // move to front
    struct nfs_page *rest = (*ppg)->next;
    (*ppg)->next = node->pages;
    node->pages = *ppg;
    *ppg = rest;
    return node->pages;
  }
  return *ppg;
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
  dprintf(INFO, "cache_read(\"%s\",  %d, %d)", node->name, file_position, *readlen);
  int pgoff = file_position & (~(4096-1));
  int vskip = file_position & (4096-1);
  int vmax = min((u32)(file_position + *readlen - pgoff), (u32)node->size - pgoff);
  vmax = min(vmax, 4096);
  struct nfs_page *page = find_page(node, pgoff);
  if (page && page->vstart <= vskip && page->vend >= vmax) {
    // page is present, and has enough data in it
    *readlen = vmax - vskip;
    dprintf(INFO, "  ==> page present (%d bytes)\n", *readlen);
    return page->data + vskip;
  }

  if (page) {
    // we only have a partial page with no overlap -- discard
    dprintf(INFO, "  ==> partial, unusable page present\n");
    commit_page(page);
    assert(page->state == 1);
    assert(node->pages == page); // should be at front
    node->pages = page->next;
    page->next = NULL;
  } else {
    dprintf(INFO, "  ==> no page present, allocating new\n");
    // no such page -- allocate
    page = cache_page();
    page->node = node;
    page->pgoff = pgoff;
  }

  int pagelen = fill_page(page);
  if (pagelen <= 0)
      return NULL;
  if (page->state == 0) num_pages_cached++;
  dprintf(INFO, "node %p, cached %d\n", node, num_pages_cached);
  page->state = 1;
  page->next = node->pages;
  node->pages = page;

  if (pagelen < vmax) {
    // page was smaller than expected
    vmax = pagelen;
  }
  *readlen = vmax - vskip;
  dprintf(INFO, "filled at least %d bytes\n", *readlen);
  return page->data + vskip;
}

struct nfs_page *next_page;
char *cache_startwrite(struct nfs_node *node, int file_position, int *writelen) {
  dprintf(INFO, "cache_startwrite(\"%s\",  %d, %d)", node->name, file_position, *writelen);
  int pgoff = file_position & (~(4096-1));
  int vskip = file_position & (4096-1);
  int vmax = min(4096, file_position + *writelen - pgoff);
  struct nfs_page *page = find_page(node, pgoff);
  if (page && page->vstart <= vmax && page->vend >= vskip) {
    // page is present, and new data overlaps old
    dprintf(INFO, "  ==> page present\n");
    *writelen = vmax - vskip;
    return page->data + vskip;
  }

  if (page) {
    // we have a partial page with data not contiguous with new range -- flush
    // and make new page (alternatively: we could read from nfs server to fill
    // out rest of page)
    dprintf(INFO, "  ==> partial, unusable page present\n");
    commit_page(page);
    assert(page->state == 1);
    assert(node->pages == page); // should be at front
    node->pages = page->next; // yank from list
    page->next = NULL;
  } else {
    // no such page -- allocate
    dprintf(INFO, "  ==> no page present, allocating new\n");
    page = cache_page();
    page->node = node;
    page->pgoff = pgoff;
  }
  if (next_page) {
    free(next_page->data);
    next_page->data = NULL;
    free(next_page);
    next_page = NULL;
  }
  next_page = page; // pick up in cache_endwrite

  *writelen = vmax - vskip;
  return page->data + vskip;
}


void cache_endwrite(struct nfs_node *node, int file_position, int writelen) {
  dprintf(INFO, "cache_endwrite(\"%s\",  %d, %d)", node->name, file_position, writelen);
  int pgoff = file_position & (~(4096-1));
  struct nfs_page *page;
  if (next_page) {
    page = next_page;
    next_page = NULL;
    assert(page && page->node == node && page->pgoff == pgoff);
    page->vstart = file_position & (4096-1);
    page->vend = file_position + writelen - pgoff;
    page->next = node->pages;
    node->pages = page;
  } else {
    page = node->pages;
    assert(page && page->node == node && page->pgoff == pgoff);
    page->vstart = min(file_position & (4096-1), page->vstart);
    page->vend = max(file_position + writelen - pgoff, page->vend);
  }
  if (page->state == 0) num_pages_cached++;
  dprintf(INFO, "node %p, cached %d\n", node, num_pages_cached);
  page->state = 2; // dirty
  if (page->pgoff + page->vend > node->size) { 
    dprintf(INFO, "node %p, size was %d, now %d\n", node, (int)node->size, page->pgoff + page->vend);
    node->size = page->pgoff + page->vend;
  }
}

