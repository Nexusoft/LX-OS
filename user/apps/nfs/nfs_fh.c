
/* This file is one big hack, to squish nfs's 28+ byte file handles into FS.svc's 7 byte file
 * handles. It also serves as a cache of nfs file handles.
 *
 * We make the following two assumptions, which should be okay in practice, for now:
 * (1) 4-byte inode numbers are unique, stable, and can be extracted from nfs file handles.
 * (2) we have plenty of ram to store all nfs file handles ever accessed in a big list.
 *
 * Given these, we keep a single data structure around:
 * fh_table -- a big set of all nfs file handles (unique modulo their inode numbers)
 *
 * The 7-byte FS_NodeID's are just indexes into this data structure.
 * Whenever we obtain a potentially new nfs file handle (e.g., from readdir), we extract the
 * inode number to ensure there are no duplicates in the table.
 *
 * We are also going to assume for now that files do not change parents.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <nexus/hashtable.h>
#include <nexus/sema.h>

#include "nfs.h"

static struct HashTable *fh_table;
static Sema fh_mutex = SEMA_MUTEX_INIT;

static int debug = 0;

void fh_init(void) {
	fh_table = hash_new(1024, sizeof(int));
}

int fh_cmp(struct nfs_node *n1, struct nfs_node *n2) {
	// the only field that matters is the inode number
#if 0
	int i;
	if (n1->fh.len != n2->fh.len) return 1;
	for (i = 0; i < n1->fh.len/4; i++) {
		if (n1->fh.data[i] != n2->fh.data[i])
			return 1;
	}
	return 0;
#endif
	int i1 = extract_inode_number(&n1->fh);
	int i2 = extract_inode_number(&n2->fh);
	return (i2 - i1);
}

struct nfs_node *fh_canonical(struct nfs_node *node, int *id) {
	P(&fh_mutex);
	int inode = extract_inode_number(&node->fh);
	struct nfs_node *prev = hash_findItem(fh_table, &inode);
	if (debug)
		printf("nfs_fh: adding node %p as <%d>, prev=%p\n", node, inode, prev);
	if (!prev) {
		hash_insert(fh_table, &inode, node);
	} else {
		if (debug) {
			printf("  prev->name = %s\n", prev->name);
			printf("  prev->inode = <%d>\n", extract_inode_number(&prev->fh));
		}
		if (prev != node) {
			if(fh_cmp(prev, node) != 0) {
				printf("error: file handle changed\n");
				printf("previous node:\n");
				debug_print_node(prev);
				printf("\n");
				printf("new node:\n");
				debug_print_node(node);
				printf("\n");
				exit(1);
			}
			int size = (prev->size > node->size) ? prev->size : node->size;
			if (node->mtime.seconds != prev->mtime.seconds ||
			    node->mtime.nseconds != prev->mtime.nseconds) {
			  /* int n = cache_free(node); // ack: recursive, calls nfs_write()
			  if (n > 0)
			    printf("nfs_cache: detected stale cache pages: %d pages flushed\n", n);
			  */
			  int n = cache_discard(node);
			  printf("nfs_cache: detected stale cache pages: %d pages discarded for %s\n", n, node->name);
			  printf("   mtime1 = %d:%d\n", node->mtime.seconds, node->mtime.nseconds);
			  printf("   mtime2 = %d:%d\n", prev->mtime.seconds, prev->mtime.nseconds);
			}
			free(node->name); 
			node->name = prev->name; // except for the name (which we keep around) ....
			memcpy(prev, node, sizeof(struct nfs_node)); // the data in node is more recent
			free(node);
			node = prev;
			node->size = size;
		}
	}
	V_nexus(&fh_mutex);
	*id = inode;
	return node;
}

static int evict_finger = 0;

void fh_evict_cache(void) {
  printf("nfs: cache has reached %d KB, evicting some pages\n", num_pages_cached * 4096 / 1024);
  int initial_cache_size = num_pages_cached;
  int target_cache_size = max_cache_pages * 3 / 4;
  P(&fh_mutex);
  // todo: iterate through fh_table, evicting pages willy nilly
  int i, n = hash_numEntries(fh_table);
  int pages_written = 0, files_flushed = 0;
  struct nfs_node **nodes = (struct nfs_node **)hash_entries(fh_table);
  for (i = 0; i < n && num_pages_cached > target_cache_size; i++) {
    int ix = (evict_finger++) % n;
    struct nfs_node *node = nodes[ix];
    if (!node) continue;
    pages_written += cache_free(node);
    files_flushed++;
  }
  free(nodes);
  printf("nfs: cache is now %d KB, down from %d KB (%d KB in %d files written back to server)\n",
      num_pages_cached * 4, initial_cache_size * 4, pages_written * 4, files_flushed);
  V_nexus(&fh_mutex);
}

int fh_put(struct nfs_node *node) {
	int id;
	fh_canonical(node, &id);
	// check cache size
	// now done in cache_page()
	//if (num_pages_cached >= max_cache_pages)
	  //fh_evict_cache();
	return id;
}


struct nfs_node *fh_get(int id) {
	P(&fh_mutex);
	struct nfs_node *node = hash_findItem(fh_table, &id);
	V_nexus(&fh_mutex);
	return node;
}
