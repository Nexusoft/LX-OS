 
/* This file is one big hack, to squish nfs's 28+ byte file handles into FS.svc's 7 byte file
 * handles. It also serves as a lookup table of nfs file handles.
 *
 * We make the following two assumptions, which should be okay in practice, for now:
 * (1) 32-bit inode numbers are unique, stable, and can be extracted from nfs file handles.
 * (2) we have plenty of ram to store all nfs file handles ever accessed in a big list.
 *
 * Given these, we keep a single data structure around:
 * fh_table -- a big set of all nfs file handles (unique modulo their inode numbers)
 *
 * The 56-bit FSID.nodeids are just wrappers around the 32-bit inodes, which serve as
 * indexes into this data structure.
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

/// lookup table from inode number (embedded in nfs identifier) to nfs_node
static struct HashTable *fh_table;
static Sema fh_mutex = SEMA_MUTEX_INIT;

void fh_init(void) {
	fh_table = hash_new(1 << 12, sizeof(int));
}

static int fh_cmp(struct nfs_node *n1, struct nfs_node *n2) {
	// the only field that matters is the inode number
	int i1 = extract_inode_number(&n1->fh);
	int i2 = extract_inode_number(&n2->fh);
	return (i2 - i1);
}

void fh_remove(struct nfs_node *node)
{
	int inode;
	
	inode = extract_inode_number(&node->fh);
	hash_delete(fh_table, &inode);
}

/** Compare a node to the items in the lookup table.
    If the node already exists, check freshness and update the lookup table 
 
    @param id will on return hold an id that is short enough to fit in an FSID
    @return the 'canonical' version of the node and updates parameter id 
 */
struct nfs_node *fh_canonical(struct nfs_node *node, int *id) {
	unsigned long long mtime[2];
	struct nfs_node *prev;	///< existing version in the lookup table
	int inode;

	P(&fh_mutex);
	
	inode = extract_inode_number(&node->fh);
	prev = hash_findItem(fh_table, &inode);
	
	// no previous? insert
	if (!prev) {
		hash_insert(fh_table, &inode, node);
	} 
	// previous? check freshness and reuse
	else {
		if (node != prev) {

			// we assume handles never change
			if (fh_cmp(prev, node) != 0) {
				printf("[nfs] file handle changed. Aborting\n");
				exit(1);
			}

			hash_delete(fh_table, &inode);
			hash_insert(fh_table, &inode, node);
		}
	}

	V_nexus(&fh_mutex);
	*id = inode;
	return node;
}

int fh_put(struct nfs_node *node) {
	int id;
	fh_canonical(node, &id);
	return id;
}

struct nfs_node *fh_get(int id) {
	P(&fh_mutex);
	struct nfs_node *node = hash_findItem(fh_table, &id);
	V_nexus(&fh_mutex);
	return node;
}

