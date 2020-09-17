/** NexusOS: An FS-independent filecache 
 
    XXX replace static local structure with one passed by callers,
        to enable multiple coexisting caches per process */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/fs.h>
#include <nexus/hashtable.h>

#define RCACHE_MAXLEN	(1 << 16)	// max no of 4kB pages in the cache

struct fscache_entry {
	FSID node;
	unsigned long off;
	char *data;
	int len; // ONLY for last (possibly incomplete) page in a file
};

static struct HashTable *fscache;

void
nxfilecache_init(int numbuckets)
{
	if (fscache) {
		fprintf(stderr, "Overwriting existing cache. Aborting\n");
		exit(1);
	}
	fscache = hash_new(numbuckets, sizeof(FSID) + sizeof(unsigned long));
}

/** Try to read a page from the readcache
    @param off marks the start of the page (must be a page-aligned offset) */
int
nxfilecache_read(FSID node, unsigned long off, char *data)
{
	struct fscache_entry key, *entry;
	char *cached_data;

	// for simplicity, we only allow full pages starting at page boundaries
	if (off & (PAGESIZE - 1))
		return -1;

	// fill in lookup elements
	key.node = node;
	key.off = off;

	// lookup
	entry = hash_findItem(fscache, &key);
	if (!entry)
		return -1;

	// return copy
	memcpy(data, entry->data, PAGESIZE);
	return entry->len;
}

/** Remove pages (if they exist) 
    NB: we may remove more, as we cache whole pages
    On write, we could add the new content to the cache as well. But we don't
 */
void
nxfilecache_invalidate(FSID node, unsigned long off_start, unsigned long off_len)
{
	struct fscache_entry key, *entry;
	unsigned long off;

	key.node = node;

	off = off_start & ~(PAGESIZE - 1);
	while (off < off_start + off_len) {
		
		// lookup
		key.off = off;
		entry = hash_delete(fscache, &key);
		
		// free
		if (entry) {
			free(entry->data);
			free(entry);
		}
		
		off += PAGESIZE;
	}
}

/** Store a page of data into the readcache.
    This must be a FULL page, unless it is the last page in the file. */
int
nxfilecache_write(FSID node, unsigned long off, const char *data, int len)
{
	struct fscache_entry *entry, *old, *old_prev, key;

	// for simplicity, we only allow pages starting at page boundaries
	if (off & (PAGESIZE - 1))
		return -1;

	// NB: cannot enforce restriction that only last fragment in a file may
	//     have length < PAGESIZE. Must be checked in caller.

	// create struct
	entry = calloc(1, sizeof(*entry));
	entry->node = node;
	entry->off = off;
	entry->len = len;

	// transfer data
	entry->data = malloc(entry->len);
	memcpy(entry->data, data, entry->len);

	// (unlikely) remove previous entry
	old = hash_findEntry(fscache, entry, NULL);
	if (old)
		hash_delete(fscache, entry);

	// (unlikely) make room
	if (hash_numEntries(fscache) == RCACHE_MAXLEN) {
                old = hash_any(fscache, (void **) &old_prev);
		if (old)
			hash_deleteEntry(fscache, old, old_prev);
	}

	// insert
	hash_insert(fscache, entry, entry);
	return 0;
}

