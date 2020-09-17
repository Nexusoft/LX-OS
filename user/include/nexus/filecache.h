/** NexusOS: An FS-independent filecache */

#ifndef NX_USER_FCACHE_H
#define NX_USER_FCACHE_H

void nxfilecache_init(int numbuckets);
int  nxfilecache_read(FSID node, unsigned long off, char *data);
int  nxfilecache_write(FSID node, unsigned long off, const char *data, int len);
void nxfilecache_invalidate(FSID node, unsigned long off_start, 
			    unsigned long off_len);

#endif /* NX_USER_FCACHE_H */

