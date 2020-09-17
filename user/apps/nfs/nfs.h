#ifndef NFS_H
#define NFS_H

#include <nexus/hashtable.h>

#include <netinet/in.h>

#include "xdr.h"

#define RPC_VERSION 2
#define TRANSPORT_TCP 6

#define STATUS_OK 0

#define SUNRPC_PORT 111

#define PROG_PORTMAP 100000
#define PROG_PORTMAP_VERSION 2
#define PROG_PORTMAP_GETPORT 3

#define PROG_MOUNT 100005
#define PROG_MOUNT_VERSION 3
#define PROG_MOUNT_MNT 1
#define PROG_MOUNT_UMNT 3

#define PROG_NFS 100003
#define PROG_NFS_VERSION 3
#define PROG_NFS_GETATTR 1
#define PROG_NFS_SETATTR 2
#define PROG_NFS_LOOKUP 3
#define PROG_NFS_READ 6
#define PROG_NFS_WRITE 7
#define PROG_NFS_CREATE 8
#define PROG_NFS_REMOVE 12
#define PROG_NFS_COMMIT 13
#define PROG_NFS_READDIR 16

enum create_mode {
	UNCHECKED = 0,
	GUARDED = 1,
	EXCLUSIVE = 2
};

enum node_type {
	NFS_REGULAR_FILE = 1,
	NFS_DIRECTORY = 2
};

enum stable_how {
	UNSTABLE = 0,
	DATA_SYNC = 1,
	FILE_SYNC = 2
};

#define NFS3_FHSIZE 64
struct nfs_fh {
	u32 len;
	u32 data[NFS3_FHSIZE/4];
};

struct nfs_time {
	u32 seconds;
	u32 nseconds;
};

struct nfs_node {
	struct nfs_fh fh;
	//struct nfs_node *parent;
	char *name;
	u32 type;
	u64 size;
	struct nfs_time mtime;
	struct nfs_page *pages;
	//int refcount;
	//unsigned int inode;
};

struct nfs_page {
  struct nfs_node *node;
  struct nfs_page *next;
  int pgoff; // 4k aligned
  char *data; // data from file at offset pgoff to pgoff+4k
  int vstart, vend; // only data at offset vstart to vend is valid
  int state; // 0 = unallocated, 1 = clean, 2 = dirty, 3 = written
};


#define NFS3_COOKIEVERFSIZE 8
struct nfs_readdir_cookie {
	u64 cookie;
	u32 cookieverf[NFS3_COOKIEVERFSIZE/4];
};

// network info
extern char server_addr[4];
extern int nfs_is_mounted;
extern unsigned int nfs_port;	
extern unsigned int mount_port;	

// auth information
extern char *local_machinename;
extern unsigned int uid;

// mount info
extern char *mount_path;
extern struct nfs_node root_node;

// file handles
void fh_init(void);
extern struct nfs_node *fh_canonical(struct nfs_node *p, int *id);
void fh_remove(struct nfs_node *node);
extern int fh_put(struct nfs_node *p);
extern struct nfs_node *fh_get(int id);
extern void fh_evict_cache(void);

// caching
int cache_free(struct nfs_node *node);
int cache_discard(struct nfs_node *node);
int cache_commit(struct nfs_node *node);
char *cache_read(struct nfs_node *node, int file_position, int *readlen);
char *cache_startwrite(struct nfs_node *node, int file_position, int *writelen);
void cache_endwrite(struct nfs_node *node, int file_position, int writelen);
extern int num_pages_cached;
extern int max_cache_pages;

// nfs functions
void debug_print_fh(struct nfs_fh *fh);
void debug_print_node(struct nfs_node *node);

int prog_nullcall(u32 port, u32 service, u32 version);

int nfs_init(char *serverip, char *mountpath, char *localmachinename, unsigned int euid);

int nfs_get_attr(struct nfs_node *node);
int nfs_set_attr(struct nfs_node *node, int file_len);

struct nfs_node *nfs_remove(struct nfs_node *parent, char *name);

char *nfs_readdir(struct nfs_node *node, int *readlen, struct nfs_readdir_cookie *cookie, int *n, int *eod);

struct nfs_node *nfs_lookup(struct nfs_node *parent, char *name);

int nfs_read(struct nfs_node *node, u64 offset, char *page);

int nfs_write(struct nfs_node *node, u64 offset, char *data, int writelen);

struct nfs_node *nfs_create(struct nfs_node *parent, char *name, int overwrite);

int nfs_mount(void);
int nfs_umount(void);

int extract_inode_number(struct nfs_fh *fh);

#endif // NFS_H
