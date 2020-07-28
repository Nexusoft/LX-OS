#ifndef _FS_H_
#define _FS_H_

#ifdef __NEXUSKERNEL__
#else
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#endif

#include <asm/types.h>
#include <nexus/ipc.h>


#define FS_INVALID	  (1)
#define FS_NOTFOUND	  (2)
#define FS_UNSUPPORTED	  (3)
#define FS_NOMEM	  (4)
#define FS_ACCESSERROR	  (5)
#define FS_BADTRUNCATE	  (6)
#define FS_ALREADYPRESENT (7)
#define FS_BUSY		  (8)
#define FS_NOTEMPTY	  (9)
#define FS_NOTDIR	  (9)
#define FS_ISDIR	  (10)
#define FS_STALE	  (11)
#define FS_BADCOOKIE	  (12)

// node types (mutually exclusive)
#define FS_NODE_FILE 0x1
#define FS_NODE_DIR  0x2

typedef struct FSID {
  int port;
  long long nodetype : 8;  	///< node types defined above
  unsigned long long nodeid : 56;
} FSID;

#define FSID_EMPTY ((FSID) { .port = 0, .nodetype = 0, .nodeid = 0 })
// note: the -1 used here for errors must match the -1 used in idl-generated IPC failure case
#define FSID_ERROR(err) ((FSID) { .port = -1, .nodetype = -1, .nodeid = -(err) })
#define FSID_INVALID FSID_ERROR(FS_INVALID)
#define FSID_DIR(theport, id) ((FSID) { .port = (theport), .nodetype = FS_NODE_DIR, .nodeid = (id) })
#define FSID_FILE(theport, id) ((FSID) { .port = (theport), .nodetype = FS_NODE_FILE, .nodeid = (id) })
#define FSID_ROOT(theport) FSID_DIR(theport, 0)

// note: the -1 used here for errors must match the -1 used in idl-generated IPC failure case
static inline int FSID_getError(FSID fsid) {
  return (fsid.nodetype == -1 ? (int)fsid.nodeid : 0);
}
static inline int FSID_isDir(FSID fsid) {
  return (fsid.nodetype == FS_NODE_DIR);
}
static inline int FSID_isFile(FSID fsid) {
  return (fsid.nodetype == FS_NODE_FILE);
}
static inline int FSID_isRoot(FSID fsid) {
  return (fsid.nodetype == FS_NODE_DIR && fsid.nodeid == 0);
}
static inline int FSID_isValid(FSID fsid) {
  return (fsid.nodetype == FS_NODE_DIR || fsid.nodetype == FS_NODE_FILE);
}
static inline int FSID_isNull(FSID fsid) {
  return (fsid.nodetype == 0);
}

static inline void FSID_print(FSID id) {
  unsigned long long nodeid = id.nodeid;

#ifndef __NEXUSKERNEL__
  printf("(%d:%d:%d %d)", (int)id.port, (int)id.nodetype, ((int*)&nodeid)[0], ((int*)&nodeid)[1]);
#else
  printk("(%d:%d:%d %d)", (int)id.port, (int)id.nodetype, ((int*)&nodeid)[0], ((int*)&nodeid)[1]);
#endif
}

// File system limit:
#define MAX_FNAME_LEN (255)

#ifndef __NEXUSKERNEL__

int nexus_chroot(FSID new_fs_root);
FSID fsid_from_fd(int fd);

#endif

#endif // _FS_H_
