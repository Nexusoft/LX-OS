#ifndef _FS_H_
#define _FS_H_

#ifdef __NEXUSKERNEL__
#include <asm/types.h>
#else
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#endif

#include <nexus/ipc.h>

#define MAX_FNAME_LEN (255)

// FS call error codes
#define FS_INVALID	  (1)
#define FS_NOTFOUND	  (2)
#define FS_UNSUPPORTED	  (3)
#define FS_NOMEM	  (4)
#define FS_ACCESSERROR	  (5)
#define FS_BADTRUNCATE	  (6)
#define FS_ALREADYPRESENT (7)
#define FS_BUSY		  (8)
#define FS_NOTEMPTY	  (9)
#define FS_NOTDIR	  (10)
#define FS_ISDIR	  (11)
#define FS_STALE	  (12)
#define FS_BADCOOKIE	  (13)
#define FS_QUOTA_SET      (14)

// node types (mutually exclusive)
#define FS_NODE_FILE 0x1
#define FS_NODE_DIR  0x2
#define FS_NODE_DEV  0x4

/// ID for all file and directory objects (similar to an inode)
struct FSID {
	int port;
	unsigned long long nodetype : 8;  	///< node types defined above
	long long nodeid : 56;
};

/// a way to print the FSID
struct FSID_pretty {
	int port;
	unsigned long long upper;
};

typedef struct FSID FSID;

/// ugly hack to be able to print the upper 64 bits
static inline unsigned long long 
fsid_upper(FSID *node) 
{
	return ((struct FSID_pretty *) node)->upper;
}

#define FSID_EMPTY ((FSID) { .port = 0, .nodetype = 0, .nodeid = 0 })
// note: the -1 used here for errors must match the -1 used in idl-generated IPC failure case
#define FSID_ERROR(err) ((FSID) { .port = -1, .nodetype = -1, .nodeid = -(err) })
#define FSID_INVALID FSID_ERROR(FS_INVALID)
#define FSID_DIR(theport, id) ((FSID) { .port = (theport), .nodetype = FS_NODE_DIR, .nodeid = (id) })
#define FSID_DEV(theport, id) ((FSID) { .port = (theport), .nodetype = FS_NODE_DEV, .nodeid = (id) })
#define FSID_FILE(theport, id) ((FSID) { .port = (theport), .nodetype = FS_NODE_FILE, .nodeid = (id) })
#define FSID_ROOT(theport) FSID_DIR(theport, 0)

static inline int FSID_equal(FSID one, FSID two) {
  return (one.port == two.port &&
	  one.nodetype == two.nodetype &&
	  one.nodeid == two.nodeid) ? 1 : 0;
}

// note: the -1 used here for errors must match the -1 used in idl-generated IPC failure case
static inline int FSID_getError(FSID fsid) {
  return ((char)fsid.nodetype == -1 ? (int)fsid.nodeid : 0);
}
static inline int FSID_isDir(FSID fsid) {
  return ((char)fsid.nodetype == FS_NODE_DIR && !__IPCPort_checkrange(fsid.port));
}
static inline int FSID_isFile(FSID fsid) {
  return ((char)fsid.nodetype == FS_NODE_FILE && !__IPCPort_checkrange(fsid.port));
}
static inline int FSID_isDev(FSID fsid) {
  return ((char)fsid.nodetype == FS_NODE_DEV && !__IPCPort_checkrange(fsid.port));
}
static inline int FSID_isRoot(FSID fsid) {
  return ((char)fsid.nodetype == FS_NODE_DIR && fsid.nodeid == 0 && !__IPCPort_checkrange(fsid.port));
}
static inline int FSID_isValid(FSID fsid) {
  return (FSID_isDir(fsid) || FSID_isFile(fsid) || FSID_isDev(fsid));
}
static inline int FSID_isNull(FSID fsid) {
  return ((char)fsid.nodetype == 0);
}

#endif // _FS_H_

