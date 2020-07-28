#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_

// #include "types.h"
#include <asm/types.h>

#include <nexus/ipc.h>

#define NAMESPACE_INVALID 	(1)
#define NAMESPACE_NOTFOUND 	(2)
#define NAMESPACE_UNSUPPORTED 	(3)
#define NAMESPACE_NOMEM 	(4)
#define NAMESPACE_ACCESSERROR 	(5)
#define NAMESPACE_BADTRUNCATE 	(6)
#define NAMESPACE_ALREADYPRESENT 	(7)


#define FS_NODE_FILE 0x1
#define FS_NODE_DIR  0x2

// node types
//#define FS_NODE_IS_FILE(T) ((T)&FS_NODE_FILE)
//#define FS_NODE_IS_DIR(T)  ((T)&FS_NODE_DIR)

struct FS_NodeID {
  unsigned long long nodetype : 8;  // node types defined above
  unsigned long long nodeid : 56;
};

#define FS_NodeID_INVALID ((struct FS_NodeID) { .nodetype = -1, .nodeid = -1 })
#define FS_NodeID_ROOT ((struct FS_NodeID) { .nodetype = FS_NODE_DIR, .nodeid = 0 })

static inline int FS_NodeID_isValid(FS_NodeID id) {
  static const FS_NodeID test = FS_NodeID_INVALID;
  return memcmp(&id,&test,sizeof(test)) != 0;
}

#ifndef __NEXUSKERNEL__
static inline void FS_NodeID_print(struct FS_NodeID id) {
  unsigned long long nodeid = id.nodeid;
  printf("(%d.%d %d)", (int)id.nodetype, ((int*)&nodeid)[0], ((int*)&nodeid)[1]);
}
#else
static inline void FS_NodeID_print(struct FS_NodeID id) {
  unsigned long long nodeid = id.nodeid;
  printk("(%d.%d %d)", (int)id.nodetype, ((int*)&nodeid)[0], ((int*)&nodeid)[1]);
}
#endif // __NEXUSKERNEL__

struct NodeID {
  //__u64 mount_node; // this suffices to reconstruct NodeId of the mount node; the fs_node_id of mount_nodes == 0
  Port_Num server_port_num;
  Connection_Handle server_conn_handle;
  struct FS_NodeID fs_node_id;
};

#define NodeID_ROOT				\
  ((struct NodeID)				\
   {						\
     .server_port_num = 0,			\
       .server_conn_handle = 0,			\
       .fs_node_id = {FS_NODE_DIR ,0}			\
   })

#define NodeID_INVALID				\
  ((struct NodeID) {				\
    .server_port_num = OID_NONE,		\
       .server_conn_handle = -1,		\
       .fs_node_id = FS_NodeID_INVALID		\
       })

struct FS_NodeID_and_Rcode {
  struct FS_NodeID fs_id;
  int error_code;
};

#define FS_NodeID_and_Rcode_ERROR(ERR) ((struct FS_NodeID_and_Rcode) { .fs_id = FS_NodeID_INVALID, .error_code = -ERR })

struct NodeID_and_Rcode {
  struct NodeID fs_id;
  int error_code;
};

#define NodeID_and_Rcode_ERROR(ERR) ((struct NodeID_and_Rcode) { .fs_id = NodeID_INVALID, .error_code = -ERR })

struct FS_iovec { // this is identical to glibc iovec
  void *iov_base;   /* Starting address */
  unsigned int iov_len;   /* Number of bytes */
};

enum EventType {
  FS_UNLINKED, // directory caching: cached path is now useless
  FS_INVALIDATED,
  FS_MODIFIED,

  /*
    from these, the following can be synthesized:
    readable
    writable
  */
};

// File system limits:
// max filename length: 255
#define MAX_FNAME_LEN (255)
// max number of entries in directory: 16M


// MRead == readdir()
// Continuation == "opaque cookie, for resuming"
// Zero-continuation on request == "begin from start"
// Zero-continuation on reply == "there is nothing more after this"
struct MReadCont {
  __u32 opaque_data[4];
};

struct MReadCont_and_Rcode {
  struct MReadCont cont;
  int error_code;
};

// a sequence of back-to-back MReadDesc's are sent in response to an MRead request
// each contains the name of a subdirectory of the target directory
// an MReadDesc with a zero name_len serves as an end-of-stream sentinel
struct MReadDesc {
  __u32 name_len;
  char data[0];
};

static inline int MReadCont_isZero(struct MReadCont cont) {
  int i;
  char *c = (char *)&cont;
  for (i = 0; i < sizeof(struct MReadCont); i++) 
	  if (*c) return 0;
  return 1;
}

static inline struct MReadDesc *MReadDesc_next(struct MReadDesc *mrd) {
  return (struct MReadDesc *)(mrd->data + mrd->name_len);
}

static inline int MReadDesc_isLast(struct MReadDesc *mrd) {
  return (MReadDesc_next(mrd)->name_len == 0);
}

static inline char *MReadDesc_name(struct MReadDesc *mrd) {
  return mrd->data;
}

static inline 
char *Namespace_findFirstPathComponentEnd(char *full_path) {
  int i;
  int found_slash = 0;
  for(i=0; full_path[i] != '\0'; i++) {
    if(full_path[i] == '/') {
      found_slash = 1;
      break;
    }
  }
  return full_path + i;
}

static inline int Namespace_validatePath(const char *path) {
  int i;
  int last_was_slash = 0;
  for(i=0; path[i] != '\0'; i++) {
    if(path[i] == '/') {
      if(last_was_slash) {
	// no 2 slashes in a row
	return 0;
      }
      last_was_slash = 1;
    } else {
      last_was_slash = 0;
    }
  }
  // can't end with slash
  return !last_was_slash && strlen(path) > 0;
}

#endif // _NAMESPACE_H_
