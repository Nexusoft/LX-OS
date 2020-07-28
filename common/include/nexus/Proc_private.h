#ifndef _PROC_PRIVATE_H_
#define _PROC_PRIVATE_H_

// #include "types.h"
#include <asm/types.h>
#include "pthread.h"
#include "util.h"
#include "hashtable.h"
#include "vector.h"

extern struct HashTable *id_table;
extern Sema *id_table_mutex;

// format of node id:
// 5 MSbs - node type
// 32 LSbs - sequential identifier (shared, type is procnodeseq)
typedef __u32 ProcNodeSeq;

enum ProcNodeType {
  ProcNode_GENERIC = 0x1, 
  ProcNode_RESOURCE = 0x2, 

  ProcNode_INTERFACE = 0x5,

  ProcNode_SET = 0x6,
  ProcNode_LIST = 0x7,

  ProcNode_PROPERTY = 0x8, ProcNode_OPCAP = 0x9, ProcNode_PATH = 0xa,

};

#define ProcNode_IMPLEMENTS_PROPERTY(N)		\
  (((N)->type == ProcNode_PROPERTY) ||		\
   ((N)->type == ProcNode_OPCAP) ||		\
   ((N)->type == ProcNode_PATH))
#define ProcNode_IS_INTERFACE(N) ((N)->type ==ProcNode_INTERFACE)
#define ProcNode_IS_PATH(N) ((N)->type ==ProcNode_PATH)

struct GenericNode;
struct GenericSet;
struct PathNode;

struct ChildrenCollection {
  PointerVector vec;
  struct HashTable *hash;
};

void ChildrenCollection_init(ChildrenCollection *coll);
void ChildrenCollection_destroyMembers(ChildrenCollection *coll);

static inline void ChildrenCollection_setOrderPreserving(ChildrenCollection *coll, int orderPreserving) {
  PointerVector_setOrderPreserving(&coll->vec, orderPreserving);
}

void ChildrenCollection_add(ChildrenCollection *coll, struct GenericNode *child);
void ChildrenCollection_delete(ChildrenCollection *coll, struct GenericNode *child);
// find does not support multiple path components!
struct GenericNode *ChildrenCollection_find(ChildrenCollection *coll, char *name);
struct GenericNode *ChildrenCollection_nth(ChildrenCollection *coll, int n);
int ChildrenCollection_len(ChildrenCollection *coll);

typedef int (*GenericNode_AllowChildFunc)(struct GenericNode *parent, struct GenericNode *child);
typedef void (*GenericNode_Destructor)(struct GenericNode *parent);
// typedef int (*GenericNode_LookupFunc)(GenericNode *node, char *filename);


#define GN_UNLINKED (0x1)
struct GenericNode {
  struct PathNode *generated_by;
  struct PathNode *managed_by;

  struct GenericSet *interfaces; // interfaces, allowChild restrict to just Interfaces 
  struct GenericSet *other_names; // paths, allowChild restrict to just Paths
  struct PathNode *canonical_name;

  // Additional nodes, expanded inline
  ChildrenCollection fixed_children; // pointers to fixed children classes. The ones above are inserted in here
  ChildrenCollection children; // GenericNode

  // internal
  char *name; // dynamically allocated
  enum ProcNodeType type;
  FSID node_id;
  int refcnt;
  Sema *mutex;

  int flags;
  int can_have_children;
  int can_have_contents;

  GenericNode_AllowChildFunc allowChild;
  GenericNode_Destructor destructor;
  // GenericNode_LookupFunc lookup;
#if 0
  int (*mread)(GenericNode *node, struct VarLen dest,
	       struct MReadCont mread_cont, int flags);
#endif

  int is_mount_point;

  // subscription lists go here
};

struct GenericList {
  GenericNode generic;
};

struct GenericSet {
  GenericNode generic;
};

// Generic needs to be in the same position for all of the below
struct ResourceNode {
  GenericNode generic;
};

struct PropertyNode;
typedef char *(*PropertyNode_AsString)(struct PropertyNode *);
typedef int (*PropertyNode_FromString)(struct PropertyNode *, const char *);
typedef char *(*PropertyNode_ValueDestructor)(char *);

struct PropertyNode {
  GenericNode generic;

  // internal 
  char *value_data;
  char *asStringCache;

  PropertyNode_AsString value_asString;
  PropertyNode_FromString value_fromString; // returns 0 if success
  PropertyNode_ValueDestructor value_destructor;
};

// OpCap property
enum OpCapCheckerType {
  UNSET,
  LFUNC,
  HASH,
};
struct OpCapNode {
  struct PropertyNode property;
  // value_asString: strdup() the string
  // value_fromString: any string
  // value_destructor: gfree

  // hidden
  enum OpCapCheckerType checkerType;
  struct OpCapNode *checker; // null if hash checker
  struct PropertyNode *hash_checker;
};

struct PathNode {
  struct PropertyNode property;
  // value_asString: strdup() the string
  // value_destructor: gfree
};

struct InterfaceNode {
  GenericNode generic;

  OpCapNode *opcap;
};


ProcNodeSeq ProcNodeSeq_allocNext(void);
// void GenericNode_init(GenericNode *node, const char *name, enum ProcNodeType type, int isTerminal);
// this inserts the ID into the table
void GenericNode_assignID(GenericNode *node);
// returns 0 if success, nonzero if error
int GenericNode_addChild(GenericNode *parent, GenericNode *child);

void GenericNode_setChildConstraint(GenericNode *node, GenericNode_AllowChildFunc allowChild);

void GenericNode_get(GenericNode *node);
void GenericNode_put(GenericNode *node);

static GenericNode *GenericNode_find(FSID id) {
  GenericNode *node = (GenericNode *)hash_findItem(id_table, &id);
  if(node == NULL) return NULL;
  GenericNode_get(node);
  return node;
}
void GenericNode_find_and_remove(FSID id) {
  void *entry, *prev;
  entry = hash_findEntry(id_table, &id, &prev);
  hash_deleteEntry(id_table, entry, prev);
}

//// ResourceNode
ResourceNode *ResourceNode_new(const char *name);

// InterfaceNode
InterfaceNode *InterfaceNode_new(const char *name);

//// GenericList
GenericList *GenericList_new(const char *name, int isTerminal);

//// GenericSet
GenericSet *GenericSet_new(const char *name, int isTerminal);

// PathNode
PathNode *PathNode_new(const char *name, int isTerminal);

#endif // _PROC_PRIVATE_H_
