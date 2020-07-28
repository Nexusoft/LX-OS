#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>

using std::cerr;
using std::vector;
using std::string;

#include <nq/gcmalloc.h>
#include <pthread.h>
#include <nq/netquery.h>
#include <nq/tuple.hh>
#include <nq/transaction.hh>

#include <nq/net_elements.hh>
#if 0
#include <nq/ip.hh>
#include <nq/util.hh>
#endif

struct T_VectorNode : T_Tuple {
  T_Vector<int32_t> int_vector;
  T_VectorNode(Transaction &transaction) :
    T_Tuple(transaction),
    int_vector(this, "T_VectorNode.int_vector")
  { }

  T_VectorNode(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid),
    int_vector(this, "T_VectorNode.int_vector")
  { };

  virtual void tspace_create(void) throw(NQ_Access_Exception) {
    tspace_create_generic("VectorNode");
  }
};

struct T_TreeNode : T_Tuple {
  T_int32 int_val;
  T_int32 is_leaf;
  T_string str_val;
  T_Reference<T_TreeNode> left, right;

  T_TreeNode(Transaction &transaction) :
    T_Tuple(transaction),
    int_val(this, "T_TreeNode.int_val"),
    is_leaf(this, "T_TreeNode.is_leaf"),
    str_val(this, "T_TreeNode.str_val"),
    left(this, "T_TreeNode.left"),
    right(this, "T_TreeNode.right")
  { }

  T_TreeNode(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid),
    int_val(this, "T_TreeNode.int_val"),
    is_leaf(this, "T_TreeNode.is_leaf"),
    str_val(this, "T_TreeNode.str_val"),
    left(this, "T_TreeNode.left"),
    right(this, "T_TreeNode.right")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception) {
    tspace_create_generic("TreeNode");
  }

  static int combine_int(T_TreeNode *l, T_TreeNode *r) {
    return l->int_val + r->int_val;
  }

  static string combine_string(T_TreeNode *l, T_TreeNode *r) {
    return string("(") + (string)l->str_val + string(" . ") +
      (string)r->str_val + string(")");
  }

  bool integrity_check(int &leaf_count)  throw(NQ_Access_Exception) {
    int i_val = int_val;
    string s_val = str_val;
    struct T_TreeNode *l = left;
    struct T_TreeNode *r = right;
    if(is_leaf) leaf_count++;
    return ((bool)(int)is_leaf) || 
      (l != NULL && r != NULL && 
       l->integrity_check(leaf_count) && r->integrity_check(leaf_count) &&
       (i_val == combine_int(l, r)) && (s_val == combine_string(l, r)));
  }
};

TSPACE_DEFINE_CLASS(VectorNode);
TSPACE_DEFINE_CLASS(TreeNode);

bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  // trust everything
  return true;
}
bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
	return true;
}


#if 0
#ifdef USE_GC
void* operator new(size_t n) {
  return GC_malloc(n);
}

void operator delete(void* p) {
  GC_free(p);
}
#endif
#endif

NQ_Tuple build_tree(Transaction *t, int val_start, int bottom_size, 
		    T_TreeNode **root_node_p,
		    vector<T_TreeNode *> &all_nodes) {
  T_TreeNode *root_node;
  // build bottom up
  int i;
  vector<T_TreeNode *> last_level;
  for(i=0; i < bottom_size; i++) {
    std::ostringstream os;
    T_TreeNode *n = new T_TreeNode(*t);
    n->tspace_create();
    all_nodes.push_back(n);

    n->int_val = val_start + i;
    os << "S(" << i << ")";
    n->str_val = os.str();
    n->is_leaf = 1;
    last_level.push_back(n);
  }

  while(last_level.size() >= 2) {
    vector<T_TreeNode *> next_level;

    // Eat two per loop iteration
    while(last_level.size() > 0) {
      T_TreeNode *n = new T_TreeNode(*t), *l, *r;
      n->tspace_create();
      all_nodes.push_back(n);

      l = last_level.back();       last_level.pop_back();
      r = last_level.back();      last_level.pop_back();

      assert(l != NULL && r != NULL);
      n->left = l;
      n->right = r;
      n->int_val = T_TreeNode::combine_int(l, r);
      n->str_val = T_TreeNode::combine_string(l, r);
      n->is_leaf = 0;
      next_level.push_back(n);
    }
    last_level = next_level;
  }
  assert(last_level.size() == 1);
  root_node = last_level.back();
  *root_node_p = root_node;
  return root_node->tid;
}

bool check_integrity(T_TreeNode *root_node, int bottom_size) {
  int leaf_count = 0;
  return root_node->integrity_check(leaf_count) && 
    leaf_count == bottom_size;
}

bool check_integrity(Transaction *t, NQ_Tuple root_tid, int bottom_size) {
  T_TreeNode *root_node = 
    dynamic_cast<T_TreeNode *>(t->get_tuple_shadow(root_tid));
  if(root_node == NULL) {
    cerr << "check integrity could not find root node!\n";
    return false;
  }
  cerr << "Root val = " << root_node->int_val << "\n";
  return check_integrity(root_node, bottom_size);
}

const int BOTTOM_SIZE = 64;
// const int BOTTOM_SIZE = 2;

void print_test_header(const string &str) {
  cerr << "=== === ===\n";
  cerr << "=== Test " << str << " ===\n";
  cerr << "=== === ===\n";
}

void FAIL(void) {
  cerr << "=============== FAIL ==============\n";
  exit(-1);
}

void SUCCESS(const string &str) {
  cerr << "====== Success (" << str << ")\n";
}

struct Spec {
  NQ_Tuple tid;
  int start;
  int bottom_size;
};

const int VECTOR_LEN = 1;
void vector_store_all(T_VectorNode *node, int count) {
  int i;
  for(i=0; i < count; i++) {
    node->int_vector[i] = i * 10;
  }
}
bool vector_load_all(T_VectorNode *node, int count) {
  int i;
  for(i=0; i < count; i++) {
    int val = node->int_vector[i];
    if(val != i * 10) {
      return false;
    }
  }
  return true;
}

bool vector_check_interleave(T_VectorNode *node, int count) {
  int i;
  for(i=0; i < count; i++) {
    int val = node->int_vector[i];
    if(i % 2 == 0) {
      if(val != i * 100) {
	return false;
      }
    } else {
      if(val != i * 10) {
	return false;
      }
    }
  }
  return true;
}

bool vector_load_all_fail(T_VectorNode *node, int count) {
  int i;
  for(i=0; i < count; i++) {
    try {
      int val;
      val = node->int_vector[i];
    } catch(NQ_Access_Exception e) {
      continue;
    }
    return false;
  }
  return true;
}

void test_vector(void) {
  print_test_header("Vector functional testing");

  if(1) {
    print_test_header("Basic commit test");
    // write values
    // read values in same transaction
    // commit
    // read values in next transaction; should be present
    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_VectorNode *node = new T_VectorNode(*t0);
    NQ_Tuple tid;
    node->tspace_create();
    cerr << "store all... ";
    vector_store_all(node, VECTOR_LEN);
    if(!vector_load_all(node, VECTOR_LEN)) {
      cerr << "Could not load everything!\n";
      exit(-1);
    }
    tid = node->tid;
    cerr << "commit... ";
    t0->commit();

    cerr << "load all... ";

    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t1->get_tuple_shadow(tid));
    if(!vector_load_all(node, VECTOR_LEN)) {
      cerr << "Could not load everything!\n";
      exit(-1);
    }
    t1->commit();
    cerr << "PASSED\n";
  }
  
  if(1) {
    print_test_header("Basic abort test");
    // write values
    // read values in same transaction
    // abort
    // read values in next transaction; should not be present
    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_VectorNode *node = new T_VectorNode(*t0);
    NQ_Tuple tid;
    node->tspace_create();
    cerr << "store all... ";
    vector_store_all(node, VECTOR_LEN);
    if(!vector_load_all(node, VECTOR_LEN)) {
      cerr << "Could not load everything!\n";
      exit(-1);
    }
    tid = node->tid;
    cerr << "abort... ";
    t0->abort();

    cerr << "load all... ";

    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t1->get_tuple_shadow(tid));
    if(node != NULL) {
      cerr << "Somehow loaded an aborted value!\n";
      exit(-1);
    }
    t1->commit();
    cerr << "PASSED\n";
  }

  if(1) {
    print_test_header("Truncate commit test");
    // truncate
    // values should be gone
    // commit
    // values should still be gone

    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_VectorNode *node = new T_VectorNode(*t0);
    NQ_Tuple tid;
    node->tspace_create();
    cerr << "store all... ";
    vector_store_all(node, VECTOR_LEN);
    tid = node->tid;
    cerr << "commit... ";
    t0->commit();

    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t1->get_tuple_shadow(tid));
    if(!vector_load_all(node, VECTOR_LEN)) {
      cerr << "Could not load everything!\n";
      exit(-1);
    }
    node->int_vector.truncate();
    if(!vector_load_all_fail(node, VECTOR_LEN)) {
      cerr << "Loaded some elements (should not happen)??\n";
      exit(-1);
    }
    cerr << "commit...";
    t1->commit();

    Transaction *t2 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t2->get_tuple_shadow(tid));
    if(!vector_load_all_fail(node, VECTOR_LEN)) {
      cerr << "Loaded some elements (should not happen)??\n";
      exit(-1);
    }
    t2->commit();
    cerr << "PASSED\n";
  }

  if(1) {
    print_test_header("Truncate abort test");
    // truncate
    // values should be gone
    // abort
    // values should still be present

    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_VectorNode *node = new T_VectorNode(*t0);
    NQ_Tuple tid;
    node->tspace_create();
    cerr << "store all... ";
    vector_store_all(node, VECTOR_LEN);
    tid = node->tid;
    cerr << "commit... ";
    t0->commit();

    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t1->get_tuple_shadow(tid));
    if(!vector_load_all(node, VECTOR_LEN)) {
      cerr << "Could not load everything!\n";
      exit(-1);
    }
    node->int_vector.truncate();
    if(!vector_load_all_fail(node, VECTOR_LEN)) {
      cerr << "Loaded some elements (should not happen)??\n";
      exit(-1);
    }
    cerr << "abort... ";
    t1->abort();

    Transaction *t2 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t2->get_tuple_shadow(tid));
    if(!vector_load_all(node, VECTOR_LEN)) {
      cerr << "Couldn't load all elements??\n";
      exit(-1);
    }
    t2->commit();
    cerr << "PASSED\n";
  }

  if(1) {
    print_test_header("Read checks");
    // Don't allow reads of uninitialized values
    // ( write something greater than test target )

    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_VectorNode *node = new T_VectorNode(*t0);
    NQ_Tuple tid;
    node->tspace_create();
    node->int_vector[10] = 1;
    if(!vector_load_all_fail(node, 1)) {
      cerr << "read did not fail like it should have\n";
      exit(-1);
    }
    tid = node->tid;
    t0->commit();

    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t1->get_tuple_shadow(tid));
    if(!vector_load_all_fail(node, 1)) {
      cerr << "read did not fail like it should have\n";
      exit(-1);
    }
    // Don't allow out of bound reads
    bool passed = false;
    try {
      int x; x = node->int_vector[-1];
    } catch(NQ_Access_Exception e) {
      passed = true;
    }
    if(!passed) {
      cerr << "did not fail like it should have\n";
      exit(-1);
    }
    passed = false;
    try {
      int x; x = node->int_vector[11];
    } catch(NQ_Access_Exception e) {
      passed = true;
    }
    if(!passed) {
      cerr << "did not fail like it should have\n";
      exit(-1);
    }
    t1->commit();

    cerr << "Passed\n";
  }

  if(1) {
    print_test_header("Multiple updates checks");
    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_VectorNode *node = new T_VectorNode(*t0);
    NQ_Tuple tid;
    node->tspace_create();
    int i;
    cerr << "write original... ";
    for(i=0; i < VECTOR_LEN; i++) {
      node->int_vector[i] = i * 10;
    }
    tid = node->tid;
    t0->commit();

    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t1->get_tuple_shadow(tid));
    cerr << "write interleave... ";
    for(i=0; i < VECTOR_LEN; i++) {
      if(i % 2 == 0) {
	node->int_vector[i] = i * 100;
      }
    }
    cerr << "check interleave 1... ";
    if(!vector_check_interleave(node, VECTOR_LEN)) {
      cerr << "interleave fail!\n";
      exit(-1);
    }
    t1->commit();

    Transaction *t2 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    node = dynamic_cast<T_VectorNode *>(t2->get_tuple_shadow(tid));
    cerr << "check interleave 2... ";
    if(!vector_check_interleave(node, VECTOR_LEN)) {
      cerr << "interleave fail!\n";
      exit(-1);
    }
    t2->commit();
  }
}

void test_individual(void) {
  print_test_header("Individual node");
  Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  T_TreeNode *n = new T_TreeNode(*t0);
  n->tspace_create();
  n->left = n;
  n->right = n;
  n->int_val = -1;
  n->str_val = string("foo");
  NQ_Tuple root_tid = n->tid;
  cerr << "obj = " << *n << "\n";
  cerr << "tid = " << root_tid << "\n";

  if(! (n->left.load() == n && n->right.load() == n &&
	n->int_val.load() == -1 && n->str_val.load() == "foo")) {
    cerr << "individual failure\n";
    FAIL();
  }
  cerr << "Individual success\n";
  t0->commit();
}

void test_abort_tree(void) {
  print_test_header("Tree structure (single abort)");
  Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  NQ_Tuple root_tid;
  T_TreeNode *root_node = NULL;
  vector<T_TreeNode*> all_nodes;

  root_tid = build_tree(t1, 0, BOTTOM_SIZE, &root_node, all_nodes);
  cerr << "Checking integrity (before commit)...";
  if(!check_integrity(root_node, BOTTOM_SIZE)) {
    cerr << "failed!\n";
    FAIL();
  } else {
    cerr << "passed\n";
  }

  t1->abort();

  Transaction *t2 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);

  cerr << "Checking if any of the nodes can be found\n";
  size_t i;
  for(i=0; i < all_nodes.size(); i++) {
    NQ_Tuple tid = all_nodes[i]->tid;
    T_TreeNode *root_node = 
      dynamic_cast<T_TreeNode *>(t2->get_tuple_shadow(tid));
    if(root_node != NULL) {
      cerr << "Found a node?\n";
      FAIL();
    }
  }
  cerr << "No nodes found (this is good)\n";
  cerr << "Checking integrity...";
  // integrity check check tspace map
  if(check_integrity(t2, root_tid, BOTTOM_SIZE)) {
    cerr << "found! (failure)!\n";
    FAIL();
  } else {
    cerr << "not found! (success)!\n";
  }
  t2->abort();
}

void test_one_tree(void) {
  print_test_header("Tree structure (single)");
  // Tree. Every node is associated with a string (int).  The string
  // (int) at every node is the concatenation (summation) of the
  // strings (int) of the immediate children.
  Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  NQ_Tuple root_tid;
  T_TreeNode *root_node = NULL;
  vector<T_TreeNode*> all_nodes;

  root_tid = build_tree(t1, 0, BOTTOM_SIZE, &root_node, all_nodes);

  // integrity check check tspace map
  cerr << "Checking integrity (before commit)...";
  if(!check_integrity(root_node, BOTTOM_SIZE)) {
    cerr << "failed!\n";
    FAIL();
  } else {
    cerr << "passed\n";
  }

  t1->commit();
  cerr << "Commited root at " << root_tid << "\n";

  Transaction *t2 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);

  cerr << "Checking integrity after commit...";
  // integrity check check tspace map
  if(!check_integrity(t2, root_tid, BOTTOM_SIZE)) {
    cerr << "failed!\n";
    FAIL();
  } else {
    cerr << "succeeded!\n";
  }
  t2->abort();
}

class TruncateTest {
  Transaction *t1;
  T_SwitchFabric *switch_fabric;
  T_Interface *interface;
  NQ_Tuple switch_fabric_tid, interface_tid;
  int truncate_pos;
public:
  TruncateTest(int truncate_pos) : 
    t1(NULL), switch_fabric(NULL), interface(NULL), 
    truncate_pos(truncate_pos)
  {
    assert(truncate_pos <= 2);
    t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    switch_fabric = new T_SwitchFabric(*t1);
    interface = new T_Interface(*t1);
    switch_fabric->tspace_create();
    interface->tspace_create();
    switch_fabric_tid = switch_fabric->get_tid();
    interface_tid = interface->get_tid();

    switch_fabric->forwarding_table.update(0x80000000, 8, Ref<T_Interface>(*t1, interface_tid));
    do_truncate(0);
    test_truncate(0);
    t1->commit();

    t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
    // interface = new T_Interface(*t1, interface_tid);
    do_truncate(1);
    test_truncate(1);
    t1->commit();

    t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
    // interface = new T_Interface(*t1, interface_tid);
    do_truncate(2);
    test_truncate(2);
    t1->commit();

    t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
    // interface = new T_Interface(*t1, interface_tid);
    test_truncate(3);
    t1->commit();
  }
private:
  void do_truncate(int pos) {
    if(pos == truncate_pos) {
      switch_fabric->forwarding_table.truncate();
    }
  }

  void test_truncate(int pos) {
    Ref<T_Interface> ref(*t1, NQ_uuid_null);
    if(pos < truncate_pos) {
      // before truncate
      if(pos > 0) {
        assert(switch_fabric->forwarding_table.size() > 0);
      }
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) == 0);
    } else {
      // after truncate
      if(pos > 0 && pos > truncate_pos) {
        // also test size
        assert(switch_fabric->forwarding_table.size() == 0);
      }
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) != 0);
    }
  }
};

struct T_Int_Trie : T_Tuple {
  T_Trie< unsigned int > table;

  T_Int_Trie(Transaction &transaction) :
    T_Tuple(transaction),
    table(this, "IntTrie.table") { }
  T_Int_Trie(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid),
    table(this, "IntTrie.table") { }

  virtual void tspace_create(void) throw(NQ_Access_Exception) {
    tspace_create_generic("IntTrie");
  }
};

TSPACE_DEFINE_CLASS(Int_Trie);

struct Test_Trie {
  T_Int_Trie *trie;
  Transaction *t;
  Test_Trie(Transaction *_t) : t(_t) {
    trie = new T_Int_Trie(*t);
    trie->tspace_create();
  }

  Test_Trie(Transaction *_t, NQ_Tuple tid) : t(_t) {
    trie = new T_Int_Trie(*t, tid);
  }
};

Test_Trie *Test_Trie_new(Transaction *t) {
  return new Test_Trie(t);
}

Test_Trie *Test_Trie_new(Transaction *t, NQ_Tuple tid) {
  return new Test_Trie(t, tid);
}

void Test_Trie_delete(Test_Trie *x) {
  printf("Test_Trie_delete() doesn't really delete\n");
}

struct Test_Trie_Entry {
  unsigned int prefix;
  unsigned int plen;
  unsigned int value;
  Test_Trie_Entry() { }
  Test_Trie_Entry(unsigned int a, unsigned int b, unsigned int c) :
    prefix(a), plen(b), value(c) { }
};

int fib_write_size = 100000;

void Test_Trie_write(Test_Trie *trie, const Test_Trie_Entry &ent) {
  trie->trie->table.update(ent.prefix, ent.plen, ent.value);
}

void Test_Trie_remove(Test_Trie *trie, unsigned int prefix, int plen) {
  trie->trie->table.erase(prefix, plen);
}

int Test_Trie_lookup(Test_Trie *trie, unsigned int address, Test_Trie_Entry *result) {
  unsigned int value;
  int rv = trie->trie->table.lookup(address, &value);
  if(rv == 0) {
    result->prefix = address;
    result->plen = -1;
    result->value = value;
  }
  return rv;
}

int Test_Trie_load_nth(Test_Trie *trie, int i, Test_Trie_Entry *result) {
  try {
    TrieValue<unsigned int> value = trie->trie->table.load(i);
    //unsigned int value = trie->trie->table.load(i).load();
    // XXX trie interface does not currently return the responsible index
    result->prefix = value.h.prefix;
    result->plen = value.h.prefix_len;
    result->value = value.val;
    return 0;
  } catch(NQ_Access_Exception &e) {
    return -1;
  }
}

extern void *g_last_write_trie;
extern "C" {
  extern void NQ_Trie_delete(void *);
};

int check_read(Test_Trie *t, unsigned int ip, unsigned int check_val) {
  Test_Trie_Entry entry;
  int rv = Test_Trie_lookup(t, ip, &entry);
  return rv == 0 && entry.value == check_val;
}

void count_matches(Test_Trie *t, int *s, int *l) {
  uint32_t short_tests[2] = { 0x01000000, 0x01000001 };
  uint32_t long_tests[2] = { 0x01010000, 0x01010001 };
  int result, rv;
  *s = 0;
  *l = 0;
  int i;
  // rv = NQ_Trie_read(trie, array[temp], &result_tmp);
  // result = (unsigned int) result_tmp;
  for(i=0; i < 2; i++) {
    Test_Trie_Entry _result;
    rv = Test_Trie_lookup(t, short_tests[i], &_result);
    result = (int)_result.value;
    if(rv == 0 && result == 0xdead) {
      *s += 1;
    }
    if(rv == 0 && result == 0xbeef) {
      *l += 1;
    }
    rv = Test_Trie_lookup(t, long_tests[i], &_result);
    result = (int)_result.value;
    if(rv == 0 && result == 0xdead) {
      *s += 1;
    }
    if(rv == 0 && result == 0xbeef) {
      *l += 1;
    }
  }
}

static void fill_bigtable(Test_Trie *trie, int limit) {
  int i;
  for(i=0; i < limit / 2; i++) {
    int v = i << 8;
    Test_Trie_Entry entry;
    entry.prefix = v;
    entry.plen = 24;
    entry.value = v;
    Test_Trie_write(trie, entry);
    v |= 0x80;
    entry.prefix = v;
    entry.plen = 25;
    entry.value = v;
    Test_Trie_write(trie, entry);
  }
}

static void check_bigtable(Test_Trie *trie, int limit, int type, int random_change) {
  int i;
  int count_24 = 0, count_25 = 0;
  int not_found = 0;
  unsigned char *found = new unsigned char[limit];
  memset(found, 0, limit);
  for(i=0; i < limit + 10; i++) {
    // printf("[%d]", i);
    Test_Trie_Entry entry;

    if(random_change && (rand() % 500 == 0)) {
      int pos = rand() % limit;
      int val = pos << 7;
      int len = (pos & 0x1) ? 25 : 24;
      Test_Trie_remove(trie, val, len);
      Test_Trie_write(trie, Test_Trie_Entry(val, len, val));
    }

    // printf("Check %d\n", i);
    int rv;
    if(type == 0) {
      rv = Test_Trie_lookup(trie, i << 7, &entry);
    } else {
      rv = Test_Trie_load_nth(trie, i, &entry);
    }
    if(i < limit) {
      if(type == 0) {
        if(!((rv == 0 ) && (entry.value == ((unsigned)i) << 7))) {
          *(char *)0 = 0;
        }
        assert(rv == 0 && (entry.value == ((unsigned)i) << 7));
      } else {
        assert(rv == 0 && 
               (unsigned int)0 <= (entry.prefix & ~0x80) && (entry.prefix & ~0x80) < (unsigned int) ((limit / 2) << 8) && 
               (entry.value == entry.prefix));
        if(entry.plen == 24) {
          assert((entry.value & 0x80) == 0);
          count_24 += 1;
        } else if(entry.plen == 25) {
          count_25 += 1;
          assert((entry.value & 0x80) == 0x80);
        } else {
          assert(0);
        }
      }
      // check for duplicates
      int j = entry.value >> 7;
      assert(0 <= j && j < limit);
      assert(found[j] == 0);
      found[j] = 1;
    } else {
      not_found++;
      assert(rv != 0);
    }
  }
  if(type == 1) {
    assert(count_24 == limit / 2);
    assert(count_25 == limit / 2);
  }
  printf("Stats: # of */24 = %d, # of */25 = %d, # not found = %d\n",
         count_24, count_25, not_found);
  for(i=0; i < limit; i++) {
    // check that everything was found
    assert(found[i]);
  }
}

#define ALLOC_PING()     printf("Alloc <%d>: ", __LINE__); print_alloc_count();

void test_trie(int count) {
  print_test_header("Trie test");
  if(1) {
    cerr << "1. Simple test: Create table, read it in current transaction, then read it after transaction commits\n";

    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_SwitchFabric *switch_fabric = new T_SwitchFabric(*t1);
    T_Interface *interface[2];
    NQ_Tuple interface_tid[2], switch_fabric_tid;
    switch_fabric->tspace_create();
    switch_fabric_tid = switch_fabric->get_tid();

    for(int i=0; i < 2; i++) {
      interface[i] = new T_Interface(*t1);
      interface[i]->tspace_create();
      interface_tid[i] = interface[i]->get_tid();
    }
ALLOC_PING();
    // lookup, update, erase, size
    {
      switch_fabric->forwarding_table.update(0x80000000, 8, Ref<T_Interface>(interface[0]));
      Ref<T_Interface> ref(*t1, NQ_uuid_null);
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) == 0 &&
             ref.load()->tid == interface_tid[0]);
      assert(switch_fabric->forwarding_table.lookup(0x80000001, &ref) == 0 &&
             ref.load()->tid == interface_tid[0]);
      assert(switch_fabric->forwarding_table.lookup(0x90000000, &ref) != 0);

      switch_fabric->forwarding_table.update(0x80000000, 8, Ref<T_Interface>(interface[1]));
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) == 0 &&
             ref.load()->tid == interface_tid[1]);
      assert(switch_fabric->forwarding_table.lookup(0x80000001, &ref) == 0 &&
             ref.load()->tid == interface_tid[1]);
      assert(switch_fabric->forwarding_table.lookup(0x90000000, &ref) != 0);
    }
ALLOC_PING();

    t1->commit();
    cerr << "Commit done\n";
    {
      cerr << "Reading data stored in previous transaction\n";
      t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
      switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
      Ref<T_Interface> ref(*t1, NQ_uuid_null);

      assert(switch_fabric->forwarding_table.size() == 1);
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) == 0 &&
             ref.load()->tid == interface_tid[1]);
      assert(switch_fabric->forwarding_table.lookup(0x80000001, &ref) == 0 &&
             ref.load()->tid == interface_tid[1]);
      assert(switch_fabric->forwarding_table.lookup(0x90000000, &ref) != 0);

      t1->abort();
    }
ALLOC_PING();
    {
      cerr << "Updating entry and looking up again\n";
      Ref<T_Interface> ref(*t1, NQ_uuid_null);

      cerr << "Same txn\n";
      t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
      switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
      switch_fabric->forwarding_table.update(0x80000000, 8, Ref<T_Interface>(*t1, interface_tid[0]));
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) == 0 &&
             ref.load()->tid == interface_tid[0]);
      t1->commit();

      cerr << "Other txn\n";
      t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
      switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
      assert(switch_fabric->forwarding_table.size() == 1);
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) == 0 &&
             ref.load()->tid == interface_tid[0]);
      t1->abort();

      cerr << "Remove, same txn\n";
      t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
      switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
      switch_fabric->forwarding_table.erase(0x80000000, 8);
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) != 0);
      t1->commit();

      cerr << "Remove, next txn\n";
      t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
      switch_fabric = new T_SwitchFabric(*t1, switch_fabric_tid);
      assert(switch_fabric->forwarding_table.size() == 0);
      assert(switch_fabric->forwarding_table.lookup(0x80000000, &ref) != 0);
      t1->commit();

      cerr << "Test truncate 0\n";
      TruncateTest _t0(0);
      cerr << "Test truncate 1\n";
      TruncateTest _t1(1);
      cerr << "Test truncate 2\n";
      TruncateTest _t2(2);
      cerr << "Test truncate done\n";
    }
ALLOC_PING();
  } else {
    cerr << "Skipping simple high level test\n";
  }
  {
ALLOC_PING();
    int i;
    // xxx no mem allocation instrumetation
    int alloc_bytes = 0;
    int free_bytes = 0;

    cerr << "2. High level version of low level test\n";
    Transaction *t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
#if 0
    switch_fabric = new T_SwitchFabric(*t);
    switch_fabric->tspace_create();
    switch_fabric_tid = switch_fabric->get_tid();
#endif
    int limit = fib_write_size;
    assert(limit >= count);

    srandom(time(NULL));

    unsigned int *array = new unsigned int[count];

    int a[5];
    int f[5];
    a[0] = alloc_bytes;
    f[0] = free_bytes;
    Test_Trie *trie = Test_Trie_new(t);
    unsigned int temp;
    const unsigned int len = 24;
    int rv;
    unsigned int result;

    for(i = 1; i < count; i++) {
      temp = random() & ~0xff;
      Test_Trie_write(trie, Test_Trie_Entry(temp, len, i));

      array[i] = temp;

      temp = (random() % i) + 1;
      Test_Trie_Entry _result;
      rv = Test_Trie_lookup(trie, array[temp], &_result);
      result = _result.value;
      // printf("read(%x)=>%p\n", array[temp], result_tmp);
      if(rv != 0 || result != temp){
        //      printf("Eeek!  Tried to read %x/%d (%d) and got %d instead!  (not a failure... just a factor of randomness: %x/%d is a prefix of %x/%d\n", array[temp]>>8, 24, temp, result);
        //      assert(array[result]);
        printf("Mismatch!\n");
      }
    }
    printf("high level committing\n");
    t->commit();

    a[1] = alloc_bytes;
    f[1] = free_bytes;
    Test_Trie_delete(trie);
    a[2] = alloc_bytes;
    f[2] = free_bytes;

    // Focused tests

    printf("Longest prefix test\n");
    t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    Test_Trie *trie2 = Test_Trie_new(t);
    uint32_t _short = 0x01000000; // 1.0.0.0 / 8
    uint32_t _long = 0x01010000; // 1.1.0.0 / 16
    int s, l;
    count_matches(trie2, &s, &l);
    assert(s == 0 && l == 0);
    Test_Trie_write(trie2, Test_Trie_Entry(_short, 8, 0xdead));
    count_matches(trie2, &s, &l);
    assert(s == 4 && l == 0);
    Test_Trie_write(trie2, Test_Trie_Entry(_long, 16, 0xbeef));
    count_matches(trie2, &s, &l);
    assert(s == 2 && l == 2);
    Test_Trie_remove(trie2, _long, 16);
    count_matches(trie2, &s, &l);
    assert(s == 4 && l == 0);
    Test_Trie_remove(trie2, _short, 8);
    count_matches(trie2, &s, &l);
    assert(s == 0 && l == 0);

    Test_Trie_write(trie2, Test_Trie_Entry(_long, 16, 0xbeef));
    count_matches(trie2, &s, &l);
    assert(s == 0 && l == 2);
    t->commit();

    // xxx need better exhaustive prefix test

    t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    trie2 = NULL;
    Test_Trie *trie3 = Test_Trie_new(t);
    printf("Overwrite test\n");
    assert(!check_read(trie3, _long, 0xbeef) && !check_read(trie3, _long, 0xdead));
    Test_Trie_write(trie3, Test_Trie_Entry(_long, 16, 0xbeef));
    assert(check_read(trie3, _long, 0xbeef) && !check_read(trie3, _long, 0xdead));
    Test_Trie_write(trie3, Test_Trie_Entry(_long, 16, 0xdead));
    assert(!check_read(trie3, _long, 0xbeef) && check_read(trie3, _long, 0xdead));
    t->commit();

    printf("Performance test\n");
    t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner, true);
    trie3 = NULL;
    Test_Trie *trie4 = Test_Trie_new(t);
    printf("Insertion performance, limit = %d\n", limit);
    time_t start_time;
    time_t end_time;
#define START_DELTA()                           \
    start_time = time(NULL)
#define PRINT_DELTA(L)                                          \
    end_time = time(NULL);                                      \
    printf("%d s to %s\n", (int)(end_time - start_time), L);

    START_DELTA();
    a[3] = alloc_bytes;
    f[3] = free_bytes;
    printf("Alloc before bigtable: "); print_alloc_count();
    fill_bigtable(trie4, limit);
    printf("Alloc after bigtable: "); print_alloc_count();
    // dump_memtrace("/tmp/obj-big.txt");
    a[4] = alloc_bytes;
    f[4] = free_bytes;
    PRINT_DELTA("insert");
    
    NQ_Tuple trie_tid = trie4->trie->get_tid();
    t->commit();
    printf("Alloc after bigtable commit: "); print_alloc_count();
    dump_memtrace("/tmp/obj-big-commit.txt");
    printf("Sem stats\n");
    NQ_print_sem_stats();

    t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    trie4 = Test_Trie_new(t, trie_tid);
    printf("Nth test\n");
    START_DELTA();
    check_bigtable(trie4, limit, 1, 0);
    PRINT_DELTA("check1");

    START_DELTA();
    check_bigtable(trie4, limit, 0, 0);
    PRINT_DELTA("check0");
#if 0
    // nth does not support random deletes
    printf("Nth test (with random deletes)\n");
    START_DELTA();
    check_bigtable(trie4, limit, 0, 1);
    PRINT_DELTA("check invalidate");
#endif

      printf("xxx need remove entry not in table\n");

    printf("--------------------------------------------------\n");
    printf("  Trie test successful\n");
    printf("  Prefixes: %d (avg length: %d)\n", count, len);
    printf(" Allocation: %d %d ;  %d %d  ; %d %d\n",
           a[0], f[0], a[1], f[1], a[2], f[2]);
    printf("Size of big table (%d entries) = %d\n", limit, (a[4] - f[4]) - (a[3] - f[3]));
    print_alloc_count();

    int before_total = a[0] - f[0];
    int after_total = a[2] - f[2];
    if(before_total != after_total) {
      printf("after total is not same as before total! %d %d\n", after_total, before_total);
    }
    printf("--------------------------------------------------\n");
#if 0
#endif
ALLOC_PING();
  }

  {
    cerr << "3. Insert override check\n";
    cerr << "xxx not implemented\n";
    exit(-1);
  }

  {
    cerr << "4. Delete slow path\n";
    cerr << "xxx not implemented\n";
    exit(-1);

    cerr << "5. Delete slow path + override\n";
    // original : 24, 16; insert 20 ; delete 24, should get new 20; current and next transaction
    cerr << "transaction interleave not implemented!\n";
  }
}

void test_multiple_trees(void) {
  print_test_header("Tree structure (multiple trees)");
  Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  vector<Spec> specs;
  size_t i;
  int start = 0;
  int bottom_size = 4;
  for(i=0; i < 4; i++,
	bottom_size *= 2, start = bottom_size) {
    vector<T_TreeNode*> all_nodes;
    T_TreeNode *root_node = NULL;
    NQ_Tuple root_tid = build_tree(t1, start, bottom_size, &root_node, all_nodes);
    Spec spec;

    spec.tid = root_tid;
    spec.start = start;
    spec.bottom_size = bottom_size;
    specs.push_back(spec);
  }
  t1->commit();
  Transaction *t2 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  for(i = 0; i < specs.size(); i++) {
    check_integrity(t2, specs[i].tid, specs[i].bottom_size);
  }
  t2->abort();
  cerr << "Got to the end (probably succeeded!)\n";
}

extern "C"  { void quicktest(int); }

void * test_thread(void*) {
  if(0) {
    test_vector();
  }
  
  if(0) {
    test_individual();
  }

  if(0) {
    test_one_tree();
  }

  if(0){
    test_abort_tree();
  }

  if(1) {
    test_trie(1000);
  }

  if(1){
    test_multiple_trees();
  }


  // Integer vector
  // Vector of trees.

  // Scalar EndpointIdentifier
  // Vector of EndpointIdentifiers

  // Graph (DFS to count number of nodes, find node with particular value)
  exit(0);
  return NULL;
}

int main(int argc, char **argv) {
  // quicktest(1000);
ALLOC_PING();
  NQ_init(0);
  NQ_cpp_lib_init();
ALLOC_PING();

  TSPACE_ADD_CLASS(VectorNode);
  TSPACE_ADD_CLASS(TreeNode);

  if(argc > 1) {
    fib_write_size = atoi(argv[1]);
  }

ALLOC_PING();
  pthread_t thread;
  pthread_create(&thread, NULL, test_thread, NULL);
  pthread_join(thread, NULL);
}
