/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 *
 *   Robert Olsson <robert.olsson@its.uu.se> Uppsala Universitet
 *     & Swedish University of Agricultural Sciences.
 *
 *   Jens Laas <jens.laas@data.slu.se> Swedish University of 
 *     Agricultural Sciences.
 * 
 *   Hans Liss <hans.liss@its.uu.se>  Uppsala Universitet
 *
 * This work is based on the LPC-trie which is originally descibed in:
 * 
 * An experimental study of compression methods for dynamic tries
 * Stefan Nilsson and Matti Tikkanen. Algorithmica, 33(1):19-33, 2002.
 * http://www.nada.kth.se/~snilsson/public/papers/dyntrie2/
 *
 *
 * IP-address lookup using LC-tries. Stefan Nilsson and Gunnar Karlsson
 * IEEE Journal on Selected Areas in Communications, 17(6):1083-1092, June 1999
 *
 * Version:	$Id: fib_trie.c,v 1.3 2005/06/08 14:20:01 robert Exp $
 *
 *
 * Code from fib_hash has been reused which includes the following header:
 *
 *
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 FIB: lookup engine and maintenance routines.
 *
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Substantial contributions to this work comes from:
 *
 *		David S. Miller, <davem@davemloft.net>
 *		Stephen Hemminger <shemminger@osdl.org>
 *		Paul E. McKenney <paulmck@us.ibm.com>
 *		Patrick McHardy <kaber@trash.net>
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <pci/types.h>
#include <arpa/inet.h>
#include <nq/trie.h>
#include <nq/netquery.h>
#include <nq/attribute.h>
#include <nq/queue.h>
#include <time.h>

#include "fib_trie.h"
#include <nq/gcmalloc.h>

//#define PING() if(big_check) printf("(%d)", __LINE__)
#define PING()

#define VERSION "0.404"

//#include "fib_lookup.h"

//#define pr_debug(X, ...) printf(X, ##__VA_ARGS__)
#define pr_debug(X, ...) 

#define smp_wmb()
#define LIST_POISON2  ((void *) 0x00200200)

#define BUG_ON(X) assert(!(X))
#define WARN_ON(X) assert(!(X))

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({                      \
      const typeof( ((type *)0)->member ) *__mptr = (ptr);      \
      (type *)( (char *)__mptr - offsetof(type,member) );})

#define rcu_dereference(X) (X)

void invoke_pending_rcu(void);
int preempt_disable_count = 0;
int read_lock = 0;
void preempt_disable(void) {
  preempt_disable_count++;
}
void preempt_enable(void) {
  if(--preempt_disable_count == 0) {
    invoke_pending_rcu();
  }
}

#define rcu_assign_pointer(p,v) ({ (p) = (v) ;})

struct rcu_head {
  QItem link;
  void (*func)(struct rcu_head *head);
};
Queue rcu_list = QUEUE_EMPTY;

void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head)) {
  if(read_lock != 0 || preempt_disable_count > 0) {
    head->func = func;
    queue_append(&rcu_list, &head->link);
  } else {
    func(head);
  }
}

void call_rcu_bh(struct rcu_head *head, void (*func)(struct rcu_head *head)) {
  if(read_lock != 0 || preempt_disable_count > 0) {
    head->func = func;
    queue_append(&rcu_list, &head->link);
  } else {
    func(head);
  }
}

void invoke_pending_rcu(void) {
  void *_head = NULL;
  // printf("invoke rcu\n");
  while(!queue_dequeue(&rcu_list, &_head)) {
    struct rcu_head *head = container_of((QItem*)_head, struct rcu_head, link);
    // printf("<%p>(%p)\n", head->func, head);
    head->func(head);
  }
}

void rcu_read_lock(void) {
  read_lock = 1;
}
void rcu_read_unlock(void) {
  read_lock = 0;
  invoke_pending_rcu();
}

struct hlist_head {
  struct hlist_node *first;
};

struct hlist_node {
        struct hlist_node *next, **pprev;
};

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each_entry_rcu(tpos, pos, head, member)		 \
	for (pos = (head)->first;					 \
	     rcu_dereference(pos) && ({ /* prefetch(pos->next); */ 1;}) && \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#define hlist_for_each_entry(tpos, pos, head, member)   \
  hlist_for_each_entry_rcu(tpos, pos, head, member)


#define hlist_for_each_entry_from(tpos, pos, member)                    \
  for (; pos && ({ /* prefetch(pos->next); */ 1;}) &&                    \
         ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;});       \
       pos = pos->next)

#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)

static inline void hlist_add_head_rcu(struct hlist_node *n,
					struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	n->pprev = &h->first;
	smp_wmb();
	if (first)
		first->pprev = &n->next;
	h->first = n;
}

static inline void hlist_add_after_rcu(struct hlist_node *prev,
				       struct hlist_node *n)
{
	n->next = prev->next;
	n->pprev = &prev->next;
	smp_wmb();
	prev->next = n;
	if (n->next)
		n->next->pprev = &n->next;
}
static inline void hlist_add_before_rcu(struct hlist_node *n,
					struct hlist_node *next)
{
	n->pprev = next->pprev;
	n->next = next;
	smp_wmb();
	next->pprev = &n->next;
	*(n->pprev) = n;
}
static inline void hlist_del_rcu(struct hlist_node *n)
{
	__hlist_del(n);
	n->pprev = LIST_POISON2;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
  return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
  return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
  return IS_ERR_VALUE((unsigned long)ptr);
}

////////////////////////////////////// End linux compatibility

#ifdef USE_TRIE_TEST_MAIN

void *count_malloc(size_t sz);
void *count_calloc(size_t nmem, size_t size);
void count_free(void *x);

#if 1
#define malloc(X) count_malloc(X)
#define calloc(X,Y) count_calloc(X,Y)
#define free(X) count_free(X)
#else
#define malloc(X) malloc(X)
#define calloc(X,Y) calloc(X,Y)
#define free(X) free(X)
#endif

#endif // USE_TRIE_TEST_MAIN

#define MAX_CHILDS 16384

//#undef CONFIG_IP_FIB_TRIE_STATS
#define CONFIG_IP_FIB_TRIE_STATS
#define CONFIG_IP_MULTIPLE_TABLES

#define KEYLENGTH (8*sizeof(t_key))
#define MASK_PFX(k, l) (((l)==0)?0:(k >> (KEYLENGTH-l)) << (KEYLENGTH-l))
#define TKEY_GET_MASK(offset, bits) (((bits)==0)?0:((t_key)(-1) << (KEYLENGTH - bits) >> offset))

typedef unsigned int t_key;

#define T_TNODE 0
#define T_LEAF  1
#define NODE_TYPE_MASK	0x1UL
#define NODE_PARENT(node)                                               \
  ((struct tnode *)rcu_dereference(((node)->parent & ~NODE_TYPE_MASK)))

#define NODE_TYPE(node) ((node)->parent & NODE_TYPE_MASK)

#define NODE_SET_PARENT(node, ptr)                              \
  rcu_assign_pointer((node)->parent,                            \
                     ((unsigned long)(ptr)) | NODE_TYPE(node))

#define IS_TNODE(n) (!(n->parent & T_LEAF))
#define IS_LEAF(n) (n->parent & T_LEAF)

struct node {
  t_key key;
  unsigned long parent;
};

struct leaf {
  t_key key;
  unsigned long parent;
  struct hlist_head list;
  struct rcu_head rcu;
};

struct leaf_info {
  struct hlist_node hlist;
  struct rcu_head rcu;
  int plen;
  // NQ-specific leaf info
  void *data;
  // struct list_head falh;
};

struct tnode {
  t_key key;
  unsigned long parent;
  unsigned short pos:5;		/* 2log(KEYLENGTH) bits needed */
  unsigned short bits:5;		/* 2log(KEYLENGTH) bits needed */
  unsigned short full_children;	/* KEYLENGTH bits needed */
  unsigned short empty_children;	/* KEYLENGTH bits needed */
  struct rcu_head rcu;
  struct node *child[0];
};

#ifdef CONFIG_IP_FIB_TRIE_STATS
struct trie_use_stats {
  unsigned int gets;
  unsigned int backtrack;
  unsigned int semantic_match_passed;
  unsigned int semantic_match_miss;
  unsigned int null_node_hit;
  unsigned int resize_node_skipped;
};
#endif

struct trie_stat {
  unsigned int totdepth;
  unsigned int maxdepth;
  unsigned int tnodes;
  unsigned int leaves;
  unsigned int nullpointers;
  unsigned int nodesizes[MAX_CHILDS];
};

struct trie {
  struct node *trie;
#ifdef CONFIG_IP_FIB_TRIE_STATS
  struct trie_use_stats stats;
#endif
  int size;
  int start;
  unsigned int revision;
};

void trie_collect_stats(struct trie *t, struct trie_stat *s);
void trie_print_stats(struct trie *t) {
  struct trie_stat stat;
  trie_collect_stats(t, &stat);
  printf("totdepth = %d, maxdepth = %d, nodes = %d, leaves = %d, nulls = %d\n", stat.totdepth, stat.maxdepth, stat.tnodes, stat.leaves, stat.nullpointers);
}

static void put_child(struct trie *t, struct tnode *tn, int i, struct node *n);
static void tnode_put_child_reorg(struct tnode *tn, int i, struct node *n, int wasfull);
static struct node *resize(struct trie *t, struct tnode *tn);
static struct tnode *inflate(struct trie *t, struct tnode *tn);
static struct tnode *halve(struct trie *t, struct tnode *tn);
static void tnode_free(struct tnode *tn);

/* rcu_read_lock needs to be hold by caller from readside */

static inline struct node *tnode_get_child(struct tnode *tn, int i)
{
  BUG_ON(i >= 1 << tn->bits);

  return rcu_dereference(tn->child[i]);
}

static inline int tnode_child_length(const struct tnode *tn)
{
  return 1 << tn->bits;
}

static inline t_key tkey_extract_bits(t_key a, int offset, int bits)
{
  if (offset < KEYLENGTH)
    return ((t_key)(a << offset)) >> (KEYLENGTH - bits);
  else
    return 0;
}

static inline int tkey_equals(t_key a, t_key b)
{
  return a == b;
}

static inline int tkey_sub_equals(t_key a, int offset, int bits, t_key b)
{
  if (bits == 0 || offset >= KEYLENGTH)
    return 1;
  bits = bits > KEYLENGTH ? KEYLENGTH : bits;
  return ((a ^ b) << offset) >> (KEYLENGTH - bits) == 0;
}

static inline int tkey_mismatch(t_key a, int offset, t_key b)
{
  t_key diff = a ^ b;
  int i = offset;

  if (!diff)
    return 0;
  while ((diff << i) >> (KEYLENGTH-1) == 0)
    i++;
  return i;
}

/*
  To understand this stuff, an understanding of keys and all their bits is 
  necessary. Every node in the trie has a key associated with it, but not 
  all of the bits in that key are significant.

  Consider a node 'n' and its parent 'tp'.

  If n is a leaf, every bit in its key is significant. Its presence is 
  necessitated by path compression, since during a tree traversal (when 
  searching for a leaf - unless we are doing an insertion) we will completely 
  ignore all skipped bits we encounter. Thus we need to verify, at the end of 
  a potentially successful search, that we have indeed been walking the 
  correct key path.

  Note that we can never "miss" the correct key in the tree if present by 
  following the wrong path. Path compression ensures that segments of the key 
  that are the same for all keys with a given prefix are skipped, but the 
  skipped part *is* identical for each node in the subtrie below the skipped 
  bit! trie_insert() in this implementation takes care of that - note the 
  call to tkey_sub_equals() in trie_insert().

  if n is an internal node - a 'tnode' here, the various parts of its key 
  have many different meanings.

  Example:  
  _________________________________________________________________
  | i | i | i | i | i | i | i | N | N | N | S | S | S | S | S | C |
  -----------------------------------------------------------------
  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15 

  _________________________________________________________________
  | C | C | C | u | u | u | u | u | u | u | u | u | u | u | u | u |
  -----------------------------------------------------------------
  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31

  tp->pos = 7
  tp->bits = 3
  n->pos = 15
  n->bits = 4

  First, let's just ignore the bits that come before the parent tp, that is 
  the bits from 0 to (tp->pos-1). They are *known* but at this point we do 
  not use them for anything.

  The bits from (tp->pos) to (tp->pos + tp->bits - 1) - "N", above - are the
  index into the parent's child array. That is, they will be used to find 
  'n' among tp's children.

  The bits from (tp->pos + tp->bits) to (n->pos - 1) - "S" - are skipped bits
  for the node n.

  All the bits we have seen so far are significant to the node n. The rest 
  of the bits are really not needed or indeed known in n->key.

  The bits from (n->pos) to (n->pos + n->bits - 1) - "C" - are the index into 
  n's child array, and will of course be different for each child.
  

  The rest of the bits, from (n->pos + n->bits) onward, are completely unknown
  at this point.

*/

static inline void check_tnode(const struct tnode *tn)
{
  WARN_ON(tn && tn->pos+tn->bits > 32);
}

static int halve_threshold = 25;
static int inflate_threshold = 50;
static int halve_threshold_root = 15;
static int inflate_threshold_root = 25; 

static void __leaf_free_rcu(struct rcu_head *head)
{
  // printf("rcu free leaf %p\n", container_of(head, struct leaf, rcu));
  free(container_of(head, struct leaf, rcu));
}

static void __leaf_info_free_rcu(struct rcu_head *head)
{
  free(container_of(head, struct leaf_info, rcu));
}

static inline void free_leaf_info(struct leaf_info *leaf)
{
  call_rcu(&leaf->rcu, __leaf_info_free_rcu);
}

static struct tnode *tnode_alloc(unsigned int size)
{
  return calloc (size, 1);
#if 0
  struct page *pages;

  if (size <= PAGE_SIZE)
    return kcalloc(size, 1, GFP_KERNEL);

  pages = alloc_pages(GFP_KERNEL|__GFP_ZERO, get_order(size));
  if (!pages)
    return NULL;

  return page_address(pages);
#endif
}

static void __tnode_free_rcu(struct rcu_head *head)
{
  struct tnode *tn = container_of(head, struct tnode, rcu);
#if 0
  unsigned int size = sizeof(struct tnode) +
    (1 << tn->bits) * sizeof(struct node *);

  if (size <= PAGE_SIZE)
    free(tn);
  else
    free_pages((unsigned long)tn, get_order(size));
#else
  // printf("rcu free node %p\n", tn);
  free(tn);
#endif
}

static inline void tnode_free(struct tnode *tn)
{
  if(IS_LEAF(tn)) {
    struct leaf *l = (struct leaf *) tn;
    call_rcu_bh(&l->rcu, __leaf_free_rcu);
  }
  else
    call_rcu(&tn->rcu, __tnode_free_rcu);
}

static struct leaf *leaf_new(void)
{
  struct leaf *l = malloc(sizeof(struct leaf));
  if (l) {
    l->parent = T_LEAF;
    INIT_HLIST_HEAD(&l->list);
  }
  return l;
}

static struct leaf_info *leaf_info_new(int plen)
{
  struct leaf_info *li = malloc(sizeof(struct leaf_info));
  if (li) {
    li->plen = plen;
    li->data = NULL;
    // INIT_LIST_HEAD(&li->falh);
  }
  return li;
}

static struct tnode* tnode_new(t_key key, int pos, int bits)
{
  int nchildren = 1<<bits;
  int sz = sizeof(struct tnode) + nchildren * sizeof(struct node *);
  struct tnode *tn = tnode_alloc(sz);

  if (tn) {
    memset(tn, 0, sz);
    tn->parent = T_TNODE;
    tn->pos = pos;
    tn->bits = bits;
    tn->key = key;
    tn->full_children = 0;
    tn->empty_children = 1<<bits;
  }

  pr_debug("AT %p s=%u %u\n", tn, (unsigned int) sizeof(struct tnode),
           (unsigned int) (sizeof(struct node) * 1<<bits));
  return tn;
}

/*
 * Check whether a tnode 'n' is "full", i.e. it is an internal node
 * and no bits are skipped. See discussion in dyntree paper p. 6
 */

static inline int tnode_full(const struct tnode *tn, const struct node *n)
{
  if (n == NULL || IS_LEAF(n))
    return 0;

  return ((struct tnode *) n)->pos == tn->pos + tn->bits;
}

static inline void put_child(struct trie *t, struct tnode *tn, int i, struct node *n)
{
  tnode_put_child_reorg(tn, i, n, -1);
}

/*
 * Add a child at position i overwriting the old value.
 * Update the value of full_children and empty_children.
 */

static void tnode_put_child_reorg(struct tnode *tn, int i, struct node *n, int wasfull)
{
  struct node *chi = tn->child[i];
  int isfull;

  BUG_ON(i >= 1<<tn->bits);


  /* update emptyChildren */
  if (n == NULL && chi != NULL)
    tn->empty_children++;
  else if (n != NULL && chi == NULL)
    tn->empty_children--;

  /* update fullChildren */
  if (wasfull == -1)
    wasfull = tnode_full(tn, chi);

  isfull = tnode_full(tn, n);
  if (wasfull && !isfull)
    tn->full_children--;
  else if (!wasfull && isfull)
    tn->full_children++;

  if (n)
    NODE_SET_PARENT(n, tn);

  rcu_assign_pointer(tn->child[i], n);
}

static struct node *resize(struct trie *t, struct tnode *tn)
{
  int i;
  int err = 0;
  struct tnode *old_tn;
  int inflate_threshold_use;
  int halve_threshold_use;

  if (!tn)
    return NULL;

  pr_debug("In tnode_resize %p inflate_threshold=%d threshold=%d\n",
           tn, inflate_threshold, halve_threshold);

  /* No children */
  if (tn->empty_children == tnode_child_length(tn)) {
    tnode_free(tn);
    return NULL;
  }
  /* One child */
  if (tn->empty_children == tnode_child_length(tn) - 1)
    for (i = 0; i < tnode_child_length(tn); i++) {
      struct node *n;

      n = tn->child[i];
      if (!n)
        continue;

      /* compress one level */
      NODE_SET_PARENT(n, NULL);
      tnode_free(tn);
      return n;
    }
  /*
   * Double as long as the resulting node has a number of
   * nonempty nodes that are above the threshold.
   */

  /*
   * From "Implementing a dynamic compressed trie" by Stefan Nilsson of
   * the Helsinki University of Technology and Matti Tikkanen of Nokia
   * Telecommunications, page 6:
   * "A node is doubled if the ratio of non-empty children to all
   * children in the *doubled* node is at least 'high'."
   *
   * 'high' in this instance is the variable 'inflate_threshold'. It
   * is expressed as a percentage, so we multiply it with
   * tnode_child_length() and instead of multiplying by 2 (since the
   * child array will be doubled by inflate()) and multiplying
   * the left-hand side by 100 (to handle the percentage thing) we
   * multiply the left-hand side by 50.
   *
   * The left-hand side may look a bit weird: tnode_child_length(tn)
   * - tn->empty_children is of course the number of non-null children
   * in the current node. tn->full_children is the number of "full"
   * children, that is non-null tnodes with a skip value of 0.
   * All of those will be doubled in the resulting inflated tnode, so
   * we just count them one extra time here.
   *
   * A clearer way to write this would be:
   *
   * to_be_doubled = tn->full_children;
   * not_to_be_doubled = tnode_child_length(tn) - tn->empty_children -
   *     tn->full_children;
   *
   * new_child_length = tnode_child_length(tn) * 2;
   *
   * new_fill_factor = 100 * (not_to_be_doubled + 2*to_be_doubled) /
   *      new_child_length;
   * if (new_fill_factor >= inflate_threshold)
   *
   * ...and so on, tho it would mess up the while () loop.
   *
   * anyway,
   * 100 * (not_to_be_doubled + 2*to_be_doubled) / new_child_length >=
   *      inflate_threshold
   *
   * avoid a division:
   * 100 * (not_to_be_doubled + 2*to_be_doubled) >=
   *      inflate_threshold * new_child_length
   *
   * expand not_to_be_doubled and to_be_doubled, and shorten:
   * 100 * (tnode_child_length(tn) - tn->empty_children +
   *    tn->full_children) >= inflate_threshold * new_child_length
   *
   * expand new_child_length:
   * 100 * (tnode_child_length(tn) - tn->empty_children +
   *    tn->full_children) >=
   *      inflate_threshold * tnode_child_length(tn) * 2
   *
   * shorten again:
   * 50 * (tn->full_children + tnode_child_length(tn) -
   *    tn->empty_children) >= inflate_threshold *
   *    tnode_child_length(tn)
   *
   */

  check_tnode(tn);

  /* Keep root node larger  */

  if(!tn->parent)
    inflate_threshold_use = inflate_threshold_root;
  else 
    inflate_threshold_use = inflate_threshold;

  err = 0;
  while ((tn->full_children > 0 &&
          50 * (tn->full_children + tnode_child_length(tn) - tn->empty_children) >=
          inflate_threshold_use * tnode_child_length(tn))) {

    old_tn = tn;
    tn = inflate(t, tn);
    if (IS_ERR(tn)) {
      tn = old_tn;
#ifdef CONFIG_IP_FIB_TRIE_STATS
      t->stats.resize_node_skipped++;
#endif
      break;
    }
  }

  check_tnode(tn);

  /*
   * Halve as long as the number of empty children in this
   * node is above threshold.
   */


  /* Keep root node larger  */

  if(!tn->parent)
    halve_threshold_use = halve_threshold_root;
  else 
    halve_threshold_use = halve_threshold;

  err = 0;
  while (tn->bits > 1 &&
         100 * (tnode_child_length(tn) - tn->empty_children) <
         halve_threshold_use * tnode_child_length(tn)) {

    old_tn = tn;
    tn = halve(t, tn);
    if (IS_ERR(tn)) {
      tn = old_tn;
#ifdef CONFIG_IP_FIB_TRIE_STATS
      t->stats.resize_node_skipped++;
#endif
      break;
    }
  }


  /* Only one child remains */
  if (tn->empty_children == tnode_child_length(tn) - 1)
    for (i = 0; i < tnode_child_length(tn); i++) {
      struct node *n;

      n = tn->child[i];
      if (!n)
        continue;

      /* compress one level */

      NODE_SET_PARENT(n, NULL);
      tnode_free(tn);
      return n;
    }

  return (struct node *) tn;
}

static struct tnode *inflate(struct trie *t, struct tnode *tn)
{
  struct tnode *inode;
  struct tnode *oldtnode = tn;
  int olen = tnode_child_length(tn);
  int i;

  pr_debug("In inflate\n");

  tn = tnode_new(oldtnode->key, oldtnode->pos, oldtnode->bits + 1);

  if (!tn)
    return ERR_PTR(-ENOMEM);

  /*
   * Preallocate and store tnodes before the actual work so we
   * don't get into an inconsistent state if memory allocation
   * fails. In case of failure we return the oldnode and  inflate
   * of tnode is ignored.
   */

  for (i = 0; i < olen; i++) {
    struct tnode *inode = (struct tnode *) tnode_get_child(oldtnode, i);

    if (inode &&
        IS_TNODE(inode) &&
        inode->pos == oldtnode->pos + oldtnode->bits &&
        inode->bits > 1) {
      struct tnode *left, *right;
      t_key m = TKEY_GET_MASK(inode->pos, 1);

      left = tnode_new(inode->key&(~m), inode->pos + 1,
                       inode->bits - 1);
      if (!left)
        goto nomem;

      right = tnode_new(inode->key|m, inode->pos + 1,
                        inode->bits - 1);

      if (!right) {
        tnode_free(left);
        goto nomem;
      }

      put_child(t, tn, 2*i, (struct node *) left);
      put_child(t, tn, 2*i+1, (struct node *) right);
    }
  }

  for (i = 0; i < olen; i++) {
    struct node *node = tnode_get_child(oldtnode, i);
    struct tnode *left, *right;
    int size, j;

    /* An empty child */
    if (node == NULL)
      continue;

    /* A leaf or an internal node with skipped bits */

    if (IS_LEAF(node) || ((struct tnode *) node)->pos >
        tn->pos + tn->bits - 1) {
      if (tkey_extract_bits(node->key, oldtnode->pos + oldtnode->bits,
                            1) == 0)
        put_child(t, tn, 2*i, node);
      else
        put_child(t, tn, 2*i+1, node);
      continue;
    }

    /* An internal node with two children */
    inode = (struct tnode *) node;

    if (inode->bits == 1) {
      put_child(t, tn, 2*i, inode->child[0]);
      put_child(t, tn, 2*i+1, inode->child[1]);

      tnode_free(inode);
      continue;
    }

    /* An internal node with more than two children */

    /* We will replace this node 'inode' with two new
     * ones, 'left' and 'right', each with half of the
     * original children. The two new nodes will have
     * a position one bit further down the key and this
     * means that the "significant" part of their keys
     * (see the discussion near the top of this file)
     * will differ by one bit, which will be "0" in
     * left's key and "1" in right's key. Since we are
     * moving the key position by one step, the bit that
     * we are moving away from - the bit at position
     * (inode->pos) - is the one that will differ between
     * left and right. So... we synthesize that bit in the
     * two  new keys.
     * The mask 'm' below will be a single "one" bit at
     * the position (inode->pos)
     */

    /* Use the old key, but set the new significant
     *   bit to zero.
     */

    left = (struct tnode *) tnode_get_child(tn, 2*i);
    put_child(t, tn, 2*i, NULL);

    BUG_ON(!left);

    right = (struct tnode *) tnode_get_child(tn, 2*i+1);
    put_child(t, tn, 2*i+1, NULL);

    BUG_ON(!right);

    size = tnode_child_length(left);
    for (j = 0; j < size; j++) {
      put_child(t, left, j, inode->child[j]);
      put_child(t, right, j, inode->child[j + size]);
    }
    put_child(t, tn, 2*i, resize(t, left));
    put_child(t, tn, 2*i+1, resize(t, right));

    tnode_free(inode);
  }
  tnode_free(oldtnode);
  return tn;
 nomem:
  {
    int size = tnode_child_length(tn);
    int j;

    for (j = 0; j < size; j++)
      if (tn->child[j])
        tnode_free((struct tnode *)tn->child[j]);

    tnode_free(tn);

    return ERR_PTR(-ENOMEM);
  }
}

static struct tnode *halve(struct trie *t, struct tnode *tn)
{
  struct tnode *oldtnode = tn;
  struct node *left, *right;
  int i;
  int olen = tnode_child_length(tn);

  pr_debug("In halve\n");

  tn = tnode_new(oldtnode->key, oldtnode->pos, oldtnode->bits - 1);

  if (!tn)
    return ERR_PTR(-ENOMEM);

  /*
   * Preallocate and store tnodes before the actual work so we
   * don't get into an inconsistent state if memory allocation
   * fails. In case of failure we return the oldnode and halve
   * of tnode is ignored.
   */

  for (i = 0; i < olen; i += 2) {
    left = tnode_get_child(oldtnode, i);
    right = tnode_get_child(oldtnode, i+1);

    /* Two nonempty children */
    if (left && right) {
      struct tnode *newn;

      newn = tnode_new(left->key, tn->pos + tn->bits, 1);

      if (!newn)
        goto nomem;

      put_child(t, tn, i/2, (struct node *)newn);
    }

  }

  for (i = 0; i < olen; i += 2) {
    struct tnode *newBinNode;

    left = tnode_get_child(oldtnode, i);
    right = tnode_get_child(oldtnode, i+1);

    /* At least one of the children is empty */
    if (left == NULL) {
      if (right == NULL)    /* Both are empty */
        continue;
      put_child(t, tn, i/2, right);
      continue;
    }

    if (right == NULL) {
      put_child(t, tn, i/2, left);
      continue;
    }

    /* Two nonempty children */
    newBinNode = (struct tnode *) tnode_get_child(tn, i/2);
    put_child(t, tn, i/2, NULL);
    put_child(t, newBinNode, 0, left);
    put_child(t, newBinNode, 1, right);
    put_child(t, tn, i/2, resize(t, newBinNode));
  }
  tnode_free(oldtnode);
  return tn;
 nomem:
  {
    int size = tnode_child_length(tn);
    int j;

    for (j = 0; j < size; j++)
      if (tn->child[j])
        tnode_free((struct tnode *)tn->child[j]);

    tnode_free(tn);

    return ERR_PTR(-ENOMEM);
  }
}

void trie_init(struct trie *t)
{
  if (!t)
    return;

  t->size = 0;
  rcu_assign_pointer(t->trie, NULL);
  t->revision = 0;
#ifdef CONFIG_IP_FIB_TRIE_STATS
  memset(&t->stats, 0, sizeof(struct trie_use_stats));
#endif
}

/* readside must use rcu_read_lock currently dump routines
   via get_fa_head and dump */

static struct leaf_info *find_leaf_info(struct leaf *l, int plen)
{
  struct hlist_head *head = &l->list;
  struct hlist_node *node;
  struct leaf_info *li;

  hlist_for_each_entry_rcu(li, node, head, hlist)
    if (li->plen == plen)
      return li;

  return NULL;
}

static void insert_leaf_info(struct hlist_head *head, struct leaf_info *new)
{
  struct leaf_info *li = NULL, *last = NULL;
  struct hlist_node *node;

  if (hlist_empty(head)) {
    hlist_add_head_rcu(&new->hlist, head);
  } else {
    hlist_for_each_entry(li, node, head, hlist) {
      if (new->plen > li->plen)
        break;

      last = li;
    }
    if (last)
      hlist_add_after_rcu(&last->hlist, &new->hlist);
    else
      hlist_add_before_rcu(&new->hlist, &li->hlist);
  }
}

static struct node *trie_rebalance(struct trie *t, struct tnode *tn)
{
  int wasfull;
  t_key cindex, key;
  struct tnode *tp = NULL;

  key = tn->key;

  while (tn != NULL && NODE_PARENT(tn) != NULL) {

    tp = NODE_PARENT(tn);
    cindex = tkey_extract_bits(key, tp->pos, tp->bits);
    wasfull = tnode_full(tp, tnode_get_child(tp, cindex));
    tn = (struct tnode *) resize (t, (struct tnode *)tn);
    tnode_put_child_reorg((struct tnode *)tp, cindex,(struct node*)tn, wasfull);

    if (!NODE_PARENT(tn))
      break;

    tn = NODE_PARENT(tn);
  }
  /* Handle last (top) tnode */
  if (IS_TNODE(tn))
    tn = (struct tnode*) resize(t, (struct tnode *)tn);

  return (struct node*) tn;
}

/* only used from updater-side */

static int trie_insert_node(struct trie *t, int *err, u32 key, int plen, void *data)
{
  int pos, newpos;
  struct tnode *tp = NULL, *tn = NULL;
  struct node *n;
  struct leaf *l;
  int missbit;
  struct leaf_info *li = NULL;
  t_key cindex;

  pos = 0;
  n = t->trie;

  /* If we point to NULL, stop. Either the tree is empty and we should
   * just put a new leaf in if, or we have reached an empty child slot,
   * and we should just put our new leaf in that.
   * If we point to a T_TNODE, check if it matches our key. Note that
   * a T_TNODE might be skipping any number of bits - its 'pos' need
   * not be the parent's 'pos'+'bits'!
   *
   * If it does match the current key, get pos/bits from it, extract
   * the index from our key, push the T_TNODE and walk the tree.
   *
   * If it doesn't, we have to replace it with a new T_TNODE.
   *
   * If we point to a T_LEAF, it might or might not have the same key
   * as we do. If it does, just change the value, update the T_LEAF's
   * value, and return it.
   * If it doesn't, we need to replace it with a T_TNODE.
   */

  while (n != NULL &&  NODE_TYPE(n) == T_TNODE) {
    tn = (struct tnode *) n;

    check_tnode(tn);

    if (tkey_sub_equals(tn->key, pos, tn->pos-pos, key)) {
      tp = tn;
      pos = tn->pos + tn->bits;
      n = tnode_get_child(tn, tkey_extract_bits(key, tn->pos, tn->bits));

      BUG_ON(n && NODE_PARENT(n) != tn);
    } else
      break;
  }

  /*
   * n  ----> NULL, LEAF or TNODE
   *
   * tp is n's (parent) ----> NULL or TNODE
   */

  BUG_ON(tp && IS_LEAF(tp));

  /* Case 1: n is a leaf. Compare prefixes */

  if (n != NULL && IS_LEAF(n) && tkey_equals(key, n->key)) {
    struct leaf *l = (struct leaf *) n;

    li = leaf_info_new(plen);

    if (!li) {
      *err = -ENOMEM;
      goto err;
    }

    insert_leaf_info(&l->list, li);
    goto done;
  }
  t->size++;
  l = leaf_new();

  if (!l) {
    *err = -ENOMEM;
    goto err;
  }

  l->key = key;
  li = leaf_info_new(plen);

  if (!li) {
    tnode_free((struct tnode *) l);
    *err = -ENOMEM;
    goto err;
  }

  insert_leaf_info(&l->list, li);

  if (t->trie && n == NULL) {
    /* Case 2: n is NULL, and will just insert a new leaf */

    NODE_SET_PARENT(l, tp);

    cindex = tkey_extract_bits(key, tp->pos, tp->bits);
    put_child(t, (struct tnode *)tp, cindex, (struct node *)l);
  } else {
    /* Case 3: n is a LEAF or a TNODE and the key doesn't match. */
    /*
     *  Add a new tnode here
     *  first tnode need some special handling
     */

    if (tp)
      pos = tp->pos+tp->bits;
    else
      pos = 0;

    if (n) {
      newpos = tkey_mismatch(key, pos, n->key);
      tn = tnode_new(n->key, newpos, 1);
    } else {
      newpos = 0;
      tn = tnode_new(key, newpos, 1); /* First tnode */
    }

    if (!tn) {
      free_leaf_info(li);
      tnode_free((struct tnode *) l);
      *err = -ENOMEM;
      goto err;
    }

    NODE_SET_PARENT(tn, tp);

    missbit = tkey_extract_bits(key, newpos, 1);
    put_child(t, tn, missbit, (struct node *)l);
    put_child(t, tn, 1-missbit, n);

    if (tp) {
      cindex = tkey_extract_bits(key, tp->pos, tp->bits);
      put_child(t, (struct tnode *)tp, cindex, (struct node *)tn);
    } else {
      rcu_assign_pointer(t->trie, (struct node *)tn); /* First tnode */
      tp = tn;
    }
  }

  if (tp && tp->pos + tp->bits > 32)
    printf("fib_trie tp=%p pos=%d, bits=%d, key=%0x plen=%d\n",
           tp, tp->pos, tp->bits, key, plen);

  /* Rebalance the trie */

  rcu_assign_pointer(t->trie, trie_rebalance(t, tp));
 done:
  t->revision++;
 err:
  if(li != NULL) {
    li->data = data;
    return 0;
  } else {
    return 1;
  }
}

/* should be called with rcu_read_lock */
static inline int check_leaf(struct trie *t, struct leaf *l,
			     t_key key, int *plen, 
			     NQ_Trie_Entry *result)
{
  int i;
  t_key mask;
  struct leaf_info *li;
  struct hlist_head *hhead = &l->list;
  struct hlist_node *node;

  hlist_for_each_entry_rcu(li, node, hhead, hlist) {
    i = li->plen;
    mask = ntohl(inet_make_mask(i));
    if (l->key != (key & mask))
      continue;
    *plen = i;
    result->header.prefix = l->key;
    result->header.prefix_len = i;
    result->value = li->data;
    return 0;
  }
  return 1;
}

/* only called from updater side */
static int trie_leaf_remove(struct trie *t, t_key key)
{
  t_key cindex;
  struct tnode *tp = NULL;
  struct node *n = t->trie;
  struct leaf *l;

  pr_debug("entering trie_leaf_remove(%p)\n", n);

  /* Note that in the case skipped bits, those bits are *not* checked!
   * When we finish this, we will have NULL or a T_LEAF, and the
   * T_LEAF may or may not match our key.
   */

  while (n != NULL && IS_TNODE(n)) {
    struct tnode *tn = (struct tnode *) n;
    check_tnode(tn);
    n = tnode_get_child(tn ,tkey_extract_bits(key, tn->pos, tn->bits));

    BUG_ON(n && NODE_PARENT(n) != tn);
  }
  l = (struct leaf *) n;

  if (!n || !tkey_equals(l->key, key))
    return 0;

  /*
   * Key found.
   * Remove the leaf and rebalance the tree
   */

  t->revision++;
  t->size--;

  preempt_disable();
  tp = NODE_PARENT(n);
  tnode_free((struct tnode *) n);

  if (tp) {
    cindex = tkey_extract_bits(key, tp->pos, tp->bits);
    put_child(t, (struct tnode *)tp, cindex, NULL);
    rcu_assign_pointer(t->trie, trie_rebalance(t, tp));
  } else
    rcu_assign_pointer(t->trie, NULL);
  preempt_enable();

  return 1;
}

static int trie_flush_leaf(struct trie *t, struct leaf *l)
{
  int found = 0;
  struct hlist_head *lih = &l->list;
  struct hlist_node *node, *tmp;
  struct leaf_info *li = NULL;

  hlist_for_each_entry_safe(li, node, tmp, lih, hlist) {
    hlist_del_rcu(&li->hlist);
    free_leaf_info(li);
  }
  return found;
}

/* rcu_read_lock needs to be hold by caller from readside */

static struct leaf *nextleaf(struct trie *t, struct leaf *thisleaf)
{
PING();
  struct node *c = (struct node *) thisleaf;
  struct tnode *p;
  int idx;
  struct node *trie = rcu_dereference(t->trie);

  if (c == NULL) {
    if (trie == NULL)
      return NULL;

    if (IS_LEAF(trie))          /* trie w. just a leaf */
      return (struct leaf *) trie;

    p = (struct tnode*) trie;  /* Start */
  } else
    p = (struct tnode *) NODE_PARENT(c);

  while (p) {
PING();
    int pos, last;

    /*  Find the next child of the parent */
    if (c) {
      pos = 1 + tkey_extract_bits(c->key, p->pos, p->bits);
    }
    else
      pos = 0;

    last = 1 << p->bits;
    for (idx = pos; idx < last ; idx++) {
PING();
      c = rcu_dereference(p->child[idx]);

      if (!c)
        continue;

      /* Decend if tnode */
      while (IS_TNODE(c)) {
PING();
        p = (struct tnode *) c;
        idx = 0;

        /* Rightmost non-NULL branch */
        if (p && IS_TNODE(p))
          while (!(c = rcu_dereference(p->child[idx]))
                 && idx < (1<<p->bits)) idx++;

        /* Done with this tnode? */
        if (idx >= (1 << p->bits) || !c)
          goto up;
      }
      return (struct leaf *) c;
    }
  up:
    /* No more children go up one step  */
    c = (struct node *) p;
    p = (struct tnode *) NODE_PARENT(p);
  }
  return NULL; /* Ready. Root of trie */
}

int trie_flush(struct trie *t)
{
  struct leaf *ll = NULL, *l = NULL;
  int found = 0, h;

  t->revision++;

  for (h = 0; (l = nextleaf(t, l)) != NULL; h++) {
    found += trie_flush_leaf(t, l);

    if (ll && hlist_empty(&ll->list))
      trie_leaf_remove(t, ll->key);
    ll = l;
  }

  if (ll && hlist_empty(&ll->list))
    trie_leaf_remove(t, ll->key);

  // Fully deallocate root; this works around a performance bug in
  // computing the length of a zero-length trie (i.e., without this,
  // that operation is O(n), rather than O(1))
  if(t->trie != NULL) {
    if(IS_TNODE(t->trie)) {
      tnode_free((struct tnode *)t->trie);
      t->trie = NULL;
    }
  }
  pr_debug("trie_flush found=%d\n", found);
  return found;
}

/* rcu_read_lock needs to be hold by caller from readside */

static struct leaf *
fib_find_node(struct trie *t, u32 key)
{
  int pos;
  struct tnode *tn;
  struct node *n;

  pos = 0;
  n = rcu_dereference(t->trie);

  while (n != NULL &&  NODE_TYPE(n) == T_TNODE) {
    tn = (struct tnode *) n;

    check_tnode(tn);

    if (tkey_sub_equals(tn->key, pos, tn->pos-pos, key)) {
      pos = tn->pos + tn->bits;
      n = tnode_get_child(tn, tkey_extract_bits(key, tn->pos, tn->bits));
    } else
      break;
  }
  /* Case we have found a leaf. Compare prefixes */

  if (n != NULL && IS_LEAF(n) && tkey_equals(key, n->key))
    return (struct leaf *)n;

  return NULL;
}

static void trie_hint_reset(struct trie_nth_hint *h) {
  memset(h, 0, sizeof(*h));
}

int trie_insert_entry(struct trie *t, u32 key, int plen, void *data) {
  u32 mask;
  struct leaf *l;
  struct leaf_info *li;

  if (plen > 32)
    return -EINVAL;

  pr_debug("Insert table=%p %08x/%d\n", t, key, plen);

  mask = ntohl(inet_make_mask(plen));

  if (key & ~mask)
    return -EINVAL;

  key = key & mask;

  l = fib_find_node(t, key);

  if(l && (li = find_leaf_info(l, plen))) {
    // update existing entry
    // printf("updating existing entry\n");
    li->data = data;
    return 0;
  } else {
    // printf("Creating new node\n");
    int err = 0;
    trie_insert_node(t, &err, key, plen, data);
    if(err != 0) {
      printf("error %d creating new node\n", err);
    }
    return err;
  }
}

int trie_delete_entry(struct trie *t, u32 key, int plen) {
  u32 mask;
  struct leaf *l;
  struct leaf_info *li;

  if (plen > 32)
    return -EINVAL;
  mask = ntohl(inet_make_mask(plen));

  if (key & ~mask)
    return -EINVAL;

  key = key & mask;
  l = fib_find_node(t, key);

  if (!l)
    return -ESRCH;

  li = find_leaf_info(l, plen);
  if (!li)
    return -ESRCH;

  hlist_del_rcu(&li->hlist);
  free_leaf_info(li);

  if (hlist_empty(&l->list))
    trie_leaf_remove(t, key);

  return 0;
}

// struct fib_result *
int trie_lookup(struct trie *t, u32 key, NQ_Trie_Entry *result)
{
  int plen, ret = 0;
  struct node *n;
  struct tnode *pn;
  int pos, bits;
  int chopped_off;
  t_key cindex = 0;
  int current_prefix_length = KEYLENGTH;
  struct tnode *cn;
  t_key node_prefix, key_prefix, pref_mismatch;
  int mp;

  rcu_read_lock();

  n = rcu_dereference(t->trie);
  if (!n)
    goto failed;

#ifdef CONFIG_IP_FIB_TRIE_STATS
  t->stats.gets++;
#endif

  /* Just a leaf? */
  if (IS_LEAF(n)) {
    if ((ret = check_leaf(t, (struct leaf *)n, key, &plen, result)) <= 0)
      goto found;
    goto failed;
  }
  pn = (struct tnode *) n;
  chopped_off = 0;

  while (pn) {
    pos = pn->pos;
    bits = pn->bits;

    if (!chopped_off)
      cindex = tkey_extract_bits(MASK_PFX(key, current_prefix_length), pos, bits);

    n = tnode_get_child(pn, cindex);

    if (n == NULL) {
#ifdef CONFIG_IP_FIB_TRIE_STATS
      t->stats.null_node_hit++;
#endif
      goto backtrace;
    }

    if (IS_LEAF(n)) {
      if ((ret = check_leaf(t, (struct leaf *)n, key, &plen, result)) <= 0)
        goto found;
      else
        goto backtrace;
    }

#define HL_OPTIMIZE
#ifdef HL_OPTIMIZE
    cn = (struct tnode *)n;

    /*
     * It's a tnode, and we can do some extra checks here if we
     * like, to avoid descending into a dead-end branch.
     * This tnode is in the parent's child array at index
     * key[p_pos..p_pos+p_bits] but potentially with some bits
     * chopped off, so in reality the index may be just a
     * subprefix, padded with zero at the end.
     * We can also take a look at any skipped bits in this
     * tnode - everything up to p_pos is supposed to be ok,
     * and the non-chopped bits of the index (se previous
     * paragraph) are also guaranteed ok, but the rest is
     * considered unknown.
     *
     * The skipped bits are key[pos+bits..cn->pos].
     */

    /* If current_prefix_length < pos+bits, we are already doing
     * actual prefix  matching, which means everything from
     * pos+(bits-chopped_off) onward must be zero along some
     * branch of this subtree - otherwise there is *no* valid
     * prefix present. Here we can only check the skipped
     * bits. Remember, since we have already indexed into the
     * parent's child array, we know that the bits we chopped of
     * *are* zero.
     */

    /* NOTA BENE: CHECKING ONLY SKIPPED BITS FOR THE NEW NODE HERE */

    if (current_prefix_length < pos+bits) {
      if (tkey_extract_bits(cn->key, current_prefix_length,
                            cn->pos - current_prefix_length) != 0 ||
          !(cn->child[0]))
        goto backtrace;
    }

    /*
     * If chopped_off=0, the index is fully validated and we
     * only need to look at the skipped bits for this, the new,
     * tnode. What we actually want to do is to find out if
     * these skipped bits match our key perfectly, or if we will
     * have to count on finding a matching prefix further down,
     * because if we do, we would like to have some way of
     * verifying the existence of such a prefix at this point.
     */

    /* The only thing we can do at this point is to verify that
     * any such matching prefix can indeed be a prefix to our
     * key, and if the bits in the node we are inspecting that
     * do not match our key are not ZERO, this cannot be true.
     * Thus, find out where there is a mismatch (before cn->pos)
     * and verify that all the mismatching bits are zero in the
     * new tnode's key.
     */

    /* Note: We aren't very concerned about the piece of the key
     * that precede pn->pos+pn->bits, since these have already been
     * checked. The bits after cn->pos aren't checked since these are
     * by definition "unknown" at this point. Thus, what we want to
     * see is if we are about to enter the "prefix matching" state,
     * and in that case verify that the skipped bits that will prevail
     * throughout this subtree are zero, as they have to be if we are
     * to find a matching prefix.
     */

    node_prefix = MASK_PFX(cn->key, cn->pos);
    key_prefix = MASK_PFX(key, cn->pos);
    pref_mismatch = key_prefix^node_prefix;
    mp = 0;

    /* In short: If skipped bits in this node do not match the search
     * key, enter the "prefix matching" state.directly.
     */
    if (pref_mismatch) {
      while (!(pref_mismatch & (1<<(KEYLENGTH-1)))) {
        mp++;
        pref_mismatch = pref_mismatch <<1;
      }
      key_prefix = tkey_extract_bits(cn->key, mp, cn->pos-mp);

      if (key_prefix != 0)
        goto backtrace;

      if (current_prefix_length >= cn->pos)
        current_prefix_length = mp;
    }
#endif
    pn = (struct tnode *)n; /* Descend */
    chopped_off = 0;
    continue;

  backtrace:
    chopped_off++;

    /* As zero don't change the child key (cindex) */
    while ((chopped_off <= pn->bits) && !(cindex & (1<<(chopped_off-1))))
      chopped_off++;

    /* Decrease current_... with bits chopped off */
    if (current_prefix_length > pn->pos + pn->bits - chopped_off)
      current_prefix_length = pn->pos + pn->bits - chopped_off;

    /*
     * Either we do the actual chop off according or if we have
     * chopped off all bits in this tnode walk up to our parent.
     */

    if (chopped_off <= pn->bits) {
      cindex &= ~(1 << (chopped_off-1));
    } else {
      if (NODE_PARENT(pn) == NULL)
        goto failed;

      /* Get Child's index */
      cindex = tkey_extract_bits(pn->key, NODE_PARENT(pn)->pos, NODE_PARENT(pn)->bits);
      pn = NODE_PARENT(pn);
      chopped_off = 0;

#ifdef CONFIG_IP_FIB_TRIE_STATS
      t->stats.backtrack++;
#endif
      goto backtrace;
    }
  }
 failed:
  ret = 1;
 found:
  rcu_read_unlock();
  return ret;
}

/* Depth first Trie walk iterator */
struct fib_trie_iter {
  struct tnode *tnode;
  struct trie *trie;
  unsigned index;
  unsigned depth;
};

static struct node *fib_trie_get_next(struct fib_trie_iter *iter)
{
  struct tnode *tn = iter->tnode;
  unsigned cindex = iter->index;
  struct tnode *p;

  pr_debug("get_next iter={node=%p index=%d depth=%d}\n",
           iter->tnode, iter->index, iter->depth);
 rescan:
  while (cindex < (1<<tn->bits)) {
    struct node *n = tnode_get_child(tn, cindex);

    if (n) {
      if (IS_LEAF(n)) {
        iter->tnode = tn;
        iter->index = cindex + 1;
      } else {
        /* push down one level */
        iter->tnode = (struct tnode *) n;
        iter->index = 0;
        ++iter->depth;
      }
      return n;
    }

    ++cindex;
  }

  /* Current node exhausted, pop back up */
  p = NODE_PARENT(tn);
  if (p) {
    cindex = tkey_extract_bits(tn->key, p->pos, p->bits)+1;
    tn = p;
    --iter->depth;
    goto rescan;
  }

  /* got root? */
  return NULL;
}

static struct node *fib_trie_get_first(struct fib_trie_iter *iter,
				       struct trie *t)
{
  struct node *n = rcu_dereference(t->trie);

  if (n && IS_TNODE(n)) {
    iter->tnode = (struct tnode *) n;
    iter->trie = t;
    iter->index = 0;
    iter->depth = 1;
    return n;
  }
  return NULL;
}

void trie_collect_stats(struct trie *t, struct trie_stat *s) {
  struct node *n;
  struct fib_trie_iter iter;

  memset(s, 0, sizeof(*s));

  rcu_read_lock();
  for (n = fib_trie_get_first(&iter, t); n;
       n = fib_trie_get_next(&iter)) {
    if (IS_LEAF(n)) {
      s->leaves++;
      s->totdepth += iter.depth;
      if (iter.depth > s->maxdepth)
        s->maxdepth = iter.depth;
    } else {
      const struct tnode *tn = (const struct tnode *) n;
      int i;

      s->tnodes++;
      s->nodesizes[tn->bits]++;
      for (i = 0; i < (1<<tn->bits); i++)
        if (!tn->child[i])
          s->nullpointers++;
    }
  }
  rcu_read_unlock();
}

static int hint_hit = 0;
static int hint_miss = 0;
int trie_nth_entry(struct trie *t, struct trie_nth_hint *hint,
                   int n, u32 *key_p, int *plen_p, void **result_p) {
  if(n < 0) {
    return 1;
  }
  int h;
  struct leaf_info *start_li = NULL;
  struct leaf *l;

  if(hint->is_valid && n == hint->n + 1) { // n.b. code probably works for n > hint->n + 1
    h = hint->n + 1;
    l = hint->prev_l;
    start_li = hint->prev_li;
    hint_hit++;
  } else {
    h = 0;
    PING();
    l = nextleaf(t, NULL);
    if(l != NULL) { // if NULL, then this is a spurious miss, since there's nothing to iterate over in this trie
      hint_miss++;
    }
  }
  int ocount = 0;
  for (; l != NULL; l = nextleaf(t, l) ) {
    struct hlist_head *head = &l->list;
    struct hlist_node *node;
    struct leaf_info *li;

    int icount = 0;
    if(start_li == NULL) {
      node = head->first;
    } else {
      // only init on the very first one
      node = start_li->hlist.next;
      start_li = NULL;
    }
    hlist_for_each_entry_from(li, node, hlist) {
      if(icount > 0) {
        printf("{%d-%d}", ocount,icount++);
      }
      if(h == n) {
        *key_p = l->key;
        *plen_p = li->plen;
        *result_p = li->data;

        hint->is_valid = 1;
        hint->n = n;
        hint->prev_l = l;
        hint->prev_li = li;
        return 0;
      }
      h++;
    }
  }
  return 1;
}

#if 0
// This is the low level interface
struct trie;

void trie_init(struct trie *t);
int trie_insert_entry(struct trie *t, u32 key, int plen, void *data);
int trie_delete_entry(struct trie *t, u32 key, int plen);
int trie_nth_entry(struct trie *t, struct leaf *start, int n, u32 *key_p, int *plen_p, void **result_p);
int trie_lookup(struct trie *t, u32 key, void **res);
void trie_collect_stats(struct trie *t, struct trie_stat *s);
#endif

NQ_Trie_Entry *_NQ_Trie_Entry(int prefix, int prefix_len, void *data) {
  static NQ_Trie_Entry ent;
  ent.header.prefix = prefix;
  ent.header.prefix_len = prefix_len;
  ent.value = data;
  return &ent;
}

NQ_Trie *NQ_Trie_new(void) {
  NQ_Trie *t = malloc(sizeof(NQ_Trie));
  t->t = malloc(sizeof(struct trie));
  trie_init(t->t);
  trie_hint_reset(&t->hint);
  return t;
}

void NQ_Trie_delete(NQ_Trie *trie) {
  //  printf("NQ_Trie_delete()\n");
  trie_flush(trie->t);
  free(trie->t);
  free(trie);
}

int NQ_Trie_lookup(NQ_Trie *trie, unsigned int path, NQ_Trie_Entry *entry) {
  int rv = trie_lookup(trie->t, path, entry);
  if(rv) {
    // printf("NQ_Trie_lookup(): could not find match (%d)!\n", rv);
    return -1;
  }
  return 0;
}

// modifications (i.e. insert and delete) will invalidate the hint

void NQ_Trie_write(NQ_Trie *trie, NQ_Trie_Entry *entry) {
  trie_hint_reset(&trie->hint);
  trie_insert_entry(trie->t, entry->header.prefix, entry->header.prefix_len, entry->value);
}

int NQ_Trie_remove(NQ_Trie *trie, unsigned int path, unsigned int length) {
  trie_hint_reset(&trie->hint);
  if(trie_delete_entry(trie->t, path, length) != 0) {
    // printf("trie_delete node tried to remove node that was not in trie\n");
    return -1;
  }
  return 0;
}

int NQ_Trie_load_nth(NQ_Trie *trie, int n, NQ_Trie_Entry *entry) {
  int plen;
  if(trie_nth_entry(trie->t, &trie->hint, n, 
                    &entry->header.prefix, &plen, &entry->value)) {
    return -1;
  }

  assert(0 <= plen && plen < 256);
  entry->header.prefix_len = plen;
  return 0;
}

int NQ_Trie_num_elems(NQ_Trie *trie) {
  int count;
  NQ_Trie_Entry entry;
  for(count = 0; NQ_Trie_load_nth(trie, count, &entry) == 0; count++) {
    // do nothing
  }
  return count;
}

void NQ_Trie_truncate(NQ_Trie *trie) {
  trie_flush(trie->t);
}

void NQ_Trie_set_subtract(NQ_Trie *t0, NQ_Trie *t1, void (*remove_hook)(NQ_Trie_Entry *)) {
  // semantics: -=
  int i;
  NQ_Trie_Entry entry;
  for(i = 0; NQ_Trie_load_nth(t1, i, &entry) == 0; i++) {
    int rv;
    NQ_Trie_Entry old_entry;
    rv = NQ_Trie_lookup_exact(t0, entry.header.prefix, entry.header.prefix_len, &old_entry);
    if(rv == 0) {
      remove_hook(&old_entry);
      rv = NQ_Trie_remove(t0, entry.header.prefix, entry.header.prefix_len);
      // removal must succeed
      assert(rv == 0);
    }
  }
  if(i > 0) {
    printf("Cleaned %d\n", i);
  }
}

void NQ_Trie_set_add(NQ_Trie *t0, NQ_Trie *t1, void (*remove_hook)(NQ_Trie_Entry *)) {
  // semantics: +=
  int num_overwrites = 0;
  int i;
  NQ_Trie_Entry entry;
  for(i = 0; NQ_Trie_load_nth(t1, i, &entry) == 0; i++) {
    NQ_Trie_Entry old_entry;
    int rv;
    rv = NQ_Trie_lookup_exact(t0, entry.header.prefix, entry.header.prefix_len, &old_entry);
    if(rv == 0) {
      remove_hook(&old_entry);
      num_overwrites++;
    }

    NQ_Trie_write(t0, &entry);
  }
  if(i > 0) {
    printf("Merged %d (%d overwritten)\n", i, num_overwrites);
  }
}

int NQ_Trie_lookup_exact(NQ_Trie *trie, unsigned int key, unsigned int plen, NQ_Trie_Entry *entry) {
  u32 mask;
  struct leaf *l;
  struct leaf_info *li;

  if (plen > 32)
    return -EINVAL;
  mask = ntohl(inet_make_mask(plen));
  
  if (key & ~mask)
    return -EINVAL;

  key = key & mask;
  l = fib_find_node(trie->t, key);

  if (!l)
    return -ESRCH;

  li = find_leaf_info(l, plen);
  if (!li)
    return -ESRCH;

  assert(key == l->key && plen == li->plen);
  entry->header.prefix = key;
  entry->header.prefix_len = li->plen;
  entry->value = li->data;
  return 0;
}

void NQ_Trie_Entry_print(NQ_Trie_Entry *ent) {
  printf("%08x/%d => %p\n", ent->header.prefix, ent->header.prefix_len, ent->value);
}

int alloc_bytes = 0;
int free_bytes = 0;
#ifdef USE_TRIE_TEST_MAIN

int check_read(NQ_Trie *t, u32 ip, u32 check_val) {
  NQ_Trie_Entry entry;
  int rv = NQ_Trie_lookup(t, ip, &entry);
  return rv == 0 &&(u32) entry.value == check_val;
}

void count_matches(NQ_Trie *t, int *s, int *l) {
  uint32_t short_tests[2] = { 0x01000000, 0x01000001 };
  uint32_t long_tests[2] = { 0x01010000, 0x01010001 };
  int result, rv;
  *s = 0;
  *l = 0;
  int i;
  // rv = NQ_Trie_read(trie, array[temp], &result_tmp);
  // result = (unsigned int) result_tmp;
  for(i=0; i < 2; i++) {
    NQ_Trie_Entry _result;
    rv = NQ_Trie_lookup(t, short_tests[i], &_result);
    result = (int)_result.value;
    if(rv == 0 && result == 0xdead) {
      *s += 1;
    }
    if(rv == 0 && result == 0xbeef) {
      *l += 1;
    }
    rv = NQ_Trie_lookup(t, long_tests[i], &_result);
    result = (int)_result.value;
    if(rv == 0 && result == 0xdead) {
      *s += 1;
    }
    if(rv == 0 && result == 0xbeef) {
      *l += 1;
    }
  }
}

static void fill_bigtable(NQ_Trie *trie, int limit) {
  int i;
  for(i=0; i < limit / 2; i++) {
    int v = i << 8;
    NQ_Trie_Entry entry;
    entry.header.prefix = v;
    entry.header.prefix_len = 24;
    entry.value = (void *)v;
    NQ_Trie_write(trie, &entry);
    v |= 0x80;
    entry.header.prefix = v;
    entry.header.prefix_len = 25;
    entry.value = (void *)v;
    NQ_Trie_write(trie, &entry);
  }
}

static void check_bigtable(NQ_Trie *trie, int limit, int random_change) {
  int i;
  int count_24 = 0, count_25 = 0;
  int not_found = 0;
  u8 *found = malloc(limit);
  memset(found, 0, limit);
  for(i=0; i < limit + 10; i++) {
    // printf("[%d]", i);
    NQ_Trie_Entry entry;

    if(random_change && (rand() % 500 == 0)) {
      int pos = rand() % limit;
      int val = pos << 7;
      int len = (pos & 0x1) ? 25 : 24;
      NQ_Trie_remove(trie, val, len);
      NQ_Trie_write(trie, _NQ_Trie_Entry(val, len, (void*)val));
    }

    int rv = NQ_Trie_load_nth(trie, i, &entry);
    if(i < limit) {
      assert(rv == 0 && 
             0 <= (entry.header.prefix & ~0x80) && (entry.header.prefix & ~0x80) < ((limit / 2) << 8) && 
             ((int) entry.value == entry.header.prefix));
      if(entry.header.prefix_len == 24) {
        assert(((int)entry.value & 0x80) == 0);
        count_24 += 1;
      } else if(entry.header.prefix_len == 25) {
        count_25 += 1;
        assert(((int)entry.value & 0x80) == 0x80);
      } else {
        assert(0);
      }
      // check for duplicates
      int j = (int)entry.value >> 7;
      assert(0 <= j && j < limit);
      assert(found[j] == 0);
      found[j] = 1;
    } else {
      not_found++;
      assert(rv != 0);
    }
  }
  assert(count_24 == limit / 2);
  assert(count_25 == limit / 2);
  printf("Stats: # of */24 = %d, # of */25 = %d, # not found = %d\n",
         count_24, count_25, not_found);
  for(i=0; i < limit; i++) {
    // check that everything was found
    assert(found[i]);
  }
}

// resolve dynamic symbol so we can breakpoint on it
void *foo = (void *)__assert_fail;
void quicktest(int count);
int main(int argc, char **argv){

  unsigned int count;
  unsigned int *array;
  NQ_Trie *trie;
  unsigned int i, temp, result;
  unsigned int len = 24;
  int rv;

  if(argc < 2){
    printf("usage: %s count\n", argv[0]);
    exit(1);
  }
  
  count = atoi(argv[1]);
  srandom(time(NULL));
  
  array = malloc(count * sizeof(unsigned int));

  int a[5];
  int f[5];
  a[0] = alloc_bytes;
  f[0] = free_bytes;
  trie = NQ_Trie_new();

  for(i = 1; i < count; i++) {

    NQ_Trie_Entry _result;
    do { // scan until unoccupied entry is found
      temp = random() & ~0xff;
      rv = NQ_Trie_lookup(trie, temp, &_result);
    } while(rv == 0);

    NQ_Trie_write(trie, _NQ_Trie_Entry(temp, len, (void *)i));
    array[i] = temp;

    temp = (random() % i) + 1;
    rv = NQ_Trie_lookup(trie, array[temp], &_result);
    result = (unsigned int) _result.value;
    // printf("read(%x)=>%p\n", array[temp], result_tmp);
    if(rv != 0 || result != temp){
//      printf("Eeek!  Tried to read %x/%d (%d) and got %d instead!  (not a failure... just a factor of randomness: %x/%d is a prefix of %x/%d\n", array[temp]>>8, 24, temp, result);
//      assert(array[result]);
      printf("Mismatch!\n");
    }
  }

  a[1] = alloc_bytes;
  f[1] = free_bytes;
  NQ_Trie_delete(trie);
  a[2] = alloc_bytes;
  f[2] = free_bytes;

  // Focused tests

  printf("Longest prefix test\n");
  NQ_Trie *trie2 = NQ_Trie_new();
  uint32_t _short = 0x01000000; // 1.0.0.0 / 8
  uint32_t _long = 0x01010000; // 1.1.0.0 / 16
  int s, l;
  count_matches(trie2, &s, &l);
  assert(s == 0 && l == 0);
  NQ_Trie_write(trie2, _NQ_Trie_Entry(_short, 8, (void *)0xdead));
  count_matches(trie2, &s, &l);
  assert(s == 4 && l == 0);
  NQ_Trie_write(trie2, _NQ_Trie_Entry(_long, 16, (void *)0xbeef));
  count_matches(trie2, &s, &l);
  assert(s == 2 && l == 2);
  NQ_Trie_remove(trie2, _long, 16);
  count_matches(trie2, &s, &l);
  assert(s == 4 && l == 0);
  NQ_Trie_remove(trie2, _short, 8);
  count_matches(trie2, &s, &l);
  assert(s == 0 && l == 0);

  NQ_Trie_write(trie2, _NQ_Trie_Entry(_long, 16, (void *)0xbeef));
  count_matches(trie2, &s, &l);
  assert(s == 0 && l == 2);

  // xxx need better exhaustive prefix test

  trie2 = NULL;
  NQ_Trie *trie3 = NQ_Trie_new();
  printf("Overwrite test\n");
  assert(!check_read(trie3, _long, 0xbeef) && !check_read(trie3, _long, 0xdead));
  NQ_Trie_write(trie3, _NQ_Trie_Entry(_long, 16, (void *)0xbeef));
  assert(check_read(trie3, _long, 0xbeef) && !check_read(trie3, _long, 0xdead));
  NQ_Trie_write(trie3, _NQ_Trie_Entry(_long, 16, (void *)0xdead));
  assert(!check_read(trie3, _long, 0xbeef) && check_read(trie3, _long, 0xdead));
  
  printf("Performance test\n");
  trie3 = NULL;
  NQ_Trie *trie4 = NQ_Trie_new();
  int limit = 290000;
  printf("Insertion performance, limit = %d\n", limit);
  time_t start_time;
  time_t end_time;
#define START_DELTA()                           \
  start_time = time(NULL)
#define PRINT_DELTA(L)                                                   \
  end_time = time(NULL);                                                \
  printf("%d s to %s\n", (int)(end_time - start_time), L);

  START_DELTA();
  a[3] = alloc_bytes;
  f[3] = free_bytes;
  fill_bigtable(trie4, limit);
  a[4] = alloc_bytes;
  f[4] = free_bytes;
  PRINT_DELTA("insert");

  trie_print_stats(trie4->t);
  printf("Nth test\n");
  START_DELTA();
  check_bigtable(trie4, limit, 0);
  PRINT_DELTA("nth test check");
  printf("Nth test (with random deletes)\n");
  if(1) {
    printf("skipping\n"); 
  } else {
    START_DELTA();
    check_bigtable(trie4, limit, 1);
    PRINT_DELTA("check invalidate");
  }
  printf("xxx need remove entry not in table\n");

  printf("--------------------------------------------------\n");
  printf("  Trie test successful\n");
  printf("  Prefixes: %d (avg length: %d)\n", count, len);
  printf(" Allocation: %d %d ;  %d %d  ; %d %d\n",
         a[0], f[0], a[1], f[1], a[2], f[2]);
  printf("Size of big table (%d entries) = %d\n", limit, (a[4] - f[4]) - (a[3] - f[3]));

  int before_total = a[0] - f[0];
  int after_total = a[2] - f[2];
  if(before_total != after_total) {
    printf("after total is not same as before total! %d %d\n", after_total, before_total);
  }
  printf("--------------------------------------------------\n");
  
  free(array);
  NQ_Trie_delete(trie);
  return 0;
}

#undef malloc
#undef calloc
#undef free

void *count_malloc(size_t sz) {
  alloc_bytes += sz;
  void *rv = malloc(sz + sizeof(int));
  *(int*) rv = sz;
  return rv + sizeof(int);
}
void *count_calloc(size_t nmem, size_t size) {
  int sz = nmem * size;
  alloc_bytes += sz;
  void *rv = malloc(sz + sizeof(int));
  *(int*) rv = sz;
  return rv + sizeof(int);
}
void count_free(void *x) {
  free_bytes += *(int *)(x - sizeof(int));
  free(x - sizeof(int));
}

#endif

void quicktest(int count) {
  // quicktest is a copy of the above low level test, for use in obj-test.cc
  printf("quicktest(%d)\n", count);
  unsigned int *array;
  NQ_Trie *trie;
  unsigned int i, temp, result;
  unsigned int len = 24;
  int rv;

  srandom(time(NULL));
  
  array = malloc(count * sizeof(unsigned int));

  int a[5];
  int f[5];
  a[0] = alloc_bytes;
  f[0] = free_bytes;
  trie = NQ_Trie_new();

  for(i = 1; i < count; i++) {
    temp = random() & ~0xff;
    NQ_Trie_write(trie, _NQ_Trie_Entry(temp, len, (void *)i));
    array[i] = temp;

    temp = (random() % i) + 1;
    NQ_Trie_Entry _result;
    rv = NQ_Trie_lookup(trie, array[temp], &_result);
    result = (unsigned int) _result.value;
    // printf("read(%x)=>%p\n", array[temp], result_tmp);
    if(rv != 0 || result != temp){
//      printf("Eeek!  Tried to read %x/%d (%d) and got %d instead!  (not a failure... just a factor of randomness: %x/%d is a prefix of %x/%d\n", array[temp]>>8, 24, temp, result);
//      assert(array[result]);
      printf("Mismatch!\n");
    }
  }

  a[1] = alloc_bytes;
  f[1] = free_bytes;
  NQ_Trie_delete(trie);
  a[2] = alloc_bytes;
  f[2] = free_bytes;
}
