/*
 *  trie.h
 *  NetQuery
 *
 *  Created by Oliver Kennedy on 1/21/08.
 *
 */

struct trie;
struct leaf;
struct trie_nth_hint {
  int is_valid;
  int n;
  struct leaf *prev_l;
  struct leaf_info *prev_li;
};

typedef struct NQ_Trie {
  struct trie *t;
  // modifying the trie should invalidat the hint
  struct trie_nth_hint hint;
} NQ_Trie;

