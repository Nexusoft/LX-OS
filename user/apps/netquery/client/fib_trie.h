#ifndef _FIB_TRIE_H_
#define _FIB_TRIE_H_

#include <nq/netquery.h>
#include <nq/attribute.h>

struct trie;

typedef struct NQ_Trie_Entry {
  NQ_Trie_Index_Args header;
  void *value;
} NQ_Trie_Entry;

void NQ_Trie_Entry_print(NQ_Trie_Entry *ent);

static inline int inet_make_mask(int logmask)
{
        if (logmask)
                return htonl(~((1<<(32-logmask))-1));
        return 0;
}

#if 0
// internal interface between high and low level of trie code

void trie_init(struct trie *t);
int trie_insert_node(struct trie *t, int *err, uint32_t key, int plen, void *data);
int trie_delete_node(struct trie *t, uint32_t key, int plen);
int trie_lookup(struct trie *t, uint32_t key, void **res);
#endif

// void trie_collect_stats(struct trie *t, struct trie_stat *s);

NQ_Trie *NQ_Trie_new(void);

void NQ_Trie_set_subtract(NQ_Trie *t0, NQ_Trie *t1, void (*remove_hook)(NQ_Trie_Entry *)); // -=
void NQ_Trie_set_add(NQ_Trie *t0, NQ_Trie *t1, void (*remove_hook)(NQ_Trie_Entry *)); // += 

void NQ_Trie_delete(NQ_Trie *trie);
void NQ_Trie_truncate(NQ_Trie *trie);
int NQ_Trie_num_elems(NQ_Trie *trie);

// void NQ_Trie_resize(NQ_Trie *trie, unsigned int size);

int NQ_Trie_lookup(NQ_Trie *trie, unsigned int path, NQ_Trie_Entry *entry);
int NQ_Trie_lookup_exact(NQ_Trie *trie, unsigned int path, unsigned int length, NQ_Trie_Entry *entry);

void NQ_Trie_write(NQ_Trie *trie, NQ_Trie_Entry *entry);
int NQ_Trie_remove(NQ_Trie *trie, unsigned int path, unsigned int prefix_length);
int NQ_Trie_load_nth(NQ_Trie *trie, int n, NQ_Trie_Entry *entry);

#endif // _FIB_TRIE_H_
