#ifndef _NEXUS_HASHTABLE_H_
#define _NEXUS_HASHTABLE_H_

#ifndef __NEXUSKERNEL__
#include  <nexus/defs.h>
#endif

// Utility functions
unsigned int SuperFastHash (const char * data, int len);

// Hash table is not thread-safe
struct HashTable;

// Returns length of entry to allocate
typedef int (Hash_VarLenFunction)(const void *key);
Hash_VarLenFunction hash_strlen; // strlen(key)+1

struct HashTable *hash_new(int num_buckets, int key_len);
struct HashTable *hash_new_vlen(int num_buckets, Hash_VarLenFunction *vlf);

typedef void (*ItemDestructor)(void *item);
void hash_setItemDestructor(struct HashTable *table, ItemDestructor dtor);

void hash_destroy(struct HashTable *table);

// multiple inserts with the same key are okay:
// e.g. insert(a), insert(b), insert(c), c = delete(), b = delete(), a = delete()
void hash_insert(struct HashTable *table, const void *key, void *item);

void *hash_findEntry(struct HashTable *table, const void *key, void **prev);
void *hash_findItem(struct HashTable *table, const void *key);
int hash_findByIndex(struct HashTable *table, int index,  void **key, char **item);
void *hash_entryToItem(void *_entry);
void *hash_entryToKey(void *_entry);

// returns previous item, if any
void *hash_delete(struct HashTable *table, const void *key);
void hash_deleteEntry(struct HashTable *table, void *_entry, void *_prev);

void hash_modifyEntryItem(struct HashTable *table, void *_entry, void *value);

typedef int (*Func)(void *item, void *arg);
typedef void (*FuncEx)(int index, void *item, void *arg);
int hash_iterate(struct HashTable *table, Func f, void *arg);
void hash_iterate_ex(struct HashTable *table, FuncEx f, void *arg);
void * hash_any(struct HashTable *table, void **prev);
void **hash_entries(struct HashTable *table);
void hash_iterateEntries(struct HashTable *table, Func f, void *arg);

int hash_numEntries(struct HashTable *table);

#ifdef __NEXUSKERNEL__
int hash_test(void);
int hash_var_test(void);
#endif

#endif 
