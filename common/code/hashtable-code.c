
#ifndef __NEXUSKERNEL__
#include <stdint.h>
#endif

// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

// note: this table supports multiple entries with the same key. They are
// managed in lifo order:
// hash_insert("a", x)
// hash_insert("a", y)
// hash_insert("a", z)
// hash_find("a") // returns z
// hash_delete("a") // returns z
// hash_delete("a") // returns y
// hash_find("a") // returns x
// hash_delete("a") // returns x
// hash_delete("a") // error

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((const uint8_t *)(d))[1] << UINT32_C(8))\
                      +((const uint8_t *)(d))[0])
#endif

int hash_strlen(const void *key) {
  return strlen((char *)key) + 1;
}

#define INVALID_HASH ((void *) (-1))

unsigned int SuperFastHash (const char * data, int len) {
unsigned int hash = len, tmp;
int rem;

    if (len <= 0 || data == INVALID_HASH) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 2;
    hash += hash >> 15;
    hash ^= hash << 10;

    return hash;
}

struct HashBucket {
	struct HashBucketEntry *next;
};

static struct HashBucketEntry sentinel;

struct HashBucketEntry {
	struct HashBucketEntry *next;
	void *item;
	char key[]; // variable length
};

struct HashTable {
	int key_len;
	int num_buckets;
	int num_entries;
	Hash_VarLenFunction *vlf;
	ItemDestructor item_dtor;
	struct HashBucket *buckets;
};

struct HashTable *hash_new(int num_buckets, int key_len) {
	struct HashTable *table;
	int i;
       
	table 		= nxcompat_calloc(1, sizeof(struct HashTable));
	table->buckets 	= nxcompat_calloc(num_buckets, sizeof(struct HashBucket));
	
	table->key_len	= key_len;
	table->num_buckets = num_buckets;

	for(i = 0; i < table->num_buckets; i++)
		table->buckets[i].next = &sentinel;
	
	return table;
}

struct HashTable *hash_new_vlen(int num_buckets, Hash_VarLenFunction *vlf) {
	struct HashTable *table = hash_new(num_buckets, 0);
	table->vlf = vlf;
	return table;
}

void hash_setItemDestructor(struct HashTable *table, ItemDestructor dtor) {
	table->item_dtor = dtor;
}

void hash_destroy(struct HashTable *table) {
	int i;

	for (i=0; i < table->num_buckets; i++) {

		struct HashBucketEntry *bucket = table->buckets[i].next;
		
		while (bucket != &sentinel) {
			struct HashBucketEntry *next = bucket->next;
			if(table->item_dtor != NULL) {
				table->item_dtor(bucket->item);
			}
			gfree(bucket);
			bucket = next;
		}
	}

	gfree(table->buckets);
	gfree(table);
}

static int hash_keylen(struct HashTable *table, const void *key) {
	if(table->vlf)
		return table->vlf(key);
	else
		return table->key_len;
}

/** Hash_insert with explicit keylength (for variable keylen tables) */
void 
hash_insert(struct HashTable *table, const void *key, void *item)
{
	struct HashBucketEntry *new_entry;
	int bucket_num, klen;

	// sanity check
	assert(item != INVALID_HASH);
	assert(table->num_buckets > 0);
	
	// hash into bucket
	klen = hash_keylen(table, key);
	assert(klen > 0);
	bucket_num = SuperFastHash(key, klen) % table->num_buckets;
	
	// create new entry
	new_entry = galloc(sizeof(*new_entry) + klen);
	new_entry->item = item;
	memcpy(new_entry->key, key, klen);

	// attach to bucket list
	new_entry->next = table->buckets[bucket_num].next;
	table->buckets[bucket_num].next = new_entry;
	table->num_entries++;
}

/** Return the entry if found
    @param prev will hold the previous entry if not NULL */
void *hash_findEntry(struct HashTable *table, const void *key, void **prev) {
	struct HashBucketEntry *entry, *prevEntry;
	int key_len, bucket_num; 
	
	if (prev) *prev = NULL;

	// hash into bucket
	key_len = hash_keylen(table, key);
	bucket_num = SuperFastHash(key, key_len) % table->num_buckets;

	// search bucket entries
	entry = table->buckets[bucket_num].next;
	prevEntry = (struct HashBucketEntry *) &table->buckets[bucket_num];
	while (entry != &sentinel) {

		// compare key to stored key
		if (key_len == hash_keylen(table, entry->key) && 
		    !memcmp(entry->key, key, key_len)) {
			if (prev) *prev = prevEntry;
			return entry;
		}

		// next
		prevEntry = entry;
		entry = entry->next;
	}

	return NULL;
}

void *hash_findItem(struct HashTable *table, const void *key) {
	void *prev;
	struct HashBucketEntry *entry = hash_findEntry(table, key, &prev);
	return (entry != NULL) ? hash_entryToItem(entry) : NULL;
}

void *hash_entryToItem(void *_entry) {
	struct HashBucketEntry *entry = (struct HashBucketEntry *)_entry;
	return entry->item;
}

void *hash_entryToKey(void *_entry) {
	struct HashBucketEntry *entry = (struct HashBucketEntry *)_entry;
	return entry->key;
}

void *hash_delete(struct HashTable *table, const void *key) {
	struct HashBucketEntry *entry, *prev;
	void *item, *_prev;
	
	entry = hash_findEntry(table, key, &_prev);
	if (!entry)
		return NULL;

	item = entry->item;
	
	// remove from list
	assert(_prev);
	prev = (struct HashBucketEntry *) _prev;
	prev->next = entry->next;

	table->num_entries--;
	gfree(entry);
	return item;
}

void hash_deleteEntry(struct HashTable *table, void *_entry, void *_prev) {
	struct HashBucketEntry *entry = (struct HashBucketEntry *)_entry;
	struct HashBucketEntry *prev = (struct HashBucketEntry *)_prev;

	prev->next = entry->next;
	table->num_entries--;
	gfree(entry);
}

int hash_numEntries(struct HashTable *table) {
	return table->num_entries;
}

/** Lookup the first <key, value> pair at or above index
    @return the next index beyond the found element (for repeated use) 
            or -1 if no entry was found */
int 
hash_findByIndex(struct HashTable *table, int index,  void **key, char **item)
{
	struct HashBucketEntry *entry;
	int buck_idx, list_idx, i;

	// have to coalese bucket index and index within bucket
	buck_idx = (index >> 16) & 0xffff;
	list_idx = index         & 0xffff;

	if (buck_idx >= table->num_buckets)
		return -1;
	
	// find last used item
	entry = table->buckets[buck_idx].next;
	for (i = 0; i < list_idx; i++) {
		if (entry == &sentinel)
			return -1;
		entry = entry->next;
	}

	do {
		// find the next element in the list
		if (entry && entry != &sentinel) {
			if (key)
				*key = entry->key;
			if (item)
				*item = entry->item;

			// return next item (in list or next bucket)
			if (entry->next && entry->next != &sentinel)
				return (buck_idx << 16) | (list_idx + 1);
			else
				return (buck_idx + 1) << 16;
		}

		// move to next bucket (if any)
		buck_idx++;
		list_idx = 0;
		if (buck_idx == table->num_buckets)
			return -1;

		entry = table->buckets[buck_idx].next;
	} while (1);
}

/** Return an arbitrary node.
    Try to return an old one, as we use this for freeing up space
    (giving an near-LRU algorithm)  

    NB: may fail: when no bucket has at least two items */
void * hash_any(struct HashTable *table, void **prev)
{ 
  struct HashBucketEntry *entry;
  int i;

  for (i = 0; i < table->num_buckets; i++) {
    entry = table->buckets[i].next;
    
    // at least two items in this bucket?
    if (entry != &sentinel && entry->next != &sentinel) {
    	if (prev)
          *prev = entry;
      	return entry->next;
    }
  }

  return NULL;
}

/** Iterate over all elements in the table, or until f returns !0 
    @return 0 if all fully traversed, 1 if a break occurred */
int hash_iterate(struct HashTable *table, Func f, void *arg) {
  int i;

  for (i = 0; i < table->num_buckets; i++) {
    struct HashBucketEntry *entry = table->buckets[i].next;
    while (entry != &sentinel) {
      if (f(entry->item, arg))
        return 1;
      entry = entry->next;
    }
  }
  return 0;
}

/** hash_iterate, but also return the index.
    It's too much dumb work to change all hash_iterate callers */
void hash_iterate_ex(struct HashTable *table, FuncEx f, void *arg)
{
  struct HashBucketEntry *entry;
  int i;

  for (i = 0; i < table->num_buckets; i++) {
    entry = table->buckets[i].next;
    while (entry != &sentinel) {
      f(*(int*) entry->key, entry->item, arg);
      entry = entry->next;
    }
  }
}

void **hash_entries(struct HashTable *table) {
  int i, j = 0, n = table->num_entries;
  void **entries = galloc(n * sizeof(void *));
  for (i = 0; i < table->num_buckets; i++){
    struct HashBucketEntry *entry = table->buckets[i].next;
    while(entry != &sentinel){
      entries[j++] = entry->item;
      entry = entry->next;
    }
  }
  assert(j == n);
  return entries;
}

void hash_iterateEntries(struct HashTable *table, Func f, void *arg) {
  int i;
  for(i = 0; i < table->num_buckets; i++){
    struct HashBucketEntry *entry = table->buckets[i].next;
    while(entry != &sentinel){
      f(entry, arg);
      entry = entry->next;
    }
  }
}

#ifdef __NEXUSKERNEL__

#ifndef NDEBUG

static struct {
	int key, value;
} tests[] = {
	{ 10, 3 * 10 },
	{ 15, 3 * 15 },
	{ 20, 3 * 20 },
	{ 25, 3 * 25 },
	{ 30, 3 * 30 },
};

static int error_count;
struct HashTable *table;

static void check_inserted(int i) {
	void *findResult = 
		hash_findItem(table, (char *)&tests[i].key);
	void *prev;
	void *findEntryResult = 
		hash_findEntry(table, (char *)&tests[i].key, &prev);
	int findValue, entryValue;

	if (findResult == NULL || findEntryResult == NULL) {
		printk("could not find inserted result @ %d\n", i);
		error_count++;
		return;
	}
	findValue = *(int*)findResult;
	entryValue = *(int*)hash_entryToItem(findEntryResult);
	if (findValue != tests[i].value) {
		printk("wrong find value @ %d\n", i);
		error_count++;
	}
	if (entryValue != tests[i].value) {
		printk("wrong find Entry value @ %d\n", i);
		error_count++;
	}
}

static void check_notInserted(int i) {
	void *findResult = 
	  hash_findItem(table, (char *)&tests[i].key);
	void *prev;
	void *findEntryResult = 
		hash_findEntry(table, (char *)&tests[i].key, &prev);

	if (findResult != NULL || findEntryResult != NULL) {
		printk("should not have found inserted result @ %d\n", i);
		error_count++;
		return;
	}
}

int 
hash_test(void) 
{
	const int num_tests = sizeof(tests) / sizeof(tests[0]);
	int i, j;
	
	table = hash_new(10, sizeof(int));

	// insert
	for (i = 0; i < num_tests; i++) {
		hash_insert(table, (char *)&tests[i].key, &tests[i].value);
		if (hash_numEntries(table) != i + 1) {
			printf("len mismatch at insert #%d\n", i);
			error_count++;
		}
		for (j = 0; j <= i; j++)
			check_inserted(j);
		for (j = i + 1; j < num_tests; j++)
			check_notInserted(j);
	}

	// delete
	for(i = 0; i < num_tests; i++) {
		if (i % 2) {
			hash_delete(table, (char *)&tests[i].key);
		} else {
			void *prev, *entry;
			entry = hash_findEntry(table, (char *)&tests[i].key, &prev);
			hash_deleteEntry(table, entry, prev);
		}

		if (hash_numEntries(table) != num_tests - i - 1) {
			printf("len mismatch at delete #%d\n", i);
			error_count++;
			assert(0);
		}

		for (j = 0; j <= i; j++)
			check_notInserted(j);
		for (j = i + 1; j < num_tests; j++)
			check_inserted(j);
	}

	if (error_count)
		printk("Encountered %d errors\n", error_count);

	hash_destroy(table);
	return error_count;
}

static struct {
	char *key, value;
} hash_var_tests[] = {
	{ "hello", 3 * 10 },
	{ "what is going on with the world", 3 * 15 },
	{ "goodbye", 3 * 20 },
	{ "good", 3 * 25 },
	{ "hell", 3 * 30 },
};

static int 
test_vlf(const void *key) 
{
	return strlen((const char *) key) + 1;
}

static void 
check_inserted_varlen(int i) 
{
	void *findResult, *findEntryResult, *prev;
	int findValue, entryValue;
       	
	// lookup item using two complementary methods
	findResult 	= hash_findItem(table, (char *) hash_var_tests[i].key);
	findEntryResult	= hash_findEntry(table, (char *) hash_var_tests[i].key, &prev);
	assert(findResult && findEntryResult);
	
	// extract values
	findValue = * (int*) findResult;
	entryValue = * (int*) hash_entryToItem(findEntryResult);
	
	// verify correspondence
	assert(findValue == hash_var_tests[i].value);
	assert(entryValue == hash_var_tests[i].value);
}

static void 
check_notInserted_varlen(int i) 
{
	void *findResult, *findEntryResult, *prev;
       	
	findResult 	= hash_findItem(table, (char *) hash_var_tests[i].key);
	findEntryResult	= hash_findEntry(table, (char *) hash_var_tests[i].key, &prev);
	assert(findResult == NULL && findEntryResult == NULL);
}

int hash_var_test(void) 
{
	const int num_tests = sizeof (hash_var_tests) / sizeof(hash_var_tests[0]);
	void *prev, *entry;
	int i, j;

	table = hash_new_vlen(10, test_vlf);
	assert(!table->num_entries);

	// insert
	for (i = 0; i < num_tests; i++) {
		hash_insert(table, (char *)hash_var_tests[i].key, &hash_var_tests[i].value);
		for( j = 0; j <= i; j++)
			check_inserted_varlen(j);
		for ( j = i + 1; j < num_tests; j++)
			check_notInserted_varlen(j);
	}
	
	assert(table->num_entries == num_tests);

	// delete
	for (i = 0; i < num_tests; i++) {
		if (i % 2) {
			hash_delete(table, (char *)hash_var_tests[i].key);
		} else {
			entry = hash_findEntry(table, (char *)hash_var_tests[i].key, &prev);
			assert(entry);
			hash_deleteEntry(table, entry, prev);
		}

		for (j = 0; j <= i; j++)
			check_notInserted_varlen(j);
		for (j = i + 1; j < num_tests; j++)
			check_inserted_varlen(j);
	}
	
	assert(!table->num_entries);
		
	if (error_count)
		printk("Encountered %d errors\n", error_count);

	hash_destroy(table);
	return error_count;
}

#endif // NDEBUG
#endif // __NEXUSKERNEL__

