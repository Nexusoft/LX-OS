
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
       
	table = (struct HashTable *) nxcompat_calloc(1, sizeof(struct HashTable));
	assert (table);

	table->buckets = nxcompat_calloc(num_buckets, sizeof(struct HashBucket));
	assert(table->buckets);
	
	table->key_len = key_len;
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
	for(i=0; i < table->num_buckets; i++) {
		struct HashBucketEntry *bucket = table->buckets[i].next;
		while(bucket != &sentinel) {
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

	// Catch some stupid bugs
	assert(item != INVALID_HASH);
	assert(table->num_buckets > 0);
	
	klen = hash_keylen(table, key);
	assert(klen > 0);
	bucket_num = SuperFastHash(key, klen) % table->num_buckets;
	
	new_entry = galloc(sizeof(*new_entry) + klen);
	assert(new_entry);

	new_entry->next = table->buckets[bucket_num].next;
	new_entry->item = item;
	memcpy(new_entry->key, key, klen);

	table->buckets[bucket_num].next = new_entry;
	table->num_entries++;
}

void *hash_findEntry(struct HashTable *table, const void *key, void **prev) {
	int key_len = hash_keylen(table, key);
	int bucket_num = SuperFastHash(key, key_len) %
		table->num_buckets;
	struct HashBucketEntry *entry = table->buckets[bucket_num].next;
	struct HashBucketEntry *prevEntry = (struct HashBucketEntry *)
		&table->buckets[bucket_num];
	while (entry != &sentinel) {
	  // printf("'%s'='%s'\n", entry->key, key);
		int key2_len = hash_keylen(table, entry->key);
		if(key_len == key2_len && memcmp(entry->key, key, key_len) == 0) {
			*prev = prevEntry;
			return entry;
		}
		prevEntry = entry;
		entry = entry->next;
	}
	*prev = NULL;
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

static void hash_destroyEntry(struct HashTable *table, struct HashBucketEntry *entry) {
#if 0
	if(table->hf != NULL) {
	}
#endif
	gfree(entry);
}

void *hash_delete(struct HashTable *table, const void *key) {
	struct HashBucketEntry *entry, *prev;
	void *item, *_prev;
	
	entry = hash_findEntry(table, key, &_prev);
	if (!entry)
		return NULL;

	item = entry->item;
	prev = (struct HashBucketEntry *)_prev;

	prev->next = entry->next;
	table->num_entries--;
	hash_destroyEntry(table, entry);
	return item;
}

void hash_deleteEntry(struct HashTable *table, void *_entry, void *_prev) {
	struct HashBucketEntry *entry = (struct HashBucketEntry *)_entry;
	struct HashBucketEntry *prev = (struct HashBucketEntry *)_prev;

	prev->next = entry->next;
	table->num_entries--;
	hash_destroyEntry(table, entry);
}

int hash_numEntries(struct HashTable *table) {
	return table->num_entries;
}

void hash_iterate(struct HashTable *table, Func f, void *arg) {
  int i;
  for (i = 0; i < table->num_buckets; i++) {
    struct HashBucketEntry *entry = table->buckets[i].next;
    while (entry != &sentinel) {
      f(entry->item, arg);
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

int test_vlf(const void *key) {
	const char *k = key;
	return strlen(k) + 1;
}

static void check_inserted_varlen(int i) {
	void *findResult = 
		hash_findItem(table, (char *)hash_var_tests[i].key);
	void *prev;
	void *findEntryResult = 
		hash_findEntry(table, (char *)hash_var_tests[i].key, &prev);
	int findValue, entryValue;

	if(findResult == NULL || findEntryResult == NULL) {
		printk("could not find inserted result @ %d\n", i);
		error_count++;
		return;
	}
	findValue = *(int*)findResult;
	entryValue = *(int*)hash_entryToItem(findEntryResult);
	if(findValue != hash_var_tests[i].value) {
		printk("wrong find value @ %d\n", i);
		error_count++;
	}
	if(entryValue != hash_var_tests[i].value) {
		printk("wrong find Entry value @ %d\n", i);
		error_count++;
	}
}

static void check_notInserted_varlen(int i) {
	void *findResult = 
	  hash_findItem(table, (char *)hash_var_tests[i].key);
	void *prev;
	void *findEntryResult = 
		hash_findEntry(table, (char *)hash_var_tests[i].key, &prev);

	if(findResult != NULL || findEntryResult != NULL) {
		printk("should not have found inserted result @ %d\n", i);
		error_count++;
		return;
	}
}

int hash_var_test(void) {
	const int num_tests = sizeof(hash_var_tests) / sizeof(hash_var_tests[0]);
	int i, j;

	table = hash_new_vlen(10, test_vlf);

	// insert
	for (i = 0; i < num_tests; i++) {
		hash_insert(table, (char *)hash_var_tests[i].key, &hash_var_tests[i].value);
		for( j = 0; j <= i; j++)
			check_inserted_varlen(j);
		for ( j = i + 1; j < num_tests; j++)
			check_notInserted_varlen(j);
	}

	// delete
	for (i = 0; i < num_tests; i++) {
		if (i % 2) {
			hash_delete(table, (char *)hash_var_tests[i].key);
		} else {
			void *prev, *entry;
			entry = hash_findEntry(table, (char *)hash_var_tests[i].key, &prev);
			hash_deleteEntry(table, entry, prev);
		}

		for (j = 0; j <= i; j++)
			check_notInserted_varlen(j);
		for (j = i + 1; j < num_tests; j++)
			check_inserted_varlen(j);
	}
	
	if (error_count)
		printk("Encountered %d errors\n", error_count);

	hash_destroy(table);
	return error_count;
}

#endif // __NEXUSKERNEL__

