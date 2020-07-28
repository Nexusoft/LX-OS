
// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

#define WORDBITLEN (32U)
#define WORDBITSHIFT (5U)
// kth level for element N

static inline int bitmap_level_row_base(struct Bitmap *map, int k) {
	return ((1U << (WORDBITSHIFT * (unsigned int)k)) - 1) / 31;
}

static inline int bitmap_level_word_offset(struct Bitmap *map, int k, int n) {
	assert(k != map->max_level_num);
	n >>= (WORDBITSHIFT * (map->max_level_num - k));
	n /= WORDBITLEN;
	return n;
}

static inline int bitmap_level_bit_offset(struct Bitmap *map, int k, int n) {
	n >>= (WORDBITSHIFT * (map->max_level_num - k));
	return n % WORDBITLEN;
}

static inline int bitmap_word_offset(struct Bitmap *map, int n) {
	return n / WORDBITLEN;
}

static inline int bitmap_bit_offset(struct Bitmap *map, int n) {
	return n % WORDBITLEN;
}

void bitmap_computeLen(int num_entries, int *len_p, int *levels_p) {
	unsigned int cmp = num_entries - 1;
	if(cmp < WORDBITLEN) {
	  cmp = WORDBITLEN;
	}
	int levels = 0;
	int treesize = 1;
	int next_level_size = WORDBITLEN;
	while(cmp / WORDBITLEN != 0) {
		cmp /= WORDBITLEN;
		levels++;
		treesize += next_level_size;
		next_level_size *= WORDBITLEN;
	}
	*len_p = treesize;
	*levels_p = levels;
}

// XXX bitmap_init and bitmap_new should not allocate the full bottom
// layer if it is not needed
void bitmap_init(struct Bitmap *map, int num_entries, int maxlen) {
	int treesize, levels;
	bitmap_computeLen(num_entries, &treesize, &levels);
	assert(sizeof(struct Bitmap) + treesize * sizeof(int) <= maxlen);
	assert(levels > 0);

	// index starts off with all 1s (each block has zeros)
	int bottom_len = sizeof(int) * (1 << (levels * WORDBITSHIFT)),
		index_len = treesize * sizeof(int) - bottom_len;
	assert(index_len >= 0);

	memset(map->data, 0xff, index_len);
	map->bottom_data = (unsigned int *) ((char *)map->data + index_len);
	memset(map->bottom_data, 0xff, bottom_len);

	map->max_level_num = levels;
	map->num_entries = num_entries;

	assert(map->data + bitmap_level_row_base(map, levels) == 
	       map->bottom_data);

	assert(num_entries <= bottom_len * 8);
}

struct Bitmap *bitmap_new(int num_entries) {
	int treesize, levels;
	bitmap_computeLen(num_entries, &treesize, &levels);
	int alloc_len = sizeof(struct Bitmap) + treesize * sizeof(int);
	struct Bitmap *map = galloc(alloc_len);
	bitmap_init(map, num_entries, alloc_len);
	return map;
}

void bitmap_destroy(struct Bitmap *map) {
	gfree(map);
}

#ifndef TEST
static
#endif
inline int arch_findFirstOne(unsigned int word, int word_offset) {
	// XXX bsfl is actually pretty slow on modern CPUs
#if 0
	int rval;
	__asm__ ("bsfl %[input], %[output] ;\n"
		 "jnz 1f ;\n"
		 "movl $-1, %[output] ;\n"
		 "1: " : [output] "=r" (rval) : [input] "rm" (word));
	return rval;
#else
	// this faster in O3
	int i, j;
	for(i=word_offset / 8; i < 4; i++) {
		if(word & (0xff << (i * 8))) {
			for(j=i * 8; j < (i + 1) * 8; j++) {
				if((word & (1 << j)) &&
				   (j >= word_offset)) {
					return j;
				}
			}
			break;
		}
	}
	return -1;
#endif
}

static inline int bitmap_findFirstZeroHelper(struct Bitmap *map, int level,
					     unsigned int parent_position,
					     unsigned int parent_value,
					     unsigned int startOffset) {
 tail_recurse: ;
	int word_offset = bitmap_level_bit_offset(map, level - 1, startOffset);
	int position = arch_findFirstOne(parent_value, word_offset);

	if(position < 0) {
		return -1;
	}
	// printf("level %d position %d parent value = %x\n", level, position, parent_value);

	// prep for tail recursion
	parent_position = parent_position * WORDBITLEN + position;

	// invariant: parent_value is always for level - 1. So if we
	// want the bottom (e.g. level max_level_num), get to
	// max_level + 1
	if(level == map->max_level_num + 1) {
		return parent_position;
	}

	int row_base = bitmap_level_row_base(map, level);
	parent_value = map->data[row_base + parent_position];
	level++;
	goto tail_recurse;
}

int bitmap_find_first_zero(struct Bitmap *map, int startOffset) {
	unsigned int top = *(unsigned int *)map->data;
	if(top == 0 || startOffset >= map->num_entries) {
	  // printk("bitmap full!\n");
		return -1;
	}
	int cand = bitmap_findFirstZeroHelper(map, 1, 0, top, startOffset);
	if(cand >= map->num_entries) {
		return -1;
	}
	return cand;
}

#define ALWAYS_PROPAGATE
static inline void bitmap_update_index_helper(struct Bitmap *map, int level, int n, int value) {
 tail_recurse: ;
	if(level < 0) return;
	int row_base = bitmap_level_row_base(map, level),
		word_offset = bitmap_level_word_offset(map, level, n);

	unsigned int *elem = map->data + row_base + word_offset;
	int bit_offset = bitmap_level_bit_offset(map, level, n);
	if(value) {
#ifndef ALWAYS_PROPAGATE
		if(*elem & (1 << bit_offset)) {
			// already reflects change
			return;
		}
#endif
		*elem |= (1 << bit_offset);
	} else {
#ifndef ALWAYS_PROPAGATE
		if(!(*elem & (1 << bit_offset))) {
			// already reflects change
			return;
		}
#endif
		*elem &= ~(1 << bit_offset);
	}
	if(*elem == (unsigned int)0) {
		// has no ones, level - 1 should be 0
		//bitmap_update_index_helper(map, level - 1, n, 0);
		level--;
		value = 0;
		goto tail_recurse;
	} else if(*elem != (unsigned int)0) {
		// has some ones, level - 1 should be 1
		// bitmap_update_index_helper(map, level - 1, n, 1);
		level--;
		value = 1;
		goto tail_recurse;
	}
}

static inline void bitmap_update_index(struct Bitmap *map, int offset) {
	// check for inconsistency at bottom level
	int word_offset = bitmap_word_offset(map, offset);
	if(*(map->bottom_data + word_offset) == (unsigned int)0) {
		// no zeros, bottom - 1 should be 0
		bitmap_update_index_helper(map, map->max_level_num - 1, offset, 0);
	} else if(*(map->bottom_data + word_offset) != (unsigned int)0) {
		// has zeros, bottom - 1 should be 1
		bitmap_update_index_helper(map, map->max_level_num - 1, offset, 1);
	}
}

void bitmap_dump(struct Bitmap *map);

#ifdef CHECK_INTEGRITY
#define PER_OP_INTEGRITY_CHECK() do { if(bitmap_integrity_check(map)) bitmap_dump(map); } while(0)
static int bitmap_integrity_check(struct Bitmap *map);
#else
#define PER_OP_INTEGRITY_CHECK()
#endif

void bitmap_set(struct Bitmap *map, int offset) {
	assert(offset < map->num_entries);
	unsigned int *elem = map->bottom_data + bitmap_word_offset(map, offset);
	*elem &= ~(1 << bitmap_bit_offset(map, offset));
	bitmap_update_index(map, offset);

	PER_OP_INTEGRITY_CHECK();
}

void bitmap_clear(struct Bitmap *map, int offset) {
	assert(offset < map->num_entries);
	unsigned int *elem = map->bottom_data + bitmap_word_offset(map, offset);
	*elem |= (1 << bitmap_bit_offset(map, offset));
	bitmap_update_index(map, offset);

	PER_OP_INTEGRITY_CHECK();
}

int bitmap_test(struct Bitmap *map, int offset) {
	assert(offset < map->num_entries);
	unsigned int *elem = map->bottom_data + bitmap_word_offset(map, offset);
	if((1 << bitmap_bit_offset(map, offset)) & *elem) {
		return 0;
	} else {
		return 1;
	}

	PER_OP_INTEGRITY_CHECK();
}

#ifdef TEST

static inline void bitmap_deep_copy(struct Bitmap *dest, struct Bitmap *src) {
  assert(0);
}

static inline FastBitmap *FastBitmap_new(int num_entries) {
  FastBitmap *rv = galloc(sizeof(FastBitmap));
  FastBitmap_init(rv, num_entries);
  return rv;
}

static inline void FastBitmap_deep_copy(FastBitmap *dest, FastBitmap *src) {
  *dest = *src;
}

static inline BigFastBitmap *BigFastBitmap_new(int num_entries) {
  BigFastBitmap *rv = galloc(sizeof(BigFastBitmap));
  BigFastBitmap_init(rv, num_entries);
  return rv;
}

static inline void BigFastBitmap_deep_copy(BigFastBitmap *dest, BigFastBitmap *src) {
  BigFastBitmap_init(dest, src->max_len);
  FastBitmap_deep_copy(&dest->l0, &src->l0);
  int i;
  for(i=0; i < dest->top_len; i++) {
    FastBitmap_deep_copy(&dest->l1[i], &src->l1[i]);
  }
}

#if 0
// default test types

// #define USE_GENERIC_CHECK

#define BITMAP_TYPE Bitmap
#define BITMAP_NEW bitmap_new
#define BITMAP_FFZ(X) bitmap_find_first_zero(X,0)
#define BITMAP_SET bitmap_set
#define BITMAP_TEST bitmap_test
#define BITMAP_CLEAR bitmap_clear
#define BITMAP_DUMP(X) bitmap_dump(X)
#define BITMAP_DEEPCOPY bitmap_deep_copy

#define BITMAP_FIRST_CHECK(X) bitmap_first_check(X)

#define LIMIT0 (32 * 32 * 32)
#define LIMIT1 (32 * 32)

#endif

long long rdtsc64(void) {
#if 0
      int v[2];
      __asm__ __volatile__("rdtsc" : "=a" (*(int*)v), "=d" (*((int*)v + 1)) : );
      return *(long long*)v;
#else
      struct timeval tv;
      long long usec;
      gettimeofday(&tv, NULL);
      usec = tv.tv_usec + tv.tv_sec * 1000000LL;
      return usec;
#endif
}

//#define DO_TIMING

static struct {
	int key;
} bitmap_tests[] = {
	{ 10 },
	{ 15 },
	{ 20 },
	{ 25 },
	{ 30 },
	{ 35 },
	{ 40 },
	{ 45 },
};

static struct BITMAP_TYPE *test_map;

static void bitmap_check_inserted(int i) {
	if(!BITMAP_TEST(test_map, bitmap_tests[i].key)) {
		printk("check_inserted: bitmap test did not return true @ %d\n", i);
		error_count++;
		return;
	}
}

static void bitmap_check_notInserted(int i) {
	if(BITMAP_TEST(test_map, bitmap_tests[i].key)) {
		printk("check_inserted: bitmap test should have returned false @ %d\n", i);
		error_count++;
		return;
	}
}

static int bitmap_integrity_check(struct Bitmap *map) {
	int lvl, i;
	int has_error = 0;
	// very stupid algorithm
	for(i=0; i < map->num_entries; i += WORDBITLEN) {
		int looking_for;
		unsigned int dat;
		if((dat = map->bottom_data[bitmap_word_offset(map, i)]) == 0) {
			looking_for = 0;
		} else {
			looking_for = 1;
		}
		for(lvl=map->max_level_num; lvl >= 0; lvl--) {
			if(lvl != map->max_level_num) {
				// special case for bottom level
				dat = map->data[bitmap_level_row_base(map, lvl) +
						bitmap_level_word_offset(map, lvl, i)];
				if(dat == 0) {
					looking_for = 0;
				} else {
					looking_for = 1;
				}
			}
			if(lvl >= 1) {
				int wordpos = bitmap_level_row_base(map, lvl - 1) +
					bitmap_level_word_offset(map, lvl - 1, i);
				unsigned int parent_dat = map->data[wordpos];
				int bitpos = bitmap_level_bit_offset(map, lvl - 1, i);
				if(parent_dat & (1 << bitpos)) {
					if(!looking_for) {
						printk("parent should not have had bit set (%d, level %d/%d, pos %d:%d, parent_dat %x)\n", i, lvl, map->max_level_num, wordpos, bitpos, parent_dat);
						has_error = 1;
						error_count++;
					}
				} else {
					if(looking_for) {
						printk("parent should have had bit set\n");
						has_error = 1;
						error_count++;
					}
				}
			}
		}
	}
	return has_error;
}

void bitmap_dump(struct Bitmap *map) {
	int lvl, j;
	for(lvl=0; lvl < map->max_level_num; lvl++) {
		int row_base = bitmap_level_row_base(map, lvl);
		int row_size = bitmap_level_row_base(map, lvl + 1) - row_base;
		printk("Row %d: ", lvl);
		for(j=0; j < row_size; j++) {
			printk("%08x ", map->data[row_base + j]);
		}
		printk("\n");
	}
	printk("Data\n");
	for(j=0; j < map->num_entries / WORDBITLEN; j++) {
		if(~map->bottom_data[j] == 0) {
			printk("0 ");
		} else {
			printk("%08x ", ~map->bottom_data[j]);
		}
	}
	printk("\n");
}

#ifdef USE_GENERIC_CHECK
int bitmap_first_check_generic(struct BITMAP_TYPE *map) {
  struct BITMAP_TYPE map2_real, *map2 = &map2_real;
  BITMAP_DEEPCOPY(map2, map);
  int position = 0;
  int first_offset = -1;
  int is_first = 1;
  while(1) {
    int fz = BITMAP_FFZ(map2);
    int i;
    if(fz < 0) {
      for(i = position; i < map2->max_len; i++) {
	if(!BITMAP_TEST(map2, i)) {
	  printk("claim of last zero is inaccurate\n");
	  error_count++;
	}
      }
      break;
    }
    BITMAP_SET(map2, fz);
    for(i = position; i < fz; i++) {
      if(!BITMAP_TEST(map2, i)) {
	printk("earlier zero!\n");
	error_count++;
      }
    }
    position = fz;
    if(is_first) {
      first_offset = fz;
      is_first = 0;
    }
  }
  return first_offset;
}
#else
int bitmap_first_check(struct Bitmap *map) {
	// Scan through all findFirstZeros
	int first = 1;
	int first_offset = -1;
	int last_offset = 0;
	while(1) {
		int offset = bitmap_find_first_zero(map, last_offset);
		if(first) {
			first_offset = offset;
			first = 0;
		}
		if(offset == -1) break;
		if(bitmap_test(map, offset)) {
			printk("returned first zero (%d %d) is set\n", offset, last_offset);
			bitmap_dump(test_map);
			error_count++;
		}
		int i;
		for(i=last_offset; i < offset; i++) {
		  if(!bitmap_test(map,i)) {
		    printk("Found a first zero that was earlier\n");
		    error_count++;
		  }
		}
		last_offset = offset + 1;
	}
	return first_offset;
}
#endif // USE_GENERIC_CHECK

int bitmap_runtest(void) {
	error_count = 0;
	int i, j, num_tests = sizeof(bitmap_tests) / sizeof(bitmap_tests[0]);
	test_map = BITMAP_NEW(LIMIT0);
	
	// test_map = bitmap_new(32 * 32);
	const int prop_test_limit = LIMIT1;

	int phase,  phase_dump[] = { 0, 0, 0, 1, 1};
	printk("Phase 1: insertion\n");
	BITMAP_DUMP(test_map);

	phase = 1;
	int first = -1;
#define DUMP() do { if(phase_dump[phase]) BITMAP_DUMP(test_map); printk("first = %d\n", first); } while(0)
	for(i=0; i < num_tests; i++) {
		printk("set %d\n", bitmap_tests[i].key);
		BITMAP_SET(test_map, bitmap_tests[i].key);
		int first = BITMAP_FIRST_CHECK(test_map);
		for(j=0; j <= i; j++) {
			bitmap_check_inserted(j);
		}
		for(j=i+1; j < num_tests; j++) {
			bitmap_check_notInserted(j);
		}
		DUMP();
	}
	printk("Phase 2: deletion\n");
	phase = 2;
	for(i=0; i < num_tests; i++) {
		printk("clear %d\n", bitmap_tests[i].key);
		BITMAP_CLEAR(test_map, bitmap_tests[i].key);
		int first = BITMAP_FIRST_CHECK(test_map);
		for(j=0; j <= i; j++) {
			bitmap_check_notInserted(j);
		}
		for(j=i+1; j < num_tests; j++) {
			bitmap_check_inserted(j);
		}
		DUMP();
	}
	if(error_count != 0) {
		printk("Encountered %d errors\n", error_count);
	}

	phase = 3;
	printk("Phase 3: tree update insert\n");
	for(i=0; i < prop_test_limit; i++) {
		// dump after 64
		BITMAP_SET(test_map, i);
		int first = BITMAP_FIRST_CHECK(test_map);
		if(!BITMAP_TEST(test_map, i)) {
			printk("phase 3 set %d didn't hold\n", i);
			error_count++;
		}
		if(i % 64 == 0) {
			printk("dumping after %d\n", i);
			DUMP();
		}
	}
	DUMP();
	printk("Check output\n");
	//getchar();

	printk("Phase 4: tree update delete\n");
	phase = 4;
	for(i=prop_test_limit - 1; i >= 0; i--) {
		// dump after 64
		BITMAP_CLEAR(test_map, i);
		int first = BITMAP_FIRST_CHECK(test_map);
		if(BITMAP_TEST(test_map, i)) {
			printk("phase 4 clear %d didn't hold\n", i);
			error_count++;
		}
		if(i % 64 == 0) {
			printk("dumping after %d\n", i);
			DUMP();
		}
	}
	DUMP();
	printk("check output\n");
	//getchar();
	printk("%d errors\n", error_count);
	return error_count;
}

#ifdef DO_SPEED_TEST
#define NUM_TESTS (1000000)
#define INTMAX (0x7fffffff)
volatile int global;
void bitmap_speedtest(void) {
	srandom(time(NULL));
	TIME_STARTFUNC(2, 0);

	int map_size = 32 * 32 * 32 * 32 * 4; // size of free page table
	//int map_size = 1 << 16; // size of port table
	test_map = bitmap_new(map_size);
	error_count = 0;
	int i;
	volatile long long int last_time, last_time0, overhead_time, actual_time;
	TIME_SEGFIRST();
	last_time = rdtsc64();
	__asm__ __volatile__("": : :"memory");
	for(i=0; i < NUM_TESTS; i++) {
		volatile int dest = random() % map_size;
		volatile int type = random() % map_size;
		global = dest + type;
		// printk("%lld\n", rdtsc64());
	}
	__asm__ __volatile__("": : :"memory");
	overhead_time = rdtsc64() - (long long)last_time;
	last_time0 = last_time;
	printk("overhead time = %lld %lld %lld\n", overhead_time, last_time0, rdtsc64());
	last_time = rdtsc64();
	__asm__ __volatile__("": : :"memory");
	TIME_SEG();
	for(i=0; i < NUM_TESTS; i++) {
		volatile int dest = random() % map_size;
		volatile int type = random();
		if(type < INTMAX / 2) {
			bitmap_set(test_map, dest);
			bitmap_clear(test_map, dest);
			bitmap_set(test_map, dest);
		} else {
			bitmap_clear(test_map, dest);
			bitmap_set(test_map, dest);
			bitmap_clear(test_map, dest);
		}
		bitmap_find_first_zero(test_map, 0);
		bitmap_find_first_zero(test_map, 0);
		int first = bitmap_find_first_zero(test_map, 0);
		if(first >= 0) {
			if(bitmap_test(test_map, first)) {
				printk("first %d was non-zero\n", first);
				error_count++;
			}
		}
#ifdef CHECK_INTEGRITY
		if(i % 64 == 0) {
			if(error_count > 0) {
				printk("error count is %d\n", error_count);
			}
			printk(".");
		}
		bitmap_integrity_check(test_map);
#endif // CHECK_INTEGRITY
	}
	TIME_SEGLAST();
	__asm__ __volatile__("": : :"memory");
	actual_time = rdtsc64() - last_time;
	last_time = rdtsc64();
	printk("actual time = %lld %lld\n", actual_time, last_time);

	TIME_ENDFUNC();
	printk("speed test got %d errors\n", error_count);
	printk("time per iteration is %lf\n", (actual_time - overhead_time) / (double) NUM_TESTS);
}
#endif // DO_SPEED_TEST

#endif // TEST

void BigFastBitmap_init(BigFastBitmap *bitmap, int len) {
  assert(0 <= len && len < MAX_FASTBITMAP_LEN * MAX_FASTBITMAP_LEN);
  bitmap->max_len = len;
  bitmap->top_len = (len + MAX_FASTBITMAP_LEN - 1) / MAX_FASTBITMAP_LEN;
  assert(bitmap->top_len > 0);

  FastBitmap_init(&bitmap->l0, bitmap->top_len);

  bitmap->l1 = galloc(sizeof(FastBitmap) * bitmap->top_len);
  int i;
  // last one is initialized with partial block
  for(i=0; i < bitmap->top_len - 1; i++) {
    FastBitmap_init(&bitmap->l1[i], MAX_FASTBITMAP_LEN);
  }
  FastBitmap_init(&bitmap->l1[bitmap->top_len - 1], 
		  len - (bitmap->top_len - 1) * MAX_FASTBITMAP_LEN);
}
void BigFastBitmap_dealloc(BigFastBitmap *bitmap) {
  int i;
  for(i=0; i < bitmap->top_len; i++) {
    FastBitmap_dealloc(&bitmap->l1[i]);
  }
}
