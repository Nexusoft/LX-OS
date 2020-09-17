#ifndef _NEXUS_BITMAP_H_
#define _NEXUS_BITMAP_H_

#include <asm/bitops.h>


////////  Simple bitmap operations  ////////

static inline void 
nxbitmap_set(char *bitmap, unsigned int element)
{
	bitmap[element >> 3] |= (1 << (element & 0x7));
}

static inline int 
nxbitmap_isset(const char *bitmap, unsigned int element)
{
	return ((bitmap[element >> 3] & (1 << (element & 0x7)))) ? 1 : 0;
}

static inline void 
nxbitmap_clear(char *bitmap, unsigned int element)
{
	bitmap[element >> 3] &= ~(1 << (element & 0x7));
}

////////  Simple 2-bit integer operations  ////////

static inline unsigned char
nxtwobit_get(const char *map, unsigned int key)
{
	unsigned int ktmp;

	ktmp = key << 1;
	return (nxbitmap_isset(map, ktmp) << 1) + 
	        nxbitmap_isset(map, ktmp + 1);
}

static inline void
nxtwobit_set(char *map, int key, unsigned char val)
{
	if (val & 0x2)
		nxbitmap_set(map, key << 1);
	else
		nxbitmap_clear(map, key << 1);

	if (val & 0x1)
		nxbitmap_set(map, (key << 1) + 1);
	else
		nxbitmap_clear(map, (key << 1) + 1);
}

////////  Simple nibble (4-bit integer) operations  ////////

static inline unsigned char
nxnibble_get(const char * map, int key)
{
	unsigned char ret;
	
	ret = map[key >> 1];
	if (key & 0x1)
		return (ret >> 4) & 0x7;
	else
		return ret & 0x7;
}

/** Set the value of a nibble.
    Somewhat SLOW implementation, but more understandable (I hope) */
static inline void
nxnibble_set(char * map, int key, unsigned char val)
{
	unsigned char mask;

	if (key & 0x1) {
		val = val << 4;
		mask = 0x0f;
	}
	else {
		val &= 0x7;
		mask = 0xf0;
	}

	// first blank the nibble
	map[key >> 1] &= mask;

	// then overwrite
	map[key >> 1] |= val;
}

int nxtwobit_selftest(void);
int nxnibble_selftest(void);

////////  Comprehensive bitmap datastructure  ////////

// NOTE: This structure inverts the bottom level bitmap
struct Bitmap {
	int max_level_num; // number of index levels
	int num_entries;
	unsigned int *bottom_data; // points to the bottom (e.g., the actual data)
	unsigned int data[0]; // everything is packed in this array
	// includes an complemented index (e.g., 1 == logical 0)
};

struct Bitmap *bitmap_new(int num_entries);
void bitmap_init(struct Bitmap *map, int num_entries, int maxlen);
void bitmap_destroy(struct Bitmap *map);

int bitmap_find_first_zero(struct Bitmap *map, int startOffset);

void bitmap_set(struct Bitmap *map, int offset);
void bitmap_clear(struct Bitmap *map, int offset);
int bitmap_test(struct Bitmap *map, int offset);


////////  Faster small bitmap datastructure  ////////

// Fast bitmap is less general, but is faster
#define MAX_FASTBITMAP_LEN (1024)
struct FastBitmap {
  unsigned int l0; // bit is 0 if there exists one non-zero child
  unsigned int l1[32];
  int max_len;
  int set_count;
};

#define WORDSIZE (32)
static inline void FastBitmap_init(FastBitmap *bitmap, int len) {
  assert(len <= MAX_FASTBITMAP_LEN);
  memset(bitmap, 0, sizeof(*bitmap));
  bitmap->max_len = len;
  bitmap->set_count = 0;
}

static inline void FastBitmap_dealloc(FastBitmap *bitmap) {
  // No allocation needed for FastBitmap
}

void FastBitmap_dump(FastBitmap *bitmap);

// Find first zero
// Return -1 if not found
static inline int FastBitmap_ffz(FastBitmap *bitmap) {
  if(bitmap->l0 == ~0) {
    return -1;
  }
  int l0_offset = ffz(bitmap->l0);
  assert(bitmap->l1[l0_offset] != ~0);
  int cand_val = l0_offset * WORDSIZE + ffz(bitmap->l1[l0_offset]);
  return (cand_val < bitmap->max_len ? cand_val : -1);
}

#define COMPUTE_OFFSETS				\
  int l0_offset = loc / WORDSIZE;		\
  int l1_offset = loc % WORDSIZE;

static inline void FastBitmap_set(FastBitmap *bitmap, int loc) {
  assert(loc < bitmap->max_len);
  COMPUTE_OFFSETS;
  int mask = 1 << l1_offset;
  if(!(bitmap->l1[l0_offset] & mask)) {
    bitmap->set_count++;
  }
  bitmap->l1[l0_offset] |= mask;
  if(bitmap->l1[l0_offset] == ~0) {
    bitmap->l0 |= (1 << l0_offset);
  }
}

static inline void FastBitmap_set_all(FastBitmap *bitmap) {
  bitmap->l0 = ~0;
  bitmap->set_count = bitmap->max_len;
  memset(bitmap->l1, 0xff, sizeof(bitmap->l1));
}

static inline __attribute__((always_inline)) void FastBitmap_clear(FastBitmap *bitmap, int loc) {
  assert(loc < bitmap->max_len);
  COMPUTE_OFFSETS;

  int mask = 1 << l1_offset;
  if(bitmap->l1[l0_offset] & mask) {
    bitmap->set_count--;
  }
  bitmap->l1[l0_offset] &= ~mask;
  bitmap->l0 &= ~(1 << l0_offset);
}

static inline int FastBitmap_test(FastBitmap *bitmap, int loc) {
  assert(loc < bitmap->max_len);
  COMPUTE_OFFSETS;
  return !!(bitmap->l1[l0_offset] & (1 << l1_offset));
}

static inline int FastBitmap_is_all_set(FastBitmap *bitmap) {
  return bitmap->set_count == bitmap->max_len;
}

#undef COMPUTE_OFFSETS


////////  Faster large bitmap datastructure  ////////

#define BOTTOM_SIZE (MAX_FASTBITMAP_LEN)
struct BigFastBitmap {
  int top_len;
  int max_len;
  FastBitmap l0;
  FastBitmap *l1;
};

#define COMPUTE_OFFSETS				\
  int l0_offset = loc / BOTTOM_SIZE;		\
  int l1_offset = loc % BOTTOM_SIZE;

// 132 bytes per bottom layer
void BigFastBitmap_init(BigFastBitmap *bitmap, int len);
void BigFastBitmap_dealloc(BigFastBitmap *bitmap);

void BigFastBitmap_dump(BigFastBitmap *bitmap);

// N.B. This is a shallow copy
static inline void BigFastBitmap_copy(BigFastBitmap *dest, BigFastBitmap *src) {
  *dest = *src;
}

static inline int BigFastBitmap_ffz(BigFastBitmap *bitmap) {
  if(FastBitmap_is_all_set(&bitmap->l0)) {
    return -1;
  }
  int l0_offset = FastBitmap_ffz(&bitmap->l0);
  assert(l0_offset >= 0);
  int l1_ffz = FastBitmap_ffz(&bitmap->l1[l0_offset]);
  assert(l1_ffz >= 0);
  int cand_val = l0_offset * BOTTOM_SIZE + l1_ffz;
  return (cand_val < bitmap->max_len ? cand_val : -1);
}

static inline void BigFastBitmap_set(BigFastBitmap *bitmap, int loc) {
  assert(loc < bitmap->max_len);
  COMPUTE_OFFSETS;
  FastBitmap_set(&bitmap->l1[l0_offset], l1_offset);
  if(FastBitmap_is_all_set(&bitmap->l1[l0_offset])) {
    FastBitmap_set(&bitmap->l0, l0_offset);
  }
}
static inline void BigFastBitmap_clear(BigFastBitmap *bitmap, int loc) {
  assert(loc < bitmap->max_len);
  COMPUTE_OFFSETS;
  FastBitmap_clear(&bitmap->l1[l0_offset], l1_offset);
  FastBitmap_clear(&bitmap->l0, l0_offset);
}
static inline int BigFastBitmap_test(BigFastBitmap *bitmap, int loc) {
  assert(loc < bitmap->max_len);
  COMPUTE_OFFSETS;
  return FastBitmap_test(&bitmap->l1[l0_offset], l1_offset);
}

#undef WORDSIZE
#undef COMPUTE_OFFSETS

#endif
