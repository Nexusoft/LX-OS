
/*
 *  trie.c
 *  NetQuery
 *
 *  Created by Oliver Kennedy on 1/21/08.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <nq/trie.h>

#define TRIE_ENTRY_SIZE 24
#define TRIE_BRANCHES 2
#define TRIE_DEFAULT_ENTRIES (500000)
#define MAX_DEPTH 32

static unsigned int read_entry(unsigned int index, unsigned char *buffer){
  unsigned int value = 0;
  int i;
  unsigned int b = (index * TRIE_ENTRY_SIZE) / 8;
  unsigned int offset = (index * TRIE_ENTRY_SIZE) % 8;
  
  //printf("read_entry(%d) (%d %d) : ", index, b, offset);
  
  for(i = 0; i < TRIE_ENTRY_SIZE; i++){
    value = value | (((buffer[b] & (0x01 << offset)) >> offset) << i);
    //printf(".%d", (buffer[b] & ((0x01 << offset))) >> offset);
    offset++;
    b += offset / 8;
    offset %= 8;
  }
  //printf("\n");
  return value;
}

static void write_entry(unsigned int index, unsigned char *buffer, unsigned int value){
  int i;
  unsigned int b = (index * TRIE_ENTRY_SIZE) / 8;
  unsigned int offset = (index * TRIE_ENTRY_SIZE) % 8;

  //printf("write_entry(%d <== %d) (%d %d) : ", index, value, b, offset);
  
  for(i = 0; i < TRIE_ENTRY_SIZE; i++){
    buffer[b] = (buffer[b] & (~(0x01 << offset))) | (((value >> i) & 0x01) << offset);
    //printf(".%d", (buffer[b] & (~(0x01 << offset))) >> offset);
    offset++;
    b += offset / 8;
    offset %= 8;
  }
  //printf("\n");
  assert(read_entry(index, buffer) == value);
}

static unsigned int size_for_entries(unsigned int cnt){
  //The following assertion is necessary to ensure that we never try to resize the trie to be bigger
  //than a link can reference.  Increase TRIE_ENTRY_SIZE if you find this assertion being violated.
  assert(!(cnt >> (TRIE_ENTRY_SIZE-1)));
  return ((TRIE_ENTRY_SIZE * cnt) / 8) + 1;
}

NQ_Trie *NQ_Trie_new(void){
  NQ_Trie *trie = malloc(sizeof(NQ_Trie));
  bzero(trie, sizeof(NQ_Trie));
  trie->buffer = malloc(size_for_entries(TRIE_DEFAULT_ENTRIES));
  trie->size = TRIE_DEFAULT_ENTRIES;
  trie->used = 1; //the root node is always allocated
  trie->first_free = 0;
  return trie;
}

void NQ_Trie_delete(NQ_Trie *trie){
  free(trie->buffer);
  free(trie);
}

void NQ_Trie_resize(NQ_Trie *trie, unsigned int size){
#ifdef USE_TRIE_TEST_MAIN
  printf("Expanding the trie to %d entries\n", size);
#endif
  if(trie->size < size){
    trie->buffer = realloc(trie->buffer, size_for_entries(size));
    trie->size = size;
  }
}

//entries are allocated/freed in groupings of TRIE_BRANCHES.  Allocs will always allocate an entry that
//satisfies the below assertion and the entries immediately following it.
static void free_trie_entry(NQ_Trie *trie, unsigned int entry){
  assert((entry % TRIE_BRANCHES) == 1);
  
  write_entry(entry, trie->buffer, trie->first_free);
  trie->first_free = entry;
}

static unsigned int alloc_trie_entry(NQ_Trie *trie){
  unsigned int entry;
  unsigned int clear_entry;
  if(trie->first_free != 0){
    entry = trie->first_free;
    trie->first_free = read_entry(trie->first_free, trie->buffer);
  } else {
    entry = trie->used;
    trie->used += TRIE_BRANCHES;
    if(trie->used >= trie->size){
      NQ_Trie_resize(trie, (trie->used * 3)/2);
    }
  }
  
  for(clear_entry = 0; clear_entry < TRIE_BRANCHES; clear_entry++){
    write_entry(clear_entry + entry, trie->buffer, 0);
  }
  
  assert((entry % TRIE_BRANCHES) == 1);
  return entry;
}

static void get_branch_entry(unsigned int *entry, unsigned int *path){
  assert((*entry % TRIE_BRANCHES) == 1);
  
  *entry += (*path) % (TRIE_BRANCHES);
  *path /= TRIE_BRANCHES;
}

//invert the path to make it easier to read from.
static unsigned int reverse_path(unsigned int path, unsigned int depth){
  unsigned int retpath = 0;
  
  for(;depth > 0; depth--){
    retpath = (retpath * TRIE_BRANCHES) + (path % TRIE_BRANCHES);
    path /= TRIE_BRANCHES;
  }
  
  return retpath;
}

static unsigned int recursive_read(NQ_Trie *trie, unsigned int currentry, unsigned int path, unsigned int depth){
  unsigned int nextentry = read_entry(currentry, trie->buffer);
  
  //printf("recursive_read(%d, %x/%d) : %d\n", currentry, path, depth, nextentry);
  
  if(depth <= 0){
    return 0;
  }
  
  if((nextentry % TRIE_BRANCHES) != 1){
    // jackpot!  We've hit a value.  (or a dead end... NULL % TRIE_BRANCHES == 0)
    // either way, we know what to return.
    return nextentry / TRIE_BRANCHES;
  }
  
  // we need to keep going deeper... what's the next step on the path?
  get_branch_entry(&nextentry, &path);
  return recursive_read(trie, nextentry, path, depth-1);
}

static void recursive_free(NQ_Trie *trie, unsigned int currentry){
  unsigned int i;
  unsigned int nextentry;
  
  for(i = 0; i < TRIE_BRANCHES; i++){
    nextentry = read_entry(currentry+i, trie->buffer);
    if((nextentry % TRIE_BRANCHES) == 1){
      recursive_free(trie, nextentry);
    }
  }
  free_trie_entry(trie, currentry);
}

static void recursive_write(NQ_Trie *trie, unsigned int currentry, unsigned int path, unsigned int depth, unsigned int value){
  unsigned int nextentry = read_entry(currentry, trie->buffer);
  unsigned int i;
  
  
  //printf("recursive_write(%d, %x/%d, %d)\n", currentry, path, depth, value);
  
  if(depth <= 0){
    if((nextentry % TRIE_BRANCHES) == 1){
      recursive_free(trie, nextentry);
    }
    write_entry(currentry, trie->buffer, value * TRIE_BRANCHES);
    return;
  }
  
  if((nextentry % TRIE_BRANCHES) != 1){
    int oldentry = nextentry;
    nextentry = alloc_trie_entry(trie);
    assert((nextentry % TRIE_BRANCHES) == 1);
    write_entry(currentry, trie->buffer, nextentry);
    for(i = 0; i < TRIE_BRANCHES; i++){
      write_entry(nextentry+i, trie->buffer, oldentry);
    }
  }
  
  get_branch_entry(&nextentry, &path);
  return recursive_write(trie, nextentry, path, depth-1, value);
}

unsigned int NQ_Trie_read(NQ_Trie *trie, unsigned int path){
  //printf("NQ_Trie_read(%x/%d)\n", path, MAX_DEPTH);
  return recursive_read(trie, 0, reverse_path(path, MAX_DEPTH), MAX_DEPTH);
}

void NQ_Trie_write(NQ_Trie *trie, unsigned int path, unsigned int length, unsigned int value){
  //printf("NQ_Trie_write(%x/%d, %d)\n", path, length, value);
  if(length > MAX_DEPTH){
    length = MAX_DEPTH;
  }
  recursive_write(trie, 0, reverse_path(path, MAX_DEPTH), length, value);
}

#ifdef USE_TRIE_TEST_MAIN

int count_matches(NQ_Trie *t, int *s, int *l) {
  uint32_t short_tests[2] = { 0x01000000, 0x01000001 };
  uint32_t long_tests[2] = { 0x01010000, 0x01010001 };
  *s = 0;
  *l = 0;
  for(i=0; i < 2; i++) {
    if(NQ_Trie_read(trie2, short_tests[i] >> 8) == 0xdead) {
      *s += 1;
    }
    if(NQ_Trie_read(trie2, long_tests[i] >> 8) == 0xbeef) {
      *l += 1;
    }
  }
}

int main(int argc, char **argv){
  unsigned int count;
  unsigned int *array;
  NQ_Trie *trie;
  unsigned int i, temp, result;
  unsigned int len = 24;

  if(argc < 1){
    printf("usage: %s count\n", argv[0]);
    exit(1);
  }
  
  count = atoi(argv[1]);
  srandom(time(NULL));
  
  trie = NQ_Trie_new();
  
  array = malloc(count * sizeof(unsigned int));
  
  for(i = 1; i < count; i++){
    temp = random();
    NQ_Trie_write(trie, temp>>8, len, i);
    array[i] = temp;

    temp = (random() % i) + 1;
    result = NQ_Trie_read(trie, array[temp]>>8);
    if(result != temp){
//      printf("Eeek!  Tried to read %x/%d (%d) and got %d instead!  (not a failure... just a factor of randomness: %x/%d is a prefix of %x/%d\n", array[temp]>>8, 24, temp, result);
//      assert(array[result]);
    }
  }

  // Focused test: do longest prefix match
  NQ_Trie *trie2 =   trie = NQ_Trie_new();
  uint32_t _short = 0x01000000; // 1.0.0.0 / 8
  uint32_t _long = 0x01010000; // 1.1.0.0 / 16
  int s, l;
  count_matches(trie2, &s, &l);
  assert(s == 0 && l == 0);
  NQ_Trie_write(trie2, _short >> 8, 8, 0xdead);
  NQ_Trie_write(trie2, _long >> 8, 16, 0xbeef);
  result = NQ_Trie_read(trie2, _short >> 8);
  if(result != 0xdead) {
    printf("could not find short\n");
    exit(-1);
  }
  result = NQ_Trie_read(trie2, _long >> 8);
  if(result != 0xbeef) {
    printf("could not find short\n");
    exit(-1);
  }

  printf("--------------------------------------------------\n");
  printf("  Trie test successful\n");
  printf("  Prefixes: %d (avg length: %d)\n", count, len);
  printf("  Allocated: %d bytes (%d entries)\n", trie->size * TRIE_ENTRY_SIZE / 8, trie->size);
  printf("  Used:  %d bytes (%d entries)\n", trie->used * TRIE_ENTRY_SIZE / 8, trie->used);
  printf("--------------------------------------------------\n");
  
  free(array);
  NQ_Trie_delete(trie);
  return 0;
}

#endif

