#include <stdio.h>
#include <nexus/Debug.interface.h>
#include <nexus/Mem.interface.h>

#include <nexus/kshmem.h>
#include <assert.h>
#include <stdlib.h>

// test alignments

#define PAGE_SIZE (4096)

int sizes[] = {
  1,
  2,
  3,
  4,
  8,
  12,
  28,

  104,
  105,
  106,
  107,
};

void init_vector(char *dest, int seed, int len) {
  int j;
  for(j=0; j < len; j++) {
    dest[j] = seed * j;
  }
}

int check_vector(char *dest, int seed, int len) {
  int j;
  for(j=0; j < len; j++) {
    char checkval = seed * j;
    if(dest[j] != checkval) {
      printf("mismatch @%d (%d %d)\n", j, dest[j], checkval);
      return 0;
    }
  }
  return 1;
}

int main(int argc, char **argv) {
  char *base = Mem_GetPages(2, 0);
  assert(base != NULL);
  int rv;
  int all_count = 0, error_count = 0;
#define CHECK(S, T)						\
  do {								\
    all_count++;						\
    rv = S;							\
    if(!(T)) {							\
      printf("Error %d on " #S " at %s:%d\n", rv, __FILE__, __LINE__);	\
      error_count++;						\
    }								\
  } while(0)

  CHECK(Mem_FreePages((unsigned int)base + PAGE_SIZE, 1), rv == 0);

  // Test normal in kernel space
  CHECK(Debug_PeekUser((char *)(NEXUS_START + PAGE_SIZE), 10), rv != 0);
  //// Test wraparound
  // CHECK(Debug_PeekUser((char *)(NEXUS_START - PAGE_SIZE), (1UL<<30) - 1), rv != 0);

  int i;
  for(i=0; i < sizeof(sizes)/ sizeof(int); i++) {
    memset(base, 0xff, PAGE_SIZE);
    char *test_vector = base;
    int size = sizes[i];
    assert(size <= PAGE_SIZE / 3);

    init_vector(base, size, size);
    char *edge = base + PAGE_SIZE - size;

    printf("[%d] ", size);
    // These should all pass
    // poke_user()
    CHECK(Debug_TransferUser(edge, test_vector, size), rv == 0);
    CHECK(check_vector(edge, size, size), rv);
    // peek_user()
    CHECK(Debug_TransferUser(edge - size, edge, size), rv == 0);
    CHECK(check_vector(edge - size, size, size), rv);

    // Now, check the fail cases
    int j;
    for(j=1; j < size; j++) {
      printf("<%d> ", j);
      CHECK(Debug_TransferUser(edge + j, test_vector, size), rv < 0);
      CHECK(Debug_TransferUser(test_vector, edge + j, size), rv < 0);
    }
  }

  if(error_count > 0) {
    printf("%d/%d errors!\n", error_count, all_count);
    exit(-1);
  }
  printf("Test succeeded\n");
  exit(0);
}

// Debug_PeekUser();
