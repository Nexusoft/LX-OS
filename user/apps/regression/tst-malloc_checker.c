#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  extern void malloc_record_enable(void);
  extern int malloc_record_disabled(void);

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-record")) {
      printf("enabling malloc recording\n");
      malloc_record_enable();
    } else {
      printf("usage: tst-malloc_checker [-record]\n");
      exit(1);
    }
  }

  // balanced malloc
  printf("Generating malloc with free (malloc recording enabled? %s)\n", malloc_record_disabled()?"no":"yes");
  for(i=0; i < 1000; i++) {
    int size = rand() % (128*1024);
    if (size < 0) size = -size;
    if (!size) continue;
    void *foo = malloc(size);
    free(foo);
  }

  printf("Generating malloc without free (malloc recording enabled? %s)\n", malloc_record_disabled()?"no":"yes");
  // malloc without free
  for(i=0; i < 1000; i++) {
    int size = 666;
    void *foo = malloc(size);
  }
  
  printf("done with malloc tests\n");
  return 0;
}
