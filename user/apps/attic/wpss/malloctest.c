#include <stdlib.h>

void b(void){
  char *p;
  p = (char *)malloc(128);
}


void a(void){
  char *ptr1, *ptr2, *ptr3, *ptr4;
  ptr1 = (char *)malloc(4);
  b();
  ptr2 = (char *)malloc(4);
  dump_mallocs();
  ptr3 = (char *)malloc(4);
  ptr4 = (char *)malloc(4);
  dump_mallocs();
  free(ptr2);
  dump_mallocs();
  free(ptr4);
  dump_mallocs();
}

int main(){

  printf("a's address is 0x%p\n", a);
  a();

  dump_mallocs();

  return 0;
}
