#include <stdio.h>

int main(void){
  printf("testing lots of stdout functions:\n\n");

  fputs("fputs literal works\n", stdout);
  fwrite("fwrite literal works\n", 21, 1, stdout);
  fputc('y', stdout);
  putc('y', stdout);
  putchar('y');
  puts("puts literal works\n");
  fprintf(stdout, "fprintf literal works\n");
  fprintf(stdout, "fprintf %s works\n", "stringarg");
  fprintf(stdout, "fprintf %d works\n", 5);

  printf("\ndone.\n");
  return 0;
}
