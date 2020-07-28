#include <nexus/env.h>

int main(int argc, char **argv) {
  chdir("/nfs");

  int tid_len;
  char *tid_data = Env_get_value("host_tid", &tid_len);
  printf("Tid len = %d\n", tid_len);
}
