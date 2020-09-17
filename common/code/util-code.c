
#include <nexus/defs.h>	// safe to include in all environments

// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

int global_debug_level = DEBUG_LEVEL_NONE;

#define isadigit(c) ((c) >= '0' && (c) <= '9')
#define isahexdigit(c) (((c) >= '0' && (c) <= '9') || ((c) >= 'a' && (c) <= 'f'))

#ifdef __NEXUSKERNEL__
int atoi(const char *s) {
  int i = 0;
  while (isadigit(*s))
    i = i*10 + *(s++) - '0';
  return i;
}
#endif

int hexatoi(const char *s) {
  int i = 0;
  while (isahexdigit(*s)) {
    if(isadigit(*s))
      i = i*16 + *(s++) - '0';
    else
      i = i*16 + *(s++) - 'a' + 10;
  }
  return i;
}

