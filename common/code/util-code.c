
#include <nexus/defs.h>	// safe to include in all environments

// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

int global_debug_level = DEBUG_LEVEL_NONE;

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

/* prepend or append a string to another string and get the result in
 * a nxcompat_alloced buffer */
char *get_string_ext(char *prefix, char *filename, char *suffix){
  int prefixlen = (prefix)?strlen(prefix):0;
  int suffixlen = (suffix)?strlen(suffix):0;
  int filelen = strlen(filename);

  int len = prefixlen + suffixlen + filelen + 1;
  char *filenameext = (char *)nxcompat_alloc(len);

  if(!filenameext)
    return NULL;
  
  if(prefix)
    strncpy(filenameext,                       prefix ,   prefixlen);

  strncpy(filenameext + prefixlen,           filename,  filelen);

  if(suffix)
    strncpy(filenameext + prefixlen + filelen, suffix,    suffixlen);

  filenameext[len - 1] = 0;

  return filenameext;
}

void put_string_ext(char *filenameext){
  nxcompat_free(filenameext);
}


/* check filename has only alphanumeric _ and - 
 * returns the first instance of a non-conforming char or -1 */
int find_badchar(char *name, int startpoint){
  if(name == NULL)
    return -1;
  if(startpoint < 0)
    startpoint = 0;
  int i;
  for(i = startpoint; i < strlen(name); i++){
    if((name[i] >= 'a') && (name[i] <= 'z'))
      continue;
    if((name[i] >= 'A') && (name[i] <= 'Z'))
      continue;
    if((name[i] >= '0') && (name[i] <= '9'))
      continue;
    if(name[i] == '_')
      continue;
    if(name[i] == '-')
      continue;
    return i;
  }
  return -1;
}

void hexdump(char *data, int len) {
  int i;
  for(i=0; i < len; i++) {
    printf("%02x ", (int)((unsigned char*)data)[i]);
    if((len + 1) % 16 == 0) {
      printf("\n");
    }
  }
}

#if 0 // alternate hexdump from Xen
void hexdump(unsigned char *data, int len) {
  int i;
  int just_did_newline = 0;
  for(i=0; i < len; i++) {
    if(i % 16 == 0) {
      printf("%p: ", data + i);
    }
    printf("%02x ", (unsigned)data[i]);
    if(i != 0 && i % 16 == 0) {
      printf("\n");
      just_did_newline = 1;
    } else {
      just_did_newline = 0;
    }
    if(i % 16 == 7) {
      printf("- ");
    }
  }
}
#endif
