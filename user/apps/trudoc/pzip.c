#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "pzip.h"

static int filesize(char *filename) {
  struct stat s;
  if (stat(filename, &s)) return 0;
  else return s.st_size;
}

static char *readfile(char *fname, int optional) {
    int n = filesize(fname);
    int fd = open(fname, O_RDONLY);
    if (fd < 0 || n <= 0) {
      if (!optional) printf("open failed: %s\n", fname);
      return NULL;
    }
    char *buf = malloc(n+1);
    int m = read(fd, buf, n);
    close(fd);
    if (m != n) {
      printf("read failed: %s\n", fname);
      return NULL;
    }
    buf[n] = '\0';
    return buf;
}

char *load_pzip(int nfiles, int nreqfiles, char **names, char *dir, int *zlen) {
  char fname[1000];
  char **contents = malloc(nfiles * sizeof(char *));
  int i;

  printf("creating package:\n");
  for (i = 0; i < nfiles; i++) {
    sprintf(fname, "%s/%s", dir, names[i]);
    int optional = (i >= nreqfiles);
    contents[i] = readfile(fname, optional);
    if (!contents[i]) {
      if (optional) {
	printf(" file %s: missing\n", fname);
	continue;
      } else {
	return NULL;
      }
    }
    printf(" file %s: %d bytes\n", fname, (int)strlen(contents[i]));
  }

  char *zip = pzip(nfiles, names, contents, zlen);
  free(contents);
  return zip;
}

static void write_int(char **z, int i) {
  memcpy(*z, &i, 4);
  *z += 4;
}

static void write_string(char **z, char *s) {
  write_int(z, strlen(s));
  memcpy(*z, s, strlen(s));
  *z += strlen(s);
}

char *pzip(int nfiles, char **names, char **contents, int *zlen)
{
  int i, n = 4;

  for (i = 0; i < nfiles; i++) {
    n += 4 + strlen(names[i])
	+ 4 + (contents[i] ? strlen(contents[i]) : 0);
  }

  char *zip = malloc(n);
  char *z = zip;

  write_int(&z, nfiles);
  for (i = 0; i < nfiles; i++) {
    write_string(&z, names[i]);
    if (contents[i])
      write_string(&z, contents[i]);
    else
      write_int(&z, -1);
  }

  *zlen = n;
  return zip;
}

char *punzip(char *zip, int zlen, char *name)
{
  int m = strlen(name);
  int n, i, nfiles;
  if (zlen < 4) return NULL;
  nfiles  = *(int *)zip;
  zip += 4;
  zlen -= 4;

  for (i = 0; i < nfiles; i++) {
    if (zlen < 4) return NULL;
    n = *(int *)zip;
    zip += 4;
    zlen -= 4;
    if (zlen < n + 4) return NULL;
    if (n == m && !strncmp(zip, name, m)) {
      zip += n;
      zlen -= n;
      n = *(int *)zip;
      zip += 4;
      zlen -= 4;
      if (n < 0 || zlen < n) return NULL;
      char *buf = malloc(n+1);
      memcpy(buf, zip, n);
      buf[n] = '\0';
      return buf;
    } else {
      zip += n;
      zlen -= n;
      n = *(int *)zip;
      if (n < 0) n = 0;
      zip += 4 + n;
      zlen -= 4 + n;
    }
  }
  return NULL;
}

int pzipcheck(char *zip, int zlen)
{
  int n, i, nfiles;
  if (zlen < 4) return -1;
  nfiles  = *(int *)zip;
  zip += 4;
  zlen -= 4;

  for (i = 0; i < nfiles; i++) {
    if (zlen < 4) return -1;
    n = *(int *)zip;
    zip += 4;
    zlen -= 4;
    if (zlen < n + 4) return -1;
    zip += n;
    zlen -= n;
    n = *(int *)zip;
    if (n < 0) n = 0;
    zip += 4 + n;
    zlen -= 4 + n;
  }
  if (zlen != 0) return -1;
  return 0;
}
