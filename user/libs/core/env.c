#include <nexus/vector.h>
#include <nexus/ipc.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/** Allocates a string on the heap containing full contents of file.
    WARNING: Only works up to 1023 bytes, does not handle signals.

    @param  file_len holds the amount of data if call was successful.
    @return NULL on failure. Success otherwise. 
            Client must free returned data. */
static char *
cat_file(const char *fname, int *file_len) 
{
  char *buf;
  int fd, len;
  
  fd = open(fname, O_RDONLY, 0);
  if (fd < 0)
    return NULL;

  buf = calloc(1, 1024);
  *file_len = read(fd, buf, 1023);
  close(fd);

  if (*file_len < 0) {
  	free(buf);
	return NULL;
  }

  return buf;
}

/** retrieve the value of an environment variable.
    Contrary to the Posix process environment (getenv/setenv),
    this is shared between processes as it is based on Nexus's 
    kernel filesystem.
 */ 
char *Env_get_value(const char *name, int *len_p) {
  char fname[513], *file;
  int flen, nlen;
  
  nlen = snprintf(fname, 512, "/env/%s", name);
  if (nlen >= sizeof(fname)) {
    printf("[env] path length exceeded maximum\n");
    return NULL;
  }

  file = cat_file(fname, &flen);
  if (!file) {
    printf("[env] no such environment variable [%s]\n", fname);
    return NULL;
  }

  if (len_p)
    *len_p = flen;
  
  return file;
}

