#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "aas_send.h"
char *odf_files[] = ODF_FILES;

#include "pzip.h"
#include "pxslt.h"
#include "odf_sign.h"

char * odf_to_docbook(char *zip, int zlen);

char *aas_cert, *aas_key;
int aas_cert_len, aas_key_len;

static int aread(int fd, char *buf, int len) {
  int tot = 0;
  while (tot < len) {
    int n = read(fd, buf+tot, len-tot);
    if (n <= 0) return n;
    tot += n;
  }
  return tot;
}

void usage(int ac, char **av) {
  fprintf(stderr, "usage: %s source_odt\n", av[0]);
  exit(1);
}

int main(int ac, char **av) {
  int i;

  if (ac != 2) usage(ac, av);

  int zlen;
  char *zip = load_pzip(ODF_NFILES, ODF_NREQUIREDFILES, odf_files, av[1], &zlen);
  if (!zip) {
    fprintf(stderr, "can't open pzip: %s\n", av[1]);
    exit(1);
  }

  char *docbook = odf_to_docbook(zip, zlen);
  if (!docbook) {
    fprintf(stderr, "can't convert\n");
    exit(1);
  }
  fprintf(stdout, "%s\n", docbook);
  return 0;
}
