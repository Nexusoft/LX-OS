
// note: this file gets transcluded into aas_send.c and aas_recv.c

static int aread(int fd, char *buf, int len) {
  int tot = 0;
  while (tot < len) {
    int n = read(fd, buf+tot, len-tot);
    if (n < 0) return n;
    tot += n;
  }
  return tot;
}


static int read_int(int fd, int *i) {
  int n = aread(fd, (char *)i, 4);
  if (n != 4) {
    printf("expected integer, got end of stream\n");
    return -1;
  }
  return 0;
}

static int read_string(int fd, char **body) {
  int len;
  if (read_int(fd, &len)) return -1;
  char *buf = malloc(len + 1);
  int n = aread(fd, buf, len);
  if (n != len) {
    printf("expected string, got end of stream\n");
    return -1;
  }
  buf[len] = '\0';
  *body = buf;
  return 0;
}

int read_pzip(int fd, char **zip, int *zlen) {
  printf("loading zip file: ");
  int n;
  if (read_int(fd, &n)) return -1;
  printf("%d bytes\n", n);
  *zip = malloc(n);
  int m = aread(fd, *zip, n);
  if (m != n) {
    free(*zip);
    *zip = NULL;
    printf("expected data, got end of stream\n");
    return -1;
  }
  *zlen = n;
  return 0;
}

static int send_int(int fd, int i) {
  write(fd, &i, 4);
  return 0;
}
static int send_string(int fd, char *s) {
  send_int(fd, strlen(s));
  write(fd, s, strlen(s));
  return 0;
}

int send_odf(int fd, char *odfdir) {
  char *odf_files[] = ODF_FILES;

  int zlen;
  char *zip = load_pzip(ODF_NFILES, ODF_NREQUIREDFILES, odf_files, odfdir, &zlen);
  if (!zip) return -1;

  printf("sending package: %d bytes\n", zlen);
  send_int(fd, zlen);
  write(fd, zip, zlen);

  free(zip);
  return 0;
}

