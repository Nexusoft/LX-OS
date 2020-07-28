#include <libtcpa/tpm.h>
#include <nexus/vkey.h>
#include <nexus/policy.h>
#include <nexus/generaltime.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <nexus/util.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <nexus/debug.h>
//#include "ca_cert.h"

char *makename(char *base, char *suffix) {
  char *name = malloc(strlen(base) + 1 + strlen(suffix) + 1);
  sprintf(name, "%s.%s", base, suffix);
  return name;
}

int main(int ac, char **av){
  int i, fd;

  char *av0 = av[0];
  ac--;
  av++;
  int s = 0;
  char *basename = NULL;
  while (ac > 0) {
    if (!strcmp(av[0], "-nrk")) {
      s = 1;
      ac--;
      av++;
      continue;
    }
    if (ac > 1 && !strcmp(av[0], "-out")) {
      basename = av[1];
      ac -= 2;
      av += 2;
      continue;
    }
    break;
  }

  for (i = 0; i < ac; i++)
    if (av[i][0] == '-')
      goto usage;

  if (ac != 0 && ac != 2) {
usage:
    fprintf(stderr, "usage: %s [-nrk] [-out basename] [<ca.crt> <nexusca.crt>]\n", av0);
    return -1;
  }

  char *name = (s ? "nrk" : "nsk");

  char *cafile = (ac ? av[0] : NEXUS_DEFAULT_CA_PATH);
  char *ncafile = (ac ? av[1] : NEXUS_DEFAULT_NEXUSCA_PATH);

  char *nskfile = (s ? NEXUS_DEFAULT_NRK_PATH : NEXUS_DEFAULT_NSK_PATH);
  char *nskcertfile = (s ? NEXUS_DEFAULT_NRKCERT_PATH : NEXUS_DEFAULT_NSKCERT_PATH);
  char *nsksformfile = (s ? NEXUS_DEFAULT_NRKSFORM_PATH : NEXUS_DEFAULT_NSKSFORM_PATH);

  if (basename) {
    nskfile = makename(basename, name);
    nskcertfile = makename(nskfile, "crt");
    nsksformfile = makename(nskfile, "signed");
  }

  VKey *k = NULL;
  printf("Checking for %s on disk: %s\n", name, nskfile);
  fd = open(nskfile, O_RDONLY);
  if (fd > 0) {
    printf("  found file... attempting to read\n");
    int len = 5000;
    unsigned char *buf = (unsigned char *)malloc(len);
    len = read(fd, buf, len);
    if (len < 0) {
      printf("  error reading file...\n");
    } else if (len == 0) {
      printf("  file appears empty...\n");
    } else {
      k = vkey_deserialize(buf, len);
      if (!k) {
	printf("  %s could not be deserialized...\n", name);
      }
    }
    free(buf);
    close(fd);
  } else {
    printf("  no such file...");
  }

  if (!k) {
    printf("Creating a new %s\n", name);
    k = vkey_create((s ? VKEY_TYPE_NRK : VKEY_TYPE_NSK), ALG_NONE /* ignored */);
    if (!k) {
      printf("  error creating %s... exiting\n", name);
      return -1;
    }
    printf("Writing new %s to disk: %s\n", name, nskfile);
    fd = open(nskfile, O_CREAT | O_WRONLY);
    if (fd <= 0) {
      printf("  error opening file...\n");
    } else {
      char *buf = vkey_serialize(k, 0);
      if (!buf) {
	printf("  error serializing %s...\n", name);
      } else {
	int len = der_msglen(buf);
	write(fd, buf, len);
	fsync(fd);
	printf("  wrote %d bytes\n", len);
	free(buf);
      }
      close(fd);
    }
  }

  char *nskcert = NULL;
  //char nskcertfile[255];
  //sprintf(nskcertfile, "%s.crt", nskfile);
  printf("Checking for %s certificate on disk: %s\n", name, nskcertfile);
  fd = open(nskcertfile, O_RDONLY);
  if (fd > 0) {
    printf("  found file... attempting to read\n");
    int len = 5000;
    unsigned char *buf = (unsigned char *)malloc(len);
    len = read(fd, buf, len);
    if (len < 0) {
      printf("  error reading file...\n");
      free(buf);
    } else if (len == 0) {
      printf("  file appears empty...\n");
      free(buf);
    } else {
      nskcert = buf;
    }
    close(fd);
  } else {
    printf("  no such file...");
  }

  char *nsksform = NULL;
  //char nsksformfile[255];
  //sprintf(nsksformfile, "%s.crt", nskfile);
  printf("Checking for %s signed formula on disk: %s\n", name, nsksformfile);
  fd = open(nsksformfile, O_RDONLY);
  if (fd > 0) {
    printf("  found file... attempting to read\n");
    int len = 5000;
    unsigned char *buf = (unsigned char *)malloc(len);
    len = read(fd, buf, len);
    if (len < 0) {
      printf("  error reading file...\n");
      free(buf);
    } else if (len == 0) {
      printf("  file appears empty...\n");
      free(buf);
    } else {
      nsksform = buf;
    }
    close(fd);
  } else {
    printf("  no such file...");
  }

  if (!nskcert || !nsksform) {
    char buf_ca[5000];
    char buf_nca[5000];
    printf("Obtaining a new %s certificate\n", name);

    fd = open(cafile, O_RDONLY);
    int calen = (fd > 0 ? read(fd, buf_ca, 5000) : 0);
    if (calen <= 0) {
      printf("  error reading ca file: %s ... exiting\n", cafile);
      return -1;
    }
    close(fd);
    fd = open(ncafile, O_RDONLY);
    int ncalen = (fd > 0 ? read(fd, buf_nca, 5000) : 0);
    if (ncalen <= 0) {
      printf("  error reading nexusca file: %s ... exiting\n", ncafile);
      return -1;
    }
    close(fd);

    int buflen, buflen2;
    char *buf = vkey_get_remote_certification(k, buf_nca, ncalen, buf_ca, calen, &buflen, &buflen2);
    if (!buf) {
      printf("  error obtaining certificate from remote CAs... exiting\n");
      return -1;
    }

    printf("Writing new %s certificate to disk: %s\n", name, nskcertfile);
    fd = open(nskcertfile, O_CREAT | O_WRONLY);
    if (fd <= 0) {
      printf("  error opening file...\n");
    } else {
      write(fd, buf, buflen);
      fsync(fd);
      printf("  wrote %d bytes\n", buflen);
      close(fd);
    }
    close(fd);

    printf("Writing new %s signed formula to disk: %s\n", name, nsksformfile);
    fd = open(nsksformfile, O_CREAT | O_WRONLY);
    if (fd <= 0) {
      printf("  error opening file...\n");
    } else {
      write(fd, buf + buflen, buflen2);
      fsync(fd);
      printf("  wrote %d bytes\n", buflen2);
      close(fd);
    }

    free(buf);
    close(fd);
  }

  printf("Success\n");
  return 0;
}

