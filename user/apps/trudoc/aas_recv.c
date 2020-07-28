#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include "pzip.h"
#include "aas_send.h"
#include "aas_eval.h"
#include "odf_sign.h"

#include "aas_common.c"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

char *aas_cert, *aas_key;
int aas_cert_len, aas_key_len;

#define AAS_CERT_PATH "/home/kwalsh/xml/stupid.cert"
#define AAS_KEY_PATH "/home/kwalsh/xml/stupid.key"

int aas_load_keys(void) {
  FILE *f;
  unsigned char *p;
  f = fopen(AAS_CERT_PATH, "r");
  if (!f) return 1;
  X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
  if (!x) return 1;
  aas_cert_len = i2d_X509(x, NULL);
  p = (unsigned char *)(aas_cert = malloc(aas_cert_len));
  i2d_X509(x, &p);
  fclose(f);

  f = fopen(AAS_KEY_PATH, "r");
  if (!f) return 1;
  RSA *r = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
  if (!r) return 1;
  aas_key_len = i2d_RSAPrivateKey(r, NULL);
  p = (unsigned char *)(aas_key = malloc(aas_key_len));
  i2d_RSAPrivateKey(r, &p);
  fclose(f);

  return 0;
}

int processTruDoc(int fd) {
  int i, n;
  char *hello;

  if (read_string(fd, &hello)) return -1;
  if (strcmp(hello, TRUDOC_HELLO)) {
    printf("expected %s, got something else\n", TRUDOC_HELLO);
    return -1;
  }
  if (read_int(fd, &n)) return -1;
  printf("loading %d files...\n", n);

  char **odf = malloc(n*sizeof(char *));
  int *len = malloc(n*sizeof(int));
  for (i = 0; i < n; i++) {
    if (read_pzip(fd, &odf[i], &len[i]))
      return -1;
  }

  printf("received %d files for processing\n", n);

  if (n == 0) {
    printf("rejecting request: no files to process\n");
    send_int(fd, 1);
    return 0;
  }

  
  // choose the formula P(T) to evaluate
  // where T = odf[0], and odf[1] .. odf[n-1] are some useful hints
  // evaluate T using the formula evaluator

  int err = aas_generic_eval(odf[0], len[0], odf+1, len+1, n-1);

  if (err) {
    printf("rejecting request: could not satisfy formula\n");
    send_int(fd, 1);
  } else {
    printf("accepting\n");
    send_int(fd, 0);
    // create a signature for ODF instead of a regular signed formula
    struct doc *doc = docsigs_parse_pzip(odf[0], len[0]);
    if (docsigs_sign(doc, aas_cert, aas_cert_len, aas_key, aas_key_len)) {
      printf("problem signing\n");
      return -1;
    }
    char *str = docsigs_writestr(doc);
    if (!str) {
      printf("problem writing document\n");
      return -1;
    }
    send_string(fd, str);
    free(str);
  }
  return 0;
}


int listenForTruDoc(short server_port) {
  struct sockaddr_in addr = { 0 };

  int fd = socket(PF_INET, SOCK_STREAM, 0);
  int err;

  int port_last = server_port + 10;
  for (;;) {
    addr.sin_port = htons(server_port);
    err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (err) {
      printf("failed to bind to port %d: errno = %d\n", server_port, errno);
      // try to reuse addr
      int on = 1;
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
      err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
      if (err) {
	printf("failed again...\n");
	if (++server_port > port_last) {
	  printf("giving up\n");
	  return -1;
	}
	continue;
      }
      break;
    }
    break;
  }

  err = listen(fd, 4);
  if (err) {
    printf("failed to listen: errno = %d\n", errno);
    return -1;
  }

  return fd;
}

int main(int ac, char **av) {

  if (ac != 1) {
    printf("usage: %s\n", av[0]);
    exit(1);
  }

  if (aas_load_keys()) {
    printf("problem loading signing keys\n");
    exit(1);
  }

  int fd = listenForTruDoc(TRUDOC_SERVER_PORT);
  if (fd < 0) exit(1);

  printf("listening for trudoc\n");

  while (1) {
    struct sockaddr_in addr;
    unsigned int addrlen = sizeof(struct sockaddr_in);
    int acceptfd = accept(fd, (struct sockaddr*)&addr, &addrlen);
    if(acceptfd < 0) {
      printf("error accepting: errno = %d\n", errno);
      break;
    }
    
    processTruDoc(acceptfd);

    // wait for close
    char c;
    while (read(acceptfd, &c, 1) > 0);
    close(acceptfd);

    printf("done processing one request\n");

    break; // for debugging, just handle one connection
  }

  printf("done for now\n");
  close(fd);

  exit(0);
}
