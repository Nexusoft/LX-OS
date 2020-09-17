#ifndef __N509_H__
#define __N509_H__
#include <nexus/typedefs.h>

N509 *N509_new(void);
void N509_fillkey(N509 *n, unsigned char *key);
void N509_fillhash(N509 *n, const char *hash);
void N509_fillipdnum(N509 *n, const char *ipdname);
int N509_size(N509 *n);
void N509_destroy(N509 *n);
unsigned char *N509_hash(N509 *n);
char *N509_getbuf(N509 *n);

#endif
