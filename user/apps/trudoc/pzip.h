#ifndef PZIP_H
#define PZIP_H

/* psuedo-zip:
 * using real zip files is not necessary at the moment; we use fake ones for
 * now.
 */

char *load_pzip(int nfiles, int nreqfiles, char **names, char *dir, int *zlen);
char *pzip(int nfiles, char **names, char **contents, int *zlen);
char *punzip(char *zip, int zlen, char *name);
int pzipcheck(char *zip, int zlen);

#endif
