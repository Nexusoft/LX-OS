/****************************************************************************/
/*                                                                          */
/* HMAC.H 03 Apr 2003                                                       */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#ifndef HMAC_H
#define HMAC_H

#include <linux/types.h>

int authhmac(unsigned char *digest, unsigned char *key,
             unsigned int keylen, unsigned char *h1, unsigned char *h2,
             unsigned char h3, ...);
int checkhmac1(unsigned char *buffer, uint32_t command,
               unsigned char *ononce, unsigned char *key, int keylen, ...);
int checkhmac2(unsigned char *buffer, uint32_t command,
               unsigned char *ononce, 
	       unsigned char *key, int keylen,
	       unsigned char *key2, int keylen2, ...);
int rawhmac(unsigned char *digest, unsigned char *key,
            unsigned int keylen, ...);

void sha1(unsigned char *input, int len, unsigned char *output);

#endif
