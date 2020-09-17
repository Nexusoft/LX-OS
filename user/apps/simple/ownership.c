/****************************************************************************/
/*                                                                          */
/*                        TCPA TakeOwnerShip Routine                        */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>

#include <tpmfunc.h>

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <nexus/init.h>

static void hex_to_bin(char *dest, const char *src, int len) {
  int i;
  for(i=0; i < len; i++) {
    int val;
    char temp[3];

    memcpy(temp, src + i * 2, 2);
    temp[2] = '\0';
    sscanf(temp, "%02x", &val);
    assert(val >= 0 && val < 256);
    dest[i] = val;
  }
}

/** wrapper around TakeOwnership routine from libTPM */
int main(int argc, char **argv){
  assert(argc == 3);
  unsigned char ownpass[TPM_HASH_SIZE];
  unsigned char srkpass[TPM_HASH_SIZE];

  printf("[tpm] setting owner password   to [%s]\n"
	 "              storage root key to [%s]\n", argv[1], argv[2]);

  hex_to_bin(ownpass, argv[1], TPM_HASH_SIZE);
  hex_to_bin(srkpass, argv[2], TPM_HASH_SIZE);

  if (TPM_TakeOwnership(ownpass, srkpass, NULL)) {
    printf("[tpm] couldn't take ownership\n");
    return 1;
  }

  printf("[tpm] ownership taken\n");
  return 0;
}

