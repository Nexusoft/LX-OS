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

#include <libtcpa/keys.h>

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <nexus/init.h>
#include <nexus/Attestation.interface.h>

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

int owner(unsigned char *ownpass, unsigned char *srkpass){
  PubKeyData tcpapubkey;
  RSA *pubkey;

  uint32_t oencdatasize;      /* owner auth data encrypted size */
  unsigned char ownerencr[RSA_MODULUS_BYTE_SIZE];
  uint32_t sencdatasize;      /* srk auth data encrypted size */
  unsigned char srkencr[RSA_MODULUS_BYTE_SIZE];

  unsigned char padded[RSA_MODULUS_BYTE_SIZE];
  unsigned char tcpa_oaep_pad_str[] = { 'T', 'C', 'P', 'A' };

  int ret;

  /* get the TCPA Endorsement Public Key */
  ret = Attestation_GetPubek(&tcpapubkey);
  if (ret != 0)
    return ret;
  
  /* convert the public key to OpenSSL format */
  pubkey = rsa_from_pubkeydata(&tcpapubkey);
  if (pubkey == NULL)
    return -1;
  memset(ownerencr, 0, sizeof ownerencr);
  memset(srkencr, 0, sizeof srkencr);

  /* Pad and then encrypt the owner data using the RSA public key */
  ret = RSA_padding_add_PKCS1_OAEP(padded, RSA_MODULUS_BYTE_SIZE,
				   ownpass, TCPA_HASH_SIZE,
				   tcpa_oaep_pad_str,
				   sizeof tcpa_oaep_pad_str);
  if (ret == 0)
    return -1;
  ret = RSA_public_encrypt(RSA_MODULUS_BYTE_SIZE, padded, ownerencr,
			   pubkey, RSA_NO_PADDING);
  if (ret < 0)
    return -1;
  oencdatasize = htonl(ret);
  /* Pad and then encrypt the SRK data using the RSA public key */
  ret = RSA_padding_add_PKCS1_OAEP(padded, RSA_MODULUS_BYTE_SIZE,
				   srkpass, TCPA_HASH_SIZE,
				   tcpa_oaep_pad_str,
				   sizeof tcpa_oaep_pad_str);
  if (ret == 0)
    return -1;
  ret = RSA_public_encrypt(RSA_MODULUS_BYTE_SIZE, padded, srkencr, pubkey,
                           RSA_NO_PADDING);
  if (ret < 0)
        return -1;

  sencdatasize = htonl(ret);
  RSA_free(pubkey);
  if (ntohl(oencdatasize) < 0)
    return -1;
  if (ntohl(sencdatasize) < 0)
    return -1;
  
  int size = ntohl(oencdatasize);
  assert(size == ntohl(sencdatasize));
  assert(size == RSA_MODULUS_BYTE_SIZE);

  ret = Attestation_TakeOwnership(ownerencr, srkencr);
  if (ret) {
    printf("take ownership failed (err = %d)\n", ret);
    return -1;
  }

  return 0;
}


/** wrapper around TakeOwnership routine from libTCPA */
int main(int argc, char **argv){
  assert(argc == 3);
  unsigned char ownpass[TCPA_HASH_SIZE];
  unsigned char srkpass[TCPA_HASH_SIZE];

  printf("[tpm] setting owner password   to [%s]\n"
	 "              storage root key to [%s]\n", argv[1], argv[2]);

  hex_to_bin(ownpass, argv[1], TCPA_HASH_SIZE);
  hex_to_bin(srkpass, argv[2], TCPA_HASH_SIZE);

  if(owner(ownpass,srkpass) < 0) {
    printf("[tpm] couldn't take ownership\n");
    return 1;
  }

  printf("[tpm] ownership taken\n");
  return 0;
}

