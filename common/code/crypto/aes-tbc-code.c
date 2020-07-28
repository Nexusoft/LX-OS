
#define AES_BLOCKSIZE (16)
#define DEBUG_TBC (0)

#define TBC_CHECK_ARGS				\
  assert(*destlen >= srclen);			\
  assert(tweaklen == AES_BLOCKSIZE);		\
  assert(ktweaklen == AES_BLOCKSIZE);

/* tweak block chaining with the ciphertext stealing variant in
 * Tweakable Block Ciphers */
int tbc_encrypt(unsigned char *src, int srclen,
		 unsigned char *dest, int *destlen, 
		 unsigned char *key, int keylen,
		 unsigned char *tweak, int tweaklen,
		 unsigned char *ktweak, int ktweaklen){
  TBC_CHECK_ARGS;

  if(srclen < AES_BLOCKSIZE){
    printf("     srclen=%d keylen=%d tweaklen=%d ktweaklen=%d\n", srclen, keylen, tweaklen, ktweaklen);
    dump_stack_trace(NULL);
  }

  struct aes_ctx ctx;
  int ciphersteal = (srclen % AES_BLOCKSIZE);
  int tbclen;
  int i;

  assert(src != NULL);
  assert(dest != NULL);
  assert(key != NULL);
  assert(tweak != NULL);
  assert(ktweak != NULL);

  if(aes_set_key(&ctx, key, keylen) < 0){
    printf("Couldn't set aes key\n");
    return -1;
  }
  
  if(ciphersteal == 0){
    tbclen = srclen;
  }else{
    assert(srclen > AES_BLOCKSIZE);
    tbclen = srclen - ciphersteal - AES_BLOCKSIZE;
  }
  
  for(i = 0; i < tbclen; i += AES_BLOCKSIZE){
    if(DEBUG_TBC){
      int j;
      printf("tweak       = ");
      for(j = 0; j < AES_BLOCKSIZE; j++)
	printf("%02x ", tweak[j]);
      printf("\n");

      printf("clr: ");
      for(j = 0; j < 16; j++)
	printf("%02x ", src[i+j]);
      printf("\n");
    }

    aes_encrypt_tweak(&ctx, dest + i, src + i, tweak, ktweak);

    tweak = dest + i;
  }
  
  if(ciphersteal != 0){
    unsigned char tmpenc[AES_BLOCKSIZE];

    int lastoff = srclen - ciphersteal;
    int secondtolastoff = lastoff - AES_BLOCKSIZE;

    if(DEBUG_TBC){
      int i;
      printf("Y | X = ");
      for(i = 0; i < ciphersteal; i++){
	printf("%02x ", tweak[i]);
      }
      printf("| ");
      for(i = ciphersteal; i < AES_BLOCKSIZE; i++){
	printf("%02x ", tweak[i]);
      }
      printf("\n");
      
      printf("M(m-1) = ");
      for(i = 0; i < AES_BLOCKSIZE; i++)
	printf("%02x ", src[secondtolastoff + i]);
      printf("\n");
    }

    aes_encrypt_tweak(&ctx, tmpenc, src + secondtolastoff, tweak, ktweak);

    if(DEBUG_TBC){
      int i;
      printf("C(m) | C' = ");
      for(i = 0; i < ciphersteal; i++){
	printf("%02x ", tmpenc[i]);
      }
      printf("| ");
      for(i = ciphersteal; i < AES_BLOCKSIZE; i++){
	printf("%02x ", tmpenc[i]);
      }
      printf("\n");
      
    }


    memcpy(dest + lastoff, tmpenc, ciphersteal);

    if(DEBUG_TBC){
      int i;
      printf("C(m) = ");
      for(i = 0; i < ciphersteal; i++)
	printf("%02x ", dest[lastoff + i]);
      printf("\n");
    }

    unsigned char last[AES_BLOCKSIZE];
    unsigned char newtweak[AES_BLOCKSIZE];
    memcpy(last, src + lastoff, ciphersteal);
    memcpy(last + ciphersteal, tmpenc + ciphersteal, AES_BLOCKSIZE - ciphersteal);

    memcpy(newtweak, tweak + ciphersteal, AES_BLOCKSIZE - ciphersteal);
    memcpy(newtweak + AES_BLOCKSIZE - ciphersteal, tmpenc, ciphersteal);

    if(DEBUG_TBC){
      int i;
      printf("M(m) | C' = ");
      for(i = 0; i < ciphersteal; i++){
	printf("%02x ", last[i]);
      }
      printf("| ");
      for(i = ciphersteal; i < AES_BLOCKSIZE; i++){
	printf("%02x ", last[i]);
      }
      printf("\n");

      printf("X | C(m) = ");
      for(i = 0; i < AES_BLOCKSIZE - ciphersteal; i++){
	printf("%02x ", newtweak[i]);
      }
      printf("| ");
      for(i = AES_BLOCKSIZE - ciphersteal; i < AES_BLOCKSIZE; i++){
	printf("%02x ", newtweak[i]);
      }
      printf("\n");
    }


    aes_encrypt_tweak(&ctx, dest + secondtolastoff, last, newtweak, ktweak);
  }

  *destlen = srclen;

  return 0;
}

int tbc_decrypt(unsigned char *src, int srclen,
		 unsigned char *dest, int *destlen, 
		 unsigned char *key, int keylen,
		 unsigned char *tweak, int tweaklen,
		 unsigned char *ktweak, int ktweaklen){
  TBC_CHECK_ARGS;

  struct aes_ctx ctx;
  int ciphersteal = (srclen % AES_BLOCKSIZE);
  int tbclen;
  int i;

  if(aes_set_key(&ctx, key, keylen) < 0){
    printf("Couldn't set aes key\n");
    return -1;
  }

  if(ciphersteal == 0){
    tbclen = srclen;
  }else{
    assert(srclen > AES_BLOCKSIZE);
    tbclen = srclen - ciphersteal - AES_BLOCKSIZE;
  }

  for(i = 0; i < tbclen; i += AES_BLOCKSIZE){
    if(DEBUG_TBC){
      int j;
      printf("tweak       = ");
      for(j = 0; j < AES_BLOCKSIZE; j++)
	printf("%02x ", tweak[j]);
      printf("\n");

      printf("enc: ");
      for(j = 0; j < 16; j++)
	printf("%02x ", src[i+j]);
      printf("\n");
    }


    aes_decrypt_tweak(&ctx, dest + i, src + i, tweak, ktweak);


    if(DEBUG_TBC){
      int j;
      printf("clr: ");
      for(j = 0; j < 16; j++)
	printf("%02x ", dest[i+j]);
      printf("\n");
    }


    tweak = src + i;
  }

  if(ciphersteal != 0){
    int lastoff = srclen - ciphersteal;
    int secondtolastoff = lastoff - AES_BLOCKSIZE;

    unsigned char newtweak[AES_BLOCKSIZE];
    memcpy(newtweak, tweak + ciphersteal, AES_BLOCKSIZE - ciphersteal);
    memcpy(newtweak + AES_BLOCKSIZE - ciphersteal, src + lastoff, ciphersteal);

    unsigned char tmpdec[AES_BLOCKSIZE];

    aes_decrypt_tweak(&ctx, tmpdec, src + secondtolastoff, newtweak, ktweak);

    memcpy(dest + lastoff, tmpdec, ciphersteal);

    unsigned char tmpenc[AES_BLOCKSIZE];
    memcpy(tmpenc, src + lastoff, ciphersteal);
    memcpy(tmpenc + ciphersteal, tmpdec + ciphersteal, AES_BLOCKSIZE - ciphersteal);

    aes_decrypt_tweak(&ctx, dest + secondtolastoff, tmpenc, tweak, ktweak);
  }

  *destlen = srclen;

  return 0;
}

