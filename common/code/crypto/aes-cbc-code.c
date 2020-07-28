#define CBC_CHECK_ARGS				\
  assert(*destlen >= srclen);			\
  assert(tweaklen == AES_BLOCKSIZE);		


void nexus_cbc_encrypt_aligned(unsigned char *src, int srclen,
			       unsigned char *dest, int *destlen, 
			       unsigned char *key, int keylen,
			       unsigned char *tweak, int tweaklen){
  CBC_CHECK_ARGS;
  struct aes_ctx ctx;

  assert((srclen % AES_BLOCKSIZE) == 0);
  int cbclen = srclen;

  if(aes_set_key(&ctx, key, keylen) < 0){
    printf("Couldn't set aes key\n");
    return;
  }

  int i;
  for(i = 0; i < cbclen; i += AES_BLOCKSIZE){
    unsigned char srcblock[AES_BLOCKSIZE];

    op_xor(AES_BLOCKSIZE, src + i, tweak, srcblock);
    aes_encrypt(&ctx, dest + i, srcblock);

    tweak = dest + i;
  }
  
  *destlen = srclen;
}

void nexus_cbc_decrypt_aligned(unsigned char *src, int srclen,
			       unsigned char *dest, int *destlen, 
			       unsigned char *key, int keylen,
			       unsigned char *tweak, int tweaklen){
  CBC_CHECK_ARGS;
  struct aes_ctx ctx;
  assert((srclen % AES_BLOCKSIZE) == 0);
  int cbclen = srclen;

  if(aes_set_key(&ctx, key, keylen) < 0){
    printf("Couldn't set aes key\n");
    return;
  }

  int i;
  for(i = 0; i < cbclen; i += AES_BLOCKSIZE){
    aes_decrypt(&ctx, dest + i, src + i);
    op_xor(AES_BLOCKSIZE, dest + i, tweak, dest + i);

    tweak = src + i;
  }
  
  *destlen = srclen;
}

void nexus_cbc_decrypt(unsigned char *src, int srclen,
		       unsigned char *dest, int *destlen, 
		       unsigned char *key, int keylen,
		       unsigned char *tweak, int tweaklen){
  CBC_CHECK_ARGS;
  int ciphersteal = (srclen % AES_BLOCKSIZE);
  int dbg = 0;

  if(ciphersteal == 0){
    nexus_cbc_decrypt_aligned(src, srclen,
			      dest, destlen,
			      key, keylen, tweak, tweaklen);
    return;
  }

  int len = srclen - ciphersteal;

  int i;
  if(dbg){
    printf("last ciphr:                         ");
    for(i = 0; i < ciphersteal; i++){
      printf("%02x ", src[len + i]);
    }
    printf("\n");

    printf("second to last ciphr:               ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", src[len - AES_BLOCKSIZE + i]);
    }
    printf("\n");
  }

  unsigned char tmpblock[AES_BLOCKSIZE];
  int tmplen = AES_BLOCKSIZE;
  nexus_cbc_decrypt_aligned(src + len - AES_BLOCKSIZE, AES_BLOCKSIZE,
			    tmpblock, &tmplen,
			    key, keylen,
			    tweak, tweaklen);
  assert(tmplen == AES_BLOCKSIZE);

  if(dbg){
    printf("decrypted second to last block:     ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", tmpblock[i]);
    }
    printf("\n");
  }

  memcpy(src + len - AES_BLOCKSIZE, src + len, ciphersteal);
  memcpy(src + len - AES_BLOCKSIZE + ciphersteal, 
	 tmpblock + ciphersteal, 
	 AES_BLOCKSIZE - ciphersteal);
  
  tmplen = len; 
  nexus_cbc_decrypt_aligned(src, len,
			    dest, &tmplen,
			    key, keylen, tweak, tweaklen);
  assert(tmplen == len);

  memcpy(dest + len, tmpblock, ciphersteal);

  if(dbg){
    printf("second to last plain:               ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", dest[len - AES_BLOCKSIZE + i]);
    }
    printf("\n");

    printf("last plain:                         ");
    for(i = 0; i < ciphersteal; i++){
      printf("%02x ", dest[len + i]);
    }
    printf("\n");
  }

  *destlen = srclen;
}

void nexus_cbc_encrypt(unsigned char *src, int srclen,
		       unsigned char *dest, int *destlen, 
		       unsigned char *key, int keylen,
		       unsigned char *tweak, int tweaklen){
  CBC_CHECK_ARGS;
  int ciphersteal = (srclen % AES_BLOCKSIZE);
  int dbg = 0;

  int len = srclen - ciphersteal;
  int tmplen = len;
  nexus_cbc_encrypt_aligned(src, len,
			    dest, &tmplen,
			    key, keylen,
			    tweak, tweaklen);
  assert(tmplen == len);

  if(len == srclen)
    return;

  int i;

  if(dbg){
    printf("last plain:            ");
    for(i = 0; i < ciphersteal; i++){
      printf("%02x ", src[len + i]);
    }
    printf("\n");

    printf("second to last plain:  ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", src[len - AES_BLOCKSIZE + i]);
    }
    printf("\n");


    printf("second to last cipher: ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", dest[len - AES_BLOCKSIZE + i]);
    }
    printf("\n");
  }

  /* ciphertext stealing */
  unsigned char tmpblock[AES_BLOCKSIZE];
  memcpy(tmpblock, src + len, ciphersteal);
  memcpy(tmpblock + ciphersteal, dest + tmplen - AES_BLOCKSIZE + ciphersteal, AES_BLOCKSIZE - ciphersteal);


  if(dbg){
    printf("last plain/cipher:     ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", tmpblock[i]);
    }
    printf("\n");
  }

  unsigned char tmpdest[AES_BLOCKSIZE];
  int tmplen2 = AES_BLOCKSIZE;
  nexus_cbc_encrypt_aligned(tmpblock, AES_BLOCKSIZE,
			    tmpdest, &tmplen2,
			    key, keylen,
			    tweak, tweaklen);
  assert(tmplen2 == AES_BLOCKSIZE);

  if(dbg){
    printf("extended  last ciphr:  ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", tmpdest[i]);
    }
    printf("\n");
  }

  /* swap the last two blocks and truncate */
  memcpy(dest + len, dest + len - AES_BLOCKSIZE, ciphersteal);
  memcpy(dest + len - AES_BLOCKSIZE, tmpdest, AES_BLOCKSIZE);

  if(dbg){
    printf("second to last cipher: ");
    for(i = 0; i < AES_BLOCKSIZE; i++){
      printf("%02x ", dest[len - AES_BLOCKSIZE + i]);
    }
    printf("\n");

    printf("last cipher:           ");
    for(i = 0; i < ciphersteal; i++){
      printf("%02x ", dest[len + i]);
    }
    printf("\n");
  }

  *destlen = srclen;
}

