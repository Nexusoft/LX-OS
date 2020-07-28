#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/buffer.h>
#include <string.h>

#define BSIZE	(8*1024)
#ifndef min
#define min(a, b) ((a<=b) ? (a) : (b))
#endif

#define CIPHER "aes-128-cbc"

void openssl_print_error(void) {
	printf("error = %s\n", ERR_error_string(ERR_get_error(), NULL));
}

void stub(void) 
{
  printf("not implemented\n");
}

RAND_METHOD rand_m;

static int init_state = 0;

void init_AES(void)
{
  ENGINE *nexus_engine;

  if(init_state == 0){
    init_state = 1;
    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();

    rand_m.seed = stub;
    rand_m.bytes = RAND_bytes;
    rand_m.cleanup = stub;
    rand_m.add = stub;
    rand_m.pseudorand = stub;
    rand_m.status = stub;

    //printf("0x%p 0x%p 0x%p\n", RAND_bytes, fakerand, &rand_m);

    nexus_engine = ENGINE_new();
    ENGINE_set_id(nexus_engine, "NexusRANDId");
    ENGINE_set_name(nexus_engine, "NexusRAND");
    if(!ENGINE_set_RAND(nexus_engine, &rand_m)) {
      printf("failed to set engine RSA!\n");
      exit(0);
    }
    if(!ENGINE_add(nexus_engine)) {
      printf("failed to add nexus engine!\n");
      exit(0);
    }
  
    ENGINE_set_default_RAND(nexus_engine);
    RAND_bytes(NULL, 0);
  }
}

int decryptAES(unsigned char *key, int keylen, 
	       unsigned char *encreg, int encsize, 
	       unsigned char *reg, int *size){
  const EVP_CIPHER *cipher=NULL;
  const EVP_MD *dgst=NULL;
  BIO *benc, *wbio;
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned char *iv;

  int index;
  char *datap;
  int len = 0;

  //printf("key=0x%p keylen=%d encreg=0x%p encsize=%d reg=0x%p size=0x%p",
  //key, keylen, encreg, encsize, reg, size);

  if(encsize > EVP_MAX_IV_LENGTH){
    iv = encreg;
    encreg = encreg + EVP_MAX_IV_LENGTH;
  }else{
    printf("encsize impossibly small!\n");
    return -1;
  }

  if(keylen != EVP_MAX_KEY_LENGTH){
    printf("dec: key is too small %d (needs to be %d)!\n", keylen, EVP_MAX_KEY_LENGTH);
    return -1;
  }

  cipher = EVP_get_cipherbyname(CIPHER);
  dgst = EVP_md5();

  if ((benc=BIO_new(BIO_f_cipher())) == NULL){
    printf("bad benc\n");
    return -1;
  }

  /* Since we may be changing parameters work on the encryption
   * context rather than calling BIO_set_cipher().
   */

  BIO_get_cipher_ctx(benc, &ctx);
  if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 0)){
    printf("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
    openssl_print_error();
    return -1;
  }
  if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0)){
    printf("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
    openssl_print_error();
    return -1;
  }
  wbio = BIO_new(BIO_s_mem());
  /* Only encrypt/decrypt as we write the file */
  if (benc != NULL)
    wbio=BIO_push(benc,wbio);
#if 0
  index = 0;
  while(index < encsize){
    if (BIO_write(wbio, encreg + index, min(BSIZE, encsize - index)) != min(BSIZE, encsize - index)){
      printf("error writing output file\n");
      return -1;
    }
    index += min(BSIZE, encsize - index);
  }
#else
  index = 0;
  while(index < encsize){
    index += BIO_write(wbio, encreg + index, encsize - index);
  }
#endif

  /* DAN: don't know why this breaks it */
#if 0
  if (!BIO_flush(wbio)){
    printf("(dec) bad decrypt\n");
    return -1;
  }
#endif

  //printf("(dec) bytes written:%8ld\n",BIO_number_written(wbio));
  len = BIO_get_mem_data(wbio, &datap);
  //printf("(dec) getting memdata: %d\n", len);
  memcpy(reg, datap, min(len, *size));
  *size = min(len, *size);
  BIO_free_all(wbio);

  return 0;
}    
#include <assert.h>
int encryptAES(unsigned char *key, int keylen, 
	       unsigned char **encreg, int *encsize, 
	       unsigned char *reg, int size){
  const EVP_CIPHER *cipher=NULL;
  const EVP_MD *dgst=NULL;
  BIO *benc, *wbio;
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned char iv[EVP_MAX_IV_LENGTH];
  BUF_MEM *encbm;

  int index;
  char *datap;
  int len = 0;
  int i;

  RAND_bytes(iv, EVP_MAX_IV_LENGTH); /* fill IV with random crap */
  /*XXX*/
  assert(EVP_MAX_IV_LENGTH == 16);
  for(i = 0; i < 16; i++) 
    iv[i] = 3;
  
  if(keylen != EVP_MAX_KEY_LENGTH){
    printf("enc: key is too small %d (needs to be %d)!\n", keylen, EVP_MAX_KEY_LENGTH);
    return -1;
  }

  cipher = EVP_get_cipherbyname(CIPHER);
  dgst = EVP_md5();

#endif
  BIO_get_cipher_ctx(benc, &ctx);
  if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1)){
    printf("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
    openssl_print_error();
    return -1;
  }

  if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1)){
    printf("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
    openssl_print_error();
    return -1;
  }
    
  wbio = BIO_new(BIO_s_mem());

  //encbm = BUF_MEM_new();
  //BUF_MEM_grow(encbm, *encsize);
  //BIO_set_mem_buf(wbio, encbm, BIO_NOCLOSE);

  /* put iv into mem_region before encrypt filter is on */
  BIO_write(wbio, iv, EVP_MAX_IV_LENGTH);

  /* Only encrypt/decrypt as we write the file */
  if (benc != NULL)
    wbio=BIO_push(benc,wbio);
    
  index = 0;
  while(index < size){
    index += BIO_write(wbio, reg + index, size - index);
  }

  if (!BIO_flush(wbio)){
    printf("bad encrypt\n");
    BIO_free_all(wbio);
    return -1;
  }

  len = BIO_get_mem_data(wbio, encreg);

  *encsize = min(len, *encsize);

  BIO_set_close(wbio, BIO_NOCLOSE);
  BIO_free_all(wbio);

  return 0;
}



